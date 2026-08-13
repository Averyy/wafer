"""Tests for AIA chasing (wafer/_aia.py).

Certificates here are generated and signed for real rather than mocked, so
the trust decisions exercise actual signature verification. A test that
stubbed _signed_by_trusted_root would pass just as happily if the check
were deleted, which is the one thing that must never happen quietly.
"""

import datetime
import ipaddress
import ssl
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from wafer import _aia, _base
from wafer._aia import (
    _ca_issuer_urls,
    _is_ca,
    _is_currently_valid,
    _is_fetchable_url,
    _load_roots,
    _signed_by_trusted_root,
    merge_pem_stacks,
    resolve_missing_intermediates,
)
from wafer._base import is_certificate_verify_failure
from wafer._errors import ConnectionFailed, WaferTimeout

from .conftest import (
    AsyncMockResponse,
    MockResponse,
    make_async_session,
    make_sync_session,
)

# ---------------------------------------------------------------------------
# Certificate fixtures
# ---------------------------------------------------------------------------

# Anchored to the real clock, not a fixed date: the chase validates fetched
# certificates against time.time(), so fixtures frozen to a literal would
# start failing wholesale once real time walked past their notAfter.
_NOW = datetime.datetime.now(datetime.timezone.utc)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _make_cert(
    subject: str,
    issuer_name: x509.Name,
    issuer_key,
    *,
    ca: bool,
    not_before: datetime.datetime = _NOW - datetime.timedelta(days=365),
    not_after: datetime.datetime = _NOW + datetime.timedelta(days=365),
    aia_url: str | None = None,
    serial: int | None = None,
):
    """Build and sign a certificate, returning (cert, private_key)."""

    key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
    )
    if aia_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(aia_url),
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="module")
def pki():
    """A root, an intermediate it signed, and a leaf naming that intermediate.

    Mirrors the real shape: the server sends only the leaf, and the leaf's
    AIA points at the intermediate the server failed to send.
    """

    root_key = _key()
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("Test Root"))
        .issuer_name(_name("Test Root"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=3650))
        .not_valid_after(_NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(root_key, hashes.SHA256())
    )
    intermediate, inter_key = _make_cert(
        "Test Intermediate", root.subject, root_key, ca=True
    )
    leaf, _ = _make_cert(
        "leaf.test",
        intermediate.subject,
        inter_key,
        ca=False,
        aia_url="http://ca.test/intermediate.crt",
    )
    # A second, unrelated hierarchy: a CA that no trusted root signed. This
    # stands in for whatever an on-path attacker would serve from the AIA URL.
    rogue_key = _key()
    rogue = (
        x509.CertificateBuilder()
        .subject_name(_name("Test Intermediate"))  # same name as the real one
        .issuer_name(_name("Test Root"))  # claims the real root as issuer
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=365))
        .not_valid_after(_NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(rogue_key, hashes.SHA256())  # self-signed, not root-signed
    )
    return {
        "root": root,
        "root_pems": _pem(root),
        "intermediate": intermediate,
        "leaf": leaf,
        "rogue": rogue,
    }


# ---------------------------------------------------------------------------
# Trust verification -- the security-critical check
# ---------------------------------------------------------------------------


class TestSignedByTrustedRoot:
    def test_accepts_certificate_signed_by_a_root_in_the_store(self, pki):
        assert _signed_by_trusted_root(pki["intermediate"], [pki["root"]])

    def test_rejects_forgery_that_merely_names_a_trusted_issuer(self, pki):
        """The whole point: matching the issuer name is not enough.

        An attacker answering the plain-HTTP AIA fetch controls every field
        of what they return, including the issuer name. Only the signature
        distinguishes a real intermediate from a minted one.
        """

        assert pki["rogue"].issuer == pki["root"].subject
        assert not _signed_by_trusted_root(pki["rogue"], [pki["root"]])

    def test_rejects_when_no_root_matches(self, pki):
        assert not _signed_by_trusted_root(pki["intermediate"], [])

    def test_rejects_leaf_signed_by_an_untrusted_intermediate(self, pki):
        # The leaf is signed by the intermediate, which is not in the store.
        assert not _signed_by_trusted_root(pki["leaf"], [pki["root"]])


# ---------------------------------------------------------------------------
# Certificate sanity gates
# ---------------------------------------------------------------------------


class TestCertificateGates:
    def test_ca_flag_required(self, pki):
        assert _is_ca(pki["intermediate"])
        assert not _is_ca(pki["leaf"])

    def test_expired_ca_rejected(self, pki):
        root_key = _key()
        expired, _ = _make_cert(
            "Expired CA",
            _name("Test Root"),
            root_key,
            ca=True,
            not_before=_NOW - datetime.timedelta(days=800),
            not_after=_NOW - datetime.timedelta(days=400),
        )
        assert not _is_currently_valid(expired, _NOW.timestamp())

    def test_not_yet_valid_ca_rejected(self):
        root_key = _key()
        future, _ = _make_cert(
            "Future CA",
            _name("Test Root"),
            root_key,
            ca=True,
            not_before=_NOW + datetime.timedelta(days=10),
            not_after=_NOW + datetime.timedelta(days=400),
        )
        assert not _is_currently_valid(future, _NOW.timestamp())

    def test_valid_ca_accepted(self, pki):
        assert _is_currently_valid(pki["intermediate"], _NOW.timestamp())


# ---------------------------------------------------------------------------
# AIA URL handling
# ---------------------------------------------------------------------------


def _resolves_to(*addresses):
    """Patch name resolution so URL checks never depend on real DNS."""

    return patch.object(
        _aia.socket,
        "getaddrinfo",
        return_value=[(2, 1, 6, "", (address, 0)) for address in addresses],
    )


class TestFetchableUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "http://cacerts.geotrust.com/GeoTrustTLSRSACAG1.crt",
            "https://ca.example.com/inter.cer",
        ],
    )
    def test_allows_public_http_urls(self, url):
        with _resolves_to("93.184.216.34"):
            assert _is_fetchable_url(url)

    def test_allows_a_public_literal_address(self):
        assert _is_fetchable_url("http://93.184.216.34/inter.crt")

    @pytest.mark.parametrize(
        "url",
        [
            "ldap://ca.example.com/cn=CA",
            "file:///etc/passwd",
            "ftp://ca.example.com/inter.crt",
            "http://127.0.0.1/inter.crt",
            "http://10.0.0.5/inter.crt",
            "http://192.168.1.1/inter.crt",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/inter.crt",
            "not a url",
            "",
        ],
    )
    def test_refuses_non_http_and_internal_targets(self, url):
        """A certificate must not be able to aim the fetch at the local network.

        The AIA URL comes from a certificate that has not been trusted yet,
        so treating it as a fetchable address is only safe if it cannot name
        loopback, link-local, or private space -- including the cloud
        metadata endpoint.
        """

        assert not _is_fetchable_url(url)

    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "192.168.1.1"],
    )
    def test_refuses_a_name_that_resolves_into_local_space(self, address):
        """Checking only literal addresses would leave the hole wide open.

        ``localhost`` and any attacker-controlled name pointing at private
        space reach exactly the same places as the literals above.
        """

        with _resolves_to(address):
            assert not _is_fetchable_url("http://internal-ca.corp/inter.crt")

    def test_refuses_a_name_with_any_local_answer(self):
        """One private answer among public ones is still a way in."""

        with _resolves_to("93.184.216.34", "127.0.0.1"):
            assert not _is_fetchable_url("http://split-horizon.test/inter.crt")

    @pytest.mark.parametrize(
        "url",
        [
            "ldap://ca.test/cn=CA",
            "ftp://ca.test/inter.crt",
            "gopher://ca.test/inter.crt",
            "file://ca.test/etc/passwd",
        ],
    )
    def test_non_http_schemes_are_refused_even_when_the_host_resolves(self, url):
        """The scheme itself must be the reason, not an unresolvable host.

        Testing ldap:// against a name that happens not to resolve, or
        file:// which parses to no hostname at all, passes whether or not
        the scheme check exists.
        """

        with _resolves_to("93.184.216.34"):
            assert not _is_fetchable_url(url)

    def test_refuses_a_name_that_does_not_resolve(self):
        with patch.object(
            _aia.socket, "getaddrinfo", side_effect=OSError("no such host")
        ):
            assert not _is_fetchable_url("http://nowhere.invalid/inter.crt")

    def test_extracts_ca_issuers_url(self, pki):
        with _resolves_to("93.184.216.34"):
            assert _ca_issuer_urls(pki["leaf"]) == [
                "http://ca.test/intermediate.crt"
            ]

    def test_no_aia_extension_yields_nothing(self, pki):
        assert _ca_issuer_urls(pki["root"]) == []

    def test_non_fetchable_aia_url_is_dropped(self):
        root_key = _key()
        cert, _ = _make_cert(
            "leaf.test",
            _name("Test Root"),
            root_key,
            ca=False,
            aia_url="ldap://ca.example.com/cn=CA",
        )
        assert _ca_issuer_urls(cert) == []


# ---------------------------------------------------------------------------
# Trust store parsing
# ---------------------------------------------------------------------------


class TestLoadRoots:
    def test_parses_a_pem_stack(self, pki):
        roots = _load_roots(pki["root_pems"])
        assert len(roots) == 1
        assert roots[0].subject == pki["root"].subject

    def test_one_unparseable_certificate_does_not_lose_the_others(self, pki):
        """macOS ships a root cryptography intends to reject outright.

        Parsing the stack in a single call would drop every root along with
        it and silently disable chasing, so the loss must stay local to the
        bad certificate.
        """

        broken = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"bm90IGEgY2VydGlmaWNhdGU=\n"
            b"-----END CERTIFICATE-----\n"
        )
        roots = _load_roots(broken + pki["root_pems"])
        assert len(roots) == 1
        assert roots[0].subject == pki["root"].subject

    def test_empty_store_yields_no_roots(self):
        assert _load_roots(b"") == []

    def test_results_are_cached_per_stack(self, pki):
        _aia._ROOT_CACHE.clear()
        first = _load_roots(pki["root_pems"])
        second = _load_roots(pki["root_pems"])
        assert first is second


# ---------------------------------------------------------------------------
# PEM merging
# ---------------------------------------------------------------------------


class TestMergePemStacks:
    def test_appends_new_certificates(self, pki):
        merged = merge_pem_stacks(pki["root_pems"], [_pem(pki["intermediate"])])
        assert len(_load_roots(merged)) == 2

    def test_drops_duplicates_of_what_the_base_already_has(self, pki):
        merged = merge_pem_stacks(pki["root_pems"], [pki["root_pems"]])
        assert len(_load_roots(merged)) == 1

    def test_handles_untidy_separators(self, pki):
        ragged = pki["root_pems"].rstrip() + b"garbage between blocks"
        merged = merge_pem_stacks(ragged, [_pem(pki["intermediate"])])
        assert len(_load_roots(merged)) == 2

    def test_empty_base_still_produces_a_usable_stack(self, pki):
        merged = merge_pem_stacks(b"", [_pem(pki["intermediate"])])
        assert len(_load_roots(merged)) == 1


# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------


class TestIsCertificateVerifyFailure:
    @pytest.mark.parametrize(
        "text",
        [
            'reason: "CERTIFICATE_VERIFY_FAILED", reason_code: 125',
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
            "unable to get local issuer certificate",
            "self signed certificate in certificate chain",
        ],
    )
    def test_recognizes_path_failures(self, text):
        assert is_certificate_verify_failure(Exception(text))

    @pytest.mark.parametrize(
        "text",
        [
            "connection refused",
            "dns error: failed to lookup address information",
            "operation timed out",
            "HANDSHAKE_FAILURE",
        ],
    )
    def test_leaves_other_transport_errors_alone(self, text):
        assert not is_certificate_verify_failure(Exception(text))


# ---------------------------------------------------------------------------
# End-to-end resolution, with the network stubbed
# ---------------------------------------------------------------------------


class TestResolveMissingIntermediates:
    @pytest.fixture(autouse=True)
    def _public_dns(self):
        """Make every AIA URL in these tests resolvable and public.

        Without this the URL checks reject the fixture hostnames outright
        and every assertion below passes without the chase ever running.
        """

        with _resolves_to("93.184.216.34"):
            yield

    def test_completes_a_chain_the_server_left_incomplete(self, pki):
        with (
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(
                _aia, "_fetch_certificate", return_value=pki["intermediate"]
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        assert out == [_pem(pki["intermediate"])]

    def test_returns_nothing_when_the_fetched_ca_is_not_root_signed(self, pki):
        """A forged intermediate must never reach the trust store.

        This is the case that decides whether chasing is safe: without the
        signature check the rogue CA would be anchored and the attacker who
        served it could then vouch for anything.
        """

        with (
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(
                _aia, "_fetch_certificate", return_value=pki["rogue"]
            ) as fetch,
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        # The forgery was fetched and then refused, not skipped earlier.
        fetch.assert_called()
        assert out == []

    def test_does_not_chase_when_the_server_sent_a_complete_chain(self, pki):
        """An expired leaf with a good chain must not trigger a fetch.

        Every rejected certificate reports the same CERTIFICATE_VERIFY_FAILED,
        so the only way to tell a missing issuer from an unrelated failure is
        to look at what the server actually sent.
        """

        with (
            patch.object(
                _aia, "_probe_chain", return_value=[pki["leaf"], pki["intermediate"]]
            ),
            patch.object(_aia, "_fetch_certificate") as fetch,
        ):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        assert out == []
        fetch.assert_not_called()

    def test_drops_the_result_when_the_host_still_will_not_verify(self, pki):
        """Proven-good intermediates are still discarded if they fix nothing.

        badssl's expired and wrong-host cases chase up to a genuine CA; adding
        it would enlarge the trust store for a connection that keeps failing.
        """

        with (
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(
                _aia, "_fetch_certificate", return_value=pki["intermediate"]
            ) as fetch,
            patch.object(_aia, "_completes_chain", return_value=False) as verify,
        ):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        # The chase ran to a trusted root and was then thrown away by the
        # verification gate, rather than failing earlier for another reason.
        fetch.assert_called()
        verify.assert_called_once()
        assert out == []

    def test_rejects_a_fetched_certificate_that_is_not_the_named_issuer(self, pki):
        other, _ = _make_cert("Unrelated CA", _name("Test Root"), _key(), ca=True)
        with (
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(_aia, "_fetch_certificate", return_value=other) as fetch,
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        fetch.assert_called()
        assert out == []

    def test_an_unreachable_issuer_endpoint_is_inconclusive(self, pki):
        """A CA endpoint being briefly down says nothing about the chain.

        Swallowed into a verdict, a momentary outage disabled chasing for
        that origin for the rest of the session.
        """

        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=_aia.FetchFailed("down")
            ),
        ):
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"]
                )

    def test_an_unusable_issuer_response_is_still_a_verdict(self, pki):
        """Bytes that arrive and are not a certificate were examined."""

        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(_aia, "_fetch_certificate", return_value=None),
        ):
            assert (
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"]
                )
                == []
            )

    def test_probe_failure_is_inconclusive_not_a_verdict(self, pki):
        """Never seeing the certificate is not the same as judging it.

        Recording it as a verdict would make a momentary probe failure -- a
        DNS hiccup, a refused connection -- permanent for the session.
        """

        with patch.object(_aia, "_probe_chain", return_value=[]):
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"]
                )

    def test_no_roots_means_no_chasing(self, pki):
        """Without a trust store there is nothing to verify against."""

        with patch.object(_aia, "_probe_chain") as probe:
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates("https://leaf.test/", b"")
        probe.assert_not_called()

    def test_url_without_a_host_is_ignored(self, pki):
        out = resolve_missing_intermediates("not-a-url", pki["root_pems"])
        assert out == []

    def test_exhausted_budget_is_inconclusive_not_a_verdict(self, pki):
        """A chase starved of budget never looked, so it must not latch."""

        with patch.object(_aia, "_probe_chain") as probe:
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"], timeout=0
                )
        probe.assert_not_called()

    def test_walks_a_two_deep_chain(self, pki):
        """Two missing intermediates still resolve, in order."""

        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Deep Root"))
            .issuer_name(_name("Deep Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        upper, upper_key = _make_cert(
            "Deep Upper", root.subject, root_key, ca=True
        )
        lower, lower_key = _make_cert(
            "Deep Lower",
            upper.subject,
            upper_key,
            ca=True,
            aia_url="http://ca.test/upper.crt",
        )
        leaf, _ = _make_cert(
            "deep.test",
            lower.subject,
            lower_key,
            ca=False,
            aia_url="http://ca.test/lower.crt",
        )
        fetched = {"http://ca.test/lower.crt": lower, "http://ca.test/upper.crt": upper}
        with (
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia,
                "_fetch_certificate",
                side_effect=lambda url, _t, _p=None: fetched[url],
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://deep.test/", _pem(root)
            )
        assert out == [_pem(lower), _pem(upper)]

    def test_a_chain_needing_the_full_depth_still_resolves(self, pki):
        """The last permitted hop must be tested against the store.

        The root check runs at the top of each pass, so a chain needing
        exactly _MAX_CHASE_DEPTH hops would be rejected after doing all the
        work to complete it.
        """

        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Chain Root"))
            .issuer_name(_name("Chain Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        depth = _aia._MAX_CHASE_DEPTH
        served = {}
        parent_name, parent_key = root.subject, root_key
        certs = []
        # Build depth CAs, root-most first.
        for level in range(depth):
            url = f"http://ca.test/lvl{level}.crt"
            cert, key = _make_cert(
                f"CA level {level}",
                parent_name,
                parent_key,
                ca=True,
                aia_url=None if level == 0 else f"http://ca.test/lvl{level - 1}.crt",
            )
            served[url] = cert
            certs.append((url, cert, key))
            parent_name, parent_key = cert.subject, key
        leaf_url, _, leaf_signer = certs[-1]
        leaf, _ = _make_cert(
            "deep.test",
            certs[-1][1].subject,
            leaf_signer,
            ca=False,
            aia_url=leaf_url,
        )
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: served[u]
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://deep.test/", _pem(root))
        assert len(out) == depth

    def test_chase_depth_is_bounded(self, pki):
        """A certificate that names itself must not loop."""

        # Genuinely self-signed: signed with its own key, so _directly_issued
        # accepts the link and the dedupe is what has to stop the walk. Signing
        # with a throwaway key instead makes the signature check reject it
        # first, and the test then passes with the dedupe deleted.
        loop_key = _key()
        looping = (
            x509.CertificateBuilder()
            .subject_name(_name("Looping CA"))
            .issuer_name(_name("Looping CA"))
            .public_key(loop_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=10))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                "http://ca.test/loop.crt"
                            ),
                        )
                    ]
                ),
                critical=False,
            )
            .sign(loop_key, hashes.SHA256())
        )
        assert _aia._directly_issued(looping, looping)
        with (
            patch.object(_aia, "_probe_chain", return_value=[looping]),
            patch.object(
                _aia, "_fetch_certificate", return_value=looping
            ) as fetch,
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://loop.test/", pki["root_pems"]
            )
        assert out == []
        # Two fetches: the first records the certificate, the second returns
        # the same one and the dedupe stops the walk. Without the dedupe the
        # loop runs to _MAX_CHASE_DEPTH, so a looser bound would pass whether
        # or not it works.
        assert fetch.call_count == 2


# ---------------------------------------------------------------------------
# Fetch limits
# ---------------------------------------------------------------------------


class TestFetchCertificate:
    def test_the_read_is_bounded(self):
        """A hostile endpoint must not be able to stream without end.

        The bound is on the read itself; asserting only that junk is
        rejected would pass whether or not any limit existed, because junk
        fails to parse as a certificate anyway.
        """

        sizes = []

        class _Response:
            def read(self, size):
                sizes.append(size)
                return b"x" * 10

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            _aia._fetch_certificate("http://ca.test/big.crt", 5.0)
        assert sizes == [_aia._MAX_CERT_BYTES + 1]

    def test_an_oversized_but_parseable_certificate_is_refused(self):
        """Rejection must be driven by size, not by failing to parse.

        A certificate stuffed with subject alternative names parses fine and
        is still over the cap, so only the length check can reject it.
        """

        key = _key()
        big = (
            x509.CertificateBuilder()
            .subject_name(_name("Enormous CA"))
            .issuer_name(_name("Enormous CA"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=10))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(f"h{i:05d}.padding.example") for i in range(3000)]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        payload = big.public_bytes(serialization.Encoding.DER)
        assert len(payload) > _aia._MAX_CERT_BYTES, len(payload)
        # Parses cleanly, so only the size check stands between it and use.
        assert x509.load_der_x509_certificate(payload) is not None

        class _Response:
            # Returns more than it was asked for, which is the case the length
            # check exists for -- truncating instead makes the payload
            # unparseable, so the check and its absence look identical.
            def read(self, size):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            assert _aia._fetch_certificate("http://ca.test/big.crt", 5.0) is None

    def test_non_certificate_payload_is_refused(self):
        class _Response:
            def read(self, size):
                return b"<html>not a certificate</html>"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            assert _aia._fetch_certificate("http://ca.test/x.crt", 5.0) is None

    def test_der_payload_is_parsed(self, pki):
        payload = _der(pki["intermediate"])

        class _Response:
            def read(self, size):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            got = _aia._fetch_certificate("http://ca.test/x.crt", 5.0)
        assert got is not None
        assert got.subject == pki["intermediate"].subject

    def test_pem_payload_is_parsed(self, pki):
        payload = _pem(pki["intermediate"])

        class _Response:
            def read(self, size):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            got = _aia._fetch_certificate("http://ca.test/x.crt", 5.0)
        assert got is not None
        assert got.subject == pki["intermediate"].subject

    def test_a_transport_failure_is_reported_not_swallowed(self):
        """No response at all is not the same as an unusable response.

        Swallowing it into None let a momentary CA outage become a settled
        "this chain cannot be completed" verdict for the whole session.
        """

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = OSError("boom")
            with pytest.raises(_aia.FetchFailed):
                _aia._fetch_certificate("http://ca.test/x.crt", 5.0)

    def test_an_unusable_response_is_still_None(self):
        class _Response:
            def read(self, size):
                return b"<html>not a certificate</html>"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            assert _aia._fetch_certificate("http://ca.test/x.crt", 5.0) is None


# ---------------------------------------------------------------------------
# Session wiring
# ---------------------------------------------------------------------------


_VERIFY_ERROR = Exception('reason: "CERTIFICATE_VERIFY_FAILED", reason_code: 125')


class TestSessionIntegration:
    def test_sync_retries_after_completing_the_chain(self, pki):
        session, mock = make_sync_session(
            [_VERIFY_ERROR, MockResponse(200, body="page")]
        )
        rebuilt = []
        session._rebuild_client = lambda: rebuilt.append(True)
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ):
            resp = session.get("https://incomplete.test/")
        assert resp.status_code == 200
        assert mock.request_count == 2
        # Rebuilt exactly once, by the chase itself under the lock that
        # installed the certificate -- not again by the caller.
        assert rebuilt == [True]
        assert session._aia_extra_pems == [_pem(pki["intermediate"])]

    def test_sync_gives_up_when_the_chain_cannot_be_completed(self):
        session, mock = make_sync_session([_VERIFY_ERROR], max_retries=0)
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ):
            with pytest.raises(ConnectionFailed):
                session.get("https://broken.test/")
        assert session._aia_extra_pems == []

    def test_one_attempt_per_host(self):
        """A chain that cannot be completed must not be re-probed forever."""

        session, mock = make_sync_session([_VERIFY_ERROR], max_retries=0)
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ) as resolve:
            for _ in range(3):
                with pytest.raises(ConnectionFailed):
                    session.get("https://broken.test/")
        assert resolve.call_count == 1

    def test_unrelated_transport_errors_do_not_chase(self):
        session, mock = make_sync_session(
            [Exception("connection refused")], max_retries=0
        )
        with patch.object(_aia, "resolve_missing_intermediates") as resolve:
            with pytest.raises(ConnectionFailed):
                session.get("https://down.test/")
        resolve.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_retries_after_completing_the_chain(self, pki):
        session, mock = make_async_session(
            [_VERIFY_ERROR, AsyncMockResponse(200, body="page")]
        )
        rebuilt = []
        session._rebuild_client = lambda: rebuilt.append(True)
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ):
            resp = await session.get("https://incomplete.test/")
        assert resp.status_code == 200
        assert mock.request_count == 2
        assert rebuilt == [True]
        assert session._aia_extra_pems == [_pem(pki["intermediate"])]

    @pytest.mark.asyncio
    async def test_async_unrelated_errors_do_not_chase(self):
        session, mock = make_async_session(
            [Exception("connection refused")], max_retries=0
        )
        with patch.object(_aia, "resolve_missing_intermediates") as resolve:
            with pytest.raises(ConnectionFailed):
                await session.get("https://down.test/")
        resolve.assert_not_called()


class TestChainLinkVerification:
    """Every hop must be signature-linked, not just the top one.

    Each collected certificate becomes a trust anchor, so verifying only the
    certificate that reaches a root would let an attacker who answers the
    plain-HTTP fetch insert a CA of their own underneath it.
    """

    def test_forged_link_under_a_genuine_root_signed_ca_is_refused(self, pki):
        # I1' claims the leaf's issuer name and points its AIA at the real,
        # root-signed intermediate, so the walk still terminates at a trusted
        # root -- but I1' signed nothing in the path.
        forged_key = _key()
        forged = (
            x509.CertificateBuilder()
            .subject_name(pki["leaf"].issuer)
            .issuer_name(pki["intermediate"].subject)
            .public_key(forged_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=10))
            .not_valid_after(_NOW + datetime.timedelta(days=300))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                "http://ca.test/real.crt"
                            ),
                        )
                    ]
                ),
                critical=False,
            )
            .sign(forged_key, hashes.SHA256())
        )
        assert forged.subject == pki["leaf"].issuer  # name matches
        served = {
            "http://ca.test/intermediate.crt": forged,
            "http://ca.test/real.crt": pki["intermediate"],
        }
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(
                _aia,
                "_fetch_certificate",
                side_effect=lambda url, _t, _p=None: served[url],
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        assert out == []

    def test_genuine_two_deep_chain_still_resolves(self, pki):
        """The linkage check must not break legitimate multi-hop chains."""

        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Deep Root"))
            .issuer_name(_name("Deep Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        upper, upper_key = _make_cert("Deep Upper", root.subject, root_key, ca=True)
        lower, lower_key = _make_cert(
            "Deep Lower",
            upper.subject,
            upper_key,
            ca=True,
            aia_url="http://ca.test/upper.crt",
        )
        leaf, _ = _make_cert(
            "deep.test",
            lower.subject,
            lower_key,
            ca=False,
            aia_url="http://ca.test/lower.crt",
        )
        served = {
            "http://ca.test/lower.crt": lower,
            "http://ca.test/upper.crt": upper,
        }
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia,
                "_fetch_certificate",
                side_effect=lambda url, _t, _p=None: served[url],
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://deep.test/", _pem(root))
        assert out == [_pem(lower), _pem(upper)]


class TestPathTop:
    """Position on the wire does not determine the top of the path."""

    def test_leaf_plus_root_is_still_treated_as_incomplete(self, pki):
        """Appending the root while omitting the intermediate is a real error.

        chain[-1] would be the self-signed, trusted root, making the chain
        look complete when the piece that matters is exactly what is missing.
        Chrome chases such a site.
        """

        top = _aia._path_top([pki["leaf"], pki["root"]])
        assert top is pki["leaf"]
        assert not _signed_by_trusted_root(top, [pki["root"]])

    def test_ordered_chain_walks_to_the_intermediate(self, pki):
        top = _aia._path_top([pki["leaf"], pki["intermediate"]])
        assert top is pki["intermediate"]

    def test_unordered_complete_chain_walks_to_the_root(self, pki):
        """TLS 1.3 drops the ordering requirement, so position means nothing.

        Sent out of order this chain is still complete, and the walk has to
        reach the root rather than stopping at whatever came last.
        """

        top = _aia._path_top([pki["leaf"], pki["root"], pki["intermediate"]])
        assert top is pki["root"]
        assert _signed_by_trusted_root(top, [pki["root"]])

    def test_unordered_incomplete_chain_stops_below_the_gap(self, pki):
        """An unrelated certificate sent last must not end the walk."""

        unrelated, _ = _make_cert(
            "Unrelated CA", _name("Somewhere Else"), _key(), ca=True
        )
        top = _aia._path_top([pki["leaf"], unrelated])
        assert top is pki["leaf"]

    def test_leaf_plus_root_is_chased_end_to_end(self, pki):
        """Drive the leaf+root shape through the chase, not just the helper.

        Reading the last certificate on the wire instead of walking issuer
        links finds a self-signed trusted root and concludes the chain is
        complete, so the chase never runs. The unit test on _path_top does
        not catch that, because it never exercises the call site.
        """

        with (
            _resolves_to("93.184.216.34"),
            # Server appends the root but omits the intermediate.
            patch.object(
                _aia, "_probe_chain", return_value=[pki["leaf"], pki["root"]]
            ),
            patch.object(
                _aia,
                "_fetch_certificate",
                side_effect=lambda u, t, p=None: pki["intermediate"],
            ) as fetch,
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        fetch.assert_called()
        assert out == [_pem(pki["intermediate"])]

    def test_single_certificate_chain_is_its_own_top(self, pki):
        assert _aia._path_top([pki["leaf"]]) is pki["leaf"]

    def test_self_signed_leaf_terminates_the_walk(self, pki):
        assert _aia._path_top([pki["root"], pki["root"]]) is pki["root"]


class TestRedirectGuard:
    """urllib follows redirects; the URL guard must run on every hop."""

    def test_redirect_into_private_space_is_refused(self):
        handler = _aia._GuardedRedirectHandler()
        assert (
            handler.redirect_request(
                None, None, 302, "Found", {}, "http://169.254.169.254/latest/"
            )
            is None
        )

    def test_redirect_to_a_non_http_scheme_is_refused(self):
        handler = _aia._GuardedRedirectHandler()
        assert (
            handler.redirect_request(None, None, 302, "Found", {}, "file:///etc/passwd")
            is None
        )

    def test_public_redirect_is_allowed(self):
        handler = _aia._GuardedRedirectHandler()
        with (
            _resolves_to("93.184.216.34"),
            patch.object(
                _aia.urllib.request.HTTPRedirectHandler,
                "redirect_request",
                return_value="allowed",
            ),
        ):
            got = handler.redirect_request(
                None, None, 302, "Found", {}, "http://cdn.ca.test/inter.crt"
            )
        assert got == "allowed"

    def test_the_guarded_handler_is_installed_on_every_fetch(self):
        class _Response:
            def read(self, size):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            _aia._fetch_certificate("http://ca.test/x.crt", 5.0)
        assert any(
            isinstance(h, _aia._GuardedRedirectHandler)
            for h in build.call_args.args
        )


class TestConnectTimeAddressGuard:
    """Validation and dialling must be one step.

    Checking a hostname and letting urllib resolve it again leaves a window
    in which the answer can change -- the certificate that named the URL is
    untrusted, so a low-TTL record answering public once and loopback next
    is entirely within reach.
    """

    def _conn(self, host):
        cls = _aia._guarded_connection_factory(_aia.http.client.HTTPConnection, 80)
        return cls(host)

    def test_a_host_resolving_into_private_space_is_refused_at_connect(self):
        conn = self._conn("rebind.test")
        with _resolves_to("127.0.0.1"):
            with pytest.raises(_aia.urllib.error.URLError):
                conn.connect()

    def test_a_public_host_is_dialled_at_its_validated_address(self):
        conn = self._conn("ca.test")
        dialled = []

        def _capture(address, timeout=None, source_address=None):
            dialled.append(address)
            raise OSError("stop before real I/O")

        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia.socket, "create_connection", _capture),
        ):
            with pytest.raises(OSError):
                conn.connect()
        assert dialled == [("93.184.216.34", 80)]

    def test_the_guard_runs_on_the_address_actually_used(self):
        """One resolution, and the dialled address comes from it."""

        conn = self._conn("flip.test")
        answers = iter([("93.184.216.34", 0), ("127.0.0.1", 0)])
        dialled = []

        def _flip(host, *a, **kw):
            return [(2, 1, 6, "", next(answers))]

        def _capture(address, timeout=None, source_address=None):
            dialled.append(address)
            raise OSError("stop")

        with (
            patch.object(_aia.socket, "getaddrinfo", _flip),
            patch.object(_aia.socket, "create_connection", _capture),
        ):
            with pytest.raises(OSError):
                conn.connect()
        # The address dialled is the one that was checked, not a re-resolve.
        assert dialled == [("93.184.216.34", 80)]


class TestChaseBudget:
    """The chase must not spend the budget the retry needs."""

    def test_takes_only_a_share_of_the_callers_remaining_time(self, pki):
        seen = {}

        def _probe(host, port, timeout, proxy=None, resolve=None):
            seen["timeout"] = timeout
            return []  # -> ChaseInconclusive, which these tests expect

        with patch.object(_aia, "_probe_chain", side_effect=_probe):
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"], timeout=60.0
                )
        # Not the full 60s, and never above the per-probe cap.
        assert seen["timeout"] <= _aia._PROBE_TIMEOUT

    def test_total_chase_is_capped_even_on_a_huge_budget(self, pki):
        with patch.object(_aia, "_probe_chain", return_value=[]) as probe:
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"], timeout=3600.0
                )
        probe.assert_called_once()

    def test_a_small_caller_budget_is_respected(self, pki):
        seen = {}

        def _probe(host, port, timeout, proxy=None, resolve=None):
            seen["timeout"] = timeout
            return []  # -> ChaseInconclusive, which these tests expect

        with patch.object(_aia, "_probe_chain", side_effect=_probe):
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"], timeout=4.0
                )
        assert seen["timeout"] <= 4.0 * _aia._MAX_BUDGET_SHARE + 0.1


class TestProxiedUrlGuard:
    """Behind a proxy the local resolver describes neither route nor policy."""

    def test_names_are_not_locally_resolved_when_proxied(self):
        with patch.object(
            _aia.socket, "getaddrinfo", side_effect=OSError("no DNS here")
        ) as resolve:
            assert _is_fetchable_url("http://ca.test/x.crt", proxied=True)
        resolve.assert_not_called()

    def test_literal_private_addresses_are_still_refused_when_proxied(self):
        assert not _is_fetchable_url("http://169.254.169.254/x", proxied=True)
        assert not _is_fetchable_url("http://127.0.0.1/x", proxied=True)

    def test_non_http_schemes_are_still_refused_when_proxied(self):
        assert not _is_fetchable_url("file:///etc/passwd", proxied=True)


class TestCertFailureIsBounded:
    """A repaired-then-still-failing origin must not spin the retry loop.

    Reporting the chase's success again on each later failure told the caller
    to retry without consuming any budget, so nothing terminated: measured at
    412,474 handshake attempts in three seconds, surfacing as WaferTimeout
    that hid the real certificate error. The fix is that a caller arriving
    after the chase settled gets False, which drops it onto the ordinary
    retry path -- bounded by retries, rotations and backoff like any other
    connection error.
    """

    def test_attempts_are_bounded_when_the_repair_does_not_take(self, pki):
        session, mock = make_sync_session(
            [_VERIFY_ERROR], max_retries=2, max_rotations=0
        )
        session._rebuild_client = lambda: None
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ):
            with pytest.raises((ConnectionFailed, WaferTimeout)):
                session.get("https://incomplete.test/", timeout=5)
        # One initial attempt, one post-chase retry, then the normal ladder.
        # The exact count does not matter; that it is small does.
        assert mock.request_count <= 8, mock.request_count

    def test_the_chase_runs_once_however_many_attempts_follow(self, pki):
        session, _ = make_sync_session([_VERIFY_ERROR], max_retries=2, max_rotations=0)
        session._rebuild_client = lambda: None
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ) as resolve:
            with pytest.raises((ConnectionFailed, WaferTimeout)):
                session.get("https://incomplete.test/", timeout=5)
        resolve.assert_called_once()

    def test_a_retry_can_still_recover_a_mixed_certificate_pool(self, pki):
        """Retries must survive: one node of a pool can serve a stale cert.

        A host behind several addresses can have a single node failing
        verification after a partial deploy, and a retry re-resolves onto a
        healthy one. Treating a certificate error as terminal would lose that.
        """

        session, mock = make_sync_session(
            [_VERIFY_ERROR, MockResponse(200, body="ok")],
            max_retries=2,
            max_rotations=0,
        )
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ):
            resp = session.get("https://mixed.test/", timeout=10)
        assert resp.status_code == 200
        assert mock.request_count == 2

    @pytest.mark.asyncio
    async def test_async_attempts_are_bounded(self, pki):
        session, mock = make_async_session(
            [_VERIFY_ERROR], max_retries=2, max_rotations=0
        )
        session._rebuild_client = lambda: None
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ):
            with pytest.raises((ConnectionFailed, WaferTimeout)):
                await session.get("https://incomplete.test/", timeout=5)
        assert mock.request_count <= 8, mock.request_count


class TestFetchedCertificateGatesEndToEnd:
    """The CA gates must be reachable through the chase, not just unit-tested.

    Call-site mutation showed deleting this gate from resolve_missing_
    intermediates left the whole suite green: both helpers had direct unit
    tests, but nothing drove a bad candidate through the chase itself.
    """

    def test_a_root_signed_non_ca_is_refused(self):
        # Signed by a trusted root, so only the CA gate can reject it.
        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Gate Root"))
            .issuer_name(_name("Gate Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        not_a_ca, key = _make_cert("Gate CA", root.subject, root_key, ca=False)
        leaf, _ = _make_cert(
            "gate.test", not_a_ca.subject, key, ca=False,
            aia_url="http://ca.test/gate.crt",
        )
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: not_a_ca
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://gate.test/", _pem(root))
        assert out == []

    def test_a_root_signed_expired_ca_is_refused(self):
        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Gate Root"))
            .issuer_name(_name("Gate Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        expired, key = _make_cert(
            "Gate CA",
            root.subject,
            root_key,
            ca=True,
            not_before=datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc),
        )
        leaf, _ = _make_cert(
            "gate.test", expired.subject, key, ca=False,
            aia_url="http://ca.test/gate.crt",
        )
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: expired
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://gate.test/", _pem(root))
        assert out == []


class TestEgressContracts:
    """Chasing must never make a connection the session would not make.

    Both guards protect documented contracts: resolve= pins destinations for
    untrusted URLs, and proxy= is the egress path the operator chose. A probe
    that dialled directly would break either one silently.
    """

    def test_resolve_pin_is_passed_to_the_chase_not_used_to_skip_it(self):
        """A pinned session must still get the fix, with the pin honored.

        fetchaller pins every fetch, so skipping the chase whenever resolve=
        is set would mean the consumer that reported the bug never sees it
        fixed. The pin is threaded into the probe instead.
        """

        pins = {"pinned.test": ["93.184.216.34"]}
        session, _ = make_sync_session(
            [_VERIFY_ERROR], max_retries=0, resolve=pins
        )
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ) as resolve:
            with pytest.raises(ConnectionFailed):
                session.get("https://pinned.test/")
        resolve.assert_called_once()
        assert resolve.call_args.kwargs["resolve"] == pins

    def test_probe_dials_the_pinned_address_not_a_resolved_one(self):
        """The pin must not be reopened by the probe's own DNS lookup."""

        created = []

        def _fake_create_connection(address, timeout=None, source_address=None):
            created.append(address)
            raise OSError("stop here")

        with (
            patch.object(_aia.http.client, "HTTPSConnection") as conn_cls,
            patch.object(
                _aia.socket, "create_connection", _fake_create_connection
            ),
        ):
            conn = conn_cls.return_value
            conn.connect.side_effect = lambda: conn._create_connection(
                ("pinned.test", 443)
            )
            _aia._probe_chain(
                "pinned.test",
                443,
                5.0,
                None,
                {"pinned.test": ["203.0.113.7"]},
            )
        assert created == [("203.0.113.7", 443)]

    @pytest.mark.parametrize(
        "proxy", ["socks5://127.0.0.1:1080", "socks4://p:1080", "https://p:8443"]
    )
    def test_untunnelable_proxies_disable_chasing(self, proxy):
        session, _ = make_sync_session([_VERIFY_ERROR], max_retries=0)
        session._proxy_url = proxy
        with patch.object(_aia, "resolve_missing_intermediates") as resolve:
            with pytest.raises(ConnectionFailed):
                session.get("https://broken.test/")
        resolve.assert_not_called()

    def test_http_proxy_is_passed_through_to_the_chase(self, pki):
        session, _ = make_sync_session(
            [_VERIFY_ERROR, MockResponse(200, body="page")]
        )
        session._proxy_url = "http://proxy.test:8080"
        session._rebuild_client = lambda: None
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ) as resolve:
            session.get("https://incomplete.test/")
        assert resolve.call_args.kwargs["proxy_url"] == "http://proxy.test:8080"

    @pytest.mark.parametrize(
        "proxy,supported",
        [
            (None, True),
            ("http://p:8080", True),
            ("https://p:8443", False),
            ("socks5://p:1080", False),
            ("socks5h://p:1080", False),
            ("socks4://p:1080", False),
        ],
    )
    def test_proxy_scheme_support(self, proxy, supported):
        assert _aia.proxy_supports_chasing(proxy) is supported

    def test_probe_tunnels_through_an_http_proxy(self):
        """The probe must reach the origin via CONNECT, not a direct socket."""

        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            _aia._probe_chain("origin.test", 443, 5.0, "http://proxy.test:8080")
        # Dialled the proxy, then tunnelled to the origin.
        assert conn_cls.call_args.args[0] == "proxy.test"
        assert conn_cls.call_args.args[1] == 8080
        conn_cls.return_value.set_tunnel.assert_called_once_with(
            "origin.test", 443, headers={}
        )

    def test_proxy_credentials_are_carried_through_the_tunnel(self):
        """Scraping proxies normally carry credentials.

        Without a Proxy-Authorization header the CONNECT gets a 407 and the
        probe dies, while the urllib fetch path survives because ProxyHandler
        reads the credentials itself -- an asymmetry that reads as "chasing
        does not work behind my proxy" and latches the origin as unfixable.
        """

        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            _aia._probe_chain(
                "origin.test", 443, 5.0, "http://bob:s3cr3t@proxy.test:8080"
            )
        headers = conn_cls.return_value.set_tunnel.call_args.kwargs["headers"]
        import base64 as _b64

        assert headers["Proxy-Authorization"] == "Basic " + _b64.b64encode(
            b"bob:s3cr3t"
        ).decode()

    def test_percent_encoded_proxy_credentials_are_decoded(self):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            _aia._probe_chain(
                "origin.test", 443, 5.0, "http://bob:p%40ss%3Aword@proxy.test:8080"
            )
        headers = conn_cls.return_value.set_tunnel.call_args.kwargs["headers"]
        import base64 as _b64

        assert headers["Proxy-Authorization"] == "Basic " + _b64.b64encode(
            b"bob:p@ss:word"
        ).decode()

    def test_probe_connects_directly_without_a_proxy(self):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            _aia._probe_chain("origin.test", 443, 5.0, None)
        assert conn_cls.call_args.args[0] == "origin.test"
        conn_cls.return_value.set_tunnel.assert_not_called()

    def test_fetch_uses_the_proxy_when_one_is_set(self, pki):
        payload = _der(pki["intermediate"])

        class _Response:
            def read(self, size):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = _Response()
            _aia._fetch_certificate(
                "http://ca.test/x.crt", 5.0, "http://proxy.test:8080"
            )
        proxies = [
            h for h in build.call_args.args
            if isinstance(h, _aia.urllib.request.ProxyHandler)
        ]
        assert len(proxies) == 1
        assert proxies[0].proxies == {
            "http": "http://proxy.test:8080",
            "https": "http://proxy.test:8080",
        }


class TestTransportConsistency:
    def test_native_transport_gets_the_proven_intermediates(self, pki):
        """One URL must not succeed or fail depending on the transport.

        The Imperva fallback builds its own SSL context, so without this a
        host whose chain the wreq path completed would still fail there.
        """

        session, _ = make_sync_session([MockResponse(200)])
        session._aia_extra_pems = [_pem(pki["intermediate"])]
        session._native_tls = None
        transport = session._native_transport()
        # Compare on subject, not serial: OpenSSL zero-pads serialNumber to an
        # even number of hex digits while Python's int formatting does not, so
        # a serial of odd hex length would mismatch at random.
        loaded = {
            tuple(sorted(part for rdn in cert["subject"] for part in rdn))
            for cert in transport._ctx.get_ca_certs()
        }
        expected = ("commonName", "Test Intermediate")
        assert any(expected in subject for subject in loaded)

    def test_a_completed_chain_rebuilds_the_native_transport(self, pki):
        """A cached context would keep failing on the chain just fixed."""

        session, _ = make_sync_session([MockResponse(200)])
        first = session._native_transport()
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ):
            assert session._complete_chain_via_aia("https://incomplete.test/")
        assert session._native_tls is None
        assert session._native_transport() is not first


class TestAnchorConstraints:
    """Anchoring must not hand back authority a root withheld."""

    def _constrained_root(self):
        key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Constrained Root"))
            .issuer_name(_name("Constrained Root"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=[x509.DNSName("example.gov")],
                    excluded_subtrees=None,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return root, key

    def test_name_constrained_root_blocks_anchoring(self, pki):
        """Anchoring below a name-constrained root would widen its reach.

        Validation stops at an anchor, so the root's permitted namespaces
        would no longer be enforced against anything the intermediate signs.
        """

        root, key = self._constrained_root()
        inter, _ = _make_cert("Constrained CA", root.subject, key, ca=True)
        assert _aia._anchoring_would_drop_constraints(inter, root)

    def test_unconstrained_root_allows_anchoring(self, pki):
        assert not _aia._anchoring_would_drop_constraints(
            pki["intermediate"], pki["root"]
        )

    def test_path_length_zero_is_not_treated_as_a_constraint(self, pki):
        """Real intermediates carry pathLen:0 and must still be usable.

        GeoTrust TLS RSA CA G1 -the certificate this feature exists to
        fetch- has pathLen:0. Refusing on it would reject the motivating
        case to guard against something an attacker cannot reach anyway.
        """

        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("PathLen Root"))
            .issuer_name(_name("PathLen Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        inter_key = _key()
        inter = (
            x509.CertificateBuilder()
            .subject_name(_name("PathLen CA"))
            .issuer_name(root.subject)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(root_key, hashes.SHA256())
        )
        assert not _aia._anchoring_would_drop_constraints(inter, root)
        assert _is_ca(inter)

    def _ca_with_eku(self, ekus):
        key = _key()
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name("EKU CA"))
            .issuer_name(_name("Some Root"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=10))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        )
        if ekus is not None:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(ekus), critical=False
            )
        return builder.sign(key, hashes.SHA256())

    def test_a_ca_barred_from_server_auth_is_refused(self):
        """EKU is enforced while walking a chain; anchoring stops that.

        Same argument as name constraints: an intermediate restricted to
        code signing must not become an anchor that can vouch for a TLS
        server.
        """

        from cryptography.x509.oid import ExtendedKeyUsageOID

        assert not _is_ca(self._ca_with_eku([ExtendedKeyUsageOID.CODE_SIGNING]))

    def test_a_ca_permitting_server_auth_is_accepted(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        assert _is_ca(
            self._ca_with_eku(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            )
        )

    def test_any_extended_key_usage_is_accepted(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        assert _is_ca(
            self._ca_with_eku([ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
        )

    def test_absent_eku_is_unrestricted(self):
        assert _is_ca(self._ca_with_eku(None))

    def test_a_server_auth_barred_ca_is_refused_end_to_end(self):
        """Drive it through the chase, not only the helper."""

        from cryptography.x509.oid import ExtendedKeyUsageOID

        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("EKU Root"))
            .issuer_name(_name("EKU Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        inter_key = _key()
        inter = (
            x509.CertificateBuilder()
            .subject_name(_name("EKU CA"))
            .issuer_name(root.subject)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        leaf, _ = _make_cert(
            "eku.test", inter.subject, inter_key, ca=False,
            aia_url="http://ca.test/inter.crt",
        )
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: inter
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://eku.test/", _pem(root))
        assert out == []

    def test_ca_without_key_cert_sign_is_refused(self):
        """CA:TRUE is the claim; keyCertSign is the permission."""

        key = _key()
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name("No Signing CA"))
            .issuer_name(_name("Some Root"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=10))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        assert not _is_ca(cert)

    def test_constrained_mid_path_certificate_aborts_the_chase(self):
        """Every collected certificate is anchored, not just the terminal one.

        A constrained certificate part-way up the walk is still a place the
        constraints would stop being enforced, so checking only the one that
        reaches a root would leave the hole open one hop down.
        """

        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Deep Root"))
            .issuer_name(_name("Deep Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        upper, upper_key = _make_cert("Deep Upper", root.subject, root_key, ca=True)
        # The constrained certificate sits BELOW the one that reaches the root.
        lower_key = _key()
        lower = (
            x509.CertificateBuilder()
            .subject_name(_name("Deep Lower"))
            .issuer_name(upper.subject)
            .public_key(lower_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=[x509.DNSName("deep.test")],
                    excluded_subtrees=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                "http://ca.test/upper.crt"
                            ),
                        )
                    ]
                ),
                critical=False,
            )
            .sign(upper_key, hashes.SHA256())
        )
        leaf, _ = _make_cert(
            "deep.test",
            lower.subject,
            lower_key,
            ca=False,
            aia_url="http://ca.test/lower.crt",
        )
        served = {
            "http://ca.test/lower.crt": lower,
            "http://ca.test/upper.crt": upper,
        }
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: served[u]
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://deep.test/", _pem(root))
        assert out == []

    def test_constrained_chain_yields_nothing_end_to_end(self):
        root, key = self._constrained_root()
        inter, inter_key = _make_cert("Constrained CA", root.subject, key, ca=True)
        leaf, _ = _make_cert(
            "site.example.gov",
            inter.subject,
            inter_key,
            ca=False,
            aia_url="http://ca.test/inter.crt",
        )
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: inter
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://site.example.gov/", _pem(root))
        assert out == []


class TestPathLengthEnforcement:
    """pathLen must be enforced because anchoring stops it being enforced.

    root -> upper(pathLen=0) -> lower(CA) -> leaf is a path RFC 5280
    rejects. Anchoring `lower` makes validation start there and never look
    at `upper`, so it would be accepted. The confirmation handshake shares
    the same blind spot, since it runs against the same anchors.
    """

    def _hierarchy(self, upper_path_len):
        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("PL Root"))
            .issuer_name(_name("PL Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        upper_key = _key()
        upper = (
            x509.CertificateBuilder()
            .subject_name(_name("PL Upper"))
            .issuer_name(root.subject)
            .public_key(upper_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=upper_path_len), True
            )
            .sign(root_key, hashes.SHA256())
        )
        lower_key = _key()
        lower = (
            x509.CertificateBuilder()
            .subject_name(_name("PL Lower"))
            .issuer_name(upper.subject)
            .public_key(lower_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                "http://ca.test/upper.crt"
                            ),
                        )
                    ]
                ),
                critical=False,
            )
            .sign(upper_key, hashes.SHA256())
        )
        leaf, _ = _make_cert(
            "pl.test", lower.subject, lower_key, ca=False,
            aia_url="http://ca.test/lower.crt",
        )
        served = {
            "http://ca.test/lower.crt": lower,
            "http://ca.test/upper.crt": upper,
        }
        return root, leaf, served

    def _chase(self, root, leaf, served):
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: served[u]
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            return resolve_missing_intermediates("https://pl.test/", _pem(root))

    def test_path_length_violation_is_refused(self):
        root, leaf, served = self._hierarchy(upper_path_len=0)
        assert self._chase(root, leaf, served) == []

    def test_sufficient_path_length_is_accepted(self):
        root, leaf, served = self._hierarchy(upper_path_len=1)
        assert len(self._chase(root, leaf, served)) == 2

    def test_unconstrained_path_length_is_accepted(self):
        root, leaf, served = self._hierarchy(upper_path_len=None)
        assert len(self._chase(root, leaf, served)) == 2

    def _root_with_path_len(self, limit):
        key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("RootPL"))
            .issuer_name(_name("RootPL"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=limit), True)
            .sign(key, hashes.SHA256())
        )
        inter, inter_key = _make_cert("RootPL CA", root.subject, key, ca=True)
        leaf, _ = _make_cert(
            "rootpl.test", inter.subject, inter_key, ca=False,
            aia_url="http://ca.test/inter.crt",
        )
        return root, leaf, inter

    def _run(self, root, leaf, inter):
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: inter
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            return resolve_missing_intermediates(
                "https://rootpl.test/", _pem(root)
            )

    def test_the_issuing_roots_own_path_length_is_enforced(self):
        """A root with pathLen:0 that issued a CA yields a chain RFC 5280
        rejects; anchoring below it would accept."""

        root, leaf, inter = self._root_with_path_len(0)
        assert self._run(root, leaf, inter) == []

    def test_a_sufficient_root_path_length_is_accepted(self):
        root, leaf, inter = self._root_with_path_len(1)
        assert len(self._run(root, leaf, inter)) == 1

    def test_an_unconstrained_root_is_accepted(self):
        root, leaf, inter = self._root_with_path_len(None)
        assert len(self._run(root, leaf, inter)) == 1

    def test_sent_intermediates_count_against_path_length(self, pki):
        """Certificates the server sent sit below the fetched one too."""

        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("PL2 Root"))
            .issuer_name(_name("PL2 Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        # pathLen=0 permits no CA below it, but the server sends one.
        upper_key = _key()
        upper = (
            x509.CertificateBuilder()
            .subject_name(_name("PL2 Upper"))
            .issuer_name(root.subject)
            .public_key(upper_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(root_key, hashes.SHA256())
        )
        sent_ca, sent_key = _make_cert(
            "PL2 Sent", upper.subject, upper_key, ca=True,
            aia_url="http://ca.test/upper.crt",
        )
        leaf, _ = _make_cert("pl.test", sent_ca.subject, sent_key, ca=False)
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf, sent_ca]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: upper
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates("https://pl.test/", _pem(root))
        assert out == []


class TestTerminalRootSignature:
    """The terminal certificate must be SIGNED by a store root, not just name it.

    The rogue fixture elsewhere is rejected one step earlier, by the
    per-hop signature check, so it never reaches this gate. This builds a
    chain whose lower links are all genuinely signed and whose terminal
    certificate only claims a trusted issuer.
    """

    def test_terminal_certificate_naming_a_root_it_lacks_a_signature_from(self, pki):
        fake_root_key = _key()
        # Same subject as the real trusted root, different key.
        impostor_top_key = _key()
        impostor_top = (
            x509.CertificateBuilder()
            .subject_name(_name("Impostor CA"))
            .issuer_name(pki["root"].subject)  # names the trusted root
            .public_key(impostor_top_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(fake_root_key, hashes.SHA256())  # but signed by nobody real
        )
        lower, lower_key = _make_cert(
            "Impostor Lower",
            impostor_top.subject,
            impostor_top_key,
            ca=True,
            aia_url="http://ca.test/top.crt",
        )
        leaf, _ = _make_cert(
            "imp.test", lower.subject, lower_key, ca=False,
            aia_url="http://ca.test/lower.crt",
        )
        served = {
            "http://ca.test/lower.crt": lower,
            "http://ca.test/top.crt": impostor_top,
        }
        # Every hop below is genuinely signed, so only the terminal
        # root-signature check can reject this.
        assert _aia._directly_issued(leaf, lower)
        assert _aia._directly_issued(lower, impostor_top)
        assert impostor_top.issuer == pki["root"].subject
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=[leaf]),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: served[u]
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://imp.test/", pki["root_pems"]
            )
        assert out == []


class TestClientPublication:
    """A rebuild must not lose a certificate a concurrent chase installed.

    _cert_store both reads and writes the shared certificate list, and every
    rotation and retirement rebuild reaches it without otherwise holding the
    lock. Unlocked, a rebuild that snapshotted the list before an install
    would write the snapshot back, erasing the proven certificate and
    overwriting the cache invalidation -- and since the origin is already
    recorded as attempted, the host stays unreachable for the session.
    """

    def test_a_rebuild_racing_an_install_keeps_the_certificate(self, pki):
        import threading as _t

        session, _ = make_sync_session([MockResponse(200)])
        first, second = _pem(pki["intermediate"]), _pem(pki["root"])
        session._aia_extra_pems = [first]
        session._aia_cert_store = None

        gate = _t.Event()
        real_drop = _aia.drop_expired_pems

        def _slow_drop(pems):
            out = real_drop(pems)
            gate.set()
            _t.Event().wait(0.2)
            return out

        with patch.object(_aia, "drop_expired_pems", _slow_drop):
            reader = _t.Thread(target=session._cert_store)
            reader.start()
            assert gate.wait(3)
            with session._aia_lock:
                session._aia_extra_pems.append(second)
                session._aia_cert_store = None
                session._aia_generation += 1
            reader.join(5)

        assert second in session._aia_extra_pems
        assert first in session._aia_extra_pems

    def test_a_stale_build_does_not_overwrite_a_newer_client(self, pki):
        """The generation compare-and-set had no test at all before this."""

        session, _ = make_sync_session([MockResponse(200)])
        builds = []

        class _Client:
            def __init__(self, **kwargs):
                builds.append(self)

        def _bump_midway(**kwargs):
            # A chase lands while this build is in flight.
            if len(builds) == 0:
                session._aia_generation += 1
            return {}

        with (
            patch.object(_aia, "drop_expired_pems", lambda p: list(p)),
            patch("wreq.blocking.Client", _Client),
            patch.object(
                type(session), "_build_client_kwargs", side_effect=_bump_midway
            ),
            patch.object(type(session), "_hydrate_jar_from_cache", lambda s: None),
        ):
            type(session)._rebuild_client(session)
        # The first candidate was discarded and a second built, so the client
        # that gets published is the one that saw the new generation.
        assert len(builds) == 2
        assert session._client is builds[-1]

    def test_the_final_attempt_never_publishes_stale_state(self, pki):
        """Giving up must not mean publishing state already known to be stale.

        Returning the last unchecked candidate publishes trust state that a
        concurrent chase has already superseded -- the exact failure this
        helper exists to prevent.
        """

        session, _ = make_sync_session([MockResponse(200)])
        seen_generations = []

        def _build():
            # Bump on every build except while the lock is held, which the
            # final attempt does -- so the last build sees a stable value.
            seen_generations.append(session._aia_generation)
            if not session._aia_lock._is_owned():
                session._aia_generation += 1
            return object()

        published = session._publish_under_generation(_build)
        assert published is not None
        # The last build ran with the generation it published under.
        assert session._aia_generation == seen_generations[-1]

    def test_publication_gives_up_after_the_retry_bound(self, pki):
        """A pathological generation churn must not spin forever."""

        session, _ = make_sync_session([MockResponse(200)])
        from wafer._base import _MAX_CLIENT_PUBLISH_ATTEMPTS

        builds = []

        class _Client:
            def __init__(self, **kwargs):
                builds.append(self)

        def _always_bump(**kwargs):
            session._aia_generation += 1
            return {}

        with (
            patch("wreq.blocking.Client", _Client),
            patch.object(
                type(session), "_build_client_kwargs", side_effect=_always_bump
            ),
            patch.object(type(session), "_hydrate_jar_from_cache", lambda s: None),
        ):
            type(session)._rebuild_client(session)
        assert len(builds) == _MAX_CLIENT_PUBLISH_ATTEMPTS
        assert session._client is builds[-1]


class TestPresentedPathCounting:
    """pathLen must count what is really below, not what happened to arrive.

    A server sending its leaf plus a stale or unrelated certificate is a
    common misconfiguration. Counting those against a fetched issuer's
    pathLen makes a perfectly good pathLen:0 CA look like a violation and
    aborts the chase for exactly the servers this feature targets.
    """

    def _leaf_and_issuer(self):
        root_key = _key()
        root = (
            x509.CertificateBuilder()
            .subject_name(_name("Junk Root"))
            .issuer_name(_name("Junk Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=3650))
            .not_valid_after(_NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(root_key, hashes.SHA256())
        )
        inter_key = _key()
        inter = (
            x509.CertificateBuilder()
            .subject_name(_name("Junk CA"))
            .issuer_name(root.subject)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=100))
            .not_valid_after(_NOW + datetime.timedelta(days=100))
            # pathLen:0 is what real intermediates carry.
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(root_key, hashes.SHA256())
        )
        leaf, _ = _make_cert(
            "junk.test", inter.subject, inter_key, ca=False,
            aia_url="http://ca.test/inter.crt",
        )
        return root, leaf, inter

    def _chase(self, root, chain, inter):
        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia, "_probe_chain", return_value=chain),
            patch.object(
                _aia, "_fetch_certificate", side_effect=lambda u, t, p=None: inter
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            return resolve_missing_intermediates("https://junk.test/", _pem(root))

    def test_leaf_only_resolves(self):
        root, leaf, inter = self._leaf_and_issuer()
        assert self._chase(root, [leaf], inter) == [_pem(inter)]

    def test_an_unrelated_extra_certificate_does_not_abort_the_chase(self, pki):
        root, leaf, inter = self._leaf_and_issuer()
        # The walk stops at the leaf, so the junk certificate is not below
        # the fetched issuer and must not count against its pathLen.
        assert self._chase(root, [leaf, pki["intermediate"]], inter) == [
            _pem(inter)
        ]

    def test_a_duplicated_leaf_does_not_abort_the_chase(self):
        root, leaf, inter = self._leaf_and_issuer()
        assert self._chase(root, [leaf, leaf], inter) == [_pem(inter)]


class TestConcurrentChase:
    """Parallel requests to one broken host must not fail the losers."""

    def test_second_caller_waits_and_reports_the_winners_result(self, pki):
        import threading as _t

        session, _ = make_sync_session([MockResponse(200)])
        started = _t.Event()
        release = _t.Event()

        def _slow(url, pems, **kw):
            started.set()
            release.wait(5)
            return [_pem(pki["intermediate"])]

        results = {}
        with patch.object(
            _aia, "resolve_missing_intermediates", side_effect=_slow
        ):
            winner = _t.Thread(
                target=lambda: results.__setitem__(
                    "winner", session._complete_chain_via_aia("https://slow.test/")
                )
            )
            winner.start()
            assert started.wait(5)
            loser = _t.Thread(
                target=lambda: results.__setitem__(
                    "loser", session._complete_chain_via_aia("https://slow.test/")
                )
            )
            loser.start()
            release.set()
            winner.join(10)
            loser.join(10)

        # The loser must not report failure for work that succeeded: it waited
        # and saw the certificate the winner installed.
        assert results["winner"] is True
        assert results["loser"] is True
        assert len(session._aia_extra_pems) == 1

    def test_a_different_port_on_one_host_is_chased_separately(self):
        """Two services on one name can present different chains.

        Keying only by hostname would let a chase against :8443 suppress the
        one :443 still needs.
        """

        session, _ = make_sync_session([MockResponse(200)])
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ) as resolve:
            session._complete_chain_via_aia("https://one.test:8443/")
            session._complete_chain_via_aia("https://one.test/")
        assert resolve.call_count == 2
        assert ("one.test", 8443) in session._aia_attempted
        assert ("one.test", 443) in session._aia_attempted

    def test_the_same_origin_is_only_chased_once(self):
        session, _ = make_sync_session([MockResponse(200)])
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ) as resolve:
            for _ in range(3):
                session._complete_chain_via_aia("https://one.test/")
        assert resolve.call_count == 1

    def test_eviction_never_removes_an_in_flight_chase(self):
        """Evicting a running chase hands its origin a second owner.

        That is the duplicate-probe race the table exists to prevent, and
        the first owner would then delete the second owner's verdict.
        """

        session, _ = make_sync_session([MockResponse(200)])
        from wafer._base import _AIA_MAX_TRACKED_HOSTS

        # Oldest entry is in flight; the rest are settled.
        busy = _base._AiaChase()
        session._aia_attempted[("busy.test", 443)] = busy
        for i in range(_AIA_MAX_TRACKED_HOSTS - 1):
            done = _base._AiaChase()
            done.done.set()
            session._aia_attempted[(f"done{i}.test", 443)] = done

        with patch.object(_aia, "resolve_missing_intermediates", return_value=[]):
            session._complete_chain_via_aia("https://fresh.test/")

        assert ("busy.test", 443) in session._aia_attempted
        assert ("fresh.test", 443) in session._aia_attempted

    def test_the_origin_table_is_bounded(self):
        session, _ = make_sync_session([MockResponse(200)])
        from wafer._base import _AIA_MAX_TRACKED_HOSTS

        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ):
            for i in range(_AIA_MAX_TRACKED_HOSTS + 20):
                session._complete_chain_via_aia(f"https://h{i}.test/")
        assert len(session._aia_attempted) == _AIA_MAX_TRACKED_HOSTS

    def test_an_inconclusive_chase_does_not_record_a_verdict(self):
        """The whole `except ChaseInconclusive` path had no coverage.

        Deleting the handler left the suite green, so the "origin is
        forgotten" behaviour was correct but unpinned.
        """

        session, _ = make_sync_session([MockResponse(200)])
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            side_effect=_aia.ChaseInconclusive("no budget"),
        ):
            assert session._complete_chain_via_aia("https://transient.test/") is False
        # Forgotten, not settled, so a later request tries again.
        assert ("transient.test", 443) not in session._aia_attempted
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ) as resolve:
            session._complete_chain_via_aia("https://transient.test/")
        resolve.assert_called_once()

    def test_an_inconclusive_chase_still_releases_waiters(self):
        session, _ = make_sync_session([MockResponse(200)])
        seen = {}

        def _capture(*a, **kw):
            seen["state"] = session._aia_attempted[("transient.test", 443)]
            raise _aia.ChaseInconclusive("no budget")

        with patch.object(
            _aia, "resolve_missing_intermediates", side_effect=_capture
        ):
            session._complete_chain_via_aia("https://transient.test/")
        assert seen["state"].done.is_set()

    def test_budget_exhausted_before_the_fetch_is_inconclusive(self, pki):
        """Out of budget mid-chase is the same non-verdict as before probing.

        The clock is burned inside the probe so this reaches the fetch
        check, not the pre-probe one -- ticking on every monotonic() call
        exhausts the budget before the probe and tests nothing here.
        """

        clock = {"t": 1000.0}

        def _probe(*a, **kw):
            clock["t"] += 10_000.0  # the probe eats the whole budget
            return [pki["leaf"]]

        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia.time, "monotonic", lambda: clock["t"]),
            patch.object(_aia, "_probe_chain", side_effect=_probe),
            patch.object(_aia, "_fetch_certificate") as fetch,
        ):
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"], timeout=30.0
                )
        fetch.assert_not_called()

    def test_budget_exhausted_before_confirmation_is_inconclusive(self, pki):
        clock = {"t": 1000.0}

        def _fetch(url, timeout, proxy=None):
            clock["t"] += 10_000.0  # the fetch eats the rest of the budget
            return pki["intermediate"]

        with (
            _resolves_to("93.184.216.34"),
            patch.object(_aia.time, "monotonic", lambda: clock["t"]),
            patch.object(_aia, "_probe_chain", return_value=[pki["leaf"]]),
            patch.object(_aia, "_fetch_certificate", side_effect=_fetch),
            patch.object(_aia, "_completes_chain") as confirm,
        ):
            with pytest.raises(_aia.ChaseInconclusive):
                resolve_missing_intermediates(
                    "https://leaf.test/", pki["root_pems"], timeout=30.0
                )
        confirm.assert_not_called()

    def test_waiters_are_released_when_the_chase_fails(self):
        session, _ = make_sync_session([MockResponse(200)])
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[]
        ):
            assert session._complete_chain_via_aia("https://broken.test/") is False
        # Event set, so a later caller answers immediately rather than blocking.
        assert session._aia_attempted[("broken.test", 443)].done.is_set()
        assert session._complete_chain_via_aia("https://broken.test/") is False

    def test_waiters_are_released_when_the_chase_raises(self):
        session, _ = make_sync_session([MockResponse(200)])
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            side_effect=RuntimeError("boom"),
        ):
            assert session._complete_chain_via_aia("https://raising.test/") is False
        assert session._aia_attempted[("raising.test", 443)].done.is_set()


class TestPython312Fallback:
    """get_unverified_chain is 3.13+; the 3.12 path must still work.

    requires-python is >=3.12, so this branch ships and runs for real users
    but never executes on this interpreter unless forced.
    """

    def test_leaf_only_fallback_when_the_chain_api_is_absent(self, pki):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            sock = conn_cls.return_value.sock
            # On 3.12 the attribute does not exist at all.
            sock.get_unverified_chain.side_effect = AttributeError
            sock.getpeercert.return_value = _der(pki["leaf"])
            chain = _aia._probe_chain("origin.test", 443, 5.0)
        assert len(chain) == 1
        assert chain[0].subject == pki["leaf"].subject

    def test_no_certificate_at_all_yields_an_empty_chain(self):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            sock = conn_cls.return_value.sock
            sock.get_unverified_chain.side_effect = AttributeError
            sock.getpeercert.return_value = None
            assert _aia._probe_chain("origin.test", 443, 5.0) == []


class TestConnectionCleanup:
    """A failed handshake must not leave its socket behind.

    _completes_chain connects on purpose to hosts whose certificates are
    still bad, so this is the common path rather than an edge case.
    """

    def test_failed_handshake_closes_the_connection(self):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            conn = conn_cls.return_value
            conn.connect.side_effect = ssl.SSLError("handshake failed")
            with pytest.raises(ssl.SSLError):
                _aia._tls_connection(
                    "origin.test", 443, ssl.create_default_context(), 5.0, None
                )
            conn.close.assert_called_once()

    def test_failed_probe_does_not_leak(self):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            conn = conn_cls.return_value
            conn.connect.side_effect = OSError("refused")
            assert _aia._probe_chain("origin.test", 443, 5.0) == []
            conn.close.assert_called_once()

    def test_failed_confirmation_does_not_leak(self, pki):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            conn = conn_cls.return_value
            conn.connect.side_effect = ssl.SSLError("still invalid")
            assert not _aia._completes_chain(
                "origin.test", 443, pki["root_pems"], [], 5.0
            )
            conn.close.assert_called_once()

    def test_successful_probe_closes_the_connection(self, pki):
        with patch.object(_aia.http.client, "HTTPSConnection") as conn_cls:
            conn = conn_cls.return_value
            conn.sock.get_unverified_chain.return_value = [_der(pki["leaf"])]
            got = _aia._probe_chain("origin.test", 443, 5.0)
            assert len(got) == 1
            conn.close.assert_called_once()


class TestAnchorExpiry:
    """An anchor's own validity is not checked by the verifier, so check here.

    A session can outlive a short-lived intermediate; without this it would
    go on trusting one the PKI has stopped vouching for.
    """

    def test_expired_anchor_is_dropped_from_the_store(self, pki):
        root_key = _key()
        expired, _ = _make_cert(
            "Expired Anchor",
            _name("Some Root"),
            root_key,
            ca=True,
            not_before=datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc),
        )
        session, _ = make_sync_session([MockResponse(200)])
        session._aia_extra_pems = [_pem(expired), _pem(pki["intermediate"])]
        session._aia_cert_store = None
        session._cert_store()
        assert session._aia_extra_pems == [_pem(pki["intermediate"])]

    def test_store_falls_back_when_every_anchor_expired(self):
        root_key = _key()
        expired, _ = _make_cert(
            "Expired Anchor",
            _name("Some Root"),
            root_key,
            ca=True,
            not_before=datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc),
        )
        session, _ = make_sync_session([MockResponse(200)])
        session._aia_extra_pems = [_pem(expired)]
        session._aia_cert_store = None
        from wafer._base import _SYSTEM_CERT_STORE

        assert session._cert_store() is _SYSTEM_CERT_STORE
        assert session._aia_extra_pems == []

    def test_pruning_runs_against_a_warm_cache(self, pki):
        """The prune must not be gated on a cold store cache.

        Both other tests here start from a fresh session whose cache is
        already None, which is the one state where a cache-gated prune would
        also run -- so they pass whether or not the gate exists. Warming the
        cache first is what pins the behaviour.
        """

        session, _ = make_sync_session([MockResponse(200)])
        session._aia_extra_pems = [_pem(pki["intermediate"])]
        session._aia_cert_store = None
        session._cert_store()
        assert session._aia_cert_store is not None  # cache now warm

        calls = []

        def _drop(pems):
            calls.append(len(pems))
            return []

        with patch.object(_aia, "drop_expired_pems", _drop):
            session._cert_store()
        assert calls, "prune skipped once the store cache was warm"
        assert session._aia_extra_pems == []

    def test_withdrawing_an_anchor_clears_the_settled_verdict(self, pki):
        """Otherwise the origin can never be repaired after a renewal.

        The chase succeeded, so the origin is settled; expiry then withdraws
        the anchor. Without clearing the verdict the host fails verification
        forever, even though its AIA now serves a renewed intermediate.
        """

        session, _ = make_sync_session([MockResponse(200)])
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ):
            assert session._complete_chain_via_aia("https://renew.test/")
        assert ("renew.test", 443) in session._aia_attempted

        with patch.object(_aia, "drop_expired_pems", lambda p: []):
            session._cert_store()
        assert ("renew.test", 443) not in session._aia_attempted

        # And the origin can now be chased again.
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["root"])],
        ) as resolve:
            assert session._complete_chain_via_aia("https://renew.test/")
        resolve.assert_called_once()

    def test_an_in_flight_chase_is_not_forgotten_by_a_prune(self, pki):
        session, _ = make_sync_session([MockResponse(200)])
        state = _base._AiaChase()
        session._aia_attempted[("busy.test", 443)] = state  # done not set
        session._aia_extra_pems = [_pem(pki["intermediate"])]
        session._aia_cert_store = None
        with patch.object(_aia, "drop_expired_pems", lambda p: []):
            session._cert_store()
        assert ("busy.test", 443) in session._aia_attempted

    def _short_lived_ca(self):
        key = _key()
        return (
            x509.CertificateBuilder()
            .subject_name(_name("Short CA"))
            .issuer_name(_name("Short Root"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(seconds=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
        )

    def test_expiry_is_enforced_without_a_client_rebuild(self, pki):
        """A session that never rotates must still stop trusting an anchor.

        Pruning only from the client build meant an already-built client held
        an expired anchor for the life of the session, and the verifier does
        not check an anchor's own validity.
        """

        session, _ = make_sync_session([MockResponse(200)])
        short = self._short_lived_ca()
        with patch.object(
            _aia, "resolve_missing_intermediates", return_value=[_pem(short)]
        ):
            assert session._complete_chain_via_aia("https://short.test/")
        assert session._aia_expires_at is not None

        # Nothing rebuilds; only time passes.
        with patch.object(
            _aia.time, "time", lambda: session._aia_expires_at + 1
        ), patch.object(_base.time, "time", lambda: session._aia_expires_at + 1):
            assert session._expire_aia_anchors_if_due() is True
        assert session._aia_extra_pems == []
        assert session._aia_expires_at is None

    def test_the_check_is_a_no_op_before_expiry(self, pki):
        session, _ = make_sync_session([MockResponse(200)])
        with patch.object(
            _aia,
            "resolve_missing_intermediates",
            return_value=[_pem(pki["intermediate"])],
        ):
            session._complete_chain_via_aia("https://live.test/")
        assert session._expire_aia_anchors_if_due() is False
        assert len(session._aia_extra_pems) == 1

    def test_the_check_is_free_when_nothing_was_chased(self):
        session, _ = make_sync_session([MockResponse(200)])
        assert session._aia_expires_at is None
        assert session._expire_aia_anchors_if_due() is False

    def test_pruning_invalidates_both_transports(self, pki):
        """An existing native-TLS transport must not keep the old anchor."""

        session, _ = make_sync_session([MockResponse(200)])
        session._aia_extra_pems = [_pem(pki["intermediate"])]
        session._aia_cert_store = None
        session._native_transport()
        assert session._native_tls is not None
        generation = session._aia_generation

        with patch.object(_aia, "drop_expired_pems", lambda p: []):
            session._cert_store()
        assert session._native_tls is None
        assert session._aia_generation > generation

    def test_live_anchors_are_kept(self, pki):
        assert _aia.drop_expired_pems([_pem(pki["intermediate"])]) == [
            _pem(pki["intermediate"])
        ]

    def test_unparseable_pem_is_dropped(self):
        assert _aia.drop_expired_pems([b"not a certificate"]) == []


class TestCertStoreSelection:
    def test_unchased_session_uses_the_shared_store(self):
        session, _ = make_sync_session([MockResponse(200)])
        from wafer._base import _SYSTEM_CERT_STORE

        assert session._cert_store() is _SYSTEM_CERT_STORE

    def test_chased_session_gets_its_own_store(self, pki):
        session, _ = make_sync_session([MockResponse(200)])
        from wafer._base import _SYSTEM_CERT_STORE

        assert _SYSTEM_CERT_STORE is not None, "no system trust store to test against"
        session._aia_extra_pems = [_pem(pki["intermediate"])]
        session._aia_cert_store = None
        store = session._cert_store()
        assert store is not None
        assert store is not _SYSTEM_CERT_STORE

    def test_store_is_built_once_and_reused(self, pki):
        """_build_client_kwargs runs on every rotation; rebuilding is waste."""

        session, _ = make_sync_session([MockResponse(200)])
        session._aia_extra_pems = [_pem(pki["intermediate"])]
        session._aia_cert_store = None
        assert session._cert_store() is session._cert_store()


def test_ip_helper_matches_stdlib_classification():
    """Guard the address checks against a stdlib behavior change."""

    assert ipaddress.ip_address("169.254.169.254").is_link_local
    assert ipaddress.ip_address("10.0.0.1").is_private
    # 203.0.113.0/24 is TEST-NET-3, which stdlib reports as private; a
    # genuinely routable address is the right positive control.
    assert not ipaddress.ip_address("93.184.216.34").is_private
