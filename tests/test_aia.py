"""Tests for AIA chasing (wafer/_aia.py).

Certificates here are generated and signed for real rather than mocked, so
the trust decisions exercise actual signature verification. A test that
stubbed _signed_by_trusted_root would pass just as happily if the check
were deleted, which is the one thing that must never happen quietly.
"""

import datetime
import ipaddress
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from wafer import _aia
from wafer._aia import (
    _ca_issuer_urls,
    _is_ca,
    _is_currently_valid,
    _is_fetchable_url,
    _load_roots,
    _signed_by_trusted_root,
    is_certificate_verify_failure,
    merge_pem_stacks,
    resolve_missing_intermediates,
)
from wafer._errors import ConnectionFailed

from .conftest import (
    AsyncMockResponse,
    MockResponse,
    make_async_session,
    make_sync_session,
)

# ---------------------------------------------------------------------------
# Certificate fixtures
# ---------------------------------------------------------------------------

_NOW = datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc)


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

    def test_probe_failure_yields_nothing(self, pki):
        with patch.object(_aia, "_probe_chain", return_value=[]):
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"]
            )
        assert out == []

    def test_no_roots_means_no_chasing(self, pki):
        """Without a trust store there is nothing to verify against."""

        with patch.object(_aia, "_probe_chain") as probe:
            out = resolve_missing_intermediates("https://leaf.test/", b"")
        assert out == []
        probe.assert_not_called()

    def test_url_without_a_host_is_ignored(self, pki):
        out = resolve_missing_intermediates("not-a-url", pki["root_pems"])
        assert out == []

    def test_exhausted_budget_stops_before_probing(self, pki):
        with patch.object(_aia, "_probe_chain") as probe:
            out = resolve_missing_intermediates(
                "https://leaf.test/", pki["root_pems"], timeout=0
            )
        assert out == []
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
                _aia, "_fetch_certificate", side_effect=lambda url, _t: fetched[url]
            ),
            patch.object(_aia, "_completes_chain", return_value=True),
        ):
            out = resolve_missing_intermediates(
                "https://deep.test/", _pem(root)
            )
        assert out == [_pem(lower), _pem(upper)]

    def test_chase_depth_is_bounded(self, pki):
        """A certificate that names itself must not loop."""

        looping, key = _make_cert(
            "Looping CA",
            _name("Looping CA"),
            _key(),
            ca=True,
            aia_url="http://ca.test/loop.crt",
        )
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
        # The loop ran and was stopped by the cap, not skipped beforehand.
        assert 0 < fetch.call_count <= _aia._MAX_CHASE_DEPTH


# ---------------------------------------------------------------------------
# Fetch limits
# ---------------------------------------------------------------------------


class TestFetchCertificate:
    def test_oversized_response_is_refused(self):
        """A hostile AIA endpoint must not be able to stream without end."""

        class _Response:
            def read(self, size):
                return b"x" * size

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "urlopen", return_value=_Response()):
            assert _aia._fetch_certificate("http://ca.test/big.crt", 5.0) is None

    def test_non_certificate_payload_is_refused(self):
        class _Response:
            def read(self, size):
                return b"<html>not a certificate</html>"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(_aia.urllib.request, "urlopen", return_value=_Response()):
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

        with patch.object(_aia.urllib.request, "urlopen", return_value=_Response()):
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

        with patch.object(_aia.urllib.request, "urlopen", return_value=_Response()):
            got = _aia._fetch_certificate("http://ca.test/x.crt", 5.0)
        assert got is not None
        assert got.subject == pki["intermediate"].subject

    def test_network_error_is_swallowed(self):
        with patch.object(
            _aia.urllib.request, "urlopen", side_effect=OSError("boom")
        ):
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
        # The client has to be rebuilt or the retry reuses the old store.
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


class TestCertStoreSelection:
    def test_unchased_session_uses_the_shared_store(self):
        session, _ = make_sync_session([MockResponse(200)])
        from wafer._base import _SYSTEM_CERT_STORE

        assert session._cert_store() is _SYSTEM_CERT_STORE

    def test_chased_session_gets_its_own_store(self, pki):
        session, _ = make_sync_session([MockResponse(200)])
        from wafer._base import _SYSTEM_CERT_STORE

        session._aia_extra_pems = [_pem(pki["intermediate"])]
        session._aia_cert_store = None
        store = session._cert_store()
        assert store is not None
        if _SYSTEM_CERT_STORE is not None:
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
