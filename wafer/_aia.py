"""AIA chasing: complete a server's incomplete certificate chain.

A TLS server is supposed to send every certificate between its leaf and a
trusted root. Some send only the leaf. The chain is not actually broken --
the missing intermediate exists and is signed by a root everyone already
trusts -- the server just fails to present it, so a strict client cannot
build a path and the handshake fails with CERTIFICATE_VERIFY_FAILED.

Browsers paper over this by fetching the missing certificate from the URL
the leaf itself names in its Authority Information Access extension, which
is why such a site loads in Chrome and fails in every HTTP library. wafer's
contract is that a site loading in a browser loads in wafer, so it chases
too.

The security-relevant part is what happens to the fetched certificate.
Adding it to a trust store makes it a trust *anchor*: BoringSSL will accept
anything it signs without ever walking up to a root. AIA URLs are plain
HTTP by RFC 5280, so an on-path attacker can answer that fetch. Handing a
forged CA anchor status would convert a handshake that fails closed today
into one that fails open -- strictly worse than the bug being fixed.

So nothing is trusted on the strength of having been fetched.
``resolve_missing_intermediates`` returns a certificate only after proving
it is signed by a root already in the caller's trust store, using that
store and no other. Once proven, anchoring it grants no authority the
issuing root did not already delegate. Anything that fails a check is
dropped and the original handshake failure stands.
"""

import ipaddress
import logging
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
import warnings
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

logger = logging.getLogger("wafer")

# A CA certificate is a couple of KB. This bounds a hostile or misconfigured
# AIA endpoint that would otherwise stream indefinitely into memory.
_MAX_CERT_BYTES = 64 * 1024

# Chase depth. Two missing intermediates is already pathological; this stops
# a chain of AIA URLs from becoming an unbounded fetch loop.
_MAX_CHASE_DEPTH = 4

# A no-verify probe reads the certificate the server offers; it never carries
# request or response data, so a MITM can influence only which certificate is
# examined, and every certificate is verified before use regardless.
_PROBE_TIMEOUT = 10.0

# The AIA fetch and the probe each get a slice of the caller's budget rather
# than the whole thing, so a stalled CA endpoint cannot consume the request
# deadline that the retry after a successful chase still needs.
_FETCH_TIMEOUT = 10.0

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

# Parsed roots, keyed by the exact PEM stack they came from. The store is
# read once at import and reused for the process lifetime, so this parses
# ~150 certificates once rather than on every chase.
_ROOT_CACHE: dict[bytes, list[x509.Certificate]] = {}

_CERT_VERIFY_MARKERS = (
    "certificate_verify_failed",
    "certificate verify failed",
    "unable to get local issuer",
    "self signed certificate",
    "self-signed certificate",
)


def is_certificate_verify_failure(error: BaseException) -> bool:
    """Report whether a transport error is a certificate path failure.

    wreq surfaces BoringSSL's verdict as an opaque nested error string, so
    this matches the reason text rather than an exception type. Matching
    conservatively is deliberate: a false positive costs one wasted probe
    and the original error is still raised, while a false negative leaves
    the site permanently unreachable.
    """

    text = str(error).lower()
    return any(marker in text for marker in _CERT_VERIFY_MARKERS)


def _load_roots(pem_stack: bytes) -> list[x509.Certificate]:
    """Parse the trust store wafer actually uses into certificates.

    Verification has to happen against the same roots the TLS client was
    given. Checking against a different store (Python's, say) could accept
    an intermediate whose root wafer does not trust, or reject one it does.

    Certificates are parsed one at a time rather than as a stack. Shipped
    trust stores contain long-lived roots that predate rules now enforced --
    macOS carries one with a non-positive serial number, which cryptography
    warns about today and intends to reject outright. Parsing the stack in
    one call means that single root takes every other root down with it and
    silently disables chasing; parsing individually costs one skipped root.
    """

    cached = _ROOT_CACHE.get(pem_stack)
    if cached is not None:
        return cached
    roots: list[x509.Certificate] = []
    with warnings.catch_warnings():
        # These certificates come from the OS trust store; the user cannot
        # act on a deprecation notice about one, so it is not worth surfacing.
        warnings.simplefilter("ignore")
        for block in _PEM_BLOCK.findall(pem_stack):
            try:
                roots.append(x509.load_pem_x509_certificate(block))
            except Exception:
                continue
    if not roots:
        logger.debug("Could not parse any roots from the trust store")
    _ROOT_CACHE[pem_stack] = roots
    return roots


def _probe_chain(host: str, port: int, timeout: float) -> list[x509.Certificate]:
    """Read the chain a server presents, leaf first, without trusting it.

    The chain cannot be completed without knowing what is missing, and the
    certificates name their own issuers in their AIA extensions -- but the
    handshake that would deliver them is the one that just failed. This
    handshake is used solely to read what was offered and is torn down
    immediately; no request is issued over it.

    Reading the whole chain rather than just the leaf is what separates an
    incomplete chain from an unrelated verification failure. Every rejected
    certificate reports the same opaque CERTIFICATE_VERIFY_FAILED, so an
    expired leaf sent with a perfectly good chain is indistinguishable from
    a valid leaf sent with no chain until the certificates are examined.
    """

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                try:
                    ders = list(tls.get_unverified_chain() or ())
                except AttributeError:
                    # get_unverified_chain is 3.13+. On 3.12 only the leaf is
                    # reachable, so a server that sent a complete chain is not
                    # detectable here -- _completes_chain catches that case
                    # before anything is added to the trust store.
                    leaf = tls.getpeercert(binary_form=True)
                    ders = [leaf] if leaf else []
    except (OSError, ssl.SSLError, ValueError):
        logger.debug("AIA probe failed for %s:%d", host, port, exc_info=True)
        return []
    chain: list[x509.Certificate] = []
    for der in ders:
        try:
            chain.append(x509.load_der_x509_certificate(der))
        except Exception:
            break
    return chain


def _completes_chain(
    host: str,
    port: int,
    trust_store_pems: bytes,
    extra_pems: list[bytes],
    timeout: float,
) -> bool:
    """Confirm the fetched intermediates actually make this host verify.

    Proving an intermediate is root-signed says it is safe to trust; it does
    not say it was the missing piece. A server whose leaf is expired, or
    whose name does not match, fails verification with a chain that was
    never incomplete, and chasing its AIA yields a real intermediate that
    changes nothing. Adding certificates to the trust store for a host that
    still will not verify is pointless, so the whole result is dropped
    unless a full verification now succeeds.
    """

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        merged = merge_pem_stacks(trust_store_pems, extra_pems)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx.load_verify_locations(cadata=merged.decode("ascii"))
    except Exception:
        logger.debug("Could not build verification context", exc_info=True)
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (OSError, ssl.SSLError, ValueError):
        logger.debug(
            "%s still does not verify with the fetched intermediates", host
        )
        return False


def _ca_issuer_urls(cert: x509.Certificate) -> list[str]:
    """Extract the caIssuers URLs a certificate names for its own issuer."""

    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []
    urls: list[str] = []
    for description in aia:
        if description.access_method != AuthorityInformationAccessOID.CA_ISSUERS:
            continue
        location = description.access_location
        if not isinstance(location, x509.UniformResourceIdentifier):
            continue
        url = location.value
        if isinstance(url, str) and _is_fetchable_url(url):
            urls.append(url)
    return urls


def _is_public_address(host: str) -> bool:
    """Report whether a literal address is outside private and local space."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
    )


def _is_fetchable_url(url: str) -> bool:
    """Allow only plain http/https AIA URLs that resolve to public addresses.

    The AIA location comes from a certificate that has not been trusted yet,
    so it is attacker-influenced input that names a URL wafer will fetch.
    Two things follow. Non-http schemes are refused, because RFC 5280 allows
    ldap:// and others that urllib would either fail on or, for file://,
    read off local disk. And the host is resolved and checked, because
    refusing only literal addresses would still let a name like
    ``internal-ca.corp`` or ``localhost`` point the fetch at the network the
    client runs on -- the metadata endpoint included.

    Resolving here and again in urllib leaves a small window where an answer
    could change between the two, which is why nothing fetched is trusted on
    the strength of where it came from.
    """

    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return _is_public_address(host)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos if info[4]}
    return bool(addresses) and all(
        _is_public_address(address) for address in addresses
    )


def _fetch_certificate(url: str, timeout: float) -> x509.Certificate | None:
    """Fetch one certificate from an AIA URL, DER or PEM.

    CAs publish DER at these URLs (``.crt``/``.cer``) but PEM appears often
    enough to be worth accepting. The response is capped: a certificate is
    a few KB and the size limit is what stops a hostile endpoint from
    streaming without end.
    """

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "wafer", "Accept": "*/*"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(_MAX_CERT_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError):
        logger.debug("AIA fetch failed for %s", url, exc_info=True)
        return None
    if not payload or len(payload) > _MAX_CERT_BYTES:
        logger.debug("AIA response from %s empty or over the size cap", url)
        return None
    try:
        return x509.load_der_x509_certificate(payload)
    except Exception:
        pass
    try:
        return x509.load_pem_x509_certificate(payload)
    except Exception:
        logger.debug("AIA response from %s is not a certificate", url)
        return None


def _is_ca(cert: x509.Certificate) -> bool:
    """Require the fetched certificate to actually claim to be a CA."""

    try:
        constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except Exception:
        return False
    return bool(getattr(constraints, "ca", False))


def _is_currently_valid(cert: x509.Certificate, now: float) -> bool:
    """Reject an expired or not-yet-valid CA certificate.

    Anchoring an expired intermediate would accept certificates the public
    PKI has already stopped vouching for.
    """

    try:
        not_before = cert.not_valid_before_utc.timestamp()
        not_after = cert.not_valid_after_utc.timestamp()
    except Exception:
        return False
    return not_before <= now <= not_after


def _signed_by_trusted_root(
    cert: x509.Certificate,
    roots: list[x509.Certificate],
) -> bool:
    """Prove a certificate is signed by a root already in the trust store.

    This is the check that keeps AIA chasing from weakening anything. A
    certificate that passes was already delegated authority by a root the
    client trusts, so anchoring it grants nothing new; a certificate that
    fails is indistinguishable from one an attacker minted, and is dropped.
    """

    for root in roots:
        if root.subject != cert.issuer:
            continue
        try:
            cert.verify_directly_issued_by(root)
        except (ValueError, TypeError):
            continue
        except Exception:
            continue
        return True
    return False


def resolve_missing_intermediates(
    url: str,
    trust_store_pems: bytes,
    *,
    timeout: float | None = None,
) -> list[bytes]:
    """Return PEM certificates that complete this host's chain, if any.

    Every returned certificate has been proven to be signed by a root in
    ``trust_store_pems``. An empty list means the chain could not be
    completed from trusted material, and the caller must let the original
    handshake failure stand.
    """

    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return []
    port = parsed.port or 443
    roots = _load_roots(trust_store_pems)
    if not roots:
        return []

    budget = timeout if timeout is not None else _PROBE_TIMEOUT + _FETCH_TIMEOUT
    deadline = time.monotonic() + budget

    def remaining(cap: float) -> float:
        return min(cap, max(0.0, deadline - time.monotonic()))

    probe_timeout = remaining(_PROBE_TIMEOUT)
    if probe_timeout <= 0:
        return []
    chain = _probe_chain(host, port, probe_timeout)
    if not chain:
        return []
    # Chase from the deepest certificate the server actually sent. A server
    # that sent part of its chain is missing only what comes above it, and
    # starting from the leaf would re-fetch what is already on the wire.
    cert = chain[-1]
    if _signed_by_trusted_root(cert, roots):
        # The chain reaches the trust store on its own, so nothing is
        # missing and the handshake failed for some other reason -- an
        # expired or revoked leaf, a name mismatch. None of that is fixable
        # by fetching certificates, and all of it must keep failing.
        logger.debug(
            "%s sent a complete chain; verification failed for another reason",
            host,
        )
        return []

    collected: list[bytes] = []
    seen: set[bytes] = set()
    anchored = False
    for _ in range(_MAX_CHASE_DEPTH):
        if _signed_by_trusted_root(cert, roots):
            # The path terminates in the existing trust store; everything
            # gathered on the way is proven material.
            anchored = True
            break
        urls = _ca_issuer_urls(cert)
        if not urls:
            break
        issuer = None
        for candidate_url in urls:
            fetch_timeout = remaining(_FETCH_TIMEOUT)
            if fetch_timeout <= 0:
                return []
            candidate = _fetch_certificate(candidate_url, fetch_timeout)
            if candidate is None:
                continue
            # The fetched certificate must be the issuer this certificate
            # actually names, a CA, and unexpired. None of these establish
            # trust on their own -- _signed_by_trusted_root does that on the
            # next pass -- they just refuse obvious junk before spending
            # another round trip on it.
            if candidate.subject != cert.issuer:
                logger.debug(
                    "AIA certificate from %s is not the named issuer",
                    candidate_url,
                )
                continue
            if not _is_ca(candidate) or not _is_currently_valid(
                candidate, time.time()
            ):
                logger.debug(
                    "AIA certificate from %s is not a valid CA", candidate_url
                )
                continue
            fingerprint = candidate.public_bytes(Encoding.DER)
            if fingerprint in seen:
                # A certificate that names itself, directly or through a
                # cycle, would otherwise be re-fetched until the depth cap.
                break
            seen.add(fingerprint)
            issuer = candidate
            break
        if issuer is None:
            break
        # Kept, but not trusted yet. The next pass decides: either this
        # certificate is signed by a root in the store and the path is
        # anchored, or its own issuer gets chased. Nothing is returned
        # unless a later pass reaches the store.
        collected.append(_to_pem(issuer))
        cert = issuer

    if not anchored or not collected:
        logger.debug("AIA chase for %s did not reach a trusted root", host)
        return []

    verify_timeout = remaining(_PROBE_TIMEOUT)
    if verify_timeout <= 0 or not _completes_chain(
        host, port, trust_store_pems, collected, verify_timeout
    ):
        return []

    logger.info(
        "Completed %s certificate chain via AIA (%d intermediate%s)",
        host,
        len(collected),
        "" if len(collected) == 1 else "s",
    )
    return collected


def _to_pem(cert: x509.Certificate) -> bytes:
    """Serialize a certificate as PEM for a wreq CertStore pem stack."""

    return cert.public_bytes(Encoding.PEM)


def merge_pem_stacks(base: bytes, extra: list[bytes]) -> bytes:
    """Concatenate PEM stacks, dropping duplicates of what base already has.

    A CertStore built from the result must parse cleanly, so blocks are
    normalized to one per line-terminated section rather than trusting the
    inputs to have tidy separators.
    """

    blocks: list[bytes] = _PEM_BLOCK.findall(base)
    known = set(blocks)
    for pem in extra:
        for block in _PEM_BLOCK.findall(pem):
            if block in known:
                continue
            known.add(block)
            blocks.append(block)
    return b"\n".join(blocks) + b"\n"
