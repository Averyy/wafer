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

import contextlib
import http.client
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

# Ceiling on the whole chase, and the largest share of the caller's remaining
# budget it may take. Per-operation caps alone do not bound the total: at
# _MAX_CHASE_DEPTH hops with several caIssuers URLs each, a tarpitting CA
# endpoint could spend every second available and leave nothing for the retry
# the chase exists to enable -- turning a ConnectionFailed into a WaferTimeout
# with no attempts used.
_MAX_CHASE_SECONDS = 25.0
_MAX_BUDGET_SHARE = 0.5

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

# Parsed roots, keyed by the exact PEM stack they came from. The store is
# read once at import and reused for the process lifetime, so this parses
# ~150 certificates once rather than on every chase.
_ROOT_CACHE: dict[bytes, list[x509.Certificate]] = {}

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


def proxy_supports_chasing(proxy_url: str | None) -> bool:
    """Report whether chasing can run without leaving the configured proxy.

    A session with a proxy has an egress path the operator chose, and every
    connection has to stay on it -- a direct probe would leak the real
    address to the origin and sidestep the egress policy entirely. Plain
    HTTP proxies can be tunnelled through with CONNECT; socks and https
    proxies cannot, here or on the native-TLS path, so chasing is skipped
    rather than quietly bypassing them.
    """

    if not proxy_url:
        return True
    try:
        scheme = urlparse(proxy_url).scheme
    except ValueError:
        return False
    return scheme == "http"


def _pin_connection(conn, port: int, pinned_ips: list[str]) -> None:
    """Dial pre-validated addresses instead of re-resolving the hostname.

    Mirrors ``NativeTLSTransport._pin_socket``: only the socket's connect
    target moves, so ``conn.host`` stays the hostname and the TLS wrap still
    passes ``server_hostname=<host>`` for correct SNI and certificate
    matching. This is what keeps a ``resolve=`` session's pin absolute -- the
    probe reaches the exact address the transport was pinned to, never a
    re-resolved one, so the DNS-rebinding window the pin exists to close is
    not reopened here.
    """

    def _connect_to_pinned(address, timeout=None, source_address=None):
        last_err = None
        for ip in pinned_ips:
            try:
                return socket.create_connection(
                    (ip, port), timeout, source_address
                )
            except OSError as exc:
                last_err = exc
        raise last_err if last_err else OSError("no pinned address reachable")

    conn._create_connection = _connect_to_pinned


def _tls_connection(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    timeout: float,
    proxy_url: str | None,
    resolve: dict[str, list[str]] | None = None,
):
    """Open a TLS connection to host:port, through the proxy when there is one.

    Returns a connected object with ``.sock`` (the SSLSocket) and ``.close()``.
    http.client sets SNI from the tunnel target, so the certificate presented
    is the origin's and not the proxy's.
    """

    if proxy_url:
        # Through a proxy the socket goes to the proxy, which resolves the
        # target itself -- the same place the wreq path's pin also stops
        # applying, so there is nothing to pin here.
        parsed = urlparse(proxy_url)
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 80,
            context=ctx,
            timeout=timeout,
        )
        conn.set_tunnel(host, port)
        _connect_or_close(conn)
        return conn
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    if resolve:
        from wafer._base import _canonical_host

        pinned = resolve.get(_canonical_host(host))
        if pinned:
            _pin_connection(conn, port, [str(a) for a in pinned])
    _connect_or_close(conn)
    return conn


def _connect_or_close(conn) -> None:
    """Connect, closing the half-open connection if the handshake fails.

    http.client assigns the TCP socket before wrapping it in TLS, so a
    handshake that fails leaves that socket open on a connection object the
    caller never receives and therefore cannot close. That is the *expected*
    path here, not an edge case: ``_completes_chain`` deliberately connects
    to hosts whose certificates are still bad, and a leak there would
    accumulate one socket per such host.
    """

    try:
        conn.connect()
    except BaseException:
        with contextlib.suppress(Exception):
            conn.close()
        raise


def _probe_chain(
    host: str,
    port: int,
    timeout: float,
    proxy_url: str | None = None,
    resolve: dict[str, list[str]] | None = None,
) -> list[x509.Certificate]:
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
    conn = None
    try:
        conn = _tls_connection(host, port, ctx, timeout, proxy_url, resolve)
        tls = conn.sock
        try:
            ders = list(tls.get_unverified_chain() or ())
        except AttributeError:
            # get_unverified_chain is 3.13+. On 3.12 only the leaf is
            # reachable, so a server that sent a complete chain is not
            # detectable here -- _completes_chain catches that case
            # before anything is added to the trust store.
            leaf = tls.getpeercert(binary_form=True)
            ders = [leaf] if leaf else []
    except (OSError, ssl.SSLError, ValueError, http.client.HTTPException):
        logger.debug("AIA probe failed for %s:%d", host, port, exc_info=True)
        return []
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
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
    proxy_url: str | None = None,
    resolve: dict[str, list[str]] | None = None,
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
    conn = None
    try:
        conn = _tls_connection(host, port, ctx, timeout, proxy_url, resolve)
        return True
    except (OSError, ssl.SSLError, ValueError, http.client.HTTPException):
        logger.debug(
            "%s still does not verify with the fetched intermediates", host
        )
        return False
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()


def _ca_issuer_urls(cert: x509.Certificate, proxied: bool = False) -> list[str]:
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
        if isinstance(url, str) and _is_fetchable_url(url, proxied=proxied):
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


def _is_fetchable_url(url: str, proxied: bool = False) -> bool:
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

    ``proxied`` skips the name lookup. When a proxy carries the fetch, the
    proxy resolves the name and enforces its own egress policy, so a local
    answer describes neither where the request goes nor what is reachable
    from there. Insisting on it would also disable chasing outright in the
    egress-restricted environments that motivate running a proxy, where the
    local resolver may not answer at all. Literal addresses are still
    refused, since those name a destination regardless of who resolves.
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
    if proxied:
        return True
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos if info[4]}
    return bool(addresses) and all(
        _is_public_address(address) for address in addresses
    )


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-run the URL guard on every redirect hop.

    urllib follows redirects by default, and the checks in
    ``_is_fetchable_url`` would otherwise apply only to the URL the
    certificate named. An attacker who controls that certificate could
    publish a perfectly public AIA URL that answers 302 to
    ``http://169.254.169.254/`` and reach straight past the guard into the
    network wafer runs in.
    """

    def __init__(self, proxy_url: str | None = None):
        super().__init__()
        self._proxy_url = proxy_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_fetchable_url(newurl, proxied=bool(self._proxy_url)):
            logger.debug("AIA redirect to %s refused by the URL guard", newurl)
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_certificate(
    url: str,
    timeout: float,
    proxy_url: str | None = None,
) -> x509.Certificate | None:
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
    handlers = [_GuardedRedirectHandler(proxy_url)]
    if proxy_url:
        # Same rule as the probe: the fetch is wafer traffic and must leave
        # by the operator's egress path, not around it.
        handlers.append(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
    try:
        opener = urllib.request.build_opener(*handlers)
        with opener.open(request, timeout=timeout) as response:
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
    """Require the fetched certificate to be a CA allowed to sign certificates.

    basicConstraints CA:TRUE is the claim; keyUsage keyCertSign is the
    permission. A certificate lacking keyCertSign may not issue certificates
    at all, so anchoring it would grant an authority its own issuer withheld.
    """

    try:
        constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except Exception:
        return False
    if not getattr(constraints, "ca", False):
        return False
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        # keyUsage is optional; absent means unrestricted.
        return True
    except Exception:
        return False
    return bool(getattr(usage, "key_cert_sign", False))


def _anchoring_would_drop_constraints(
    cert: x509.Certificate,
    root: x509.Certificate,
) -> bool:
    """Detect authority a root withheld that anchoring would hand back.

    A certificate in the store is a trust *anchor*, and validation stops
    there -- so restrictions the root placed on this intermediate stop being
    enforced. Name constraints are the case that matters: a root trusted
    only for the namespaces it lists would, once an intermediate beneath it
    is anchored, effectively vouch for names it never could. Rather than
    reimplement constraint enforcement, refuse to anchor at all when
    constraints are present. Such a chain is rare in the public web PKI, and
    failing on one site beats silently widening a CA's reach for a session.

    pathLenConstraint is deliberately *not* treated this way. Real
    intermediates carry pathLen:0 as a matter of course -- GeoTrust TLS RSA
    CA G1, the certificate this whole feature exists to fetch, is one -- and
    it constrains how many CAs may appear *below* the certificate, which
    anchoring does not widen in any way an attacker can reach without the
    CA's private key. Refusing on it would reject the motivating case to
    guard against nothing.
    """

    return any(_has_name_constraints(source) for source in (root, cert))


def _has_name_constraints(cert: x509.Certificate) -> bool:
    """Report whether a certificate carries a name-constraints extension.

    Checked for every certificate that would be anchored, not only the one
    that reaches a root: each collected certificate goes into the store, so
    each is a place where constraints would stop being enforced.
    """

    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
    except x509.ExtensionNotFound:
        return False
    except Exception:
        # Unreadable extensions are treated as constraining: refusing to
        # anchor costs one site, guessing wrong widens a CA.
        return True
    return True


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


def _path_top(chain: list[x509.Certificate]) -> x509.Certificate:
    """Walk from the leaf through the presented certificates and return the top.

    The last certificate on the wire is not reliably the top of the path.
    TLS 1.3 drops the ordering requirement, and a common misconfiguration is
    to append the *root* while omitting the intermediate -- which would make
    the final certificate self-signed and trusted, and the chain look
    complete when the piece that matters is exactly what is missing. Chrome
    chases such a site; reading position rather than issuer links would mean
    wafer never does.
    """

    by_subject: dict[bytes, x509.Certificate] = {}
    for cert in chain[1:]:
        by_subject.setdefault(cert.subject.public_bytes(), cert)
    current = chain[0]
    for _ in range(len(chain)):
        if current.issuer == current.subject:
            break
        issuer = by_subject.get(current.issuer.public_bytes())
        if issuer is None or not _directly_issued(current, issuer):
            break
        current = issuer
    return current


def _directly_issued(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Prove ``issuer`` signed ``cert``, by signature rather than by name.

    Subject and issuer names are just fields in a document an attacker can
    author, so a name match proves nothing on its own.
    """

    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:
        return False
    return True


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

    return _issuing_root(cert, roots) is not None


def _issuing_root(
    cert: x509.Certificate,
    roots: list[x509.Certificate],
) -> x509.Certificate | None:
    """Return the store root that signed this certificate, if any."""

    for root in roots:
        if root.subject == cert.issuer and _directly_issued(cert, root):
            return root
    return None


def resolve_missing_intermediates(
    url: str,
    trust_store_pems: bytes,
    *,
    timeout: float | None = None,
    proxy_url: str | None = None,
    resolve: dict[str, list[str]] | None = None,
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

    if timeout is None:
        budget = _PROBE_TIMEOUT + _FETCH_TIMEOUT
    else:
        # Never take more than a share of what the caller has left: the retry
        # after a successful chase still needs budget to run in.
        budget = min(timeout * _MAX_BUDGET_SHARE, _MAX_CHASE_SECONDS)
    deadline = time.monotonic() + budget

    def remaining(cap: float) -> float:
        return min(cap, max(0.0, deadline - time.monotonic()))

    probe_timeout = remaining(_PROBE_TIMEOUT)
    if probe_timeout <= 0:
        return []
    chain = _probe_chain(host, port, probe_timeout, proxy_url, resolve)
    if not chain:
        return []
    # Chase from the top of the path the server actually sent. A server that
    # sent part of its chain is missing only what comes above it, and
    # starting from the leaf would re-fetch what is already on the wire.
    cert = _path_top(chain)
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
        issuing_root = _issuing_root(cert, roots)
        if issuing_root is not None:
            # The path terminates in the existing trust store; everything
            # gathered on the way is proven material.
            if _anchoring_would_drop_constraints(cert, issuing_root):
                logger.debug(
                    "Refusing to anchor %s: its root constrains it and "
                    "anchoring would stop those constraints being enforced",
                    host,
                )
                return []
            anchored = True
            break
        urls = _ca_issuer_urls(cert, proxied=bool(proxy_url))
        if not urls:
            break
        issuer = None
        for candidate_url in urls:
            fetch_timeout = remaining(_FETCH_TIMEOUT)
            if fetch_timeout <= 0:
                return []
            candidate = _fetch_certificate(
                candidate_url, fetch_timeout, proxy_url
            )
            if candidate is None:
                continue
            # The fetched certificate must have actually signed the one that
            # named it, by signature and not by name. Checking only that the
            # subject matches would let an attacker who answers the fetch
            # insert a CA of their own here: the pass that reaches a trusted
            # root proves the certificate at the *top* of the walk, and every
            # link below it would ride in unverified while still being
            # anchored. Linking each hop by signature makes the whole path
            # provable from the leaf up.
            if not _directly_issued(cert, candidate):
                logger.debug(
                    "AIA certificate from %s did not sign the certificate "
                    "that named it",
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
            if _has_name_constraints(candidate):
                # Every collected certificate is anchored, not just the one
                # that reaches a root, so a constrained certificate anywhere
                # in the path is a place those constraints would stop being
                # enforced. Abandon the whole chase rather than anchor it.
                logger.debug(
                    "Refusing the chase for %s: %s is name-constrained and "
                    "anchoring it would stop those constraints applying",
                    host,
                    candidate_url,
                )
                return []
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
    else:
        # The loop ran its full depth without breaking, so the last fetched
        # certificate was never tested against the store -- the check happens
        # at the top of the next pass, which never came. A chain needing
        # exactly _MAX_CHASE_DEPTH hops would otherwise be rejected after
        # doing all the work to complete it.
        issuing_root = _issuing_root(cert, roots)
        if issuing_root is not None and not _anchoring_would_drop_constraints(
            cert, issuing_root
        ):
            anchored = True

    if not anchored or not collected:
        logger.debug("AIA chase for %s did not reach a trusted root", host)
        return []

    verify_timeout = remaining(_PROBE_TIMEOUT)
    if verify_timeout <= 0 or not _completes_chain(
        host,
        port,
        trust_store_pems,
        collected,
        verify_timeout,
        proxy_url,
        resolve,
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
