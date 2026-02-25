"""BaseSession -- shared configuration and logic, zero I/O."""

import datetime
import logging
import platform
import random
import subprocess
from urllib.parse import urlencode, urljoin, urlparse

from rnet import CertStore, Emulation, Method

from wafer._cookies import CookieCache
from wafer._fingerprint import FingerprintManager
from wafer._kasada import generate_cd
from wafer._kasada import get_session as get_kasada_session
from wafer._opera_mini import OperaMiniIdentity
from wafer._profiles import Profile
from wafer._ratelimit import RateLimiter
from wafer._safari import SafariIdentity

logger = logging.getLogger("wafer")

_METHOD_MAP: dict[str, Method] = {
    "GET": Method.GET,
    "POST": Method.POST,
    "PUT": Method.PUT,
    "DELETE": Method.DELETE,
    "HEAD": Method.HEAD,
    "OPTIONS": Method.OPTIONS,
    "PATCH": Method.PATCH,
    "TRACE": Method.TRACE,
}


def _to_method(method: str) -> Method:
    """Convert a string HTTP method to rnet Method enum."""
    try:
        return _METHOD_MAP[method.upper()]
    except KeyError:
        raise ValueError(f"Unknown HTTP method: {method}") from None


def _load_system_cert_store() -> CertStore | None:
    """Load system CA certificates into an rnet CertStore."""
    try:
        if platform.system() == "Darwin":
            result = subprocess.run(
                [
                    "security",
                    "find-certificate",
                    "-a",
                    "-p",
                    "/System/Library/Keychains/"
                    "SystemRootCertificates.keychain",
                ],
                capture_output=True,
            )
            if result.returncode == 0 and result.stdout:
                return CertStore.from_pem_stack(result.stdout)
        elif platform.system() == "Linux":
            for path in [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
            ]:
                try:
                    with open(path, "rb") as f:
                        return CertStore.from_pem_stack(f.read())
                except FileNotFoundError:
                    continue
        # Fallback: try certifi if available
        try:
            import certifi

            with open(certifi.where(), "rb") as f:
                return CertStore.from_pem_stack(f.read())
        except ImportError:
            pass
    except Exception:
        logger.debug(
            "Failed to load system certs", exc_info=True
        )
    return None


# Cache the cert store at module load time
_SYSTEM_CERT_STORE = _load_system_cert_store()
if _SYSTEM_CERT_STORE:
    logger.debug("Loaded system CA certificate store")
else:
    logger.debug(
        "No system CA store found; using rnet defaults"
    )

# Default to newest Chrome emulation profile
DEFAULT_EMULATION = Emulation.Chrome145

DEFAULT_HEADERS = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
}

DEFAULT_CONNECT_TIMEOUT = datetime.timedelta(seconds=10)
DEFAULT_TIMEOUT = datetime.timedelta(seconds=30)


def _normalize_timeout(val) -> datetime.timedelta:
    if isinstance(val, datetime.timedelta):
        return val
    return datetime.timedelta(seconds=float(val))


_BINARY_CONTENT_PREFIXES = (
    "image/",
    "audio/",
    "video/",
    "font/",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/octet-stream",
    "application/wasm",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/vnd.",
)


def _is_binary_content_type(content_type: str) -> bool:
    """Check if a Content-Type indicates binary (non-text) content.

    Binary responses skip challenge detection and body-as-text decoding.
    WAF challenges always return text/html, so this is safe.
    Unknown or missing content types are treated as text (conservative).
    """
    ct = content_type.lower().split(";")[0].strip()
    if not ct:
        return False
    return any(ct.startswith(p) for p in _BINARY_CONTENT_PREFIXES)


def _is_challengeable_content_type(content_type: str) -> bool:
    """Check if a Content-Type could be a WAF challenge page.

    WAF challenges are always HTML pages. JSON/XML API responses should
    never be browser-solved - even if they contain challenge markers in
    cookies/headers (e.g. AliExpress MTop API returns x5secdata cookies
    on JSON 200 responses). Browser-solving a JSON endpoint just renders
    raw JSON and times out.

    Returns True for HTML and unknown/missing content types (conservative).
    """
    ct = content_type.lower().split(";")[0].strip()
    if not ct:
        return True  # Unknown - assume HTML (conservative)
    # Explicit non-HTML text types that should NOT trigger challenge solving
    if ct in (
        "application/json",
        "application/xml",
        "text/xml",
        "text/plain",
        "text/csv",
    ):
        return False
    return True


def _decode_headers(header_map) -> dict[str, str]:
    """Decode rnet HeaderMap to lowercase string dict.

    rnet's HeaderMap: keys() returns unique bytes keys (deduped),
    get()/[] returns only the first value, get_all() returns all
    values for a key. We use get_all() so multi-value headers
    (especially Set-Cookie) are fully captured, joined with "; ".
    """
    result: dict[str, str] = {}
    for raw_key in header_map.keys():
        k = raw_key.decode("ascii", errors="replace").lower()
        all_vals = header_map.get_all(k)
        parts = [v.decode("utf-8", errors="replace") for v in all_vals]
        result[k] = "; ".join(parts)
    return result


def _extract_location(header_map) -> str:
    """Extract Location header from raw HeaderMap without full decode.

    Used on redirect hops to avoid decoding every header just to
    read Location.
    """
    raw = header_map.get("location")
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


class BaseSession:
    """Shared logic for sync and async sessions. No I/O."""

    def __init__(
        self,
        emulation: Emulation | None = None,
        headers: dict[str, str] | None = None,
        connect_timeout: datetime.timedelta | float | int | None = None,
        timeout: datetime.timedelta | float | int | None = None,
        max_retries: int = 3,
        max_rotations: int = 2,
        cache_dir: str | None = None,
        max_failures: int | None = 3,
        rate_limit: float = 0.0,
        rate_jitter: float = 0.0,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        embed_origin: str | None = None,
        embed_referers: list[str] | None = None,
        embed: str | None = None,
        proxy: str | None = None,
        browser_solver=None,
        rotate_every: int | None = None,
        profile: Profile | None = None,
        safari_locale: str = "us",
    ):
        self._profile = profile
        self._om_identity = (
            OperaMiniIdentity()
            if profile is Profile.OPERA_MINI
            else None
        )
        self._safari_locale = safari_locale
        self._safari_identity = (
            SafariIdentity(locale=safari_locale)
            if profile is Profile.SAFARI
            else None
        )

        if headers is not None:
            self.headers = headers
        elif self._safari_identity is not None:
            self.headers = self._safari_identity.client_headers()
        else:
            self.headers = dict(DEFAULT_HEADERS)
        self.connect_timeout = (
            _normalize_timeout(connect_timeout)
            if connect_timeout is not None
            else DEFAULT_CONNECT_TIMEOUT
        )
        self.timeout = (
            _normalize_timeout(timeout)
            if timeout is not None
            else DEFAULT_TIMEOUT
        )
        self.max_retries = max_retries
        self.max_rotations = max_rotations
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.max_failures = max_failures

        if profile is Profile.SAFARI:
            self._fingerprint = None
        else:
            self._fingerprint = FingerprintManager(
                emulation or DEFAULT_EMULATION
            )

        # Per-domain rate limiter
        if rate_limit > 0:
            self._rate_limiter: RateLimiter | None = RateLimiter(
                min_interval=rate_limit,
                jitter=rate_jitter,
            )
        else:
            self._rate_limiter = None

        # Session health: consecutive failure count per domain
        self._domain_failures: dict[str, int] = {}

        # Cookie cache (disk persistence)
        if cache_dir is not None:
            self._cookie_cache: CookieCache | None = CookieCache(
                cache_dir
            )
        else:
            self._cookie_cache = None

        # Referer chain tracking: last URL fetched per domain
        self._last_url: dict[str, str] = {}

        # Embed mode: "xhr" or "iframe"
        # embed_origin without embed= defaults to "xhr"
        if embed_origin and embed is None:
            embed = "xhr"
        self._embed = embed
        self._embed_origin = embed_origin
        self._embed_referers = embed_referers or []

        # Proxy
        self._proxy = None
        if proxy:
            from rnet import Proxy

            self._proxy = Proxy.all(proxy)

        # Optional browser solver for JS challenges.
        self._browser_solver = browser_solver

        # TLS session rotation: rebuild client every N requests
        self._rotate_every = rotate_every
        self._request_count = 0

        # Cache client-level headers for fast delta in _build_headers
        self._client_headers = self._compute_client_headers()

        if profile is Profile.SAFARI:
            logger.debug(
                "Session created with Safari profile, timeout=%s",
                self.timeout,
            )
        elif embed_origin:
            logger.info(
                "Session created in embed mode: origin=%s, "
                "referers=%d, emulation=%s",
                embed_origin,
                len(self._embed_referers),
                self._fingerprint.current,
            )
        else:
            logger.debug(
                "Session created with emulation=%s, timeout=%s",
                self._fingerprint.current,
                self.timeout,
            )

    @property
    def emulation(self) -> Emulation | None:
        """Current Emulation profile (delegates to FingerprintManager)."""
        if self._fingerprint is None:
            return None
        return self._fingerprint.current

    def _compute_client_headers(self) -> dict[str, str]:
        """Compute client-level headers snapshot.

        Cached as self._client_headers to avoid regenerating sec-ch-ua
        strings on every _build_headers call. Must be refreshed after
        fingerprint rotation (_build_client_kwargs does this).

        Embed mode adjustments happen here (not in _build_headers) because
        rnet's header model is additive: per-request headers cannot remove
        or replace client-level headers, they only add. Setting a header
        at both levels creates HTTP/2 duplicates that WAFs detect.
        """
        headers = dict(self.headers)
        if self._fingerprint is not None:
            headers.update(self._fingerprint.sec_ch_ua_headers())

        if self._embed:
            # Strip Sec-Fetch-* from client level. _build_headers sets
            # the correct values per-request (they vary by URL for
            # Sec-Fetch-Site). Leaving them at client level would create
            # HTTP/2 duplicates, especially after Safari fallback (which
            # sets Sec-Fetch-Dest: document, Sec-Fetch-Mode: navigate).
            for key in list(headers):
                if key.startswith("Sec-Fetch-"):
                    del headers[key]

        if self._embed == "xhr":
            # XHR/fetch never sends navigation-only headers. Strip from
            # client level since rnet can't remove them per-request.
            headers.pop("Cache-Control", None)
            headers.pop("Upgrade-Insecure-Requests", None)
            # Replace navigation Accept with XHR Accept at client level
            # (setting it per-request would duplicate with the old value).
            headers["Accept"] = "*/*"

        return headers

    def _compute_sec_fetch_site(self, url: str) -> str:
        """Compute Sec-Fetch-Site based on embed_origin vs request URL.

        Returns "same-origin", "same-site", or "cross-site" per the spec.
        """
        if not self._embed_origin:
            return "cross-site"

        origin = urlparse(self._embed_origin)
        request = urlparse(url)
        origin_host = origin.hostname or ""
        request_host = request.hostname or ""

        # Same origin: same scheme + host + port
        origin_port = origin.port or (443 if origin.scheme == "https" else 80)
        request_port = request.port or (443 if request.scheme == "https" else 80)
        if (
            origin.scheme == request.scheme
            and origin_host == request_host
            and origin_port == request_port
        ):
            return "same-origin"

        # Same site: same scheme + same registrable domain (TLD+1 heuristic)
        origin_parts = origin_host.rsplit(".", 2)
        request_parts = request_host.rsplit(".", 2)
        origin_root = (
            ".".join(origin_parts[-2:])
            if len(origin_parts) >= 2
            else origin_host
        )
        request_root = (
            ".".join(request_parts[-2:])
            if len(request_parts) >= 2
            else request_host
        )
        if origin.scheme == request.scheme and origin_root == request_root:
            return "same-site"

        return "cross-site"

    def _build_headers(
        self, url: str, extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Build per-request headers as a delta over client-level headers.

        Returns only headers that differ from what's already set on the
        rnet Client (via _build_client_kwargs). This avoids sending
        duplicate headers in HTTP/2 frames, which strict WAFs like
        Cloudflare detect as non-browser behavior.

        Order: session defaults → sec-ch-ua → auto Host → referer/embed →
        per-request overrides. Any auto-header can be suppressed by
        setting it to empty string in session headers or per-request
        overrides; empty-string values are stripped at the end.
        """
        # Opera Mini: identity headers are already at client level
        # (set in _build_client_kwargs). Only return per-request
        # overrides — returning the full identity here would duplicate
        # every header at both client and request level.
        if self._profile is Profile.OPERA_MINI:
            return dict(extra) if extra else {}

        # Use cached client-level headers (refreshed on rotation/rebuild)
        client_headers = self._client_headers

        # Full merged headers (same logic as before)
        merged = dict(client_headers)

        parsed = urlparse(url)
        domain = parsed.hostname or ""

        if self._embed == "xhr":
            # XHR/fetch impersonation. Accept and navigation headers
            # already fixed at client level by _compute_client_headers.
            merged["Origin"] = self._embed_origin or ""
            merged["Sec-Fetch-Site"] = self._compute_sec_fetch_site(url)
            merged["Sec-Fetch-Mode"] = "cors"
            merged["Sec-Fetch-Dest"] = "empty"
            if self._embed_referers:
                merged["Referer"] = random.choice(self._embed_referers)
            logger.debug(
                "Embed mode (xhr): Origin=%s, Sec-Fetch-Site=%s, Referer=%s",
                self._embed_origin,
                merged["Sec-Fetch-Site"],
                merged.get("Referer", "(none)"),
            )
        elif self._embed == "iframe":
            # Iframe navigation impersonation
            merged["Sec-Fetch-Site"] = self._compute_sec_fetch_site(url)
            merged["Sec-Fetch-Mode"] = "navigate"
            merged["Sec-Fetch-Dest"] = "iframe"
            # No Origin for GET navigations
            if self._embed_referers:
                merged["Referer"] = random.choice(self._embed_referers)
            logger.debug(
                "Embed mode (iframe): Sec-Fetch-Site=%s, Referer=%s",
                merged["Sec-Fetch-Site"],
                merged.get("Referer", "(none)"),
            )
        else:
            # Normal referer chain: auto-set from last URL on same domain
            if "Referer" not in merged and domain in self._last_url:
                merged["Referer"] = self._last_url[domain]
                logger.debug(
                    "Auto-Referer: %s", self._last_url[domain]
                )

        # Kasada: inject CT + CD if domain has active session with
        # valid ST. Sending CT without CD is worse than neither —
        # Kasada rejects unaccompanied tokens. Cookie-based auth
        # (without CT/CD headers) works for some deployments.
        kasada = get_kasada_session(domain)
        if kasada and kasada.st:
            merged["x-kpsdk-ct"] = kasada.ct
            merged["x-kpsdk-cd"] = generate_cd(kasada.st)

        # Per-request overrides (last to win)
        if extra:
            merged.update(extra)

        # Return only the delta: headers not already at client level,
        # or with a different value (e.g. user per-request override).
        # Strip empty-string values (suppression mechanism).
        delta = {}
        for k, v in merged.items():
            if v == "":
                continue
            if k not in client_headers or client_headers[k] != v:
                delta[k] = v
        return delta

    def _record_url(self, url: str) -> None:
        """Record the URL for referer chain tracking."""
        domain = urlparse(url).hostname
        if domain:
            self._last_url[domain] = url

    def _record_failure(self, domain: str) -> bool:
        """Record a 403/429 failure for a domain.

        Returns True if the session should be retired (threshold hit).
        """
        count = self._domain_failures.get(domain, 0) + 1
        self._domain_failures[domain] = count
        if (
            self.max_failures is not None
            and count >= self.max_failures
        ):
            logger.warning(
                "Session health: %d consecutive failures for %s "
                "(threshold=%d), retiring",
                count,
                domain,
                self.max_failures,
            )
            return True
        return False

    def _record_success(self, domain: str) -> None:
        """Record a successful response for a domain, resetting failures."""
        if domain in self._domain_failures:
            del self._domain_failures[domain]

    def _switch_to_safari(self) -> None:
        """Switch from Chrome to Safari identity for rotation fallback.

        Safari has a fundamentally different TLS/H2 fingerprint, making
        it much more effective than rotating between Chrome versions.
        Only called for default Chrome sessions (not Safari or Opera Mini).
        """
        self._safari_identity = SafariIdentity(locale=self._safari_locale)
        self._fingerprint = None
        self.headers = self._safari_identity.client_headers()
        logger.info("Rotation fallback: switched to Safari profile")

    def _rotation_delay(self) -> float:
        """Delay before a rotation retry: rate limiter interval + 1s.

        Ensures rotation retries never fire faster than the user's
        configured rate limit, with an extra 1s penalty on top.
        """
        base = self._rate_limiter.min_interval if self._rate_limiter else 0.0
        return base + 1.0

    @staticmethod
    def _apply_params(url: str, params: dict[str, str] | None) -> str:
        """Append query parameters to a URL.

        rnet doesn't support a params= kwarg, so wafer handles it by
        building the query string into the URL before passing to rnet.
        """
        if not params:
            return url
        sep = "&" if "?" in url else "?"
        return url + sep + urlencode(params)

    @staticmethod
    def _resolve_redirect_url(base_url: str, location: str) -> str:
        """Resolve a Location header value to an absolute URL.

        Handles:
        - Absolute URLs (https://...)
        - Protocol-relative URLs (//host/path)
        - Relative URLs (/path, path)
        """
        location = location.strip()
        if location.startswith("//"):
            # Protocol-relative: inherit scheme from base URL
            scheme = urlparse(base_url).scheme or "https"
            location = f"{scheme}:{location}"
        resolved = urljoin(base_url, location)
        # Ensure path is not empty (some servers omit it)
        parsed = urlparse(resolved)
        if not parsed.path:
            resolved = parsed._replace(path="/").geturl()
        return resolved

    @classmethod
    def bulk(cls, **kwargs):
        """Constructor with defaults tuned for high-volume bulk scraping.

        Returns responses instead of raising on 429/challenge/empty when
        rotation/retry is opted out. Disables health retirement.
        """
        defaults = {
            "max_retries": 1,
            "max_rotations": 0,
            "max_failures": None,
        }
        defaults.update(kwargs)
        return cls(**defaults)

    def _build_client_kwargs(self) -> dict:
        """Build kwargs for rnet Client construction.

        Not called for Opera Mini (which bypasses rnet entirely).
        Safari uses TlsOptions + Http2Options (no Emulation).
        Chrome uses Emulation (no TlsOptions).

        Also refreshes the cached _client_headers snapshot so that
        _build_headers picks up any fingerprint changes.
        """
        # Refresh cached client headers (fingerprint may have rotated)
        self._client_headers = self._compute_client_headers()

        if self._safari_identity is not None:
            # Safari: custom TLS + H2, no Emulation
            kwargs = {
                "tls_options": self._safari_identity.tls_options(),
                "http2_options": self._safari_identity.http2_options(),
                "headers": dict(self.headers),
                "connect_timeout": self.connect_timeout,
                "timeout": self.timeout,
                "cookie_store": True,
            }
        else:
            # Chrome: Emulation + sec-ch-ua headers
            # (reuse cached _client_headers instead of regenerating)
            kwargs = {
                "emulation": self._fingerprint.current,
                "headers": dict(self._client_headers),
                "connect_timeout": self.connect_timeout,
                "timeout": self.timeout,
                "cookie_store": True,
            }
        if _SYSTEM_CERT_STORE is not None:
            kwargs["verify"] = _SYSTEM_CERT_STORE
        if self._proxy is not None:
            kwargs["proxies"] = [self._proxy]
        return kwargs
