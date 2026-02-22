"""BaseSession -- shared configuration and logic, zero I/O."""

import datetime
import logging
import platform
import random
import subprocess
from urllib.parse import urljoin, urlparse

from rnet import CertStore, Emulation, Method

from wafer._cookies import CookieCache
from wafer._fingerprint import FingerprintManager
from wafer._ratelimit import RateLimiter

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


def _decode_headers(header_map) -> dict[str, str]:
    """Decode rnet HeaderMap to lowercase string dict.

    rnet's HeaderMap: keys() returns unique bytes keys (deduped),
    get()/[] returns only the first value, get_all() returns all
    values for a key. We use get_all() so multi-value headers
    (especially Set-Cookie) are fully captured, joined with "; ".
    """
    result: dict[str, str] = {}
    for raw_key in header_map.keys():
        k = (
            raw_key.decode("ascii", errors="replace").lower()
            if isinstance(raw_key, bytes)
            else str(raw_key).lower()
        )
        all_vals = header_map.get_all(k)
        parts = []
        for val in all_vals:
            parts.append(
                val.decode("utf-8", errors="replace")
                if isinstance(val, bytes)
                else str(val)
            )
        result[k] = "; ".join(parts)
    return result


class BaseSession:
    """Shared logic for sync and async sessions. No I/O."""

    def __init__(
        self,
        emulation: Emulation | None = None,
        headers: dict[str, str] | None = None,
        connect_timeout: datetime.timedelta | None = None,
        timeout: datetime.timedelta | None = None,
        max_retries: int = 3,
        max_rotations: int = 10,
        cache_dir: str | None = "./data/wafer/cookies",
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
    ):
        self.headers = (
            headers
            if headers is not None
            else dict(DEFAULT_HEADERS)
        )
        self.connect_timeout = (
            connect_timeout or DEFAULT_CONNECT_TIMEOUT
        )
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.max_retries = max_retries
        self.max_rotations = max_rotations
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.max_failures = max_failures

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

        # Optional browser solver for JS challenges
        self._browser_solver = browser_solver

        # TLS session rotation: rebuild client every N requests
        self._rotate_every = rotate_every
        self._request_count = 0

        if embed_origin:
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
    def emulation(self) -> Emulation:
        """Current Emulation profile (delegates to FingerprintManager)."""
        return self._fingerprint.current

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
        # Client-level headers (same set baked into the rnet Client)
        client_headers = dict(self.headers)
        client_headers.update(self._fingerprint.sec_ch_ua_headers())

        # Full merged headers (same logic as before)
        merged = dict(client_headers)

        parsed = urlparse(url)
        domain = parsed.hostname or ""

        if self._embed == "xhr":
            # XHR/fetch impersonation
            merged["Origin"] = self._embed_origin or ""
            merged["Sec-Fetch-Site"] = "cross-site"
            merged["Sec-Fetch-Mode"] = "cors"
            merged["Sec-Fetch-Dest"] = "empty"
            merged["Accept"] = "*/*"
            # Remove navigation-only headers
            merged.pop("Upgrade-Insecure-Requests", None)
            merged.pop("Cache-Control", None)
            # NO X-Requested-With (fetch() never sets it)
            if self._embed_referers:
                # Origin-only referer (strip path)
                ref = random.choice(self._embed_referers)
                parsed_ref = urlparse(ref)
                merged["Referer"] = (
                    f"{parsed_ref.scheme}://{parsed_ref.netloc}/"
                )
            logger.debug(
                "Embed mode (xhr): Origin=%s, Referer=%s",
                self._embed_origin,
                merged.get("Referer", "(none)"),
            )
        elif self._embed == "iframe":
            # Iframe navigation impersonation
            merged["Sec-Fetch-Site"] = "cross-site"
            merged["Sec-Fetch-Mode"] = "navigate"
            merged["Sec-Fetch-Dest"] = "iframe"
            # No Origin for GET navigations
            if self._embed_referers:
                ref = random.choice(self._embed_referers)
                parsed_ref = urlparse(ref)
                merged["Referer"] = (
                    f"{parsed_ref.scheme}://{parsed_ref.netloc}/"
                )
            logger.debug(
                "Embed mode (iframe): Referer=%s",
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
        from wafer._kasada import generate_cd, get_session
        kasada = get_session(domain)
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
        rotation/retry is opted out. Disables health retirement and
        cookie disk caching.
        """
        defaults = {
            "max_retries": 1,
            "max_rotations": 0,
            "max_failures": None,
            "cache_dir": None,
        }
        defaults.update(kwargs)
        return cls(**defaults)

    def _build_client_kwargs(self) -> dict:
        """Build kwargs for rnet Client construction."""
        # Client-level headers: session defaults + sec-ch-ua only.
        # Per-request headers (Host, Referer, embed) are added in
        # _build_headers(url, extra) at request time.
        client_headers = dict(self.headers)
        client_headers.update(self._fingerprint.sec_ch_ua_headers())
        kwargs = {
            "emulation": self._fingerprint.current,
            "headers": client_headers,
            "connect_timeout": self.connect_timeout,
            "timeout": self.timeout,
            "cookie_store": True,
        }
        if _SYSTEM_CERT_STORE is not None:
            kwargs["verify"] = _SYSTEM_CERT_STORE
        if self._proxy is not None:
            kwargs["proxies"] = [self._proxy]
        return kwargs
