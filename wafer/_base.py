"""BaseSession -- shared configuration and logic, zero I/O."""

import datetime
import logging
import platform
import random
import subprocess
import time
from urllib.parse import urlencode, urljoin, urlparse

from wreq import CertStore, Emulation, Method

from wafer._cookies import CookieCache
from wafer._dart import DartIdentity
from wafer._fingerprint import (
    FingerprintManager,
    build_fingerprint_envelope,
    emulation_family,
    emulation_user_agent,
    family_headers,
)
from wafer._kasada import get_session as get_kasada_session  # noqa: F401
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
    """Convert a string HTTP method to wreq Method enum."""
    try:
        return _METHOD_MAP[method.upper()]
    except KeyError:
        raise ValueError(f"Unknown HTTP method: {method}") from None


def _load_system_cert_store() -> CertStore | None:
    """Load system CA certificates into a wreq CertStore."""
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
        "No system CA store found; using wreq defaults"
    )

# Default to newest Chrome emulation profile
DEFAULT_EMULATION = Emulation.Chrome147

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
    """Decode wreq HeaderMap to lowercase string dict.

    wreq's HeaderMap: keys() returns unique bytes keys (deduped),
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
        attempt_timeout: datetime.timedelta | float | int | None = None,
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
        self._dart_identity = (
            DartIdentity()
            if profile is Profile.DART
            else None
        )

        # Resolve the browser family of the chosen TLS Emulation so a
        # non-Chrome emulation (Firefox/Edge) gets a coherent HTTP header
        # envelope instead of Chrome's DEFAULT_HEADERS. Only meaningful for
        # Emulation-based profiles (not Safari/Opera Mini/Dart, which carry
        # their own identity headers).
        self._emulation_family = (
            emulation_family(emulation or DEFAULT_EMULATION)
            if profile not in (Profile.SAFARI, Profile.OPERA_MINI, Profile.DART)
            else None
        )

        if headers is not None:
            self.headers = headers
        elif self._safari_identity is not None:
            self.headers = self._safari_identity.client_headers()
        elif self._dart_identity is not None:
            self.headers = self._dart_identity.client_headers()
        else:
            # Per-family navigation envelope. Firefox sends NO sec-ch-ua and
            # a Firefox-shaped Accept; Edge is Chromium (Chrome-like headers,
            # Microsoft Edge brand in sec-ch-ua). Falls back to Chrome's
            # DEFAULT_HEADERS for the Chrome family and any unrecognized one.
            env = family_headers(self._emulation_family)
            self.headers = env if env is not None else dict(DEFAULT_HEADERS)
        # Chrome-mode headers, restored by _switch_to_chrome() when rotation
        # escalates back to a Chrome fingerprint. This MUST be the real Chrome
        # navigation envelope, NOT the session's starting family envelope: a
        # Firefox/Edge-emulation session would otherwise send Firefox's Accept
        # / "...;q=0.5" Accept-Language on a Chrome TLS fingerprint -
        # incoherent. When the user passed explicit headers=, the documented
        # full-replace contract wins (we keep their set across rotation so the
        # rotated request still reflects what they asked for). Identity
        # profiles (Safari/Dart) carry their own headers, so None for them.
        if self._safari_identity is not None or self._dart_identity is not None:
            self._chrome_headers = None
        elif headers is not None:
            self._chrome_headers = dict(headers)
        else:
            self._chrome_headers = dict(DEFAULT_HEADERS)
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
        # Per-attempt cap: bounds each individual wreq attempt so the
        # retry/rotation machinery can fire within the total budget.
        # None (default) = no per-attempt cap (an attempt may use the
        # whole remaining budget, matching requests/httpx-naive usage).
        self.attempt_timeout = (
            _normalize_timeout(attempt_timeout)
            if attempt_timeout is not None
            else None
        )
        self.max_retries = max_retries
        self.max_rotations = max_rotations
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.max_failures = max_failures

        if profile in (Profile.SAFARI, Profile.OPERA_MINI, Profile.DART):
            # Safari/Dart use TlsOptions (not Emulation). Opera Mini
            # bypasses wreq entirely. None need FingerprintManager.
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
        self._tried_safari = profile in (Profile.SAFARI, Profile.DART)

        # Cookie cache (disk persistence)
        if cache_dir is not None and profile is not Profile.OPERA_MINI:
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
        if embed and profile is Profile.DART:
            raise ValueError(
                "Embed mode is not supported with Profile.DART "
                "(Dart apps don't send Sec-Fetch-* headers)"
            )
        self._embed = embed
        self._embed_origin = embed_origin
        self._embed_referers = embed_referers or []

        # Proxy
        self._proxy = None
        self._proxy_url = proxy  # raw URL, for the native-TLS transport
        if proxy:
            from wreq import Proxy

            self._proxy = Proxy.all(proxy)

        # Optional browser solver for JS challenges. The session closes
        # a solver only if it created the solver itself (_owns_solver);
        # a solver passed in via browser_solver= is shared and its
        # lifecycle belongs to the caller. wafer never auto-creates a
        # solver today, so _owns_solver is always False for now -- the
        # flag keeps the ownership invariant explicit and future-proof.
        self._browser_solver = browser_solver
        self._owns_solver = False

        # Native-TLS fallback (urllib/OpenSSL) for WAFs that fingerprint
        # the BoringSSL stack wreq is built on (Imperva/Incapsula). Lazily
        # created. Hostnames proven to need it are routed through it on
        # later requests too: wreq gets challenged even *with* the WAF
        # cookies, so once a domain goes native the whole flow stays there.
        self._native_tls = None
        self._native_tls_domains: set[str] = set()

        # TLS session rotation: rebuild client every N requests
        self._rotate_every = rotate_every
        self._request_count = 0

        # Cache client-level headers for fast delta in _build_headers
        self._client_headers = self._compute_client_headers()

        if self._fingerprint is None:
            logger.debug(
                "Session created with %s profile, timeout=%s",
                profile.name if profile else "custom",
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

    def _serving_user_agent(self) -> str | None:
        """The User-Agent actually serving requests for this session.

        Identity profiles (Safari/Dart/Opera Mini) carry their own UA in
        self.headers; Emulation-based sessions get the UA from wreq, which
        we reconstruct from the current Emulation.
        """
        if self._safari_identity is not None:
            return self._safari_identity.user_agent
        if self._dart_identity is not None:
            return self._dart_identity.user_agent
        if self._om_identity is not None:
            return self._om_identity.user_agent
        # User-supplied headers override (e.g. headers={"User-Agent": ...})
        for k, v in self.headers.items():
            if k.lower() == "user-agent" and v:
                return v
        if self._fingerprint is not None:
            return emulation_user_agent(self._fingerprint.current)
        return None

    def fingerprint_envelope(self) -> dict:
        """Return the coherent client identity this session serves with.

        A snapshot of the User-Agent + Client Hint identity that wafer puts
        on the wire, consistent with the headers actually sent. Useful for
        feeding the same identity to other tooling (e.g. signing a JS
        challenge) or diagnosing a 403.

        Always returns a dict with these keys:

        - ``user_agent``: ``str | None``
        - ``family``: ``"chrome" | "edge" | "firefox" | "opera" |
          "safari" | "dart" | "opera_mini" | None``
        - ``emulation``: ``repr()`` of the Emulation, or the Profile name
          for Safari/Dart/Opera Mini (e.g. ``"Profile.Chrome147"``,
          ``"safari"``)
        - ``sec_ch_ua`` / ``sec_ch_ua_mobile`` / ``sec_ch_ua_platform``:
          the low-entropy Client Hints. ``None`` for Firefox/Safari (no
          client hints) and for Opera (wreq's Emulation emits accurate
          Opera hints itself; wafer doesn't re-derive them)
        - ``full_version_list``: ``Sec-CH-UA-Full-Version-List`` (or None)
        - ``platform_version``: ``Sec-CH-UA-Platform-Version`` (or None)
        - ``user_agent_data``: the ``navigator.userAgentData`` shape Chromium
          exposes (``None`` for Firefox/Safari)

        For non-Emulation profiles (Safari/Dart/Opera Mini) only the
        ``user_agent``, ``family``, and ``emulation`` fields are populated;
        the Client-Hint fields are ``None`` (those identities send none).
        """
        ua = self._serving_user_agent()
        if self._fingerprint is not None:
            env = build_fingerprint_envelope(self._fingerprint.current, ua)
            return env
        # Non-Emulation identity profile (Safari / Dart / Opera Mini). Each
        # is its own "family"; use the Profile value so it matches the
        # `emulation` field (e.g. "dart", "opera_mini", "safari"). A default
        # Chrome session that ROTATED to Safari has _safari_identity set but
        # _profile is None -- still report "safari" for it.
        if self._safari_identity is not None:
            family = "safari"
        elif self._profile is not None:
            family = self._profile.value
        else:
            family = None
        profile_name = self._profile.value if self._profile else None
        return {
            "user_agent": ua,
            "family": family,
            "emulation": profile_name,
            "sec_ch_ua": None,
            "sec_ch_ua_mobile": None,
            "sec_ch_ua_platform": None,
            "full_version_list": None,
            "platform_version": None,
            "user_agent_data": None,
        }

    def _serving_emulation_repr(self) -> str | None:
        """The repr()/profile string of the identity serving requests.

        Stamped on every WaferResponse as ``resp.emulation`` so callers can
        diagnose which fingerprint served a 403/regression. For Emulation
        sessions it's ``repr(Emulation.XxxNNN)``; for Safari/Dart/Opera Mini
        it's the profile name.
        """
        if self._fingerprint is not None:
            return repr(self._fingerprint.current)
        if self._profile is not None:
            return self._profile.value
        return None

    def _compute_client_headers(self) -> dict[str, str]:
        """Compute client-level headers snapshot.

        Cached as self._client_headers to avoid regenerating sec-ch-ua
        strings on every _build_headers call. Must be refreshed after
        fingerprint rotation (_build_client_kwargs does this).

        Embed mode adjustments happen here (not in _build_headers) because
        wreq's header model is additive: per-request headers cannot remove
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
            # client level since wreq can't remove them per-request.
            headers.pop("Cache-Control", None)
            headers.pop("Upgrade-Insecure-Requests", None)
            # Replace navigation Accept with XHR Accept at client level
            # (setting it per-request would duplicate with the old value).
            headers["Accept"] = "*/*"

        return headers

    def _compute_sec_fetch_site(self, url: str) -> str:
        """Compute Sec-Fetch-Site based on embed_origin vs request URL.

        Returns "same-origin", "same-site", or "cross-site" per the spec.

        Limitation: same-site uses a naive TLD+1 heuristic (last two
        hostname labels) instead of a Public Suffix List lookup. This
        gives wrong results for multi-label TLDs like .co.uk, .com.au,
        and .github.io - two unrelated .co.uk domains would incorrectly
        be classified as same-site. Override per-request if needed:
        ``headers={"Sec-Fetch-Site": "cross-site"}``.
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
        method: str = "GET",
    ) -> dict[str, str]:
        """Build per-request headers as a delta over client-level headers.

        Returns only headers that differ from what's already set on the
        wreq Client (via _build_client_kwargs). This avoids sending
        duplicate headers in HTTP/2 frames, which strict WAFs like
        Cloudflare detect as non-browser behavior.

        Order: session defaults → sec-ch-ua → auto Host → referer/embed →
        per-request overrides. Any auto-header can be suppressed by
        setting it to empty string in session headers or per-request
        overrides; empty-string values are stripped at the end.
        """
        # Opera Mini / Dart: identity headers are already at client level
        # (set in _build_client_kwargs). Only return per-request
        # overrides -- returning the full identity here would duplicate
        # every header at both client and request level.
        if self._profile in (Profile.OPERA_MINI, Profile.DART):
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
            # POST/PUT/PATCH/DELETE navigations send Origin (Fetch spec);
            # GET/HEAD navigations do not.
            if method.upper() not in ("GET", "HEAD"):
                merged["Origin"] = self._embed_origin or ""
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

        # Kasada: CT+CD headers require x-kpsdk-h HMAC to be valid.
        # Without H, sending CT+CD causes server rejection (worse
        # than cookies alone). Cookie-only auth works for most
        # deployments; passthrough handles the rest. CT/ST are
        # still captured and cached for future H generation.
        # kasada = get_kasada_session(domain)
        # if kasada and kasada.st:
        #     merged["x-kpsdk-ct"] = kasada.ct
        #     merged["x-kpsdk-cd"] = generate_cd(kasada.st)

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
        self._tried_safari = True
        self.headers = self._safari_identity.client_headers()
        logger.info("Rotation fallback: switched to Safari profile")

    def _switch_to_chrome(self) -> None:
        """Switch back from Safari to Chrome with a rotated version.

        Called during rotation escalation when Safari didn't help either.
        Restores Chrome TLS identity with a different version than default.
        """
        self._safari_identity = None
        self._fingerprint = FingerprintManager(DEFAULT_EMULATION)
        self._fingerprint.rotate()
        self.headers = (
            dict(self._chrome_headers)
            if self._chrome_headers
            else dict(DEFAULT_HEADERS)
        )
        logger.info(
            "Rotation: switched to Chrome %s",
            self._fingerprint.current,
        )

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

        wreq doesn't support a params= kwarg, so wafer handles it by
        building the query string into the URL before passing to wreq.
        """
        if not params:
            return url
        sep = "&" if "?" in url else "?"
        return url + sep + urlencode(params)

    @staticmethod
    def _is_cross_origin(old_url: str, new_url: str) -> bool:
        """True if redirect crosses origin (different host)."""
        old_host = urlparse(old_url).hostname or ""
        new_host = urlparse(new_url).hostname or ""
        return old_host != new_host

    @staticmethod
    def _strip_sensitive_headers(
        extra_headers: dict[str, str] | None,
        cross_origin: bool,
        method_changed: bool,
    ) -> dict[str, str] | None:
        """Strip headers that should not survive a redirect hop.

        Per the Fetch spec and consistent with requests/httpx/curl:
        - Authorization is stripped on cross-origin redirects
        - Content-Type is stripped when method changes (POST → GET)
        """
        if extra_headers is None:
            return None
        drop = set()
        if cross_origin:
            drop.add("authorization")
        if method_changed:
            drop.update(("content-type", "content-length"))
        if not drop:
            return extra_headers
        filtered = {
            k: v for k, v in extra_headers.items()
            if k.lower() not in drop
        }
        if len(filtered) != len(extra_headers):
            logger.debug(
                "Redirect: stripped headers %s",
                drop & {k.lower() for k in extra_headers},
            )
        return filtered or None

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
        """Build kwargs for wreq Client construction.

        Not called for Opera Mini (which bypasses wreq entirely).
        Safari uses TlsOptions + Http2Options (no Emulation).
        Chrome uses Emulation (no TlsOptions).

        Also refreshes the cached _client_headers snapshot so that
        _build_headers picks up any fingerprint changes.
        """
        # Refresh cached client headers (fingerprint may have rotated)
        self._client_headers = self._compute_client_headers()

        if self._dart_identity is not None:
            # Dart: custom TLS, no Emulation. HTTP/1.1 is forced by
            # omitting ALPN in TlsOptions (not http1_only, which
            # injects an ALPN extension that breaks the fingerprint).
            kwargs = {
                "tls_options": self._dart_identity.tls_options(),
                "headers": dict(self._client_headers),
                "connect_timeout": self.connect_timeout,
                "timeout": self.timeout,
                "cookie_store": True,
            }
        elif self._safari_identity is not None:
            # Safari: custom TLS + H2, no Emulation.
            # Use _client_headers (not self.headers) so embed mode
            # stripping of Sec-Fetch-* is reflected at client level,
            # matching what _build_headers uses for delta computation.
            kwargs = {
                "tls_options": self._safari_identity.tls_options(),
                "http2_options": self._safari_identity.http2_options(),
                "headers": dict(self._client_headers),
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
            kwargs["tls_verify"] = _SYSTEM_CERT_STORE
        if self._proxy is not None:
            kwargs["proxies"] = [self._proxy]
        return kwargs

    # ------------------------------------------------------------------
    # Native-TLS fallback (urllib / system OpenSSL)
    # ------------------------------------------------------------------

    def _native_tls_usable(self) -> bool:
        """Whether the native-TLS path can be used for this session.

        http.client can only CONNECT-tunnel an ``http://`` proxy. With a
        ``socks://``/``https://`` proxy the native transport would have to
        either leak the real IP or fail every attempt, so we skip it entirely
        and let the (proxy-aware) wreq path handle the challenge instead.
        """
        if not self._proxy_url:
            return True
        return urlparse(self._proxy_url).scheme == "http"

    def _imperva_embedder(self, challenge, url, extra_headers, kwargs):
        """Origin page to browser-solve an Imperva API-host challenge, or None.

        Imperva serves a top-level navigation to an API host its interactive
        "Error 15" block; the real flow loads the site's origin page (earning
        the registrable-domain reese84/incap cookies) and calls the API via
        same-site XHR. Returns that embedder origin for Imperva when a browser
        solver is present, else None - callers pass it unconditionally.
        """
        from wafer._challenge import ChallengeType

        if challenge != ChallengeType.IMPERVA or self._browser_solver is None:
            return None
        from wafer.browser._imperva import imperva_embedder

        merged: dict = {}
        if extra_headers:
            merged.update(extra_headers)
        hdrs = kwargs.get("headers")
        if hdrs:
            merged.update(hdrs)
        return imperva_embedder(url, merged)

    def _browser_replay(self, method, kwargs) -> dict:
        """Replay descriptor (method/body/content-type) for an in-page XHR.

        Lets the Imperva embedder solve re-issue the *original* request -
        GET or POST with its form/json/body - as a same-site fetch from the
        origin page, so the caller gets the real response directly.
        """
        body, content_type = self._extract_native_body(kwargs)
        return {
            "method": (method if isinstance(method, str) else "GET").upper(),
            "body": body.decode("utf-8", errors="replace") if body else None,
            "content_type": content_type,
        }

    def _native_transport(self):
        """Lazily create the per-session native-TLS transport."""
        if self._native_tls is None:
            from wafer._native_tls import NativeTLSTransport

            self._native_tls = NativeTLSTransport(
                follow_redirects=self.follow_redirects,
                proxy_url=self._proxy_url,
            )
        return self._native_tls

    def _native_user_agent(self, extra_headers: dict[str, str] | None) -> str:
        """Pick a User-Agent for the native path.

        Prefer a caller-supplied UA, then the session identity's UA
        (Safari/Dart set one in self.headers), then a host Chrome UA
        derived from the current fingerprint version.
        """
        if extra_headers:
            for k, v in extra_headers.items():
                if k.lower() == "user-agent" and v:
                    return v
        for k, v in self.headers.items():
            if k.lower() == "user-agent" and v:
                return v
        from wafer._fingerprint import chrome_version, host_user_agent

        major = None
        if self._fingerprint is not None:
            major = chrome_version(self._fingerprint.current)
        if major is None:
            major = chrome_version(DEFAULT_EMULATION) or 147
        return host_user_agent(major)

    def _native_prepare(
        self,
        extra_headers: dict[str, str] | None,
        kwargs: dict,
    ) -> tuple[dict[str, str], bytes | None]:
        """Build the sanitized header set and request body for the native path.

        Strips browser-fingerprint headers (Sec-Fetch-*, Sec-Ch-Ua) so the
        request reads as a generic OpenSSL client, and mirrors wreq's
        ``form=``/``json=``/``body=`` kwargs into a raw body + Content-Type.
        """
        from wafer._native_tls import sanitize_headers

        # Minimal "API client" shape: UA + Accept, plus whatever the caller
        # passed (Origin/Referer). sanitize_headers then drops anything
        # browser-typical (Sec-Fetch-*, Accept-Language/Encoding) that would
        # make Imperva challenge an OpenSSL client under rate pressure.
        headers = {
            "User-Agent": self._native_user_agent(extra_headers),
            "Accept": "*/*",
        }
        if extra_headers:
            headers.update(extra_headers)
        headers = sanitize_headers(headers)

        body, content_type = self._extract_native_body(kwargs)
        if content_type and not any(
            k.lower() == "content-type" for k in headers
        ):
            headers["Content-Type"] = content_type
        return headers, body

    @staticmethod
    def _extract_native_body(kwargs: dict) -> tuple[bytes | None, str | None]:
        """Convert wreq body kwargs (form/json/body) to raw bytes + Content-Type."""
        form = kwargs.get("form")
        if form is not None:
            return (
                urlencode(form).encode(),
                "application/x-www-form-urlencoded",
            )
        payload = kwargs.get("json")
        if payload is not None:
            import json as _json

            return _json.dumps(payload).encode(), "application/json"
        raw = kwargs.get("body")
        if raw is not None:
            return (
                raw.encode() if isinstance(raw, str) else raw,
                None,
            )
        return None, None

    def _native_make_response(
        self,
        status: int,
        headers: dict[str, str],
        body_bytes: bytes,
        final_url: str,
        start_time: float,
        state=None,
        raw_set_cookie: list[str] | None = None,
    ):
        """Build a WaferResponse from a native-TLS result, tagging any challenge."""
        from wafer._challenge import detect_challenge
        from wafer._response import WaferResponse

        content_type = headers.get("content-type", "")
        challenge_type = None
        if not _is_binary_content_type(
            content_type
        ) and _is_challengeable_content_type(content_type):
            text = body_bytes.decode("utf-8", errors="replace")
            detected = detect_challenge(status, headers, text)
            challenge_type = detected.value if detected else None
        return WaferResponse(
            status_code=status,
            content=body_bytes,
            # text deliberately not pre-set: .text decodes lazily from
            # content with charset detection (header param / meta tag).
            text=None,
            headers=headers,
            url=final_url,
            elapsed=time.monotonic() - start_time,
            # The native path is only ever reached as a fallback (after an
            # Imperva challenge, or for an already-pinned host), so the caller
            # never got this from a clean first attempt -> was_retried=True even
            # though the wreq retry/rotation counters stay 0.
            was_retried=True,
            retries=state.normal_retries if state else 0,
            rotations=state.rotation_retries if state else 0,
            inline_solves=state.inline_solves if state else 0,
            challenge_type=challenge_type,
            emulation=self._serving_emulation_repr(),
            raw_set_cookie=raw_set_cookie,
        )

    @staticmethod
    def _cookie_applies_to_host(cookie_domain: str | None, host: str) -> bool:
        """True if a stored cookie's Domain covers ``host`` (RFC 6265 5.1.3)."""
        # TODO(phase8): no PSL check - a public-suffix Domain (e.g. co.uk)
        # over-matches; closed when PSL-lite lands
        domain = (cookie_domain or "").lstrip(".").lower()
        if not domain or not host:
            return False
        host = host.lower()
        return host == domain or host.endswith("." + domain)

    def get_cookie(self, name: str, url: str) -> str | None:
        """Read a cookie value from the session's cookie jar(s).

        Looks up ``name`` scoped to ``url``'s host: exact-host cookies
        first, then parent-domain cookies (``Domain=.example.com``
        matching ``www.example.com``). Reads whichever jars the session
        actually uses -- the wreq jar, the native-TLS (Imperva bypass)
        jar, and the Opera Mini jar. Cookies with the ``Secure`` flag
        are only returned for ``https://`` URLs (RFC 6265 5.4). Returns
        the cookie value, or None if not found. Never raises.
        """
        host = urlparse(url).hostname or ""
        # Secure cookies must not be exposed to non-https origins
        # (wreq's Jar.get does not enforce this itself).
        secure_ok = urlparse(url).scheme == "https"
        client = getattr(self, "_client", None)
        if client is not None:
            jar = getattr(client, "cookie_jar", None)
            if jar is not None:
                try:
                    cookie = jar.get(name, url)
                    if cookie is not None and (
                        secure_ok or not cookie.secure
                    ):
                        return cookie.value
                    # Jar.get() matches the host exactly; if it found
                    # nothing, scan for parent-domain cookies
                    # (Domain=.example.com). Don't scan after a Secure
                    # rejection -- a less-specific match must not win.
                    if cookie is None:
                        for c in jar.get_all():
                            if (
                                c.name == name
                                and (secure_ok or not c.secure)
                                and self._cookie_applies_to_host(
                                    c.domain, host
                                )
                            ):
                                return c.value
                except Exception:
                    logger.debug(
                        "Cookie jar read failed for %r", name, exc_info=True
                    )
        # Native-TLS jar (Imperva OpenSSL bypass): http.cookiejar.CookieJar
        if self._native_tls is not None:
            for c in self._native_tls._jar:
                if (
                    c.name == name
                    and (secure_ok or not c.secure)
                    and self._cookie_applies_to_host(c.domain, host)
                ):
                    return c.value
        # Opera Mini urllib jar: http.cookiejar.CookieJar
        if self._om_identity is not None:
            for c in self._om_identity._cookie_jar:
                if (
                    c.name == name
                    and (secure_ok or not c.secure)
                    and self._cookie_applies_to_host(c.domain, host)
                ):
                    return c.value
        return None
