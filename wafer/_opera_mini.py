"""Opera Mini Extreme mode profile — identity generation and HTTP transport.

Opera Mini in Extreme/Mini mode routes through Opera's Presto proxy servers,
which render pages server-side and return compressed OBML. Google detects the
Presto UA string and serves SSR HTML with parseable /url?q= result links
instead of the JS-heavy SPA served to Chrome/Chromium.

This module generates realistic Opera Mini header sets with:
- Confirmed real Opera Mini client versions (from APKMirror + real UA captures)
- Confirmed real device models (from whatmyuseragent.com + StatCounter Africa)
- Confirmed real server/transcoder versions (from live UA captures)
- Correlated device + stock Chrome versions (reflects emerging market update lag)
- Randomized X-OperaMini-Features per device capability

HTTP transport: bypasses rnet entirely, using Python's urllib (system OpenSSL).
This gives perfect header control (no Chrome Sec-Ch-Ua/Sec-Fetch-* leakage)
and a more realistic TLS fingerprint — real Opera Mini routes through
nginx/OpenSSL proxy infrastructure, not BoringSSL/Chrome.
"""

import gzip
import io
import logging
import random
import socket
import ssl
import urllib.error
import zlib
from datetime import date
from http.cookiejar import CookieJar
from urllib.request import (
    HTTPCookieProcessor,
    HTTPSHandler,
    Request,
    build_opener,
)

logger = logging.getLogger("wafer")

# ---------------------------------------------------------------------------
# Frozen components (haven't changed since 2015, unlikely to ever change)
# ---------------------------------------------------------------------------
_PRESTO_VERSION = "2.12.423"      # Server-side rendering engine
_EQUIV_DESKTOP = "12.16"          # Equivalent desktop Opera version (frozen)

# ---------------------------------------------------------------------------
# Confirmed Opera Mini client versions (proxy-mode Presto UA format)
#
# Sources: APKMirror release dates + real UA captures on whatmyuseragent.com
# and useragents.io. Format: MAJOR.MINOR.2254 (2254 is fixed product line).
# All entries confirmed from real data — no guessed/extrapolated versions.
# ---------------------------------------------------------------------------
_OM_VERSIONS = [
    "98.0.2254",   # Feb 2026 (APKMirror, useragents.io)
    "97.1.2254",   # Feb 2026 (APKMirror, whatmyuseragent)
    "97.0.2254",   # Dec 2025 (APKMirror)
    "96.1.2254",   # Dec 2025 (useragents.io)
    "96.0.2254",   # Oct 2025 (APKMirror)
    "95.0.2254",   # Sep 2025 (APKMirror)
    "94.0.2254",   # Aug 2025 (APKMirror)
    "93.0.2254",   # Jul 2025 (whatmyuseragent)
    "92.0.2254",   # Jun 2025 (whatmyuseragent)
    "91.0.2254",   # May 2025 (whatmyuseragent)
    "90.1.2254",   # Apr 2025 (whatmyuseragent)
    "90.0.2254",   # Apr 2025 (whatmyuseragent)
    "89.0.2254",   # Mar 2025 (APKMirror)
    "88.0.2254",   # Feb 2025 (whatmyuseragent)
    "87.1.2254",   # Dec 2024 (whatmyuseragent)
    "87.0.2254",   # Dec 2024 (whatmyuseragent)
    "86.0.2254",   # Dec 2024 (whatmyuseragent)
    "85.0.2254",   # Oct 2024 (whatmyuseragent)
    "84.0.2254",   # Aug 2024 (whatmyuseragent)
    "83.1.2254",   # Jul 2024 (whatmyuseragent)
]

# ---------------------------------------------------------------------------
# Confirmed server/transcoder proxy versions from real UAs.
# These appear after the slash: Opera Mini/XX.X.2254/SERVER_VERSION.
# Server updates independently — newer versions appear with older clients.
#
# Sources: whatmyuseragent.com, useragents.io
# ---------------------------------------------------------------------------
_SERVER_VERSIONS = [
    "191.396",   # newest; seen with 96.1, 98.0
    "191.379",   # most common; seen with 71-93, widespread
    "191.376",   # seen with 87.1, 88.0
    "191.370",   # seen with 80.0, 87.0, 88.0
    "191.361",   # seen with 80.0, 85.0, 86.0, 87.1
    "191.359",   # seen with 84.0, 85.0
    "191.356",   # seen with 85.0
    "191.347",   # seen with 82.0, 83.0, 83.1, 84.0
    "191.343",   # seen with 80.0
    "191.340",   # seen with 78.0, 79.0, 80.0
]

# Weight toward newer/common server versions
_SERVER_VERSION_WEIGHTS = [
    3,   # 191.396
    10,  # 191.379 (dominant)
    2,   # 191.376
    2,   # 191.370
    2,   # 191.361
    1,   # 191.359
    1,   # 191.356
    1,   # 191.347
    1,   # 191.343
    1,   # 191.340
]

# ---------------------------------------------------------------------------
# Chrome version derivation for Device-Stock-UA
# ---------------------------------------------------------------------------

# Anchor: Chrome 133 released ~Jan 15, 2025
_CHROME_ANCHOR_VERSION = 133
_CHROME_ANCHOR_DATE = date(2025, 1, 15)
_CHROME_BUILD_ANCHOR = 6099       # Chrome 120.0.6099.x
_CHROME_BUILD_PER_VER = 65        # ~65 build increment per major version


def _stock_chrome_ua(model: str, android_ver: int, lag_months: int) -> str:
    """Generate a stock device Chrome UA with realistic version lag.

    Emerging market Opera Mini users typically lag 3-12 months behind
    the latest Chrome due to manual/delayed updates.
    """
    today = date.today()
    months = (
        (today.year - _CHROME_ANCHOR_DATE.year) * 12
        + (today.month - _CHROME_ANCHOR_DATE.month)
    )
    chrome_ver = _CHROME_ANCHOR_VERSION + max(months - lag_months, 0)
    build = _CHROME_BUILD_ANCHOR + (chrome_ver - 120) * _CHROME_BUILD_PER_VER
    patches = [144, 105, 193, 143, 112, 101, 164, 127]
    patch = patches[chrome_ver % len(patches)]
    return (
        f"Mozilla/5.0 (Linux; Android {android_ver}; {model}) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{chrome_ver}.0.{build}.{patch} Mobile Safari/537.36"
    )


# ---------------------------------------------------------------------------
# Device pool — confirmed from real Opera Mini user agents
#
# Sources:
#   whatmyuseragent.com (real UAs per device model)
#   StatCounter Africa (vendor + Android version share, Jan 2026)
#   Counterpoint/IDC Africa smartphone shipments 2024
#   GSMArena device specs (model codes, Android versions)
#   APKMirror (Opera Mini release versions)
#
# Format: (build_model, x_operamini_phone, android_version)
# ---------------------------------------------------------------------------
_DEVICES = [
    # Samsung (~35% Africa web traffic, StatCounter Jan 2026)
    ("SM-A065F",  "Samsung # SM-A065F",  14),   # Galaxy A06 — #1 seller SA 2025
    ("SM-A155F",  "Samsung # SM-A155F",  14),   # Galaxy A15 — top seller Africa
    ("SM-A057F",  "Samsung # SM-A057F",  14),   # Galaxy A05s — budget
    ("SM-A145F",  "Samsung # SM-A145F",  14),   # Galaxy A14 — huge installed base
    ("SM-A515F",  "Samsung # SM-A515F",  13),   # Galaxy A51 — legacy mid-range
    ("SM-A127F",  "Samsung # SM-A127F",  13),   # Galaxy A12 Exynos — massive base
    ("SM-A125F",  "Samsung # SM-A125F",  12),   # Galaxy A12 Snapdragon
    ("SM-A346E",  "Samsung # SM-A346E",  14),   # Galaxy A34 5G — mid-range
    # TECNO (Transsion #1 vendor Africa by units, IDC 2024)
    ("TECNO KJ5",  "TECNO # TECNO KJ5",  13),  # Spark 20 — mega-seller
    ("TECNO CK6",  "TECNO # TECNO CK6",  13),  # Camon 20 — mid-range flagship
    ("TECNO BG6h", "TECNO # TECNO BG6h", 13),  # Pop 8 — ultra-budget
    ("TECNO KI5",  "TECNO # TECNO KI5",  12),  # Spark Go 2023
    ("TECNO BF7",  "TECNO # TECNO BF7",  13),  # Spark Go 2024
    # Infinix (Transsion sub-brand)
    ("Infinix X6528", "Infinix # Infinix X6528", 13),  # Hot 40i — budget
    ("Infinix X6836", "Infinix # Infinix X6836", 13),  # Hot 40
    ("Infinix X6525", "Infinix # Infinix X6525", 13),  # Smart 8
    # Xiaomi (7.6% Africa web traffic)
    ("23028RNCAG", "Xiaomi # Redmi Note 12", 13),
    ("23053RN02A", "Xiaomi # Redmi 12",      14),
    # itel (Transsion ultra-budget brand)
    ("itel A665L", "itel # itel A665L",  13),   # A70
    ("itel P662L", "itel # itel P662L",  12),   # P40
    # Nokia (HMD budget)
    ("Nokia C22",  "Nokia # Nokia C22",  13),
]

# Feature set combinations (varies by device capability)
_FEATURE_SETS = [
    "advanced, file_system, secure, touch, viewport",
    "advanced, camera, file_system, secure, touch, viewport",
    "advanced, camera, download, file_system, secure, touch, viewport",
    "advanced, download, file_system, routing, secure, touch, viewport",
    "advanced, camera, download, file_system, folding, secure, touch, viewport",
]

# Chrome version lag tiers (months behind latest)
# Reflects emerging market update behavior
_LAG_TIERS = [3, 7, 12]

# Locales weighted by Opera Mini's actual user geography.
# Opera Mini is dominant in Africa, India, SE Asia, Russia, Eastern Europe.
_LOCALES = [
    "en", "en", "en",           # English (global)
    "id",                        # Indonesian (huge user base)
    "ru",                        # Russian
    "vi",                        # Vietnamese
    "fr",                        # French (West Africa)
    "tr",                        # Turkish
    "uk",                        # Ukrainian
    "th",                        # Thai
    "pl",                        # Polish
]

# Accept-Language with region codes to avoid duplicate bare tags.
# e.g. "fr-FR,fr;q=0.9,en;q=0.5" not "fr,fr;q=0.9,en;q=0.5".
_LOCALE_ACCEPT_LANG = {
    "en": "en-US,en;q=0.9",
    "id": "id-ID,id;q=0.9,en;q=0.5",
    "ru": "ru-RU,ru;q=0.9,en;q=0.5",
    "vi": "vi-VN,vi;q=0.9,en;q=0.5",
    "fr": "fr-FR,fr;q=0.9,en;q=0.5",
    "tr": "tr-TR,tr;q=0.9,en;q=0.5",
    "uk": "uk-UA,uk;q=0.9,en;q=0.5",
    "th": "th-TH,th;q=0.9,en;q=0.5",
    "pl": "pl-PL,pl;q=0.9,en;q=0.5",
}


class OperaMiniIdentity:
    """A bound Opera Mini device identity for a session.

    Created once per session. Device, locale, and features are fixed for the
    session lifetime (a real phone doesn't change identity mid-session).
    Server version varies per-request (different proxy instances).
    """

    def __init__(self):
        self.om_version = random.choice(_OM_VERSIONS)
        model, self.phone_header, android_ver = random.choice(_DEVICES)
        lag = random.choice(_LAG_TIERS)
        self.stock_ua = _stock_chrome_ua(model, android_ver, lag)
        self.features = random.choice(_FEATURE_SETS)
        self._locale = random.choice(_LOCALES)
        self._accept_lang = _LOCALE_ACCEPT_LANG[self._locale]

        # ~40% of real UAs include "Android {ver}", rest just "Android"
        if random.random() < 0.4:
            self._platform = f"Android {android_ver}"
        else:
            self._platform = "Android"

        # HTTP transport: stdlib urllib with system OpenSSL.
        # Gives perfect header control and realistic TLS fingerprint.
        ssl_ctx = ssl.create_default_context()
        self._cookie_jar = CookieJar()
        self._opener = build_opener(
            HTTPSHandler(context=ssl_ctx),
            HTTPCookieProcessor(self._cookie_jar),
        )

    def _build_ua(self) -> str:
        """Build UA string with a random server version (varies per request).

        Real Opera Mini routes through a pool of transcoder proxy servers,
        each running a slightly different build. The server version in the
        UA string changes between requests.
        """
        server_ver = random.choices(
            _SERVER_VERSIONS, weights=_SERVER_VERSION_WEIGHTS, k=1
        )[0]
        return (
            f"Opera/9.80 ({self._platform}; Opera Mini/"
            f"{self.om_version}/{server_ver}; U; {self._locale}) "
            f"Presto/{_PRESTO_VERSION} Version/{_EQUIV_DESKTOP}"
        )

    @property
    def user_agent(self) -> str:
        """Current UA string (server version varies per access)."""
        return self._build_ua()

    def headers(self) -> dict[str, str]:
        """Return the full Opera Mini header set for this identity."""
        return {
            "User-Agent": self._build_ua(),
            "Accept": (
                "text/html, application/xml;q=0.9, application/xhtml+xml, "
                "image/png, image/webp, image/jpeg, image/gif, "
                "image/x-xbitmap, */*;q=0.1"
            ),
            "Accept-Language": self._accept_lang,
            "Accept-Encoding": "deflate, gzip, x-gzip, identity, *;q=0",
            "Connection": "Keep-Alive",
            "X-OperaMini-Features": self.features,
            "X-OperaMini-Phone": self.phone_header,
            "X-OperaMini-Phone-UA": self.stock_ua,
            "Device-Stock-UA": self.stock_ua,
        }

    def request(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, str], str, str]:
        """Send an HTTP GET via stdlib urllib (bypasses rnet).

        Returns (status_code, headers_dict, body_text, final_url).
        final_url reflects the actual URL after any redirects (for SSRF checks).
        Uses system OpenSSL for TLS — no Chrome header leakage,
        more realistic fingerprint for Opera Mini proxy.
        """
        merged = self.headers()
        if headers:
            merged.update(headers)

        req = Request(url)
        for k, v in merged.items():
            req.add_header(k, v)

        logger.debug("Opera Mini GET %s", url)
        try:
            resp = self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            # urllib raises on non-2xx. Catch and return as normal
            # response so callers get a WaferResponse (same as Chrome path).
            resp = e
        except socket.timeout as e:
            from wafer._errors import WaferTimeout

            raise WaferTimeout(url, timeout) from e
        except urllib.error.URLError as e:
            from wafer._errors import ConnectionFailed

            raise ConnectionFailed(url, str(e.reason)) from e

        try:
            raw = resp.read()
        except socket.timeout as e:
            from wafer._errors import WaferTimeout

            raise WaferTimeout(url, timeout) from e
        except OSError as e:
            from wafer._errors import ConnectionFailed

            raise ConnectionFailed(url, str(e)) from e
        encoding = resp.headers.get("Content-Encoding", "")
        if encoding in ("gzip", "x-gzip"):
            try:
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            except (gzip.BadGzipFile, EOFError, OSError):
                pass  # return raw bytes — will decode with replacement
        elif encoding == "deflate":
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                try:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                except zlib.error:
                    pass  # return raw bytes

        text = raw.decode("utf-8", errors="replace")
        resp_headers = {
            k.lower(): v for k, v in resp.headers.items()
        }
        final_url = resp.url or url
        return resp.status, resp_headers, text, final_url
