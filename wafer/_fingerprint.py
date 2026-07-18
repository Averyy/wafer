"""Fingerprint management: profile selection, rotation, pinning, sec-ch-ua."""

import logging
import platform
import re
import struct

from wreq import Emulation

logger = logging.getLogger("wafer")

# ---------------------------------------------------------------------------
# sec-ch-ua GREASE algorithm (from Chromium source)
# https://source.chromium.org/chromium/chromium/src/+/main:
#   components/embedder_support/user_agent_utils.cc
# ---------------------------------------------------------------------------

_GREASY_CHARS = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
_GREASED_VERSIONS = ["8", "99", "24"]
_BRAND_ORDER = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
]


def generate_sec_ch_ua(
    major_version: int, brand: str = "Google Chrome"
) -> str:
    """Generate sec-ch-ua header matching Chrome's deterministic GREASE algorithm.

    Seeded by the Chrome major version number:
    - Brand name: "Not" + char1 + "A" + char2 + "Brand"
    - Brand version: cycles through ["8", "99", "24"]
    - Brand order: 3 brands shuffled via permutation table
      (shuffled[order[i]] = brands[i])
    """
    seed = major_version

    char1 = _GREASY_CHARS[seed % 11]
    char2 = _GREASY_CHARS[(seed + 1) % 11]
    grease_brand = f"Not{char1}A{char2}Brand"
    grease_version = _GREASED_VERSIONS[seed % 3]

    brands = [
        (grease_brand, grease_version),
        ("Chromium", str(major_version)),
        (brand, str(major_version)),
    ]

    order = _BRAND_ORDER[seed % 6]
    shuffled: list[tuple[str, str]] = [("", "")] * 3
    for i in range(3):
        shuffled[order[i]] = brands[i]

    return ", ".join(f'"{b}";v="{v}"' for b, v in shuffled)


def sec_ch_ua(major_version: int, brand: str = "Google Chrome") -> str:
    """Public: build a ``sec-ch-ua`` header value for a Chromium browser.

    Supported, stable wrapper over the internal Chrome GREASE algorithm.
    Pass ``brand="Microsoft Edge"`` for an Edge identity (Chrome and Edge
    share the GREASE ordering; only the brand token differs). Firefox and
    Safari send no ``sec-ch-ua`` at all, so this is Chromium-only.
    """
    return generate_sec_ch_ua(major_version, brand=brand)


# ---------------------------------------------------------------------------
# Platform detection (for sec-ch-ua-platform)
# ---------------------------------------------------------------------------

def _detect_platform() -> str:
    """Detect host platform for sec-ch-ua-platform header."""
    system = platform.system()
    if system == "Darwin":
        return '"macOS"'
    if system == "Linux":
        return '"Linux"'
    if system == "Windows":
        return '"Windows"'
    return '"Windows"'


_HOST_PLATFORM = _detect_platform()


# UA-reduced platform tokens. Chrome's User-Agent Reduction freezes these
# strings (e.g. macOS always reports "Intel Mac OS X 10_15_7" even on Apple
# Silicon), so they match what wreq's Chrome Emulation puts on the wire.
_UA_PLATFORM_TOKENS = {
    "Darwin": "Macintosh; Intel Mac OS X 10_15_7",
    "Windows": "Windows NT 10.0; Win64; x64",
    "Linux": "X11; Linux x86_64",
}


def host_user_agent(major_version: int) -> str:
    """Build a UA-reduced Chrome User-Agent string for the host platform.

    Chrome's UA Reduction freezes the platform token and collapses the
    version to ``MAJOR.0.0.0``, so this reproduces what wreq's Chrome
    Emulation sends. Used by the native-TLS fallback transport, which has
    to supply its own UA (urllib doesn't go through wreq's Emulation).
    """
    token = _UA_PLATFORM_TOKENS.get(
        platform.system(), _UA_PLATFORM_TOKENS["Windows"]
    )
    return (
        f"Mozilla/5.0 ({token}) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major_version}.0.0.0 Safari/537.36"
    )


# Firefox freezes the macOS token at "Intel Mac OS X 10.15" (no "_7"),
# unlike the Chromium "Intel Mac OS X 10_15_7". Wire-verified 2026-06-12.
_FIREFOX_UA_PLATFORM_TOKENS = {
    "Darwin": "Macintosh; Intel Mac OS X 10.15",
    "Windows": "Windows NT 10.0; Win64; x64",
    "Linux": "X11; Linux x86_64",
}


def emulation_user_agent(emulation: Emulation) -> str | None:
    """Reconstruct the User-Agent wreq sends for an Emulation, for the host.

    Mirrors wreq's per-family UA shape (wire-verified 2026-06-12):

    - Chrome: ``...Chrome/{major}.0.0.0 Safari/537.36`` (UA-reduced)
    - Edge:   ``...Chrome/{major}.0.0.0 Safari/537.36 Edg/{edge_build}``
    - Firefox:``Mozilla/5.0 ({token}; rv:{major}.0) Gecko/20100101
      Firefox/{major}.0``

    Returns ``None`` for families wafer doesn't reconstruct here (Safari,
    Opera, OkHttp - those use their own identity modules or aren't UA-stamped
    from this path). The Chrome segment is UA-reduced (``MAJOR.0.0.0``). The
    Edge ``Edg/`` segment carries the REAL Edge build (e.g. ``147.0.3912.51``):
    Edge does NOT UA-reduce the ``Edg/`` token, and wreq's wire UA emits the
    full build (wire-verified Edge146/147, 2026-06-12). This also keeps the
    envelope UA coherent with the Edge ``sec-ch-ua-full-version-list``, which
    carries the same Edge build.
    """
    family = emulation_family(emulation)
    ver = emulation_major_version(emulation)
    if ver is None:
        return None
    if family == "chrome":
        return host_user_agent(ver)
    if family == "edge":
        return f"{host_user_agent(ver)} Edg/{_edge_full_version(ver)}"
    if family == "firefox":
        token = _FIREFOX_UA_PLATFORM_TOKENS.get(
            platform.system(), _FIREFOX_UA_PLATFORM_TOKENS["Windows"]
        )
        return (
            f"Mozilla/5.0 ({token}; rv:{ver}.0) "
            f"Gecko/20100101 Firefox/{ver}.0"
        )
    return None


# ---------------------------------------------------------------------------
# High-entropy Client Hints (Sec-CH-UA-Arch, Bitness, Full-Version, etc.)
# Real Chrome sends these after a site requests them via Accept-CH /
# Critical-CH.  Cloudflare (manta.com) and other strict WAFs require
# them for cf_clearance cookie replay.
# ---------------------------------------------------------------------------

def _detect_arch() -> str:
    """Detect CPU architecture for Sec-CH-UA-Arch."""
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return '"arm"'
    return '"x86"'


def _detect_bitness() -> str:
    """Detect pointer size for Sec-CH-UA-Bitness."""
    return f'"{struct.calcsize("P") * 8}"'


def _detect_platform_version() -> str:
    """Detect OS version for Sec-CH-UA-Platform-Version."""
    system = platform.system()
    if system == "Darwin":
        # Chrome uses NSProcessInfo.processInfo.operatingSystemVersion,
        # which returns the macOS marketing version (e.g. "26.2.0"),
        # NOT the Darwin kernel version (platform.release()).
        ver = platform.mac_ver()[0]  # e.g. "26.2" or "15.2.1"
        if not ver:
            return '"15.0.0"'
        parts = ver.split(".")
        major = parts[0]
        minor = parts[1] if len(parts) > 1 else "0"
        patch = parts[2] if len(parts) > 2 else "0"
        return f'"{major}.{minor}.{patch}"'
    if system == "Linux":
        try:
            release = platform.release()  # e.g. "6.5.0-44-generic"
            parts = release.split(".")
            return f'"{parts[0]}.{parts[1] if len(parts) > 1 else "0"}.0"'
        except Exception:
            return '"6.0.0"'
    if system == "Windows":
        ver = platform.version()  # e.g. "10.0.22631"
        parts = ver.split(".")
        if len(parts) >= 3:
            return f'"{parts[0]}.{parts[1]}.{parts[2]}"'
        return '"10.0.0"'
    return '"10.0.0"'


# Chrome full version format: MAJOR.0.BUILD.PATCH
# Real build numbers from versionhistory.googleapis.com (first stable release).
_CHROME_BUILDS: dict[int, tuple[int, int]] = {
    130: (6723, 58),
    131: (6778, 69),
    132: (6834, 83),
    133: (6943, 33),
    134: (6998, 35),
    135: (7049, 42),
    136: (7103, 49),
    137: (7151, 37),
    138: (7204, 46),
    139: (7258, 42),
    140: (7339, 34),
    141: (7390, 47),
    142: (7444, 48),
    143: (7499, 52),
    144: (7559, 46),
    145: (7632, 46),
    146: (7680, 31),
    147: (7727, 24),
    148: (7778, 217),
    149: (7827, 201),
}

# Fallback for versions outside the lookup table.
_FULL_VERSION_ANCHOR = (130, 6723, 58)
_CHROME_BUILDS_DEFAULT_MAJOR = max(_CHROME_BUILDS)


def _full_version(major: int) -> str:
    """Return a real Chrome full version string, or a plausible approximation."""
    if major in _CHROME_BUILDS:
        build, patch = _CHROME_BUILDS[major]
        return f"{major}.0.{build}.{patch}"
    anchor_major, anchor_build, anchor_patch = _FULL_VERSION_ANCHOR
    build = anchor_build + (major - anchor_major) * 61
    return f"{major}.0.{build}.{anchor_patch}"


# Microsoft Edge full-version format: MAJOR.0.BUILD.PATCH. The Edge build
# series is DISTINCT from Chrome's (Edge 147 = 147.0.3912.x, Chrome 147 =
# 147.0.7727.x) even though both share the same Chromium MAJOR. Real
# first-stable Edge build numbers from the Microsoft Update Catalog /
# Edge release notes (and wire-verified for the values wreq actually emits:
# Edge146 -> 3856.109, Edge147 -> 3912.51, 2026-06-12 via tls.peet.ws).
# Used ONLY for the "Microsoft Edge" brand in sec-ch-ua-full-version[-list]
# and the reconstructed Edge UA; the "Chromium" brand keeps the shared Chrome
# build (_CHROME_BUILDS), because Edge IS that Chromium under the hood.
# IMPORTANT: refresh this alongside _CHROME_BUILDS when bumping wreq (see
# CLAUDE.md "When upgrading wreq").
_EDGE_BUILDS: dict[int, tuple[int, int]] = {
    122: (2365, 66),
    127: (2651, 74),
    131: (2903, 48),
    134: (3124, 51),
    135: (3179, 54),
    136: (3240, 50),
    137: (3296, 68),
    138: (3351, 55),
    139: (3405, 86),
    140: (3485, 54),
    141: (3537, 57),
    142: (3595, 53),
    143: (3650, 66),
    144: (3719, 82),
    145: (3800, 58),
    146: (3856, 109),  # wire-verified: the build wreq's Edge146 UA emits
    147: (3912, 51),   # wire-verified: the build wreq's Edge147 UA emits
    148: (3967, 96),   # Edge 148 stable (MS Edge update API); wreq's Edge148
                       # UA is reduced to 148.0.0.0 so the build can't be
                       # wire-read - the full build lives only in wafer's
                       # generated full-version-list, which needs a real one.
}

# Linear-approximation fallback for Edge majors not in the table (same
# pattern as Chrome's). Anchor on Edge147 -> 3912; the Edge build series
# advances ~55-56 per major across the recent range (3856->3912->3967->4022).
_EDGE_VERSION_ANCHOR = (147, 3912, 51)
_EDGE_BUILD_STEP = 56


def _edge_full_version(major: int) -> str:
    """Return a real Edge full version string, or a plausible approximation.

    The "Microsoft Edge" brand carries Edge's OWN build, not Chrome's.
    """
    if major in _EDGE_BUILDS:
        build, patch = _EDGE_BUILDS[major]
        return f"{major}.0.{build}.{patch}"
    anchor_major, anchor_build, anchor_patch = _EDGE_VERSION_ANCHOR
    build = anchor_build + (major - anchor_major) * _EDGE_BUILD_STEP
    return f"{major}.0.{build}.{anchor_patch}"


def _brand_full_version(family: str | None, major: int) -> str:
    """Full version for a family's primary brand (Edge build for Edge, else Chrome)."""
    if family == "edge":
        return _edge_full_version(major)
    return _full_version(major)


def full_version(major: int) -> str:
    """Public: a real Chrome full version (``MAJOR.0.BUILD.PATCH``) for ``major``.

    Supported, stable wrapper over the internal Chrome build-number table.
    Returns the real first-stable build number when known, or a plausible
    linear approximation for versions outside the table.
    """
    return _full_version(major)


def generate_sec_ch_ua_full_version_list(
    major_version: int,
    brand: str = "Google Chrome",
    full_version_override: str | None = None,
    brand_full_version: str | None = None,
) -> str:
    """Generate Sec-CH-UA-Full-Version-List with full version numbers.

    The "Chromium" brand always carries the shared Chromium build
    (*full_version_override* if given -- e.g. a real ``browser.version``
    like ``"145.0.7632.117"`` -- else the static Chrome build table).

    *brand_full_version* sets the version for the *primary* brand
    (e.g. "Microsoft Edge") independently. Edge ships a DISTINCT build
    number from the Chromium it embeds (Edge147 = 147.0.3912.51 while
    Chromium147 = 147.0.7727.24), so the Edge brand must NOT inherit the
    Chromium build. When omitted, the primary brand uses the Chromium
    version (correct for "Google Chrome", whose build IS the Chromium one).
    """
    seed = major_version
    chromium_ver = full_version_override or _full_version(major_version)
    primary_ver = brand_full_version or chromium_ver

    char1 = _GREASY_CHARS[seed % 11]
    char2 = _GREASY_CHARS[(seed + 1) % 11]
    grease_brand = f"Not{char1}A{char2}Brand"
    grease_version = _GREASED_VERSIONS[seed % 3]
    grease_full = f"{grease_version}.0.0.0"

    brands = [
        (grease_brand, grease_full),
        ("Chromium", chromium_ver),
        (brand, primary_ver),
    ]

    order = _BRAND_ORDER[seed % 6]
    shuffled: list[tuple[str, str]] = [("", "")] * 3
    for i in range(3):
        shuffled[order[i]] = brands[i]

    return ", ".join(f'"{b}";v="{v}"' for b, v in shuffled)


_HOST_ARCH = _detect_arch()
_HOST_BITNESS = _detect_bitness()
_HOST_PLATFORM_VERSION = _detect_platform_version()

# navigator.platform values per OS (for CDP Emulation.setUserAgentOverride).
_NAVIGATOR_PLATFORM: dict[str, str] = {
    "Darwin": "MacIntel",
    "Windows": "Win32",
    "Linux": "Linux x86_64",
}


def _parse_header_brands(header_str: str) -> list[dict[str, str]]:
    """Parse a ``sec-ch-ua`` style header into ``[{"brand": ..., "version": ...}]``.

    Expected format: ``'"BrandA";v="VerA", "BrandB";v="VerB"'``.
    """
    brands: list[dict[str, str]] = []
    for entry in header_str.split(", "):
        parts = entry.split(";v=", 1)
        if len(parts) != 2:
            continue
        brands.append({
            "brand": parts[0].strip('"'),
            "version": parts[1].strip('"'),
        })
    return brands


def cdp_ua_metadata(
    ua: str, browser_version: str | None = None,
) -> dict:
    """Build the ``Emulation.setUserAgentOverride`` params for CDP.

    Returns a dict ready to pass to ``cdp.send("Emulation.setUserAgentOverride", ...)``.

    *browser_version* is the real full Chrome version from
    ``browser.version`` (e.g. ``"145.0.7632.117"``).  Chrome's UA
    string uses the reduced format (``MAJOR.0.0.0``), so the full
    version can't be extracted from it.  When provided, it's used for
    ``fullVersionList`` and ``fullVersion`` so ``getHighEntropyValues()``
    returns values consistent with the actual browser binary.
    """
    major = chrome_version_from_ua(ua)
    if major is None:
        major = _CHROME_BUILDS_DEFAULT_MAJOR

    # Use real browser version for fullVersionList (high-entropy).
    # Falls back to our build-number table when browser_version
    # isn't available (e.g. TLS-only usage).
    real_full = browser_version or _full_version(major)
    full_version_list = generate_sec_ch_ua_full_version_list(
        major, full_version_override=real_full,
    )

    system = platform.system()
    nav_platform = _NAVIGATOR_PLATFORM.get(system, "Linux x86_64")

    return {
        "userAgent": ua,
        "platform": nav_platform,
        "userAgentMetadata": {
            "brands": _parse_header_brands(generate_sec_ch_ua(major)),
            "fullVersionList": _parse_header_brands(full_version_list),
            "fullVersion": real_full,
            "platform": _HOST_PLATFORM.strip('"'),
            "platformVersion": _HOST_PLATFORM_VERSION.strip('"'),
            "architecture": _HOST_ARCH.strip('"'),
            "bitness": _HOST_BITNESS.strip('"'),
            "model": "",
            "mobile": False,
            "wow64": False,
        },
    }


# ---------------------------------------------------------------------------
# Browser-family classification
# ---------------------------------------------------------------------------
#
# wreq's Emulation enum spans several browser families (Chrome, Edge,
# Firefox, Opera, Safari). repr(Emulation.XxxNNN) is "Profile.XxxNNN", so
# the family + version can be derived from the repr string. Chrome and Edge
# are Chromium-based (they send sec-ch-ua client hints); Firefox and Safari
# are not (no client hints at all). Each family also has its own navigation
# Accept / Accept-Language envelope.

# Family name -> sec-ch-ua brand token (None = wafer emits no client hints
# for this family). Opera is Chromium and DOES send sec-ch-ua, but wreq's
# Opera Emulation already injects accurate, Opera-correct hints at the
# client level (wire-verified 2026-06-12 against tls.peet.ws:
# `"Not:A-Brand";v="99", "Opera";v="130", "Chromium";v="146"` -- Opera 130
# rides Chromium 146, real Opera GREASE format). wafer's own Chrome-GREASE
# generator produces the WRONG values for Opera (wrong Chromium major, wrong
# GREASE char, Chrome full-version table), and emitting them at the client
# level CLOBBERS wreq's correct native hints (no H2 duplication -- a single
# header line -- but a degraded fingerprint). So wafer emits NOTHING for
# Opera and lets wreq's native hints stand. Firefox/Safari send no hints at
# all. (The envelope still reports family="opera"; only the brand is None.)
_FAMILY_BRAND: dict[str, str | None] = {
    "chrome": "Google Chrome",
    "edge": "Microsoft Edge",
    "firefox": None,
    "opera": None,
    "safari": None,
}

# The optional ``[A-Za-z]+`` between the family name and the version digits
# captures wreq's profile *variants* (e.g. ``FirefoxAndroid135``,
# ``FirefoxPrivate136``, ``SafariIos26_2``, ``SafariIPad18``,
# ``SafariIpad26_2``) so they classify into their base family instead of
# returning None (which would wrongly fall back to Chrome's header envelope).
# OkHttp profiles still match nothing here -> family None -> no client hints.
_FAMILY_RE = re.compile(
    r"^Profile\.(Chrome|Edge|Firefox|Opera|Safari)(?:[A-Za-z]+)?(\d+)"
)


def emulation_family(emulation: Emulation) -> str | None:
    """Classify an Emulation profile into a browser family.

    Returns one of ``"chrome"``, ``"edge"``, ``"firefox"``, ``"opera"``,
    ``"safari"`` (lowercased family name), or ``None`` if the profile's
    ``repr()`` doesn't match a known family (e.g. ``Emulation.random``).
    The family is derived from ``repr(emulation)`` (``"Profile.XxxNNN"``)
    since the enum is not hashable and has no ``.name``.
    """
    m = _FAMILY_RE.match(repr(emulation))
    if m is None:
        return None
    return m.group(1).lower()


def emulation_major_version(emulation: Emulation) -> int | None:
    """Extract the major version from any family's Emulation profile, or None."""
    m = _FAMILY_RE.match(repr(emulation))
    if m is None:
        return None
    return int(m.group(2))


# Mobile Emulation profiles carry a phone/tablet TLS shape + a mobile UA from
# wreq (iPhone/iPad Safari, Android Firefox). They are detected from the
# variant token in the profile repr (``Ios``/``IPad``/``Ipad``/``Android``/
# ``Mobile``). wreq exposes NO mobile *Chromium* profile (verified
# 2026-06-12 via ``dir(Emulation)``: only ``SafariIos*``, ``SafariIPad*``,
# ``SafariIpad*`` and ``FirefoxAndroid*``), so every mobile identity is in the
# safari/firefox families -- which send no sec-ch-ua at all. wafer therefore
# never emits ``sec-ch-ua-mobile: ?1`` (that hint only exists for Chromium,
# and there is no mobile Chromium profile to attach it to).
_MOBILE_RE = re.compile(r"^Profile\.\w*?(Ios|IPad|Ipad|Android|Mobile)", re.I)


def emulation_is_mobile(emulation: Emulation) -> bool:
    """True if the Emulation profile is a mobile (phone/tablet) identity.

    Matches wreq's mobile variants -- iOS / iPad Safari (``SafariIos*``,
    ``SafariIPad*``, ``SafariIpad*``) and Android Firefox
    (``FirefoxAndroid*``). Desktop profiles return ``False``.
    """
    return bool(_MOBILE_RE.match(repr(emulation)))


# Per-family navigation Accept / Accept-Language / Accept-Encoding envelope.
# Wire-verified 2026-06-12 against tls.peet.ws + tools.scrapfly.io (the
# values wreq itself sends for each Emulation, cross-checked with MDN's
# "List of default Accept values"). Firefox 132+ (our Firefox149 target)
# uses the SHORT Accept - the longer image/avif... form is Firefox 128-131
# and is stale. Edge is Chromium, so it shares Chrome's navigation Accept
# (only the sec-ch-ua brand differs).
_CHROME_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)
_FIREFOX_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)
# Safari's navigation Accept is the SHORT WebKit form (no image/avif, no
# signed-exchange -- those are Chromium-only). Wire-verified 2026-06-12
# against tls.peet.ws: the identical envelope ships for desktop Safari
# (Emulation.Safari26_2) and mobile iOS/iPad Safari (SafariIos26_2,
# SafariIpad26_2) -- only the TLS shape + UA differ, which wreq sets itself.
# Safari uses `q=0.9` Accept-Language (like Chrome, unlike Firefox's q=0.5),
# `gzip, deflate, br` (NO zstd), and sends NO Cache-Control /
# Upgrade-Insecure-Requests and NO sec-ch-ua client hints.
_SAFARI_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)

# Navigation header envelope per family (the headers a real browser of
# that family sends on a top-level navigation, minus sec-ch-ua, which is
# generated dynamically per version). Chrome/Edge include the navigation
# Cache-Control / Upgrade-Insecure-Requests; Firefox does too.
_FAMILY_HEADERS: dict[str, dict[str, str]] = {
    "chrome": {
        "Accept": _CHROME_ACCEPT,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
    },
    "edge": {
        "Accept": _CHROME_ACCEPT,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
    },
    "firefox": {
        "Accept": _FIREFOX_ACCEPT,
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Upgrade-Insecure-Requests": "1",
    },
    # wreq's native Safari Emulation profiles (desktop Safari26*, mobile
    # SafariIos*/SafariIPad*). These carry a coherent Safari TLS shape + Safari
    # UA from wreq; without this envelope a Safari-Emulation session would
    # serve Chrome's DEFAULT_HEADERS (image/avif Accept, zstd, Cache-Control,
    # Upgrade-Insecure-Requests) over a Safari fingerprint -- incoherent.
    # NOTE: this is for wreq's Safari Emulation members, distinct from
    # Profile.SAFARI (wafer's custom-TlsOptions Safari identity, which supplies
    # its own headers via SafariIdentity.client_headers()).
    "safari": {
        "Accept": _SAFARI_ACCEPT,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
}


def family_headers(family: str | None) -> dict[str, str] | None:
    """Return the navigation header envelope for a browser family, or None.

    Returns a fresh copy of the family's Accept / Accept-Language /
    Accept-Encoding (+ navigation) headers, or ``None`` for families with
    no defined envelope (the caller then keeps the Chrome ``DEFAULT_HEADERS``).
    """
    if family is None:
        return None
    env = _FAMILY_HEADERS.get(family)
    return dict(env) if env is not None else None


# ---------------------------------------------------------------------------
# Chrome profile discovery
# ---------------------------------------------------------------------------

_CHROME_RE = re.compile(r"^Chrome(\d+)$")


def _discover_chrome_profiles() -> list[tuple[int, Emulation]]:
    """Discover Chrome Emulation profiles from wreq, sorted newest-first."""
    profiles = []
    for name in dir(Emulation):
        m = _CHROME_RE.match(name)
        if m:
            profiles.append((int(m.group(1)), getattr(Emulation, name)))
    profiles.sort(reverse=True)
    return profiles


CHROME_PROFILES: list[tuple[int, Emulation]] = _discover_chrome_profiles()

_VERSION_BY_REPR: dict[str, int] = {
    repr(em): ver for ver, em in CHROME_PROFILES
}

_EMULATION_BY_VERSION: dict[int, Emulation] = {
    ver: em for ver, em in CHROME_PROFILES
}


def chrome_version(emulation: Emulation) -> int | None:
    """Extract Chrome major version from an Emulation profile, or None."""
    return _VERSION_BY_REPR.get(repr(emulation))


def emulation_for_version(version: int) -> Emulation | None:
    """Find the Emulation profile matching a Chrome major version, or None."""
    return _EMULATION_BY_VERSION.get(version)


# ---------------------------------------------------------------------------
# Cross-family rotation ladder
# ---------------------------------------------------------------------------
#
# WAF reputation pools key on BROWSER FAMILY, so the strongest rotation axis
# is to escalate ACROSS families (Chrome -> Firefox -> Safari -> Edge) before
# cycling versions WITHIN a family (Chrome145 -> 146 -> 147 all share one
# Chromium reputation pool, so version bumps are the *weakest* axis). The
# ladder is therefore: a fresh TLS session on the starting family (handled in
# the retry loop), then each *other* family in turn, then version cycling.
#
# "safari" is intentionally a string sentinel, not an Emulation: wafer's
# Safari fingerprint is a custom TlsOptions/Http2Options identity (Safari 26
# M3/M4, wire-verified) that wreq's own Emulation.Safari26* profiles do NOT
# match. The retry loop maps the "safari" rung onto SafariIdentity via
# _switch_to_safari(); the Emulation families map onto FingerprintManager.

# Newest wreq Emulation member per non-Chrome family used in the ladder.
# Pinned to concrete members (not auto-discovered) so the ladder is
# deterministic and so a wreq bump that adds a newer member is a conscious
# update (mirrors DEFAULT_EMULATION). Refresh alongside DEFAULT_EMULATION.
FIREFOX_LADDER_EMULATION = Emulation.Firefox151
EDGE_LADDER_EMULATION = Emulation.Edge148

# The deterministic family escalation order. "chrome" is the implicit start
# (the default family); the loop walks the *remaining* rungs in this order
# after the rotation-1 fresh-session retry. Each rung is either an Emulation
# (mapped via FingerprintManager) or the "safari" sentinel (mapped via
# SafariIdentity). The trailing None means "fall back to cycling versions
# within the current family" (FingerprintManager.rotate over Chrome versions).
ROTATION_LADDER: list[object] = [
    FIREFOX_LADDER_EMULATION,  # rung 2: Firefox (Gecko TLS, no client hints)
    "safari",                  # rung 3: Safari (custom TlsOptions identity)
    EDGE_LADDER_EMULATION,     # rung 4: Edge (Chromium, "Microsoft Edge" brand)
    None,                      # rung 5+: cycle Chrome versions within family
]


_UA_CHROME_RE = re.compile(r"Chrome/(\d+)")
_UA_CHROME_FULL_RE = re.compile(r"Chrome/(\d+\.\d+\.\d+\.\d+)")


def chrome_version_from_ua(user_agent: str) -> int | None:
    """Extract Chrome major version from a User-Agent string."""
    m = _UA_CHROME_RE.search(user_agent)
    return int(m.group(1)) if m else None


def chrome_full_version_from_ua(user_agent: str) -> str | None:
    """Extract the full Chrome version (e.g. ``145.0.7632.117``) from a UA."""
    m = _UA_CHROME_FULL_RE.search(user_agent)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# FingerprintManager
# ---------------------------------------------------------------------------


class FingerprintManager:
    """Manages Emulation profile selection, rotation on 403, and pinning."""

    def __init__(self, initial: Emulation | None = None):
        if initial is None:
            initial = CHROME_PROFILES[0][1]
        self._current = initial
        self._pinned = False
        self._rotation_index = 0
        # Identity overrides set after a browser solve (pin_to_browser).
        # They let the replayed UA + client hints match the EXACT Chrome
        # version of the solving browser even when wreq has no matching
        # Emulation (Patchright's Chromium is often newer than wreq's newest
        # profile), so UA/CH-bound WAF cookies (cf_clearance, DataDome)
        # validate on the wreq replay. ``None`` = use the Emulation defaults.
        self._ua_override: str | None = None
        self._ch_version_override: int | None = None
        self._ch_full_version_override: str | None = None

    @property
    def current(self) -> Emulation:
        return self._current

    @property
    def pinned(self) -> bool:
        return self._pinned

    @property
    def ua_override(self) -> str | None:
        """User-Agent to send instead of the Emulation default, or None.

        Set by :meth:`pin_to_browser` so a browser-solved session replays
        the solving browser's exact UA (WAF clearance cookies are UA-bound).
        """
        return self._ua_override

    @property
    def ch_version_override(self) -> int | None:
        """Client-hint major version to present, or None for the Emulation's.

        Set by :meth:`pin_to_browser`; lets diagnostics/tooling read the
        version actually on the wire when it differs from the TLS profile.
        """
        return self._ch_version_override

    @property
    def ch_full_version_override(self) -> str | None:
        """Client-hint full build to present, or None for the Emulation's."""
        return self._ch_full_version_override

    def pin(self) -> None:
        """Pin current fingerprint (cookies are bound to this TLS identity)."""
        if not self._pinned:
            self._pinned = True
            logger.debug("Fingerprint pinned to %s", self._current)

    def pin_to_browser(
        self,
        user_agent: str,
        major_version: int,
        full_version: str | None = None,
    ) -> None:
        """Align the replay identity to a browser that just solved a challenge.

        WAF clearance cookies (Cloudflare ``cf_clearance``, DataDome, ...) are
        bound to the solving browser's TLS shape AND its User-Agent +
        client-hint version. This pins the TLS emulation to the closest
        available Chrome profile (exact match if wreq has it, else the newest)
        and records the browser's EXACT UA + client-hint version so the cookie
        validates when replayed over wreq.

        Patchright's bundled Chromium is often NEWER than wreq's newest
        Emulation (e.g. Chrome 150 vs Chrome 149). Adjacent Chrome majors are
        wire-identical on JA4/H2, so pinning Chrome 149's TLS while presenting
        Chrome 150's UA + hints is coherent to a WAF -- and necessary, because
        replaying the freshly minted cookie under the wrong UA is rejected on
        the very first request (the whole reason a solve "doesn't stick").
        """
        exact = emulation_for_version(major_version)
        self._current = exact or CHROME_PROFILES[0][1]
        self._pinned = True
        self._rotation_index = 0
        self._ua_override = user_agent
        self._ch_version_override = major_version
        self._ch_full_version_override = full_version
        if exact is None:
            # The solving browser (Patchright's Chromium) is NEWER than any wreq
            # Emulation. Handled: TLS pins the newest profile (JA4/H2 identical
            # across adjacent Chrome majors) and the UA/hints follow the real
            # browser, so cookie replay still works. Surfaced at WARNING so the
            # skew is visible (it used to fail silently) -- bump DEFAULT_EMULATION
            # + _CHROME_BUILDS once wreq ships this Chrome profile so the TLS
            # shape tracks it too. See CLAUDE.md wreq-upgrade steps.
            newest = emulation_major_version(self._current)
            logger.warning(
                "Solving browser is Chrome %s but newest wreq Emulation is "
                "Chrome %s; pinning %s TLS with the browser's real Chrome %s "
                "UA/hints (cookie replay works; update wreq to close the gap)",
                major_version,
                newest,
                self._current,
                major_version,
            )
        else:
            logger.debug(
                "Fingerprint pinned to browser: emulation=%s ua_version=%s (%s)",
                self._current,
                major_version,
                full_version or "reduced",
            )

    def rotate(self) -> Emulation:
        """Rotate to a different Chrome profile. Returns the new Emulation.

        No-op if pinned.  Cycles through all Chrome profiles except current.
        """
        if self._pinned:
            logger.debug("Fingerprint is pinned, skipping rotation")
            return self._current

        candidates = [em for _, em in CHROME_PROFILES if em != self._current]
        if not candidates:
            logger.warning("No alternative Chrome profiles for rotation")
            return self._current

        self._current = candidates[self._rotation_index % len(candidates)]
        self._rotation_index += 1
        logger.debug("Rotated fingerprint to %s", self._current)
        return self._current

    def reset(self, emulation: Emulation | None = None) -> None:
        """Full identity reset: new fingerprint, clear pinning and overrides."""
        self._current = emulation or CHROME_PROFILES[0][1]
        self._pinned = False
        self._rotation_index = 0
        self._ua_override = None
        self._ch_version_override = None
        self._ch_full_version_override = None
        logger.debug("Fingerprint reset to %s", self._current)

    def sec_ch_ua_headers(self) -> dict[str, str]:
        """Generate sec-ch-ua headers for the current emulation profile.

        Family-aware: Chrome and Edge send the full low- + high-entropy
        Client Hint set with the family's brand token ("Google Chrome" /
        "Microsoft Edge"). Firefox, Safari, AND Opera return ``{}`` here:
        Firefox/Safari send no client hints at all, and Opera's hints are
        injected accurately by wreq's own Emulation (wafer would clobber
        them with wrong Chrome-GREASE values -- see ``_FAMILY_BRAND``).

        Includes both low-entropy (always sent) and high-entropy Client
        Hints (sent after Accept-CH / Critical-CH).  Strict WAFs like
        Cloudflare on manta.com require high-entropy hints for
        cf_clearance cookie replay.
        """
        family = emulation_family(self._current)
        brand = _FAMILY_BRAND.get(family) if family else None
        # After a browser solve the client-hint version follows the solving
        # browser (pin_to_browser), which may be newer than any wreq profile.
        ver = (
            self._ch_version_override
            if self._ch_version_override is not None
            else emulation_major_version(self._current)
        )
        # Firefox/Safari (brand None) and unknown profiles send no hints.
        if brand is None or ver is None:
            return {}
        # The primary brand's full version is family-specific: Edge ships its
        # own build, so the "Microsoft Edge" brand must NOT carry Chrome's.
        brand_full = (
            self._ch_full_version_override
            if self._ch_full_version_override is not None
            else _brand_full_version(family, ver)
        )
        # After a Chrome browser solve the override IS the real browser.version,
        # so the "Chromium" brand must carry that exact build too (real Chrome
        # sends the same build for "Chromium" and "Google Chrome"). None leaves
        # the Chromium build to the static table. Only Chrome sets the override
        # (pin_to_browser always pins a Chrome emulation); Edge keeps its
        # distinct-build behaviour.
        chromium_full = self._ch_full_version_override
        return {
            # Low-entropy (always sent by Chromium browsers)
            "sec-ch-ua": generate_sec_ch_ua(ver, brand=brand),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": _HOST_PLATFORM,
            # High-entropy (sent after Accept-CH / Critical-CH)
            "sec-ch-ua-arch": _HOST_ARCH,
            "sec-ch-ua-bitness": _HOST_BITNESS,
            "sec-ch-ua-full-version": f'"{brand_full}"',
            "sec-ch-ua-full-version-list": (
                generate_sec_ch_ua_full_version_list(
                    ver,
                    brand=brand,
                    full_version_override=chromium_full,
                    brand_full_version=brand_full,
                )
            ),
            "sec-ch-ua-model": '""',
            "sec-ch-ua-platform-version": _HOST_PLATFORM_VERSION,
        }


# ---------------------------------------------------------------------------
# Public fingerprint envelope
# ---------------------------------------------------------------------------


def build_fingerprint_envelope(
    emulation: Emulation,
    user_agent: str | None = None,
    *,
    ch_major_version: int | None = None,
    ch_full_version: str | None = None,
) -> dict:
    """Build the coherent client-identity envelope for an Emulation profile.

    Returns the User-Agent + Client Hint identity that wafer actually puts
    on the wire for ``emulation``, kept consistent with
    ``FingerprintManager.sec_ch_ua_headers`` (same builders, same brand,
    same host entropy).

    ``ch_major_version`` / ``ch_full_version`` override the client-hint
    version (and full build) independently of ``emulation``. wafer sets them
    after a browser solve so the envelope reflects the solving browser's real
    version even when it is newer than any wreq Emulation (Chrome family only).

    Keys (always present):

    - ``user_agent``: ``str | None`` -- the UA wreq sends for this profile
      (the caller supplies it; wreq sets it from the Emulation, wafer never
      overrides it for Chrome/Edge/Firefox)
    - ``family``: ``"chrome" | "edge" | "firefox" | "opera" | "safari" | None``
    - ``emulation``: ``repr(emulation)`` (e.g. ``"Profile.Chrome147"``)
    - ``sec_ch_ua`` / ``sec_ch_ua_mobile`` / ``sec_ch_ua_platform``:
      the low-entropy Client Hints. ``None`` for Firefox/Safari (no client
      hints) and for Opera (wreq's Emulation emits accurate Opera hints
      itself; wafer doesn't re-derive them -- only Chrome/Edge are populated)
    - ``full_version_list``: the ``Sec-CH-UA-Full-Version-List`` value
      (``None`` except for Chrome/Edge). For Edge the "Microsoft Edge" brand
      carries Edge's OWN build (e.g. ``147.0.3912.51``) while "Chromium"
      keeps the shared Chrome build -- they are deliberately different.
    - ``platform_version``: ``Sec-CH-UA-Platform-Version`` (``None`` except
      for Chrome/Edge)
    - ``user_agent_data``: the ``navigator.userAgentData`` shape Chromium
      exposes to JS (``brands`` / ``mobile`` / ``platform``), ``None`` except
      for Chrome/Edge
    - ``is_mobile``: ``bool`` -- ``True`` for a mobile (phone/tablet) wreq
      Emulation identity (iOS/iPad Safari, Android Firefox). These send NO
      ``sec-ch-ua`` (Safari/Firefox have no client hints), so ``is_mobile``
      is the only mobility signal; wreq exposes no mobile Chromium profile,
      so ``sec_ch_ua_mobile`` is never ``"?1"``
    """
    family = emulation_family(emulation)
    brand = _FAMILY_BRAND.get(family) if family else None
    # The version overrides exist for the Chrome browser solver only (wafer's
    # solver is always Chromium). Ignore them for any other family so a caller
    # can't produce an incoherent Edge envelope (Edge ships a build distinct
    # from Chromium, so an override would wrongly collapse the two brands).
    if family != "chrome":
        ch_major_version = None
        ch_full_version = None
    # A full-build override without its major would desync the sec-ch-ua major
    # from the full-version-list build; the two are meant to be supplied together
    # (pin_to_browser always does). Drop a lone full-version override.
    if ch_major_version is None:
        ch_full_version = None
    ver = (
        ch_major_version
        if ch_major_version is not None
        else emulation_major_version(emulation)
    )
    is_mobile = emulation_is_mobile(emulation)

    envelope: dict = {
        "user_agent": user_agent,
        "family": family,
        "emulation": repr(emulation),
        "sec_ch_ua": None,
        "sec_ch_ua_mobile": None,
        "sec_ch_ua_platform": None,
        "full_version_list": None,
        "platform_version": None,
        "user_agent_data": None,
        "is_mobile": is_mobile,
    }

    # Firefox / Safari (brand None) and unknown profiles: no client hints,
    # no navigator.userAgentData. Leave the CH fields as None. Mobile Safari /
    # Firefox land here too -- is_mobile is set, but no sec-ch-ua (those
    # families send none, mobile or not).
    if brand is None or ver is None:
        return envelope

    brand_full = (
        ch_full_version
        if ch_full_version is not None
        else _brand_full_version(family, ver)
    )
    # Chrome browser-solve override: "Chromium" carries the same real build as
    # "Google Chrome" (see sec_ch_ua_headers). None keeps the static table.
    chromium_full = ch_full_version
    full_version_list = generate_sec_ch_ua_full_version_list(
        ver,
        brand=brand,
        full_version_override=chromium_full,
        brand_full_version=brand_full,
    )
    envelope.update(
        {
            "sec_ch_ua": generate_sec_ch_ua(ver, brand=brand),
            "sec_ch_ua_mobile": "?0",
            "sec_ch_ua_platform": _HOST_PLATFORM,
            "full_version_list": full_version_list,
            "platform_version": _HOST_PLATFORM_VERSION,
            "user_agent_data": {
                "brands": _parse_header_brands(
                    generate_sec_ch_ua(ver, brand=brand)
                ),
                "fullVersionList": _parse_header_brands(full_version_list),
                "mobile": False,
                "platform": _HOST_PLATFORM.strip('"'),
                "platformVersion": _HOST_PLATFORM_VERSION.strip('"'),
                "architecture": _HOST_ARCH.strip('"'),
                "bitness": _HOST_BITNESS.strip('"'),
                "model": "",
            },
        }
    )
    return envelope
