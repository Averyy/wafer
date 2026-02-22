"""Fingerprint management: profile selection, rotation, pinning, sec-ch-ua."""

import logging
import platform
import re
import struct

from rnet import Emulation

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
        ver = platform.mac_ver()[0]  # e.g. "26.2"
        # Chrome reports macOS kernel version, not marketing version.
        # macOS 15.x → kernel 24.x, 14.x → 23.x, etc.
        # platform.mac_ver() returns the marketing version on modern Python,
        # but Chrome reports kernel. Use uname for accuracy.
        try:
            uname_ver = platform.release()  # e.g. "25.2.0"
            parts = uname_ver.split(".")
            return f'"{parts[0]}.{parts[1] if len(parts) > 1 else "0"}.0"'
        except Exception:
            return f'"{ver}"' if ver else '"15.0.0"'
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
# Build numbers increment ~65 per major version from a known anchor.
_FULL_VERSION_ANCHOR = (130, 6723, 91)  # Chrome 130.0.6723.91


def _full_version(major: int) -> str:
    """Generate a plausible Chrome full version string."""
    anchor_major, anchor_build, anchor_patch = _FULL_VERSION_ANCHOR
    build = anchor_build + (major - anchor_major) * 65
    return f"{major}.0.{build}.{anchor_patch}"


def generate_sec_ch_ua_full_version_list(
    major_version: int, brand: str = "Google Chrome"
) -> str:
    """Generate Sec-CH-UA-Full-Version-List with full version numbers."""
    seed = major_version
    full_ver = _full_version(major_version)

    char1 = _GREASY_CHARS[seed % 11]
    char2 = _GREASY_CHARS[(seed + 1) % 11]
    grease_brand = f"Not{char1}A{char2}Brand"
    grease_version = _GREASED_VERSIONS[seed % 3]
    grease_full = f"{grease_version}.0.0.0"

    brands = [
        (grease_brand, grease_full),
        ("Chromium", full_ver),
        (brand, full_ver),
    ]

    order = _BRAND_ORDER[seed % 6]
    shuffled: list[tuple[str, str]] = [("", "")] * 3
    for i in range(3):
        shuffled[order[i]] = brands[i]

    return ", ".join(f'"{b}";v="{v}"' for b, v in shuffled)


_HOST_ARCH = _detect_arch()
_HOST_BITNESS = _detect_bitness()
_HOST_PLATFORM_VERSION = _detect_platform_version()


# ---------------------------------------------------------------------------
# Chrome profile discovery
# ---------------------------------------------------------------------------

_CHROME_RE = re.compile(r"^Chrome(\d+)$")


def _discover_chrome_profiles() -> list[tuple[int, Emulation]]:
    """Discover Chrome Emulation profiles from rnet, sorted newest-first."""
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


_UA_CHROME_RE = re.compile(r"Chrome/(\d+)")


def chrome_version_from_ua(user_agent: str) -> int | None:
    """Extract Chrome major version from a User-Agent string."""
    m = _UA_CHROME_RE.search(user_agent)
    return int(m.group(1)) if m else None


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

    @property
    def current(self) -> Emulation:
        return self._current

    @property
    def pinned(self) -> bool:
        return self._pinned

    def pin(self) -> None:
        """Pin current fingerprint (cookies are bound to this TLS identity)."""
        if not self._pinned:
            self._pinned = True
            logger.debug("Fingerprint pinned to %s", self._current)

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
        """Full identity reset: new fingerprint, clear pinning."""
        self._current = emulation or CHROME_PROFILES[0][1]
        self._pinned = False
        self._rotation_index = 0
        logger.debug("Fingerprint reset to %s", self._current)

    def sec_ch_ua_headers(self) -> dict[str, str]:
        """Generate sec-ch-ua headers for the current Chrome profile.

        Includes both low-entropy (always sent) and high-entropy Client
        Hints (sent after Accept-CH / Critical-CH).  Strict WAFs like
        Cloudflare on manta.com require high-entropy hints for
        cf_clearance cookie replay.
        """
        ver = chrome_version(self._current)
        if ver is None:
            return {}
        return {
            # Low-entropy (always sent by Chrome)
            "sec-ch-ua": generate_sec_ch_ua(ver),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": _HOST_PLATFORM,
            # High-entropy (sent after Accept-CH / Critical-CH)
            "sec-ch-ua-arch": _HOST_ARCH,
            "sec-ch-ua-bitness": _HOST_BITNESS,
            "sec-ch-ua-full-version": f'"{_full_version(ver)}"',
            "sec-ch-ua-full-version-list": (
                generate_sec_ch_ua_full_version_list(ver)
            ),
            "sec-ch-ua-model": '""',
            "sec-ch-ua-platform-version": _HOST_PLATFORM_VERSION,
        }
