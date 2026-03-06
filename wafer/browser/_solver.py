"""Patchright-based browser challenge solving.

This module contains the core ``BrowserSolver`` class: browser
lifecycle, extension management, recording loading, mouse replay
methods, and the ``solve()`` / ``intercept_iframe()`` dispatch.

WAF-specific logic lives in dedicated modules:

- ``_cloudflare`` — Cloudflare Turnstile
- ``_akamai`` — Akamai _abck
- ``_datadome`` — DataDome
- ``_awswaf`` — AWS WAF JS challenge
- ``_perimeterx`` — PerimeterX press-and-hold
- ``_shape`` — F5 Shape interstitial
- ``_imperva`` — Imperva / Incapsula reese84
- ``_drag`` — GeeTest / Alibaba drag/slider puzzle
- ``_hcaptcha`` — hCaptcha checkbox
- ``_recaptcha`` — reCAPTCHA v2 checkbox
- ``_recaptcha_grid`` — reCAPTCHA v2 image grid (EfficientNet + D-FINE)
"""

import csv
import importlib.resources
import io
import logging
import math
import random
import sys
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger("wafer")

# ---------------------------------------------------------------------------
# Stealth: no JS injection needed.
#
# The ``--disable-blink-features=AutomationControlled`` launch flag
# makes ``navigator.webdriver`` return ``false`` via a native getter
# (``[native code]``).  Real system Chrome headful provides native
# plugins, WebGL, permissions, chrome.csi/loadTimes, and voices.
#
# Previous approach: injected JS overrides via route interception or
# CDP.  This was actively harmful because:
# - navigator.webdriver override replaced a native getter with an
#   arrow function detectable via ``toString()``
# - chrome.runtime stub had only 2 keys + non-native functions
# - speechSynthesis.getVoices wrapper leaked source in toString()
# - Route interception broke WAF iframes (DataDome WASM PoW)
#
# If a future Chrome/Patchright change breaks native stealth, use
# CDP ``Page.addScriptToEvaluateOnNewDocument`` (requires
# ``Page.enable`` first, do NOT detach the session).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Headless fingerprint patch (macOS)
#
# Headless Chrome on macOS leaks 6 properties that WAFs detect from
# cross-origin iframes (e.g. DataDome's geo.captcha-delivery.com):
#   colorDepth/pixelDepth: 24 (should be 30 on Retina)
#   outerWidth: == innerWidth (should be +2 for window chrome)
#   outerHeight: == innerHeight (should be +80 for title/tab/toolbar)
#   screenY/screenTop: ~22 (should be ~56 with menu bar)
#
# CDP Page.addScriptToEvaluateOnNewDocument only reaches same-origin
# frames (OOPIFs are separate targets).  Cross-origin iframes need
# the fix injected directly via frame.evaluate() - see
# patch_frame_headless() below.
#
# The JS guard (isMac && outerWidth === innerWidth) is intentional:
# outerWidth === innerWidth is the headless signature on macOS.  The
# script is registered on all platforms but only activates on macOS
# headless.  If a future Chrome changes headless outerWidth, the
# Python-side self._headless gate still prevents headed-mode injection.
# ---------------------------------------------------------------------------
_HEADLESS_FIX_SCRIPT = r"""(function () {
  var isMac = navigator.platform === 'MacIntel' ||
    navigator.userAgent.indexOf('Mac OS X') !== -1;
  // In headed mode outerWidth > innerWidth (window chrome adds ~2px).
  // In headless, outerWidth === innerWidth OR 0 (early document load
  // during cross-origin navigation).  Skip only when > innerWidth.
  if (!isMac || window.outerWidth > window.innerWidth) return;
  var _ts = Function.prototype.toString;
  var _m = new Map();
  var _nts = function () {
    return _m.has(this) ? _m.get(this) : _ts.call(this);
  };
  Object.defineProperty(_nts, 'name', {value: 'toString'});
  Object.defineProperty(_nts, 'length', {value: 0});
  Function.prototype.toString = _nts;
  _m.set(_nts, 'function toString() { [native code] }');
  function patch(obj, prop, val) {
    var orig = Object.getOwnPropertyDescriptor(obj, prop);
    if (!orig || !orig.get) return;
    var g = typeof val === 'function' ? val : function () { return val; };
    Object.defineProperty(g, 'name', {value: orig.get.name});
    var desc = {get: g, enumerable: orig.enumerable, configurable: true};
    if (orig.set) desc.set = orig.set;
    Object.defineProperty(obj, prop, desc);
    _m.set(g, _ts.call(orig.get));
  }
  // screen.colorDepth/pixelDepth: headless reports 24 (8-bit), real
  // macOS is 30 (10-bit).  Safe to patch because --force-color-profile=
  // scrgb-linear makes the CSS media queries match (color:10 = true,
  // dynamic-range:high = true), so there's no cross-check inconsistency.
  patch(Screen.prototype, 'colorDepth', 30);
  patch(Screen.prototype, 'pixelDepth', 30);
  patch(window, 'outerWidth', function () { return window.innerWidth + 2; });
  patch(window, 'outerHeight', function () { return window.innerHeight + 80; });
  patch(window, 'screenY', function () { return 56; });
  patch(window, 'screenTop', function () { return 56; });
  // Screen dimensions: headless reports viewport == screen which is
  // impossible on a real display.  Pick a plausible macOS resolution
  // (CSS pixels at default "looks like" scaling) that fits the viewport.
  var displays = [
    [1440, 900],  [1512, 982],  [1710, 1107],
    [1728, 1117], [2560, 1440]
  ];
  var vw = window.innerWidth, vh = window.innerHeight;
  var sw = 2560, sh = 1440;
  for (var i = 0; i < displays.length; i++) {
    if (displays[i][0] > vw && displays[i][1] > vh + 120) {
      sw = displays[i][0]; sh = displays[i][1]; break;
    }
  }
  var menuBar = 37;
  patch(Screen.prototype, 'width', sw);
  patch(Screen.prototype, 'height', sh);
  patch(Screen.prototype, 'availWidth', sw);
  patch(Screen.prototype, 'availHeight', sh - menuBar);
  patch(Screen.prototype, 'availTop', menuBar);
  patch(Screen.prototype, 'availLeft', 0);
})();"""


# ---------------------------------------------------------------------------
# screenX/screenY fix for CDP Input.dispatchMouseEvent
#
# Chromium bug #40280325: CDP mouse events set screenX=clientX and
# screenY=clientY instead of adding the window position offset.
# WAFs (esp. DataDome) compare screenX/Y vs clientX/Y to detect
# CDP-dispatched events.  This script patches the getters so they
# add the window position when the bug is detected (val == clientXY).
#
# Previously shipped as an MV3 extension, but extensions don't load
# in Playwright's new_context() (incognito-like).  Now injected via
# CDP Page.addScriptToEvaluateOnNewDocument for same-origin frames.
# Cross-origin iframes need patch_frame_screenxy() called directly.
# ---------------------------------------------------------------------------
_SCREENXY_FIX_SCRIPT = r"""(function () {
  var origSX = Object.getOwnPropertyDescriptor(MouseEvent.prototype, 'screenX');
  var origSY = Object.getOwnPropertyDescriptor(MouseEvent.prototype, 'screenY');
  if (!origSX || !origSY) return;
  [MouseEvent, PointerEvent].forEach(function (cls) {
    Object.defineProperty(cls.prototype, 'screenX', {
      get: function () {
        var val = origSX.get.call(this);
        if (val === this.clientX) return val + (window.screenX || 0);
        return val;
      }
    });
    Object.defineProperty(cls.prototype, 'screenY', {
      get: function () {
        var val = origSY.get.call(this);
        if (val === this.clientY)
          return val + (window.screenY || 0)
            + (window.outerHeight - window.innerHeight);
        return val;
      }
    });
  });
})();"""


def patch_frame_screenxy(frame) -> None:
    """Inject screenXY fix into a cross-origin frame.

    With site isolation enabled (the default), CDP init scripts only
    reach same-origin frames.  Cross-origin iframes (DataDome's
    captcha-delivery, Baxia, etc.) need the fix injected directly
    so CDP mouse events have correct screenX/screenY values.
    """
    try:
        frame.evaluate(_SCREENXY_FIX_SCRIPT)
    except Exception:
        pass


def patch_frame_headless(frame) -> None:
    """Inject headless fingerprint fix into a cross-origin frame.

    Same rationale as patch_frame_screenxy: CDP init scripts don't
    reach cross-origin iframes.  WAFs that check colorDepth,
    outerWidth, screen dimensions from inside their iframe need
    the headless patches injected directly.
    """
    try:
        frame.evaluate(_HEADLESS_FIX_SCRIPT)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Recording helpers (module-level, shared by all BrowserSolver instances)
# ---------------------------------------------------------------------------

# Direction -> approximate angle (radians) for atan2(dy, dx) from start->target.
# Used as fallback when metadata lacks start/end coordinates.
_DIRECTION_ANGLES: dict[str, float] = {
    "to_center_from_ul": 0.57,   # down-right
    "to_center_from_ur": 2.55,   # down-left
    "to_center_from_l": 0.12,    # right, slightly down
    "to_center_from_bl": -0.40,  # up-right
    "to_center_from_br": -2.72,  # up-left
    "to_lower_from_ul": 0.85,    # steep down-right
}


def _parse_metadata(line: str) -> dict[str, str]:
    """Parse a ``# key=val key=val`` metadata comment line."""
    meta: dict[str, str] = {}
    if not line.startswith("#"):
        return meta
    for token in line[1:].strip().split():
        if "=" in token:
            k, v = token.split("=", 1)
            meta[k] = v
    return meta


def _parse_csv_rows(
    text: str, fields: tuple[str, ...]
) -> list[dict[str, float]]:
    """Parse CSV text (skipping ``#`` comment lines) into a list of dicts."""
    clean = "\n".join(
        line for line in text.splitlines() if not line.startswith("#")
    )
    rows: list[dict[str, float]] = []
    reader = csv.DictReader(io.StringIO(clean))
    for row in reader:
        rows.append({f: float(row[f]) for f in fields})
    return rows


def _angle_from_metadata(meta: dict[str, str]) -> float:
    """Compute approach angle from path metadata start/end coordinates."""
    try:
        sx, sy = (int(v) for v in meta["start"].split(","))
        ex, ey = (int(v) for v in meta["end"].split(","))
        return math.atan2(ey - sy, ex - sx)
    except (KeyError, ValueError):
        pass
    # Fallback: infer from direction name
    direction = meta.get("direction", "")
    return _DIRECTION_ANGLES.get(direction, 0.6)


# Realistic viewport sizes (width, height) weighted toward common resolutions
_VIEWPORTS = [
    (1920, 1080),
    (1366, 768),
    (1536, 864),
    (1440, 900),
    (1280, 720),
]


@dataclass
class _BrowseState:
    """Tracks playback position within a browse recording."""

    rows: list[dict[str, float]]
    index: int
    time_scale: float
    origin_x: float
    origin_y: float
    scroll_scale: float
    current_x: float
    current_y: float


@dataclass
class CapturedResponse:
    """A single HTTP response captured during iframe interception."""

    url: str
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass
class SolveResult:
    """Result of browser-based challenge solving."""

    cookies: list[dict]
    user_agent: str
    extras: dict | None = None
    response: CapturedResponse | None = None


@dataclass
class InterceptResult:
    """Result of iframe interception.

    Contains all cookies and HTTP responses captured from the target
    domain while the embedder page (and its iframes) loaded.
    """

    cookies: list[dict]
    responses: list[CapturedResponse]
    user_agent: str


class BrowserSolver:
    """Solves WAF challenges using a real Chrome browser via patchright.

    Manages a persistent Chrome instance with idle timeout. Cookies are
    extracted after challenge resolution and returned for injection into
    the rnet session.

    Must run headful (headless = 16.7% bypass rate in benchmarks).
    Uses system Chrome via channel="chrome" for best stealth.
    """

    def __init__(
        self,
        headless: bool = False,
        idle_timeout: float = 300.0,
        solve_timeout: float = 30.0,
    ):
        try:
            import patchright  # noqa: F401
        except ImportError:
            raise ImportError(
                "BrowserSolver requires the [browser] extra. "
                "Install it with: pip install wafer-py[browser]"
            ) from None
        self._headless = headless
        self._idle_timeout = idle_timeout
        self._solve_timeout = solve_timeout
        self._playwright = None
        self._browser = None
        self._lock = threading.Lock()
        self._last_used: float = 0.0
        self._browser_ua: str | None = None
        self._browser_version: str | None = None
        # Recording caches (lazy-loaded on first PX encounter)
        self._idle_recordings: list[dict] | None = None
        self._path_recordings: list[dict] | None = None
        self._hold_recordings: list[dict] | None = None
        self._drag_recordings: list[dict] | None = None
        self._slide_recordings: list[dict] | None = None
        self._browse_recordings: list[dict] | None = None
        self._grid_recordings: list[dict] | None = None

    _browser_installed = False

    def _ensure_browser_installed(self) -> None:
        """Auto-install patchright browser binaries if missing."""
        if BrowserSolver._browser_installed:
            return
        import subprocess

        from patchright._impl._driver import (
            compute_driver_executable,
            get_driver_env,
        )

        driver = compute_driver_executable()
        env = get_driver_env()
        logger.debug("Running patchright install chromium...")
        try:
            result = subprocess.run(
                [*driver, "install", "chromium"],
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            # When using channel="chrome" (system Chrome), the
            # downloaded Chromium binary isn't needed. Log and
            # continue - launch() will fail later if it really
            # was required.
            logger.warning(
                "patchright install chromium timed out after 60s, "
                "continuing (system Chrome may still work)"
            )
            BrowserSolver._browser_installed = True
            return
        if result.returncode != 0:
            raise RuntimeError(
                "Failed to install patchright browser binaries. "
                "Install manually with: patchright install chromium\n"
                f"{result.stderr}"
            )
        logger.debug("patchright browsers ready")
        BrowserSolver._browser_installed = True

    def _ensure_browser(self) -> None:
        """Launch browser if not running or if idle too long."""
        now = time.monotonic()

        if self._browser is not None:
            if (
                self._last_used > 0
                and (now - self._last_used) > self._idle_timeout
            ):
                logger.debug(
                    "Browser idle timeout (%.0fs), closing",
                    now - self._last_used,
                )
                self._close_browser()
            elif self._browser.is_connected():
                return
            else:
                logger.debug("Browser disconnected, relaunching")
                self._close_browser()

        try:
            from patchright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "patchright is required for browser solving. "
                "Install with: pip install wafer-py[browser]"
            ) from None

        self._ensure_browser_installed()

        launch_args = [
            "--disable-blink-features=AutomationControlled",
            # Force real GPU instead of SwiftShader.  Without this,
            # WebGL exposes "SwiftShader" as the renderer - a dead
            # giveaway for automated browsers.  Metal on macOS,
            # ANGLE+GL on Linux/Windows.
            "--enable-gpu",
            "--use-gl=angle",
        ]
        if sys.platform == "darwin":
            launch_args.append("--use-angle=metal")

        ignored = [
            # --enable-automation: sets internal automation state,
            # removes chrome.runtime from window.chrome.
            "--enable-automation",
            # --force-color-profile=srgb: alters canvas fingerprint
            # (real Chrome uses system profile).
            "--force-color-profile=srgb",
        ]

        if self._headless:
            # Use --headless=new (Chrome 112+) instead of the old
            # --headless mode.  The new mode uses Chrome's real
            # compositor pipeline, which gives full performance.now
            # timer resolution (old mode clamps to 100us - a known
            # timing-based detection signal).
            launch_args.append("--headless=new")
            ignored.append("--headless")

            if sys.platform == "darwin":
                # Force scRGB-linear color profile so the rendering
                # pipeline reports 10-bit color (color: 10) and HDR
                # (dynamic-range: high).  Without this, headless
                # Chrome on macOS reports 8-bit sRGB, and WAFs like
                # Kasada cross-check CSS computed styles against
                # screen.colorDepth to detect headless.
                launch_args.append(
                    "--force-color-profile=scrgb-linear"
                )

        try:
            logger.debug("Starting playwright driver...")
            self._playwright = sync_playwright().start()
            logger.debug("Launching Chrome (headless=%s)...", self._headless)
            self._browser = self._playwright.chromium.launch(
                channel="chrome",
                headless=self._headless,
                args=launch_args,
                ignore_default_args=ignored,
                timeout=30000,
            )
        except Exception:
            self._close_browser()
            raise

        # Capture the real Chrome full version (e.g. "145.0.7632.117")
        # for CDP metadata.  The UA string is reduced to MAJOR.0.0.0
        # so we can't extract the full version from there.
        self._browser_version = self._browser.version

        # Headless Chrome exposes "HeadlessChrome" in the UA string,
        # which WAF fingerprinting (Kasada, DataDome, etc.) detects
        # instantly.  Probe the real UA and patch it so every context
        # we create uses the corrected value.
        if self._headless:
            probe = self._browser.new_page()
            raw_ua = probe.evaluate("navigator.userAgent")
            probe.close()
            if "HeadlessChrome" in raw_ua:
                self._browser_ua = raw_ua.replace(
                    "HeadlessChrome", "Chrome"
                )
            else:
                self._browser_ua = raw_ua

        self._last_used = now
        logger.info("Browser launched (headless=%s)", self._headless)

    def _close_browser(self) -> None:
        """Shut down browser and playwright."""
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        self._browser_ua = None
        self._browser_version = None

    def _create_context(self):
        """Create a new browser context with realistic settings."""
        kwargs: dict = {}
        if self._headless:
            # Headless has no real window, so we must set a viewport
            # and DPR explicitly.
            viewport = random.choice(_VIEWPORTS)
            kwargs["viewport"] = {
                "width": viewport[0], "height": viewport[1],
            }
            # macOS Retina displays are always DPR 2.  Non-Retina
            # Macs are extinct.  Linux/Windows default to 1.
            dpr = 2 if sys.platform == "darwin" else 1
            kwargs["device_scale_factor"] = dpr
        else:
            # Headed: let the browser use its natural window size.
            # Forcing a viewport larger than the screen causes
            # innerHeight > outerHeight, which is impossible in a
            # real browser and detected by DataDome.  The real
            # display's DPR is already correct.
            kwargs["no_viewport"] = True
        # Inject corrected UA so headless contexts don't leak
        # "HeadlessChrome" to WAF fingerprinters.
        if self._browser_ua:
            kwargs["user_agent"] = self._browser_ua
        return self._browser.new_context(**kwargs)

    def _setup_headless_patches(
        self, page, *, challenge_type: str | None = None,
    ) -> None:
        """Register fingerprint patches via CDP.

        Must be called after page creation but before navigation.

        **All modes** (headed + headless):
        - Fixes ``navigator.languages`` to ``["en-US", "en"]`` via
          CDP ``Emulation.setUserAgentOverride`` with ``acceptLanguage``.
        - Injects screenX/screenY fix for CDP mouse event bug
          (Chromium #40280325) via ``Page.addScriptToEvaluateOnNewDocument``.

        **Headless only** (additional):
        - Injects headless fingerprint fix script (colorDepth, outerWidth,
          outerHeight, screenY patches for macOS).  Skipped for Kasada
          because the Function.prototype.toString wrapper is detected
          by ips.js; scrgb-linear alone suffices for Kasada.
        - Fixes ``navigator.userAgentData`` via CDP ``userAgentMetadata``
          so the JS ``NavigatorUAData`` API matches the corrected UA.
        """
        # Guard against double registration (each call creates a new
        # CDP session and re-registers the init script).
        if getattr(page, "_wafer_headless_patched", False):
            return
        page._wafer_headless_patched = True  # type: ignore[attr-defined]
        cdp = page.context.new_cdp_session(page)
        cdp.send("Page.enable")

        # screenXY fix: runs in both headed and headless modes.
        # Must fire before any page JS to intercept mouse events.
        cdp.send("Page.addScriptToEvaluateOnNewDocument", {
            "source": _SCREENXY_FIX_SCRIPT,
        })

        if self._headless:
            # Kasada's ips.js and Akamai's behavioral challenge JS
            # detect the Function.prototype.toString wrapper in
            # _HEADLESS_FIX_SCRIPT.  Kasada withholds x-kpsdk-r;
            # Akamai behavioral refuses to set session cookies.
            # scrgb-linear alone handles the CSS cross-checks.
            if challenge_type not in ("kasada", "akamai"):
                cdp.send("Page.addScriptToEvaluateOnNewDocument", {
                    "source": _HEADLESS_FIX_SCRIPT,
                })

            # On macOS, --force-color-profile=scrgb-linear already
            # makes (color: 10), (dynamic-range: high), and
            # (color-gamut: p3) match headed Chrome.  The only
            # remaining gap is color-gamut on non-macOS headless,
            # which CDP Emulation.setEmulatedMedia can patch.
            if sys.platform == "darwin":
                cdp.send("Emulation.setEmulatedMedia", {
                    "features": [
                        {"name": "color-gamut", "value": "p3"},
                    ],
                })

            # Fix navigator.userAgentData + languages.
            ua = self._browser_ua or ""
            if ua:
                self._apply_ua_metadata(
                    cdp, ua, self._browser_version,
                )
        else:
            # Headed: fix navigator.languages AND provide
            # userAgentMetadata.  Without metadata, the CDP
            # setUserAgentOverride call strips sec-ch-ua HTTP
            # headers entirely — a strong WAF detection signal.
            ua = self._browser_ua or page.evaluate(
                "navigator.userAgent"
            )
            self._apply_ua_metadata(
                cdp, ua, self._browser_version,
            )

        # Do NOT detach the CDP session - that removes registered
        # scripts.  GC-safe: Playwright's channel registry keeps it
        # alive for the page's lifetime.

    @staticmethod
    def _apply_ua_metadata(
        cdp, ua: str, browser_version: str | None = None,
    ) -> None:
        """Set CDP userAgentMetadata so navigator.userAgentData matches.

        Delegates to ``wafer._fingerprint.cdp_ua_metadata`` which
        reuses the same arch, bitness, platform version, and brand
        algorithms used for HTTP sec-ch-ua headers.  Also sets
        ``acceptLanguage`` so ``navigator.languages`` returns
        ``["en-US", "en"]`` instead of the default ``["en-US"]``.

        *browser_version* is the real full version from ``browser.version``
        (e.g. ``"145.0.7632.117"``).  The UA string is reduced to
        ``MAJOR.0.0.0`` so the full version can't be extracted from it.
        """
        from wafer._fingerprint import cdp_ua_metadata

        params = cdp_ua_metadata(ua, browser_version=browser_version)
        params["acceptLanguage"] = "en-US,en"
        cdp.send("Emulation.setUserAgentOverride", params)

    # ------------------------------------------------------------------
    # Recording loader
    # ------------------------------------------------------------------

    def _ensure_recordings(self) -> bool:
        """Lazy-load human mouse recordings on first PX encounter.

        Returns True if all required categories (idles, paths, holds)
        have at least one recording.  Caches results so subsequent
        calls are free.
        """
        if self._idle_recordings is not None:
            return bool(
                self._idle_recordings
                and self._path_recordings
                and self._hold_recordings
            )

        self._idle_recordings = []
        self._path_recordings = []
        self._hold_recordings = []
        self._drag_recordings = []
        self._slide_recordings = []
        self._browse_recordings = []
        self._grid_recordings = []

        try:
            rec_dir = (
                importlib.resources.files("wafer.browser")
                / "_recordings"
            )
        except Exception:
            logger.debug("Recordings package not found")
            return False

        # --- idles ---
        try:
            for f in (rec_dir / "idles").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                rows = _parse_csv_rows(text, ("t", "dx", "dy"))
                if rows:
                    self._idle_recordings.append(
                        {"rows": rows, "name": name}
                    )
        except Exception:
            logger.debug("Failed to load idle recordings", exc_info=True)

        # --- paths ---
        try:
            for f in (rec_dir / "paths").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                angle = _angle_from_metadata(meta)
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._path_recordings.append(
                        {
                            "rows": rows,
                            "angle": angle,
                            "meta": meta,
                            "name": name,
                        }
                    )
        except Exception:
            logger.debug("Failed to load path recordings", exc_info=True)

        # --- holds ---
        try:
            for f in (rec_dir / "holds").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                rows = _parse_csv_rows(text, ("t", "dx", "dy"))
                if rows:
                    self._hold_recordings.append(
                        {"rows": rows, "name": name}
                    )
        except Exception:
            logger.debug("Failed to load hold recordings", exc_info=True)

        # --- drags ---
        try:
            for f in (rec_dir / "drags").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._drag_recordings.append(
                        {"rows": rows, "meta": meta, "name": name}
                    )
        except Exception:
            logger.debug("Failed to load drag recordings", exc_info=True)

        # --- slide_drags (full-width "slide to verify" drags) ---
        try:
            for f in (rec_dir / "slide_drags").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._slide_recordings.append(
                        {"rows": rows, "meta": meta, "name": name}
                    )
        except Exception:
            logger.debug("Failed to load slide recordings", exc_info=True)

        # --- browses ---
        try:
            for f in (rec_dir / "browses").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                rows = _parse_csv_rows(
                    text, ("t", "dx", "dy", "scroll_y")
                )
                if rows:
                    self._browse_recordings.append({
                        "rows": rows,
                        "max_scroll": int(
                            meta.get("max_scroll", "0")
                        ),
                        "sections": int(
                            meta.get("sections", "0")
                        ),
                        "name": name,
                    })
        except Exception:
            logger.debug("Failed to load browse recordings", exc_info=True)

        # --- grids (short-hop paths for tile clicking) ---
        try:
            for f in (rec_dir / "grids").iterdir():
                name = str(f).rsplit("/", 1)[-1]
                if not name.endswith(".csv"):
                    continue
                text = f.read_text()
                meta = _parse_metadata(text.splitlines()[0])
                angle = _angle_from_metadata(meta)
                rows = _parse_csv_rows(text, ("t", "rx", "ry"))
                if rows:
                    self._grid_recordings.append(
                        {
                            "rows": rows,
                            "angle": angle,
                            "meta": meta,
                            "name": name,
                        }
                    )
        except Exception:
            logger.debug("Failed to load grid recordings", exc_info=True)

        logger.info(
            "Loaded %d idle + %d path + %d hold + %d drag"
            " + %d slide + %d grid + %d browse recordings",
            len(self._idle_recordings),
            len(self._path_recordings),
            len(self._hold_recordings),
            len(self._drag_recordings),
            len(self._slide_recordings),
            len(self._grid_recordings),
            len(self._browse_recordings),
        )
        return bool(
            self._idle_recordings
            and self._path_recordings
            and self._hold_recordings
        )

    # ------------------------------------------------------------------
    # Mouse replay methods (shared by PX and future drag solvers)
    # ------------------------------------------------------------------

    def _pick_path(
        self,
        start_x: float,
        start_y: float,
        target_x: float,
        target_y: float,
        pool: list[dict] | None = None,
    ) -> dict:
        """Pick a recorded path whose direction best matches the move."""
        recordings = pool if pool is not None else self._path_recordings
        angle = math.atan2(
            target_y - start_y, target_x - start_x
        )

        def _angle_diff(rec: dict) -> float:
            diff = abs(rec["angle"] - angle)
            return min(diff, 2 * math.pi - diff)

        best = min(recordings, key=_angle_diff)
        return best

    def _replay_idle(
        self, page, origin_x: float, origin_y: float
    ) -> tuple[float, float]:
        """Replay recorded idle mouse movement.

        Returns the final ``(x, y)`` position.
        """
        rec = random.choice(self._idle_recordings)
        recording = rec["rows"]
        time_scale = random.uniform(0.85, 1.15)
        duration = recording[-1]["t"] * time_scale if recording else 0

        logger.info(
            "Idle: %s (%.1fs, %d points) from (%.0f, %.0f)",
            rec["name"],
            duration,
            len(recording),
            origin_x,
            origin_y,
        )

        page.mouse.move(origin_x, origin_y)
        t0 = time.monotonic()
        final_x, final_y = origin_x, origin_y

        for row in recording:
            target_t = row["t"] * time_scale
            elapsed = time.monotonic() - t0
            delay = target_t - elapsed
            if delay > 0:
                time.sleep(delay)

            final_x = origin_x + row["dx"]
            final_y = origin_y + row["dy"]
            page.mouse.move(final_x, final_y)

        return final_x, final_y

    def _replay_path(
        self,
        page,
        start_x: float,
        start_y: float,
        target_x: float,
        target_y: float,
        pool: list[dict] | None = None,
    ) -> None:
        """Replay a recorded human path from start to target."""
        rec = self._pick_path(
            start_x, start_y, target_x, target_y, pool=pool
        )
        recording = rec["rows"]
        dx = target_x - start_x
        dy = target_y - start_y
        time_scale = random.uniform(0.85, 1.15)
        duration = recording[-1]["t"] * time_scale if recording else 0

        logger.info(
            "Path: %s (%s, %.1fs, %d points) "
            "(%.0f,%.0f) -> (%.0f,%.0f)",
            rec["name"],
            rec["meta"].get("direction", "?"),
            duration,
            len(recording),
            start_x,
            start_y,
            target_x,
            target_y,
        )

        page.mouse.move(start_x, start_y)
        t0 = time.monotonic()

        for row in recording:
            target_t = row["t"] * time_scale
            elapsed = time.monotonic() - t0
            delay = target_t - elapsed
            if delay > 0:
                time.sleep(delay)

            x = start_x + row["rx"] * dx
            y = start_y + row["ry"] * dy
            page.mouse.move(x, y)

    def _replay_drag(
        self,
        page,
        start_x: float,
        start_y: float,
        end_x: float,
        end_y: float,
    ) -> None:
        """Replay a recorded drag from start to end.

        Recordings include an optional pre-drag hover phase (natural
        pause near the handle before clicking).  The ``mousedown_t``
        metadata field marks when the click happens — events before it
        are replayed as cursor movement without the button held.

        The recording's ``ry`` values are normalized against the original
        horizontal track width (not vertical displacement).  This preserves
        natural vertical wobble even for perfectly horizontal drags where
        ``end_y ≈ start_y``.
        """
        dx = end_x - start_x
        target_dist = abs(dx)

        # Pick recording with closest original drag distance — a 50px
        # drag has a fundamentally different speed/deceleration profile
        # than a 300px drag, so matching distance keeps it natural.
        def _drag_dist(rec: dict) -> float:
            meta = rec.get("meta", {})
            if "start" in meta and "end" in meta:
                try:
                    sx, _ = meta["start"].split(",")
                    ex, _ = meta["end"].split(",")
                    return abs(int(ex) - int(sx))
                except (ValueError, IndexError):
                    pass
            return 0.0

        # Sort by distance similarity, pick randomly from top 3 closest
        # to add slight variation while keeping the profile realistic.
        ranked = sorted(
            self._drag_recordings,
            key=lambda r: abs(_drag_dist(r) - target_dist),
        )
        pool = ranked[: min(3, len(ranked))]
        recording = random.choice(pool)
        rows = recording["rows"]
        meta = recording.get("meta", {})
        mousedown_t = float(meta.get("mousedown_t", "0"))
        time_scale = random.uniform(0.85, 1.15)

        page.mouse.move(start_x, start_y)
        t0 = time.monotonic()
        mouse_down = False

        for row in rows:
            # Transition from hover to drag at mousedown_t
            if not mouse_down and row["t"] >= mousedown_t:
                mouse_down = True
                page.mouse.down()

            target_t = row["t"] * time_scale
            elapsed = time.monotonic() - t0
            delay = target_t - elapsed
            if delay > 0:
                time.sleep(delay)

            x = start_x + row["rx"] * dx
            y = start_y + row["ry"] * abs(dx)
            page.mouse.move(x, y)

        if not mouse_down:
            page.mouse.down()
        page.mouse.up()

    # ------------------------------------------------------------------
    # Browse replay (background mouse/scroll during solver waits)
    # ------------------------------------------------------------------

    def _start_browse(
        self,
        page,
        origin_x: float,
        origin_y: float,
    ) -> _BrowseState | None:
        """Begin a browse recording for replay during solver waits.

        Returns a ``_BrowseState`` to pass to ``_replay_browse_chunk()``,
        or ``None`` if no browse recordings are available.
        """
        if self._browse_recordings is None:
            self._ensure_recordings()
        if not self._browse_recordings:
            return None

        rec = random.choice(self._browse_recordings)
        scroll_scale = 1.0
        time_scale = random.uniform(0.85, 1.15)

        logger.debug(
            "Browse: %s (%d points, scale=%.2f) from (%.0f, %.0f)",
            rec.get("name", "?"),
            len(rec["rows"]),
            time_scale,
            origin_x,
            origin_y,
        )

        try:
            page.mouse.move(origin_x, origin_y)
        except Exception:
            pass

        return _BrowseState(
            rows=rec["rows"],
            index=0,
            time_scale=time_scale,
            origin_x=origin_x,
            origin_y=origin_y,
            scroll_scale=scroll_scale,
            current_x=origin_x,
            current_y=origin_y,
        )

    def _replay_browse_chunk(
        self,
        page,
        state: _BrowseState | None,
        duration: float,
    ) -> None:
        """Replay a chunk of browse recording for *duration* seconds.

        Falls back to ``time.sleep(duration)`` when *state* is ``None``
        or the recording is exhausted.
        """
        if state is None or state.index >= len(state.rows):
            time.sleep(duration)
            return

        deadline = time.monotonic() + duration
        prev_t = (
            state.rows[state.index - 1]["t"]
            if state.index > 0
            else state.rows[state.index]["t"]
        )

        while state.index < len(state.rows):
            now = time.monotonic()
            if now >= deadline:
                break

            row = state.rows[state.index]
            delay = (row["t"] - prev_t) * state.time_scale
            if delay > 0:
                remaining = deadline - now
                if delay > remaining:
                    time.sleep(remaining)
                    break
                time.sleep(delay)

            x = state.origin_x + row["dx"]
            y = state.origin_y + row["dy"]
            try:
                page.mouse.move(x, y)
            except Exception:
                break

            scroll_y = row.get("scroll_y", 0)
            if scroll_y:
                try:
                    page.mouse.wheel(
                        0, scroll_y * state.scroll_scale
                    )
                except Exception:
                    pass

            state.current_x = x
            state.current_y = y
            prev_t = row["t"]
            state.index += 1

        # If recording exhausted before duration, sleep remainder
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)

    # ------------------------------------------------------------------
    # PX convenience wrappers (delegate to _perimeterx module)
    # ------------------------------------------------------------------

    def _has_px_challenge(self, page) -> bool:
        from wafer.browser._perimeterx import has_px_challenge
        return has_px_challenge(page)

    def _find_px_button(self, page, timeout: float = 30.0):
        from wafer.browser._perimeterx import find_px_button
        return find_px_button(page, timeout)

    def _solve_perimeterx(self, page, timeout_ms: int) -> bool:
        from wafer.browser._perimeterx import solve_perimeterx
        return solve_perimeterx(self, page, timeout_ms)

    # ------------------------------------------------------------------
    # Solve dispatch
    # ------------------------------------------------------------------

    def solve(
        self,
        url: str,
        challenge_type: str | None = None,
        timeout: float | None = None,
    ) -> SolveResult | None:
        """Solve a WAF challenge by navigating in a real browser.

        Returns SolveResult with cookies and user_agent, or None on
        failure.
        """
        if timeout is None:
            timeout = self._solve_timeout
        timeout_ms = int(timeout * 1000)

        with self._lock:
            try:
                self._ensure_browser()
            except Exception:
                logger.warning(
                    "Failed to launch browser", exc_info=True
                )
                return None

            context = None
            try:
                context = self._create_context()
                page = context.new_page()
                self._setup_headless_patches(
                    page, challenge_type=challenge_type,
                )

                if self._browser_ua is None:
                    self._browser_ua = page.evaluate(
                        "navigator.userAgent"
                    )
                    logger.debug("Browser UA: %s", self._browser_ua)

                logger.info(
                    "Browser solving %s challenge at %s",
                    challenge_type or "unknown",
                    url,
                )

                # No JS stealth injection needed.  The launch flag
                # --disable-blink-features=AutomationControlled
                # handles navigator.webdriver natively.  See comment
                # block at top of file for rationale.

                # Kasada: attach /tl listener BEFORE navigation
                # (the /tl POST can fire during page load)
                if challenge_type == "kasada":
                    from wafer.browser._kasada import (
                        setup_kasada_listener,
                    )
                    setup_kasada_listener(page)

                nav_response = None
                try:
                    nav_response = page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=timeout_ms,
                    )
                except Exception:
                    logger.debug(
                        "Browser navigation timeout/error",
                        exc_info=True,
                    )

                # WAF-specific wait strategy
                solved = self._dispatch_challenge(
                    page, challenge_type, timeout_ms
                )


                cookies = context.cookies()

                if not cookies:
                    logger.warning(
                        "Browser solve yielded no cookies for %s",
                        url,
                    )
                    return None

                self._last_used = time.monotonic()

                # Build passthrough response when browser got real
                # content without solving a challenge (WAF only
                # challenges non-browser TLS clients)
                captured = None
                if (
                    not solved
                    and nav_response is not None
                    and 200 <= nav_response.status < 300
                ):
                    try:
                        body = nav_response.body()
                    except Exception:
                        body = b""
                    # nav_response body may be empty after a
                    # client-side redirect/reload.  Fall back to
                    # page.content() which reflects the final DOM.
                    if len(body) <= 1024:
                        try:
                            html = page.content()
                            if len(html) > 1024:
                                body = html.encode("utf-8")
                        except Exception:
                            pass
                    if len(body) > 1024:
                        nav_headers = {}
                        try:
                            for k, v in nav_response.headers.items():
                                nav_headers[k] = v
                        except Exception:
                            pass
                        captured = CapturedResponse(
                            url=nav_response.url,
                            status=nav_response.status,
                            headers=nav_headers,
                            body=body,
                        )
                        logger.info(
                            "Browser passthrough for %s at %s "
                            "(%d bytes, %d cookies)",
                            challenge_type or "unknown",
                            url,
                            len(body),
                            len(cookies),
                        )

                # Auto-resolve passthrough: WAF served a challenge
                # (nav 403) but the browser resolved it in the
                # background (WASM PoW, auto-cookie).  The page may
                # have redirected to real content by now.
                if not solved and captured is None:
                    try:
                        html = page.content()
                    except Exception:
                        html = ""
                    if len(html) > 1024:
                        head = html[:10000].lower()
                        is_challenge = (
                            "captcha-delivery" in head
                            or "kpsdk" in head
                            or "px-captcha" in head
                            or "reese84" in head
                            or "just a moment" in head
                            or "cf_chl" in head
                            or "challenge-platform" in head
                            or "chl_page" in head
                        )
                        if not is_challenge:
                            body = html.encode("utf-8")
                            cookies = context.cookies()
                            captured = CapturedResponse(
                                url=page.url,
                                status=200,
                                headers={
                                    "content-type": (
                                        "text/html; charset=utf-8"
                                    )
                                },
                                body=body,
                            )
                            logger.info(
                                "Browser auto-resolve passthrough "
                                "for %s at %s (%d bytes, %d cookies)",
                                challenge_type or "unknown",
                                page.url,
                                len(body),
                                len(cookies),
                            )

                # Post-solve passthrough: after solving, the page
                # may auto-reload to real content.  Capture it
                # when cookie replay is unreliable (TLS-bound).
                # The browser needs time to redirect after cookie
                # update, so retry up to 5s for real content.
                if solved and captured is None:
                    passthrough_deadline = time.monotonic() + 5
                    while time.monotonic() < passthrough_deadline:
                        try:
                            html = page.content()
                        except Exception:
                            html = ""
                        head = html[:10000].lower()
                        is_challenge = (
                            "kpsdk" in head
                            or "captcha-delivery" in head
                            or ("akamai" in head and "_abck" in head)
                            or "perimeterx" in head
                            or "px-captcha" in head
                            or "reese84" in head
                            or "just a moment" in head
                            or "cf_chl" in head
                            or "challenge-platform" in head
                            or "chl_page" in head
                        )
                        # Detect soft-block pages (e.g. F5 Shape
                        # redirects to siteclosed/invitation.html).
                        page_url = page.url.lower()
                        is_block = (
                            "invitation" in page_url
                            or "siteclosed" in page_url
                        )
                        if (
                            len(html) > 1024
                            and not is_challenge
                            and not is_block
                        ):
                            body = html.encode("utf-8")
                            # Re-read cookies after redirect —
                            # new page may have set more.
                            cookies = context.cookies()
                            captured = CapturedResponse(
                                url=page.url,
                                status=200,
                                headers={
                                    "content-type": (
                                        "text/html; charset=utf-8"
                                    )
                                },
                                body=body,
                            )
                            logger.info(
                                "%s passthrough at %s "
                                "(%d bytes, %d cookies)",
                                challenge_type or "unknown",
                                page.url,
                                len(body),
                                len(cookies),
                            )
                            break
                        time.sleep(1)

                if solved:
                    logger.info(
                        "Browser solved %s challenge at %s "
                        "(%d cookies)",
                        challenge_type or "unknown",
                        url,
                        len(cookies),
                    )
                elif captured is None:
                    logger.warning(
                        "Browser solve timed out for %s at %s, "
                        "returning %d cookies anyway",
                        challenge_type or "unknown",
                        url,
                        len(cookies),
                    )

                extras = getattr(page, "_kasada_result", None)

                return SolveResult(
                    cookies=cookies,
                    user_agent=self._browser_ua or "",
                    extras=extras,
                    response=captured,
                )

            except Exception:
                logger.warning(
                    "Browser solve failed for %s",
                    url,
                    exc_info=True,
                )
                return None
            finally:
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass

    def _dispatch_challenge(
        self, page, challenge_type: str | None, timeout_ms: int
    ) -> bool:
        """Route to the correct WAF-specific solver."""
        if challenge_type == "cloudflare":
            from wafer.browser._cloudflare import (
                wait_for_cloudflare,
            )
            return wait_for_cloudflare(self, page, timeout_ms)
        elif challenge_type == "akamai":
            from wafer.browser._akamai import wait_for_akamai
            return wait_for_akamai(self, page, timeout_ms)
        elif challenge_type == "datadome":
            from wafer.browser._datadome import wait_for_datadome
            return wait_for_datadome(self, page, timeout_ms)
        elif challenge_type == "perimeterx":
            from wafer.browser._perimeterx import (
                solve_perimeterx,
            )
            return solve_perimeterx(self, page, timeout_ms)
        elif challenge_type == "awswaf":
            from wafer.browser._awswaf import wait_for_awswaf
            return wait_for_awswaf(self, page, timeout_ms)
        elif challenge_type == "kasada":
            from wafer.browser._kasada import wait_for_kasada
            return wait_for_kasada(self, page, timeout_ms)
        elif challenge_type == "shape":
            from wafer.browser._shape import wait_for_shape
            return wait_for_shape(self, page, timeout_ms)
        elif challenge_type == "imperva":
            from wafer.browser._imperva import wait_for_imperva
            return wait_for_imperva(self, page, timeout_ms)
        elif challenge_type == "geetest":
            from wafer.browser._drag import solve_drag
            return solve_drag(self, page, timeout_ms)
        elif challenge_type in ("baxia", "tmd"):
            from wafer.browser._drag import solve_baxia
            return solve_baxia(self, page, timeout_ms)
        elif challenge_type == "hcaptcha":
            from wafer.browser._hcaptcha import wait_for_hcaptcha
            return wait_for_hcaptcha(self, page, timeout_ms)
        elif challenge_type == "recaptcha":
            from wafer.browser._recaptcha import wait_for_recaptcha
            return wait_for_recaptcha(self, page, timeout_ms)
        else:
            return self._wait_for_generic(page, timeout_ms)

    def _wait_for_generic(self, page, timeout_ms: int) -> bool:
        """Generic wait: network idle + extra time for JS execution."""
        try:
            page.wait_for_load_state(
                "networkidle", timeout=timeout_ms
            )
            time.sleep(2)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Iframe interception
    # ------------------------------------------------------------------

    def intercept_iframe(
        self,
        embedder_url: str,
        target_domain: str,
        timeout: float | None = None,
    ) -> InterceptResult | None:
        """Navigate to an embedder page and capture iframe traffic.

        Loads ``embedder_url`` in a real browser, waits for iframes to
        load, and captures all HTTP responses + cookies from
        ``target_domain``.

        Args:
            embedder_url: The page containing the iframe to intercept.
            target_domain: Domain to capture traffic from. Matches any
                subdomain (e.g., "marinetraffic.com" matches
                "www.marinetraffic.com").
            timeout: Max seconds to wait. Defaults to ``solve_timeout``.

        Returns:
            InterceptResult with cookies and captured responses, or
            None on failure.
        """
        if timeout is None:
            timeout = self._solve_timeout
        timeout_ms = int(timeout * 1000)

        with self._lock:
            try:
                self._ensure_browser()
            except Exception:
                logger.warning(
                    "Failed to launch browser for iframe intercept",
                    exc_info=True,
                )
                return None

            context = None
            try:
                context = self._create_context()
                page = context.new_page()
                self._setup_headless_patches(page)

                if self._browser_ua is None:
                    self._browser_ua = page.evaluate(
                        "navigator.userAgent"
                    )

                captured: list[CapturedResponse] = []

                def _on_response(response):
                    try:
                        url = response.url
                        # Match target domain (including subdomains)
                        from urllib.parse import urlparse

                        host = urlparse(url).hostname or ""
                        if not (
                            host == target_domain
                            or host.endswith("." + target_domain)
                        ):
                            return
                        # Read body — may fail for redirects/empty
                        try:
                            body = response.body()
                        except Exception:
                            body = b""
                        headers = {}
                        try:
                            for k, v in response.headers.items():
                                headers[k] = v
                        except Exception:
                            pass
                        captured.append(
                            CapturedResponse(
                                url=url,
                                status=response.status,
                                headers=headers,
                                body=body,
                            )
                        )
                    except Exception:
                        pass

                page.on("response", _on_response)

                logger.info(
                    "Iframe intercept: navigating to %s, "
                    "capturing %s",
                    embedder_url,
                    target_domain,
                )

                try:
                    page.goto(
                        embedder_url,
                        wait_until="domcontentloaded",
                        timeout=timeout_ms,
                    )
                except Exception:
                    logger.debug(
                        "Iframe intercept navigation timeout/error",
                        exc_info=True,
                    )

                # Wait for network to settle (iframes loading)
                try:
                    page.wait_for_load_state(
                        "networkidle", timeout=timeout_ms
                    )
                except Exception:
                    pass

                # Brief extra settle for late JS
                time.sleep(1)

                # Extract cookies for target domain
                all_cookies = context.cookies()
                target_cookies = [
                    c
                    for c in all_cookies
                    if (
                        c.get("domain", "").lstrip(".") == target_domain
                        or c.get("domain", "").endswith("." + target_domain)
                    )
                ]

                self._last_used = time.monotonic()

                logger.info(
                    "Iframe intercept captured %d responses, "
                    "%d cookies from %s",
                    len(captured),
                    len(target_cookies),
                    target_domain,
                )

                return InterceptResult(
                    cookies=target_cookies,
                    responses=captured,
                    user_agent=self._browser_ua or "",
                )

            except Exception:
                logger.warning(
                    "Iframe intercept failed for %s",
                    embedder_url,
                    exc_info=True,
                )
                return None
            finally:
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass

    def close(self) -> None:
        """Shut down browser and release resources."""
        with self._lock:
            self._close_browser()
            logger.debug("BrowserSolver closed")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        # Attempt graceful close without lock (GC finalizer context).
        # _close_browser uses try/except on every operation so this
        # is safe even if the browser is mid-operation.
        try:
            self._close_browser()
        except Exception:
            pass
