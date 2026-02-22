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
"""

import csv
import importlib.resources
import io
import logging
import math
import os
import random
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger("wafer")

# ---------------------------------------------------------------------------
# Stealth injection (for Baxia/TMD — Patchright doesn't patch webdriver)
# ---------------------------------------------------------------------------

_STEALTH_SCRIPT = b"""<script>
Object.defineProperty(Navigator.prototype, 'webdriver', {
    get: () => false,
    configurable: true,
});
if (window.chrome && !window.chrome.runtime) {
    window.chrome.runtime = {
        connect: function() {},
        sendMessage: function() {},
    };
}
</script>"""


def _install_stealth_route(page) -> None:
    """Intercept document navigations and inject stealth script.

    Patches ``navigator.webdriver`` to false by injecting a script
    tag at the start of every HTML response.  This runs before any
    page scripts, unlike ``add_init_script()`` which has DNS issues
    in Patchright with system Chrome.
    """
    def _stealth_route(route):
        if route.request.resource_type != "document":
            route.continue_()
            return
        try:
            resp = route.fetch()
        except Exception:
            route.continue_()
            return
        body = resp.body()
        if b"<head>" in body:
            body = body.replace(b"<head>", b"<head>" + _STEALTH_SCRIPT)
        elif b"<script>" in body:
            body = _STEALTH_SCRIPT + body
        # Playwright's route.fetch() returns decompressed body, but
        # resp.headers retains original Content-Encoding. Forwarding
        # both causes the browser to double-decompress → garbled HTML.
        hdrs = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in ("content-encoding", "content-length")
        }
        route.fulfill(
            status=resp.status,
            headers=hdrs,
            body=body,
        )

    page.route("**/*", _stealth_route)


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
        self._headless = headless
        self._idle_timeout = idle_timeout
        self._solve_timeout = solve_timeout
        self._playwright = None
        self._browser = None
        self._lock = threading.Lock()
        self._last_used: float = 0.0
        self._browser_ua: str | None = None
        self._extension_dir: str | None = None
        # Recording caches (lazy-loaded on first PX encounter)
        self._idle_recordings: list[list[dict[str, float]]] | None = None
        self._path_recordings: list[dict] | None = None
        self._hold_recordings: list[list[dict[str, float]]] | None = None
        self._drag_recordings: list[list[dict[str, float]]] | None = None
        self._slide_recordings: list[dict] | None = None
        self._browse_recordings: list[dict] | None = None

    def _ensure_extension(self) -> str | None:
        """Extract the screenX/screenY fix extension to a temp dir.

        Returns the path to the unpacked extension directory, or None if
        the extension files aren't available.
        """
        if self._extension_dir and os.path.isdir(self._extension_dir):
            return self._extension_dir

        try:
            ext_pkg = (
                importlib.resources.files("wafer.browser")
                / "_extensions"
                / "screenxy"
            )
            manifest = (ext_pkg / "manifest.json").read_text()
            content_js = (ext_pkg / "content.js").read_text()
        except Exception:
            logger.debug("screenXY extension not found in package")
            return None

        tmp = tempfile.mkdtemp(prefix="wafer_ext_")
        with open(os.path.join(tmp, "manifest.json"), "w") as f:
            f.write(manifest)
        with open(os.path.join(tmp, "content.js"), "w") as f:
            f.write(content_js)

        self._extension_dir = tmp
        logger.debug("Extracted screenXY extension to %s", tmp)
        return tmp

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

        launch_args = ["--disable-blink-features=AutomationControlled"]

        ext_dir = self._ensure_extension()
        if ext_dir:
            launch_args.append(f"--load-extension={ext_dir}")
            launch_args.append(
                f"--disable-extensions-except={ext_dir}"
            )

        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(
            channel="chrome",
            headless=self._headless,
            args=launch_args,
        )
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
        if self._extension_dir:
            try:
                shutil.rmtree(self._extension_dir)
            except Exception:
                pass
            self._extension_dir = None

    def _create_context(self):
        """Create a new browser context with realistic settings."""
        viewport = random.choice(_VIEWPORTS)
        return self._browser.new_context(
            viewport={"width": viewport[0], "height": viewport[1]},
        )

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
            pass

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
            pass

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
            pass

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
            pass

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
            pass

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
            pass

        logger.info(
            "Loaded %d idle + %d path + %d hold + %d drag"
            " + %d slide + %d browse recordings",
            len(self._idle_recordings),
            len(self._path_recordings),
            len(self._hold_recordings),
            len(self._drag_recordings),
            len(self._slide_recordings),
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
    ) -> dict:
        """Pick a recorded path whose direction best matches the move."""
        angle = math.atan2(
            target_y - start_y, target_x - start_x
        )

        def _angle_diff(rec: dict) -> float:
            diff = abs(rec["angle"] - angle)
            return min(diff, 2 * math.pi - diff)

        best = min(self._path_recordings, key=_angle_diff)
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
    ) -> None:
        """Replay a recorded human path from start to target."""
        rec = self._pick_path(
            start_x, start_y, target_x, target_y
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
        max_scroll = rec.get("max_scroll", 0)
        scroll_scale = 1.0 if max_scroll <= 0 else 1.0
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

                # Baxia/TMD: inject stealth script via route
                # interception to patch navigator.webdriver before
                # any page scripts run.  Patchright doesn't patch
                # this on system Chrome.
                if challenge_type in ("baxia", "tmd"):
                    _install_stealth_route(page)

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

                # Wait for page to fully settle before extracting
                try:
                    page.wait_for_load_state(
                        "networkidle", timeout=5000
                    )
                except Exception:
                    pass

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
                    if target_domain in (c.get("domain", ""))
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
