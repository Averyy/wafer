# Baxia NoCaptcha Slider Solver

## Status

**Detection**: Done. HTTP-level: `/_____tmd_____/punish` in response body (`_challenge.py`). Browser-level: `#nc_1_n1z` handle or `#nc_1_wrapper` in DOM (`_drag.py::detect_drag_vendor`).

**Browser solve**: Done. Live-solved on AliExpress (Feb 2026). System Chrome with `--disable-blink-features=AutomationControlled` provides native `navigator.webdriver=false`. Result detected via URL navigation (page leaves punish URL).

**Dispatch**: `challenge_type="tmd"` or `"baxia"` routes to `solve_baxia()` in `_solver.py`.

## Architecture

```
wafer/browser/
  _solver.py          # BrowserSolver: mouse replay, solve() dispatch for "baxia"/"tmd"
  _drag.py            # Baxia-specific: _find_baxia_frame, _get_baxia_geometry,
                      #   _attempt_baxia_drag (retry loop), _check_baxia_result,
                      #   _page_left_punish, solve_baxia
  _recordings/
    slide_drags/      # 15 full-width "slide to verify" drags (300px track, 42px handle)
    drags/            # 26 variable-width drags (32-301px, fallback for slide)
```

## Alibaba Baxia System

**Alibaba Baxia** -Alibaba's proprietary CAPTCHA/anti-bot platform. JS global: `window.__baxia__`. SDK from `assets.alicdn.com/g/baxia/baxiaCommon.js`. Also `window.initAliyunCaptcha` (Alibaba Cloud CAPTCHA 2.0).

### Modes

| Mode | Description | Solver Status |
|---|---|---|
| **Invisible** | No interaction. Behavioral scoring from device fingerprint. | N/A -passes automatically for real browsers |
| **Slider** | Drag horizontal bar full-width. Behavioral analysis only. | **Solved** |
| **Puzzle** | Drag jigsaw piece to notch in background image. CV needed. | Ready (same `find_notch()` as GeeTest) -not yet triggered live |
| **Image Restoration** | Reassemble shuffled image blocks. Needs DL/CNN. | **Deferred** -fall back to CAPTCHA service |
| **Visual Reasoning** | Rotate/select correct view. Deprecated Sept 2025. | **Deferred** -skip gracefully |

### TMD Challenge Flow

1. rnet HTTP client hits AliExpress → 200 with JS redirect to `/_____tmd_____/punish?x5secdata=...`
2. Punish page has no `<head>` -bare `<script>` tag with redirect + config
3. Redirect loads NoCaptcha SDK which renders slider widget
4. User drags slider → behavioral payload sent server-side
5. On success: page redirects to original URL with real content

### Selectors

```
#nc_1_n1z      -SPAN.nc_iconfont.btn_slide (42×30px handle)
#nc_1_n1t      -DIV.nc_scale (300×34px track)
#nc_1__bg      -DIV.nc_bg (fill bar, width grows with drag)
#nc_1_wrapper  -DIV.nc_wrapper (300×34px)
#nocaptcha     -DIV.nc-container
.nc-lang-cnt   -SPAN "Please slide to verify"
```

### Triggers

- **IP frequency**: 4,000 req/hour or 10,000/day from same IP
- **Device frequency**: 150 req/hour or 400/day from same device fingerprint
- **Virtual environment**: VMware, VirtualBox, Hyper-V, Parallels detected
- **Init timing**: JS must run 2+ seconds before interaction (enforced server-side)

## Key Decisions

### navigator.webdriver -Root Cause of All Rejections

Baxia NoCaptcha SDK checks `navigator.webdriver` and auto-rejects any interaction from automated browsers, regardless of mouse behavior quality.

**Fix**: `--disable-blink-features=AutomationControlled` Chrome launch flag makes `navigator.webdriver` return `false` via a native `[native code]` getter. No JS injection needed. System Chrome headful provides real plugins, WebGL, permissions, and voices natively.

**Previous approach (removed)**: Route interception injected JS overrides into every document response. This was actively harmful -the `() => false` arrow function was detectable via `toString()`, and route interception broke WAF iframes (DataDome WASM PoW, CSP, SRI).

### Result Detection via URL Navigation

When Baxia accepts the slider, it redirects the page from the punish URL to real content. This causes frame detachment. `_page_left_punish()` checks if the page URL no longer contains `/_____tmd_____/` or `punish` -if so, the solve succeeded. This check runs both in the normal polling loop and in the exception handler.

### Widget Destruction = Rejection

When Baxia rejects a drag, it removes ALL `#nc_1_*` elements from DOM, shows error text ("Oops... something's wrong. Please refresh and try again. (error:xxxxx)"), then recreates a fresh widget after ~6s. `_check_baxia_result` detects this via `!handle && sawMovement`.

### Wall-Clock Timing

CDP `page.mouse.move()` has ~8-10ms overhead per call. With 300+ events per recording, naive per-event sleep inflated 5s recordings to 13s+. Fixed: `_replay_path`/`_replay_drag` track `time.monotonic()` from start instead of accumulating per-event delays.

## Behavioral Detection Signals

7 signals Baxia's ML model analyzes during drag:

1. **Trajectory shape** -humans curve slightly (hesitation arc, approach curve). Straight-line ratio ≈ 1.0 = bot.
2. **Speed distribution** -asymmetric bell: slow start, peak middle, decelerate at end. Symmetric = bot.
3. **Overshoot + correction** -humans drag past target then correct. Absence = bot signal.
4. **Y-axis wobble** -small vertical deviations throughout. Zero variance = bot.
5. **Timing irregularity** -micro-pauses, hesitations, bursts. Fixed intervals = bot.
6. **Acceleration profile** -smooth, continuous. High-frequency noise = bot.
7. **Micro-jitter during pauses** -hand tremor at 3-25 Hz. Entirely absent in bots.

All 7 naturally present in recorded human trajectories from mousse.

## Test Infrastructure

- **Mock**: `tests/mocks/baxia/slide.html` -canvas-generated slider, exact Baxia dimensions
- **Demo**: `tests/demo_baxia_solve.py` -offline solve against mock
- **Live test**: `tests/live_baxia.py` -triggers TMD via rnet, solves with Patchright
- **Recordings**: 15 slide_drags (3-5.4s, 196-380 events each) in `_recordings/slide_drags/`
