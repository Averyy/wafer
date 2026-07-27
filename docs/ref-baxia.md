# Baxia NoCaptcha Slider Solver

## Status

**Detection**: Done. HTTP-level: `/_____tmd_____/punish` in response body (`_challenge.py`). Browser-level: `#nc_1_n1z` handle or `#nc_1_wrapper` in DOM (`_drag.py::detect_drag_vendor`).

**Browser solve**: Implemented and live-verified. Re-verified 2026-07-27 on
**system Chrome 150.0.7871.182** (macOS, headed), i.e. a Chrome newer than
wafer's `DEFAULT_EMULATION`: an Alibaba search burst triggered TMD on the first
request, the slider solved on its first attempt, and the request returned 200 /
1.43MB of real results in 19.5s, followed by 11 consecutive ~2s 200s replaying
the earned `x5sec`. A repeat run after the navigation-budget fix solved again
for 12/12 200s. One of those runs logged `Baxia result remained pending after
release` and still succeeded, which is the intended contract: widget state is
an intermediate signal and the authoritative `x5sec` check decides. Note a
single cold request usually passes with no challenge at all, so exercising the
solver requires a burst. **Headless verified too** (2026-07-27): an
18-query burst solved on the first challenge and returned 18/18 200s. This
only works because the headless fingerprint patches are now re-applied on
navigation; while they were inert the slider still solved but earned no
target-scoped `x5sec` for three consecutive rounds. See the status note at
the top of `docs/ref-headless.md`. System Chrome uses
`--disable-blink-features=AutomationControlled`. The browser and wafer's
transport client hints must carry the same four-part Chrome version; startup
achieves that by pinning wafer's UA and hints onto the installed browser, so a
Chrome auto-update logs a warning rather than disabling every solver.

**Dispatch**: `challenge_type="tmd"` or `"baxia"` routes to `solve_baxia()` in `_solver.py`.

## Architecture

```
wafer/browser/
  _solver.py          # BrowserSolver: mouse replay, solve() dispatch for "baxia"/"tmd"
  _drag.py            # Baxia-specific: _find_baxia_frame, _get_baxia_geometry,
                      #   _attempt_baxia_drag (one punishment document),
                      #   _check_baxia_result,
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

1. wreq HTTP client hits Alibaba/AliExpress → 200 with JS redirect to `/_____tmd_____/punish?x5secdata=...`
2. Punish page has no `<head>` -bare `<script>` tag with redirect + config
3. Redirect loads NoCaptcha SDK which renders slider widget
4. User drags slider → behavioral payload sent server-side
5. On success: the page reaches the exact safe callback from the immutable
   issued URL, or mints a new/changed target-scoped `x5sec`
6. The outer solver independently checks that clearance against Alibaba's
   strict callback or AliExpress's native MTop retry before replaying HTTP

Wafer is normally invoked with the original application URL whose response
contains the punishment redirect. That immutable URL is the exact retry
target. If it is invoked with an ACS punishment URL instead, the callback must
pass the strict same-family parser; arbitrary non-punishment ACS URLs remain
invalid.

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

### Native Browser Identity and Continuous Input

Baxia NoCaptcha SDK checks `navigator.webdriver` and auto-rejects any interaction from automated browsers, regardless of mouse behavior quality.

**Fixes**: `--disable-blink-features=AutomationControlled` makes
`navigator.webdriver` return `false` via a native `[native code]` getter. The
recorded approach path joins the first hover sample rather than jumping from
the handle to it, and mousedown is emitted only after the recording's
timestamp and coordinate have been replayed. No JS stealth injection is
needed. System Chrome headful provides real plugins, WebGL, permissions, and
voices natively.

**Previous approach (removed)**: Route interception injected JS overrides into every document response. This was actively harmful -the `() => false` arrow function was detectable via `toString()`, and route interception broke WAF iframes (DataDome WASM PoW, CSP, SRI).

### Authoritative Result Detection

Widget text/classes are intermediate signals only. A solve requires either:

- navigation to the exact credential-free HTTPS callback encoded in the
  immutable issued punishment URL, on the same Alibaba/AliExpress family, or
- a new/changed, non-empty, unexpired `x5sec` whose domain and path apply to
  the exact original application URL (or the strictly parsed callback when the
  solver was explicitly given a punishment URL).

Arbitrary navigation away from the punishment page (including login, error,
captcha, or cousin-domain URLs) is not success. The outer TMD gate repeats the
cookie-scope check against the original application target, Alibaba's strict
callback, or AliExpress's native MTop endpoint as appropriate; cookies never
cross those domain families.

### Widget Destruction = Rejection

When Baxia rejects a drag, it can remove all `#nc_1_*` elements and expose a
short rotating SDK error code before recreating the widget. Result checks
detect that bounded error marker even when rejection happens before any handle
or movement appears; arbitrary page text and challenge URLs are never logged.

Invasive structural/event screenshots and event-contract listeners are off by
default. They require `WAFER_BAXIA_DIAGNOSTICS=1`; screenshots additionally
require an absolute `WAFER_BAXIA_DIAGNOSTIC_DIR`.

### Wall-Clock Timing

CDP `page.mouse.move()` has ~8-10ms overhead per call. With 300+ events per
recording, naive per-event sleep inflated 5s recordings to 13s+.
`_replay_path`/`_replay_drag` therefore track `time.monotonic()` from start
instead of accumulating per-event delays. A rejected punishment document is
one-use, so it receives exactly one genuine recorded drag. For a sufficiently
long request, the transport creates up to three fresh browser contexts and
fairly partitions the remaining deadline among them while reserving up to 15
seconds for authoritative native-HTTP replay. A bounded solver-level history
excludes rejected recordings across those contexts.

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
- **Live test**: `tests/live_baxia.py` -triggers TMD via wreq, solves with Patchright
- **Recordings**: 15 slide_drags (3-5.4s, 196-380 events each) in `_recordings/slide_drags/`
