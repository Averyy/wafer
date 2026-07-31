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

**Transport clearance vs browser content (2026-07-29)**: a new/changed
target-scoped `x5sec` is authoritative evidence that the HTTP transport can
replay the request. Exact target navigation is a separate browser-only outcome:
the DOM must no longer classify as TMD, and the validated document may be
returned for that GET without claiming future wreq requests are cleared.

This distinction fixed a false success on `alibaba.com/trade/search`. The page
could remain at the exact application URL after the slider iframe disappeared
while its main DOM was still the 119KB `Captcha Interception` punishment page.
The old predicate called that solved, imported only `arms_uid`/`tfstk`, and then
received TMD on every transport replay. Iframe disappearance is now
intermediate evidence only, and the cookie/target poll is independently bounded
by `_TMD_CLEARANCE_POLL_SECONDS`.

Live verification after the fix triggered TMD on the first Alibaba search:
the first drag minted a fresh target-scoped `x5sec`, and wreq replay returned
200 / 706,018 bytes of real results in 21.05s. `session.render()` independently
triggered and solved TMD, then returned the settled 2,563,704-byte search page
in 27.1s.

A budget already spent by such a wasted attempt makes a *later* request skip
its browser solve entirely, which is why a failing capture can show
`Challenge detected: tmd` with zero Baxia lines. That skip now logs at WARNING
rather than DEBUG, so the silence is explained in the log rather than looking
like the drag solver never engaging.

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
    slide_drags/      # 16 full-width "slide to verify" drags (300px track, 42px handle)
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
5. On success, the browser either mints a new/changed target-scoped `x5sec` or
   reaches a challenge-free exact application document
6. The outer solver replays HTTP only for `x5sec`; a challenge-free document
   without transferable clearance is returned as browser passthrough for that
   GET

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

Widget text/classes, iframe disappearance, and an unchanged application URL are
intermediate signals only. Transport replay requires:

- a new/changed, non-empty, unexpired `x5sec` whose domain and path apply to
  the exact original application URL (or the strictly parsed callback when the
  solver was explicitly given a punishment URL).

An exact application target/callback whose main DOM no longer detects as TMD
can instead be captured as browser-only content for a GET. It is not treated as
transferable clearance. Arbitrary navigation away from the punishment page
(including login, error, captcha, or cousin-domain URLs), a missing iframe with
punishment markup still present, and a small transition shell are not success.
The outer TMD gate repeats the cookie-scope check against the original
application target, Alibaba's strict callback, or AliExpress's native MTop
endpoint as appropriate; cookies never cross those domain families.

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

All 7 naturally present in recorded human trajectories from mousse -but only
if replay preserves them.

### Signal 3 was being replayed away (fixed 2026-07-31)

`_replay_drag` clamped **every** pressed pointer sample to the slider interval,
when only the release coordinate needs constraining. All 15 original slide recordings
overshoot the endpoint and correct back (2-11% of their pressed samples,
0.2-8.4px past at a 258px track); the clamp flattened every one, so wafer's
drag decelerated onto the endpoint and never passed it -the exact absence
signal 3 looks for. The handle pins at the track maximum either way, so the
overshoot only ever changed the pointer trace, never the result.

Alibaba began rejecting every drag with a rotating `sdk_error_code` while the
drag itself was mechanically perfect: trusted events, full 258px travel,
`max_fill=279`, correct geometry. Restoring the overshoot took live gated
`alibaba.com/trade/search` from 0/2 requests (0/6 drags accepted) to 4/5
requests. Constrain only the final release sample.

When a drag is refused with the mechanics provably correct, suspect the
replay pipeline flattening a signal this list says humans emit -not geometry.

### The slide corpus was recorded at puzzle-drag pace (fixed 2026-07-31)

A human slide captured on the live Alibaba widget and **accepted by the SDK**:

| | Human | Shipped corpus |
|---|---|---|
| Pressed duration | 0.76s | 3.07-5.42s |
| Speed | 421 px/s | 48-84 px/s |
| Release | rx 1.26 (64px past travel) | clamped to 1.0 |
| Event rate | 44/s | 34-49/s |

Event *rate* matched, so this was never sampling -the corpus is simply ~7x
too slow. `mousse/README.md` specifies slide mode as "confident and fast";
the recordings did not follow it and nothing checked. wafer was replaying
mis-recorded data faithfully.

`_replay_drag(full_track_slide=True)` (set only at the Baxia call site) compresses
the **pressed** phase into `_SLIDE_DRAG_SECONDS` and subsamples to
`_SLIDE_EVENT_RATE`. The pre-mousedown hover is untouched: it is deliberate
thinking time and the human's was a comparable ~1s. Subsampling is
load-bearing, not cosmetic -CDP move dispatch costs ~8-10ms, so a 250-event
drag cannot physically be emitted in 0.76s and the compression would silently
not happen. Live traces show `drag_scale` 0.127-0.170, `keep_every` 4-7.

Mousse now rejects a take outside 0.35-1.40s at record time. Re-recording the
corpus at true slide pace is the durable fix; compression of the old traces is
the interim one. Result after the change: a 10-query burst returned 10/10 real
result pages, TMD triggered and solved on the first request and the earned
`x5sec` replayed for the remaining nine at ~2s each.

### Both changes are scoped to full-track slides

`_replay_drag` is shared with GeeTest/PerimeterX puzzle drags, so BOTH the
speed compression and the unclamped release ride the single
`full_track_slide=True` flag set at the Baxia call site. Neither reaches
`solve_drag`.

That scoping is load-bearing, not tidiness. A placement drag aims at a
CV-computed notch offset with no physical stop, and 6 of the 26 shipped
puzzle recordings in `_recordings/drags/` release past their own target (up
to rx=1.074). An unconditional clamp removal would drop the piece past the
notch and silently regress GeeTest, whose 12/12 live result predates this
work. The pressed-pointer clamp is therefore still applied on the default
path; only a full-track slide, whose handle pins at the track maximum, is
exempt.

### Do not retry inside a rejected document

Lines above describe Baxia destroying and recreating the widget, which reads
as an invitation to retry in place, and `_attempt_baxia_drag` defaults to
`max_attempts=5`. `solve_baxia` deliberately passes 1.

Measured 2026-07-31 at `max_attempts=2` over 5 live gated requests: the reset
poll does find a recreated handle at `left == 0`, and **every** in-widget
attempt 2/2 was rejected. Every success came from attempt 1 in a fresh browser
context. Failure latency doubled (~67s to ~120s) because the retry spent the
deadline that pays for the fresh context. The document is spent for clearance
even though the widget looks alive.

## Test Infrastructure

- **Mock**: `tests/mocks/baxia/slide.html` -canvas-generated slider, exact Baxia dimensions
- **Demo**: `tests/demo_baxia_solve.py` -offline solve against mock
- **Live test**: `tests/live_baxia.py` -triggers TMD via wreq, solves with Patchright
- **Recordings**: 16 slide_drags in `_recordings/slide_drags/`. slide_001-015 are the
  original mis-paced takes (3-5.4s, 196-380 events); slide_016 is the live human
  reference (0.76s, 87 events). Replay compresses the former toward the latter.
