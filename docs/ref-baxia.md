# Baxia NoCaptcha Slider Solver

## Status

**Detection**: Done. HTTP-level: `/_____tmd_____/punish` in response body (`_challenge.py`). Browser-level: `#nc_1_n1z` handle or `#nc_1_wrapper` in DOM (`_drag.py::detect_drag_vendor`).

**Browser solve**: Implemented and live-verified. Re-verified 2026-07-27 on
**system Chrome 150.0.7871.182** (macOS, headed), i.e. newer than
wafer's `DEFAULT_EMULATION` at the time (Chrome149): an Alibaba search burst triggered TMD on the first
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

#### MTop reCAPTCHA punishments (`action=captcharecaptcha`)

AliExpress MTop (`acs.aliexpress.com/h5/<api>/<version>/`) answers a session
it distrusts with `FAIL_SYS_USER_VALIDATE` and an issued URL of the form
`/h5/<api>/<version>/_____tmd_____/punish?x5secdata=..&x5step=2&action=captcharecaptcha`
(observed 2026-10-05, including on the token-bootstrap request itself, so no
`_m_h5_tk` is minted until it is solved). Two properties of this shape matter:

- **It carries no callback.** The retry target is the endpoint its path names
  (`_baxia_punish_mtop_endpoint`) on the AliExpress host that issued it, for a
  well-formed MTop API at a numeric version. Before this, `_tmd_retry_target`
  returned None, the fresh x5sec was never looked for, and every successful
  solve was reported as a failure.
- **The checkbox usually auto-passes and TMD tears the widget down at once.**
  It consumes the token, loads `/_____tmd_____/page/third_validate_close_page`
  and navigates to `www.aliexpress.com/` about a second after the click, before
  `aria-checked` can be read. Under TMD (`protocol_completion_is_intermediate`)
  a torn-down anchor after our click hands off to the outer x5sec gate, which
  stays authoritative; generic reCAPTCHA callers never take that path. Waiting
  on for a token instead spent the whole budget (150 s) and pre-empted the
  gate. Live: solve plus clearance in ~7 s, MTop then answers `SUCCESS`.
  Measured order after the click: `reload` returns `nocaptcha`, `userverify`
  returns a token, the anchor detaches, and only then does
  `/_____tmd_____/validate` set `x5sec` (domain `.aliexpress.com`, path `/`),
  about 130 ms later. The gate's bounded poll covers that gap, so detachment
  is safe to hand off on. Google's verdict is logged at hand-off
  (`google_verdict=`) but is not required: the body read can lose the race
  with the teardown, and one in-page dialog solve below cleared with no
  accepted verdict recorded.
- **A rendered page carries it in place.** `session.render()` of an AliExpress
  item page shows the punishment as a dialog iframe
  (`recom-acs.aliexpress.com//h5/mtop.relationrecommend.aliexpressrecommend.recommend/1.0/_____tmd_____/punish?..&action=captcharecaptcha`)
  while the main frame stays on the item URL. With no issued URL to trust,
  dispatch reads the action from that child frame
  (`_tmd_recaptcha_frame_present`); a Google frame alone never counts, and an
  issued slider URL is never overridden. Before this the slider solver waited
  out the whole render budget for a widget that never exists. Live: the item
  page renders hydrated (~370 KB, `runParams`, no TMD) in ~20 s.
- **The image grid hands off the same way.** Under TMD, a widget torn down
  after a submitted Verify is a `torn_down` outcome in both post-Verify
  windows and goes to the outer gate instead of reloading a grid that no
  longer exists. Observed live (2026-10-05, fetchaller's product read of
  item 4000085910726): Google escalated to 4x4 grids, the third Verify's
  `uvresp` was `continued` (so the protocol hand-off could not fire), TMD
  tore the widget down, `torn_down` handed off, and the gate found a new
  `x5sec`; the product came back in 59.5 s.

##### Why a cold session draws it, and how to avoid it (2026-10-08)

Every cold session's MTop token bootstrap drew the reCAPTCHA. The decisive
input is one cookie, `_baxia_sec_cookie_` (`.aliexpress.com`, about 1 KB,
URL-encoded JSON beginning `{"lwrid":...`, six-month expiry), which Baxia's
page script sets in the browser. wafer's request shape is not involved.
Measured live with wafer only, one request at a time, against
`mtop.aliexpress.pdp.pc.query`:

| Session state before the unsigned bootstrap | Request shape | Answer |
|---|---|---|
| cold | navigation GET, `Referer: www` (the consumer's) | `FAIL_SYS_USER_VALIDATE`, captcharecaptcha |
| cold | `embed="xhr"` (Origin, `cors`/`empty`) | same |
| cold | JSONP script shape (`*/*`, `no-cors`/`script`), the browser's own params | same |
| after a wreq GET of `www.aliexpress.com/` | navigation | same |
| after a wreq GET of the item page (adds `ali_apache_id`, `JSESSIONID`) | script | same |
| cold, `_m_h5_tk` minted first via `mtop.ae.cookie.render` (no captcha) | signed pdp call | same |
| only `_baxia_sec_cookie_` copied from a real Chrome visit of `www` | script | `FAIL_SYS_TOKEN_EMPTY` + `_m_h5_tk` |
| only `_baxia_sec_cookie_` copied | navigation, `data={}` (the consumer's exact shape) | `FAIL_SYS_TOKEN_EMPTY` + `_m_h5_tk` |
| same real Chrome visit, nothing copied (control) | script | `FAIL_SYS_USER_VALIDATE` |

A real Chrome (system 154, cold profile) opening an item page sends this same
API as its first MTop call with token `undefined` and gets
`FAIL_SYS_TOKEN_EMPTY`, then `SUCCESS`; its request carries
`_baxia_sec_cookie_`. Benign APIs (`mtop.ae.cookie.render`) mint `_m_h5_tk`
without it, but the token alone does not get a signed pdp call through.

wafer cannot mint the cookie over HTTP, so the avoidance is a browser visit
of the origin before the first MTop call:
`session.browser_prime("https://www.aliexpress.com/")`. It imports
`_baxia_sec_cookie_` and the page's own `_m_h5_tk`; the next signed
`pdp.pc.query` answered `SUCCESS` (57 KB) in 4 of 4 cold sessions (16.7s,
16.8s and 16.7s headed, 17.0s headless, total including the browser launch),
with three product reads in a row in the headless run. Solving the punishment instead
took 18.5-103.8s over 1-7 image rounds (8 of 9 live solves succeeded, see
`docs/ref-recaptcha.md`), and 75-130s for the consumer that reported it.

It does not get past a punishment a browser gets too. About 40 minutes into
back-to-back test sessions from one machine (some 25 punished bootstraps,
solves and primes), the primed call drew the reCAPTCHA in 3 of 3 runs, and so
did a cold real Chrome's own item page: its first `pdp.pc.query`, sent with
`_baxia_sec_cookie_`, answered `FAIL_SYS_USER_VALIDATE`. Prime first, and
keep solving the issued URL as the fallback. After 22 minutes with no traffic
the same real Chrome's item page passed again, and so did a primed session.

The browser's timezone decides it too. fetchaller's Linux image (UTC, the
container default) primed 4 of 4 times and was punished on every first call
(2026-10-08). Reproduced in that image from a Toronto IP, one variable at a
time, with the primed pdp call:

| Browser timezone | Answer |
|---|---|
| UTC (container default) | punished, 4 of 4 |
| America/Toronto (the IP's) | `SUCCESS`, 4 of 4 |
| America/Los_Angeles | `SUCCESS` |
| Europe/London | punished |

macOS on local time passed in between. So the clock has to be plausible for the
IP's location, not exact. `BrowserSolver(timezone=...)` sets `TZ` for the
browser process only (native, every frame and worker agree), and a UTC clock
logs a one-time WARNING at launch. Cold solves in the same image succeeded 4 of
4 on either clock (UTC 1 and 8 image rounds, Toronto 2 and 2): too few runs to
say the clock changes how many rounds Google asks for.

A TMD solve used to empty the session's jar: the client rebuilt after the
identity pin started a fresh one, so an MTop `_m_h5_tk` set over HTTP was gone
and the signed retry answered `FAIL_SYS_TOKEN_EMPTY` (fetchaller, 3 runs). The
rebuild now keeps the jar, and the browser's cookies replace same-name ones.

`browser_prime` used to return `False` here although it had imported the
cookies: the homepage shows no challenge, so the solver hands back a
passthrough document rather than a solve. It now returns `True` when the
passthrough imported cookies for the origin (`state_only` in
`_try_browser_solve`; live, `True` with `SUCCESS` after it). `True` still says
nothing about MTop's answer.

The MTop API name in a punishment path is not a family marker. An inventory
of the MTop calls live AliExpress pages make (2026-10-05) found
`mtop.ae.cookie.render` and `mtop.relationrecommend.aliexpressrecommend.recommend`
on `acs.aliexpress.com`, and the latter on `recom-acs.aliexpress.com`, which
issued the dialog punishment. The parser used to require `mtop.aliexpress.*`
on AliExpress, so a callback-less punishment for the first two returned None
(the original bug again), and the `recom-acs` one was retried verbatim as a
non-punishment URL. Now any well-formed `mtop.<a>.<b>...` name parses and only
an API naming the other family (`mtop.alibaba.*` on AliExpress, and the
reverse) is rejected. The retry target keeps the issuing host. Live: the
captured `recom-acs` dialog punishment, solved through
`browser_solve_challenge`, retried
`https://recom-acs.aliexpress.com/h5/mtop.relationrecommend.aliexpressrecommend.recommend/1.0/`
and found a new `x5sec` in 5.7 s. Callback-less Alibaba punishments still fail
closed: none has been observed.

Wafer is normally invoked with the original application URL whose response
contains the punishment redirect. That immutable URL is the exact retry
target. If it is invoked with an ACS punishment URL instead, the callback must
pass the strict same-family parser; arbitrary non-punishment ACS URLs remain
invalid. The one exception is the callback-less AliExpress MTop punishment
above, whose retry target is the endpoint its own path names on its own host.

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

The application target may come back with parameters added, and still counts:
same scheme, host, port and path, and every issued parameter with its value
(`_url_extends`, compared decoded). After an accepted slide Alibaba's search
lands on the issued URL plus `has4Tab` and `tab`, about 1s after release.
Demanding an exact URL logged every such accept as "pending" until the gate's
`x5sec` check caught up, and an accept that minted no new `x5sec` could not be
captured at all (2026-10-08). The strict callback still has to match exactly.

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
