# Browser Fingerprint Overrides

Every override BrowserSolver applies to Patchright/Chrome, organized by mechanism. Includes research log of failed approaches at the end.

## Headless identity in every target (2026-10-05)

Measured on Chrome 154.0.8037.98, Patchright 1.59.1, macOS 26.6.2 on an Apple
M4, against a local server, by `tests/test_headless_leaks.py`. A page there
opens a cross-site iframe, an iframe nested back on the top site (A->B->A), a
worker inside the iframe, and a dedicated, a shared and a service worker. Each
reports `navigator.userAgent`, `userAgentData` with high-entropy hints,
`navigator.languages`, and per frame devicePixelRatio, screen, colorDepth and
outer size. The server records every request's `User-Agent` and `sec-ch-ua*`
headers, with high-entropy hints opted into through `Accept-CH`. Headed
Chrome with no hardening is the reference.

Released v0.7.1 leaked in both solver modes:

| Surface | Headless | Headed, after preflight or a first solve |
|---|---|---|
| Service worker `navigator.userAgent`, `sw.js` fetch, worker fetches | `HeadlessChrome/154.0.0.0` | correct |
| Shared worker `navigator.userAgent` and fetches | `HeadlessChrome/154.0.0.0` | correct |
| Cross-site iframes, nested iframes, iframe workers | `architecture: x86`, `platformVersion: 10.15.7`, in JS and in `sec-ch-ua-*` | same |
| Cross-site iframe screen / colorDepth | `800x600` / 24 under a `2560x1440` / 30 top document | correct |
| devicePixelRatio | top 2, cross-site iframe 1; an A->B->A page drops the top to 1 too | correct |
| `navigator.userActivation.hasBeenActive` | `true` on a page nobody touched | correct |

Where each came from, and what fixes it:

- **`HeadlessChrome` in workers.** Chromium builds it into its own default UA
  whenever the `--headless` switch is present
  (`components/embedder_support/user_agent_utils.cc`, `GetUserAgentInternal`).
  A context-level `user_agent=` never reaches service workers (Patchright's
  `crServiceWorker.js` applies no UA) or shared workers (Patchright detaches
  them on attach). A per-target `Network`/`Emulation.setUserAgentOverride`
  fixes a service worker's fetches but not its `navigator.userAgent`, which is
  fixed when the worker starts. Only `--user-agent` on the command line
  reaches them, so `hardened_launch_config(user_agent=...)` adds it for
  headless launches, and BrowserSolver reads the UA from a first launch and
  relaunches with it.
- **The cost of `--user-agent`.** Chromium deliberately sends only low-entropy
  client hints for a command-line UA (same file, `GetUserAgentMetadata`: "For
  users providing a valid user-agent override via the command line"). Every
  target therefore gets the full metadata from CDP: the page directly, and
  iframes, dedicated workers and service workers through auto-attach on the
  page's session (unflattened, paused until their overrides are in, nested
  iframes recursively).
- **Service and shared workers are not held by pausing them.** Patchright
  resumes every service worker the moment it attaches (`crServiceWorker.js`
  sends `Runtime.runIfWaitingForDebugger` in its constructor) and detaches
  from shared workers at once, and a worker starts on the first resume from
  any client. With wafer's handler delayed 400ms, 15 of 15 service workers
  read the launch's empty high-entropy hints. Acknowledged overrides are no
  proof either: a worker reads `navigator.userAgentData` from whatever its
  own inspector holds at that moment (`WorkerGlobalScope::GetUserAgentMetadata`),
  and its start parameters carry Chrome's default metadata
  (`service_worker_version.cc`, `shared_worker_host.cc`).
- **Service workers are held by the main-script throttle.** Chromium holds a
  new service worker's script fetch until every flattened session
  auto-attached under the registering page resumes it
  (`ThrottleServiceWorkerMainScriptFetch`); an unflattened session never gets
  one (`TargetHandler::Session::IsWaitingForDebuggerOnStart` needs a
  `devtools_session_`, set only for flattened sessions). So a second page
  session auto-attaches service workers flattened, an unflattened session
  from the browser applies the override, and detaching the flattened one
  releases the fetch. The override queues and is in place before the script
  runs: 0 of 10 wrong with the 400ms delay, and the live suite went from 2-4
  failing runs in 10 to 0 in 10. Service workers registered by a cross-site
  iframe get no throttle and are held by their script fetch instead (see
  "Partly covered" below).
- **Shared workers are held by their script fetch.** Chromium has no
  main-script throttle for them and attaches them to no page, so they are
  found through a browser session (only flattened auto-attach is allowed
  there) and overridden through an unflattened `Target.attachToTarget`. What
  holds one is its script fetch: the browser session intercepts every request
  of type `Other` (`Fetch.enable`, request stage), and Chrome reports a worker
  script's `networkId` as the worker's own target id, so each fetch is matched
  to exactly its worker and held until that worker's override is sent. Every
  other request is continued at once. Chrome announces the worker before its
  script fetch starts (every attach arrived first, measured), so the hold is
  in place when the fetch pauses. Measured on the real code path (2026-10-06,
  20 shared workers on one script URL, each reading `fullVersionList` at
  once): with wafer's override delayed 400ms, 60 of 60 read it empty without
  the hold and 0 of 60 with it, sync and async; async at normal speed went
  from 33 of 100 without it to 1 of 900 with it. Opening the unflattened session
  emits a second attach event reporting the worker paused; detaching that
  session drops its override, so repeat attaches are ignored by target id.
  With the driver preload (next bullet) the pause holds the worker by itself;
  the fetch hold stays for a driver started without it, where it still holds
  a worker whose script comes over the network.
- **Patchright's resume, and the driver preload that removes it.**
  Patchright detaches from a shared worker only after its
  `Runtime.runIfWaitingForDebugger` is answered (`crConnection.js`,
  `detach`), and Chrome queues that resume until the worker exists
  (`devtools_session.cc`, `DispatchProtocolMessageInternal` falls through to
  the agent). Patchright's session attaches first, so its resume is flushed
  ahead of wafer's override, the pause on start quits on the first resume
  (`worker_thread_debugger.cc`), and `getHighEntropyValues` copies the
  metadata synchronously when called (`navigator_ua_data.cc`). Nothing wafer
  queues overtakes it: waiting for the override's acknowledgement, a
  `Debugger.pause`, and a `beforeScriptExecution` instrumentation breakpoint
  each left the same 5 in 400 wrong, though the pause or breakpoint fired on
  85-99% of workers. And a `blob:` script is loaded through the blob URL
  loader factory directly, which DevTools interception never wraps
  (`worker_script_fetcher.cc`, `CreateScriptLoader`), so the fetch hold
  cannot reach a blob worker at all: 13 of 100 empty under async and 18-20
  of 100 under sync at normal speed, 10 of 10 with the 400ms delay. The fix
  is to keep Patchright off shared workers: `hardened_driver_env()` starts
  the driver with `NODE_OPTIONS=--require _driver_preload.js`, which adds a
  filter to the root session's `Target.setAutoAttach` excluding
  `shared_worker` (and otherwise Chromium's default: exclude `browser` and
  `tab`, `target_handler.cc`). wafer's browser session is then the only one
  that pauses them, and it resumes each through the session that carried the
  override, so the worker processes the override first. Measured
  2026-10-06 on chewy.com's real sensor worker (a `blob:` shared worker that
  calls `getHighEntropyValues` with `fullVersionList`, `platformVersion` and
  `architecture` as soon as a page connects): 17 of 100 empty under sync and
  15 of 100 under async before, 0 of 100 each after, 0 of 10 with the 400ms
  delay, and through `BrowserSolver.render` 6 of 60 before, 0 of 60 after.
  The live suite, with a `blob:` shared worker asserted strictly, passed 10
  runs in 10. BrowserSolver starts its driver this way; callers driving their
  own Playwright wrap their start in it. Without a wafer session nobody
  pauses a shared worker, so headed browsers and unhardened pages run them at
  once. `TestHardenedDriverEnv` runs the installed driver's own
  `crConnection.js` under the preload, so a Patchright upgrade that moves what
  it patches fails there rather than silently restoring the race. Dropping
  `--user-agent` instead would give full high-entropy hints natively (0 of
  300 empty) but `HeadlessChrome` in `navigator.userAgent` in 300 of 300.
- **The preload also keeps the driver alive through a detached element.**
  Patchright's `ElementHandle.evaluateExpression` (javascript.js) starts an
  element adoption into the evaluation's world and never awaits it; when the
  page navigates during the call, that `DOM.describeNode` rejects with nothing
  handling it, and Node's default for an unhandled rejection ended the whole
  driver. A dead driver ends the sync dispatcher, so the worker's pending call
  spins forever and every later solve timed out behind it (Alibaba's slider
  navigating mid-poll, 179s, 2026-10-08). The preload drops unhandled CDP
  `ProtocolError`s (a target or context that is gone) and re-throws anything
  else. If a driver still dies under a busy worker, `BrowserSolver` logs one
  ERROR and refuses later work at once instead of queuing it.
- **Which solver sites use shared workers** (headless, 2026-10-06).
  realtor.com started one and chewy.com two, all from `blob:` URLs;
  Cloudflare, DataDome (allegro.pl, idealista.com), Imperva, AWS WAF and
  Shape started none. Kasada's worker on both reads `navigator.userAgent`,
  `platform`, `userAgentData.platform` and `languages`, which match the page
  even when the override loses (10 of 10 with the 400ms delay); chewy's
  second worker is the sensor above. Headed Chrome has no `--user-agent`, so
  its workers carry Chrome's own full metadata. v0.7.1 got every shared
  worker wrong in headless, `HeadlessChrome` in its UA included.
- **A shared worker created again resumes through wafer's session.** When a
  shared worker closes and a page creates it again (same name and URL),
  Chrome reuses its agent host while wafer's session is attached: the target
  id stays, no attach is announced, and the worker starts paused for that
  session (`shared_worker_devtools_manager.cc`, `WorkerCreated`:
  `pause_on_start = IsAttached()`). Unresumed, it never ran: the second and
  third creations hung in every run. Wafer's session receives
  `Inspector.targetReloadedAfterCrash` and resumes the worker there; the
  override survives the restart (the renderer restores the session's
  emulation state on reattach), and all rounds read the full metadata.
  Service workers are unaffected: one stopped and restarted under wafer
  answered with the full metadata, twice.
- **`x86` / `10.15.7` in iframes.** Playwright attaches its own metadata to a
  context-level `user_agent=`, guessing `architecture` and taking
  `platformVersion` from the frozen UA token. The page override hid it in the
  top document only. Contexts now carry no `user_agent`.
- **Iframe screen and colorDepth.** The window patch derived its geometry from
  `innerWidth`, which in an iframe is the iframe's. It now takes one geometry
  computed from the viewport and is injected into every iframe through
  auto-attach. In real Chrome an iframe's `outerWidth` is the window's.
- **devicePixelRatio.** Playwright's `device_scale_factor` reaches only the top
  frame. `--force-device-scale-factor=<the display's scale>` (headless macOS)
  sets every frame; with viewport emulation, pair it with the same
  `device_scale_factor`, or the top frame alone reports the context's value.
  `harden_page` warns when it is not 2.
- **The real display, natively (2026-10-06).** Headless macOS launches now
  describe the Mac's main display to Chrome: `--screen-info` (bounds and
  work-area insets in device pixels, `colorDepth` 30 on a P3 display), read
  once per process from AppKit through `osascript` (`NSScreen.mainScreen`:
  frame, visibleFrame, backingScaleFactor, P3 gamut), and `--window-size` of
  the page plus Chrome's 87px toolbar. A context with `no_viewport=True` then
  reports what headed Chrome on that Mac does, in the top frame and every
  iframe, with no script: on this Mac screen 1710x1107, available
  1710x1018 at top 34 (menu bar) above a 55pt Dock, `colorDepth` 30,
  devicePixelRatio 2, `outerWidth == innerWidth`, `outerHeight` 87 above
  `innerHeight`, `screenX/Y` 22/56, all equal to headed Chrome. Viewport
  emulation replaces the screen with the viewport and drops the menu bar and
  Dock, which is why the window script existed; `harden_page` and the solver
  now skip it whenever the page already reports the real display
  (`_native_window`: a work area below a menu bar, an outer window taller
  than the page, a screen wider than it). BrowserSolver opens its headless
  macOS contexts that way, with one page size per solver chosen among the
  common ones that fit the display. This also ends the Kasada and Akamai
  exception: their pages used to go without the window script (their scripts
  detect its `Function.prototype.toString` wrapper) and so reported
  `colorDepth` 24 and the viewport as the screen; they now get the same
  native geometry as every other page. The live suite compares screen,
  available area, `colorDepth` and the outer-inner deltas with headed Chrome
  outright; without `--screen-info` it fails (`1710x1070@0,37` against
  `1710x1018@0,34`). Headless solves on all nine solver sites passed on it.
- **User activation.** The init-script fallback re-applied scripts with
  `Frame.evaluate`, which Playwright sends with `userGesture: true`. Under
  Patchright it also runs in an isolated world the page cannot see, so it
  never patched anything the page reads. It now uses CDP `Runtime.evaluate`
  with `userGesture: false`, in the page's own world.

After the fix, every configuration matches headed Chrome in all of the above:
`harden_page` sync, `harden_page_async` with a persistent profile, a caller who
still passes a context-level UA, and BrowserSolver headless and headed after
preflight. Shared workers match too when the driver was started under
`hardened_driver_env()`, as BrowserSolver's is; a caller who starts it
without leaves them racing Patchright's resume (bullets above). The live test fails
against v0.7.1 and passes after, 10 runs in 10.

**Live solves, 2026-10-06** (system Chrome 154, direct `solver.solve`, one
at a time, alternating versions):

| Target | Leaking state | Result |
|---|---|---|
| idealista.com, DataDome, headed | v0.7.1 after `preflight()` or a first solve | interactive captcha, failed 5 of 5 |
| idealista.com, DataDome, headed | v0.3.4; v0.7.1 first solve; this fix incl. second solves | passed 7 of 7 (real 231KB page) |
| allegro.pl, DataDome, headed, two solves | v0.7.1 / this fix | second solve failed / passed |
| allegro.pl, DataDome, headless | v0.7.1 / this fix | failed 2 of 2 / passed 3 of 3 |
| scrapingcourse.com Turnstile, headed and headless | v0.3.4, v0.7.1, this fix | all passed, no difference |

The headed failures isolate to the context-level UA: the same v0.7.1 code
passed without `preflight()` and failed with it, alternating. It entered in
v0.4.0, which first set the headed solver's UA (`_capture_preflight_identity`
and the first-solve UA read) and so first handed headed contexts one.

Also measured, against the same headed reference, and equal: notification
permission and its permissions-API state, `window.chrome` keys,
hardwareConcurrency, deviceMemory, WebGL vendor and renderer, media devices,
plugins and mime types, `pdfViewerEnabled`, `webdriver`, timezone, locale,
focus, visibility, storage quota, audio sample rate, font checks, and
`performance.now` resolution. The available area (`availTop`, `availHeight`)
now matches too, from the real display; it differed while it came from the
window script's fixed 37px menu bar with no Dock. One difference remains,
not a headless marker: `navigator.connection` rtt/downlink, which varies
between headed runs too.

Not covered: headless on Linux and Windows (the window patch and the forced
scale factor are macOS-only, and nothing here was measured off macOS).

Formerly partly covered, now held (measured 2026-10-06):

- **Popups (fixed 2026-10-06).** A hardened page hardens every popup it
  opens. Its first document used to run with the launch's defaults:
  Patchright resumes a new tab at the end of its own setup, sending a
  user-agent override first only when the context has a user agent or locale
  (`crPage.js`, `FrameSession._initialize`), so a browser-level hold
  released nothing (0 of 5) and wafer's channel overriding the new page on
  attach lost the race (1 of 20). The driver preload now sends the override
  `harden_page` published (`_publish_ua_override`, keyed by the browser's own
  user agent, in the private file `WAFER_UA_PARAMS` names) on every page
  session that set none, right before Patchright's
  `Runtime.runIfWaitingForDebugger`, and Chrome handles a session's commands
  in order. The popup's first script now reads the full version list,
  `arm` and the platform version (5 of 5, 0 of 3 before), and on macOS
  headless the native display covers its screen with no script. The live
  suite reads the popup's first script and checks its document request's
  client hints against headed Chrome; it fails without the injection.
- **Service workers registered by a cross-site iframe (fixed 2026-10-06).**
  They attach to the top page, not to the iframe, while Chromium's
  main-script throttle looks for sessions on the registering frame, so the
  throttle does not hold them. Their script fetch is held instead: the
  browser session that intercepts `Other` requests for shared workers also
  holds a service worker's script, matched by URL (the fetch carries no
  `networkId`), from its attach until its override is sent. With the
  override delayed 400ms while events keep flowing, 0 of 15 read the right
  high-entropy hints without the hold and 15 of 15 with it; 45 of 45 at
  normal speed. (The earlier "10 of 10 wrong" predates the interception;
  with it but no URL hold, a delay that blocks the thread looked fixed only
  because the blocked thread also delayed continuing the fetch.) The live
  suite now registers one from its cross-site iframe and checks the hints
  it reads the moment its script runs.

Constraints the design carries:

- **Paused children wait for the Python thread.** Iframes and workers attach
  paused and only wafer's CDP session releases them. Sync Playwright delivers
  the events that do so only while the thread is inside a Playwright call, so
  a plain `time.sleep` held an iframe created mid-sleep for the rest of it
  (first script 1730ms after creation under a 2s sleep, against 18ms
  unhardened). Solver code sleeps through `wafer.browser._pump.idle`, which
  waits on the bound page instead; `test_solver_sleeps_release_late_iframes`
  covers it. Callers of the sync `harden_page` must wait with
  `page.wait_for_timeout`, not `time.sleep`. Async callers are unaffected.
  In headless mode the browser session's hold works the same way: every
  request of type `Other` (worker scripts, `<object>` and `<embed>` loads)
  waits for the thread to continue it. A caller's own `page.route` stacks on
  it: with a catch-all route, shared, dedicated and service workers and an
  `<object>` all loaded, sync and async (2026-10-06).
- **Depth cap.** Each level of out-of-process iframe nests the routed message
  in one more JSON string, and escaping doubles per level, so a page nesting
  alternating cross-site iframes could make messages grow as 2^depth. Children
  are attached four levels deep (`_MAX_CHILD_DEPTH`); deeper ones keep Chrome's
  own identity and are not paused.
- **User activation is only as clean as the reads that touch the page.**
  Every Playwright evaluation, locator check and `page.content()` is sent with
  `userGesture: true` (`crExecutionContext.js`, `evaluateWithArguments`), which
  sets `navigator.userActivation.hasBeenActive` on that frame and its
  ancestors. The fallback, the post-navigation patch check, the render settle
  loop and the solver's other page reads go through CDP `Runtime.evaluate`
  instead (`_quiet_read`), and the live test asserts no frame is activated by
  them. Solver flows that inspect a challenge through Playwright locators
  before their first click still set it; most then click, which sets it
  legitimately.
- **One geometry per page, fixed at hardening time** (viewport emulation
  only). The window script's geometry comes from the viewport when
  `harden_page` runs; a later `set_viewport_size` leaves the outer size and
  screen at the old values. Nothing in wafer resizes. Native pages
  (`no_viewport=True`) have no script and follow the real window.
- **One display per process.** The main display is read once; a display
  change while the process runs is not followed. Without a window server
  (`osascript` fails) a default 1512x982 MacBook Pro is used. Only the main
  display is described, so a Mac with a second display reports
  `screen.isExtended` false where headed Chrome reports true.
- **Shared workers get the first page's override.** One browser session
  serves the whole browser, and its fetch hold covers every page in it.
- **The headless solver launches Chrome twice on first start**, once to read
  the UA and once with it; an idle relaunch reuses the UA it already has. Both
  launches share the solve deadline. The first launch gets no network
  (`_OFFLINE_ARGS`: a proxy nothing listens on, and
  `--disable-background-networking`): started without `--user-agent`, its
  background traffic carried `HeadlessChrome`, measured as a Chrome
  network-time request to `clients2.google.com` going out through the
  configured proxy (2026-10-06). v0.7.1 sent that on every headless launch.

## CDP init scripts do not execute - re-applied on navigation (2026-07-27)

Measured against Patchright with system Chrome 150.0.7871.182 on macOS.
`Page.addScriptToEvaluateOnNewDocument` accepts the registration and returns
an identifier, and the CDP session is live (`Runtime.evaluate` works on the
same session), but the registered script never executes -- verified with a
script whose only job was to set `window.__probe`, which stayed `undefined`
across two navigations. `page.add_init_script()` and
`context.add_init_script()` are not alternatives: both break navigation
outright under Patchright.

`_install_init_script_fallback` re-applies the same scripts on
`framenavigated`, through CDP `Runtime.evaluate` with `userGesture: false`.
This lands just after document-start rather than before it, so a WAF that
fingerprints at document-start could still read pre-patch values; it is a
fallback for an injection that was otherwise doing nothing at all.

It originally used `Frame.evaluate`. Under Patchright that runs in an isolated
world the page cannot see, so the measurements below read the patch back from
the same isolated world it was applied in, and Playwright sends it with
`userGesture: true`, which left `navigator.userActivation.hasBeenActive` true
on every page (2026-10-05, see above). On Chrome 154 with Patchright 1.59.1 the
CDP registration does execute in the page's own world; each script detects its
own patch and returns, so the fallback costs one evaluation per navigation.

Effect, measured on the same page: `outerWidth/innerWidth/colorDepth/screenY`
goes from `1366/1366/24/22` (a plain headless signature) to
`1538/1536/30/56`. `_verify_headless_patches` logs a warning if the values
still look unpatched after navigation, so a future regression is loud rather
than silent.

Headless Alibaba Baxia before and after is the end-to-end proof: the slider
solved either way, but before the fallback it earned no target-scoped `x5sec`
three rounds running and ended in `ChallengeDetected`, and after it earns
clearance on the first solve and the burst completes 18/18 200s.

**Headless is not uniformly fixed.** Measured 2026-07-27, fresh solver per
target:

| WAF | headless result |
|---|---|
| Cloudflare | 200 in 11.8s |
| Kasada | 200 / 687KB in 12.7s |
| Alibaba Baxia | solves first challenge, 18/18 200s |
| **DataDome** | **fails** -- `ChallengeDetected`, and `_verify_headless_patches` reports `outerWidth=1440 innerWidth=1440 colorDepth=24` |

**2026-10-06 update:** with the headless identity fix below, headless DataDome
on allegro.pl passed 3 of 3 (v0.7.1 failed 2 of 2, alternating). The table
above is the 2026-07-27 measurement.

DataDome is the case the after-document-start limitation actually bites: its
`tag.js` fingerprints at document start, so it reads the pre-patch values
before `framenavigated` fires. The WAFs that fingerprint later see the patched
window. Use `headless=False` for DataDome; headed passes it in ~6s.

Closing that gap needs injection that genuinely runs before first script
execution, which is the thing Patchright is currently preventing.

## Launch Args

Passed to `chromium.launch(args=[...])`.

Built by `hardened_launch_config(headless=…, proxied=…, user_agent=…)` in `wafer/browser/_solver.py`,
which `_ensure_browser` consumes and which is exported from `wafer.browser` for
callers driving their own Playwright. This table and that function must agree;
`tests/test_hardened_launch.py` asserts the solver launches with exactly what
the function returns. The per-page half is the same arrangement:
`_page_hardening_commands` and `_child_target_commands` feed both the public
`harden_page` and the solver's `_setup_headless_patches`, and
`tests/test_harden_page.py` asserts the two send the same commands.

### Removed

`--disable-site-isolation-trials` and its companion
`--disable-features=IsolateOrigins,site-per-process` were dropped. They forced
all frames into one process so CDP scripts reached cross-origin iframes, but
Cloudflare detects the flag and Turnstile would not resolve while it was set
(researchgate.net, 2026-03-06 -see `docs/site-list.md`). Cross-origin frames are
now reached through auto-attach on the page's CDP session, which gives every
out-of-process iframe the page's scripts and UA override before its document
runs. The `patch_frame_headless()` / `patch_frame_screenxy()` helpers that
injected into challenge frames with `Frame.evaluate` were removed (2026-10-05):
under Patchright they landed in an isolated world the frame's scripts cannot
see, and their `userGesture: true` marked the frame as user-activated before
any click.

| Arg | Purpose | Mode |
|---|---|---|
| `--disable-blink-features=AutomationControlled` | Makes `navigator.webdriver` return `false` via native getter. | Both |
| `--enable-gpu` | Forces real GPU where there is one. Without it, WebGL exposes `"SwiftShader"` as renderer even on a GPU host. | Both |
| `--disable-updater-scheduler` | Stops branded Chrome waking Google Updater 19s after launch. The updater inherits the stdio pipes Playwright waits on, so every close after that point took 17-26s on macOS (Chromium issue 481087595; measured 2026-10-05 on Chrome 154: 17.1s without, 0.2s with). Browser-process only, invisible to pages. Honored from about M148 (commit #1605857); older builds ignore it. | Both |
| `--use-gl=angle` | Uses ANGLE for GPU rendering (pairs with `--enable-gpu`). | Both |
| `--use-angle=gl` + `--ignore-gpu-blocklist` | Linux with a GPU (`gpu=True`, or by default when the process can open a `/dev/dri/renderD*` node): selects Mesa OpenGL explicitly; automatic ANGLE selection can yield `gl=none` and remove WebGL. | Linux |
| `--use-angle=swiftshader` + `--enable-unsafe-swiftshader` | Linux without a GPU (`gpu=False`, or by default with no usable render node, e.g. a container without GPU passthrough). Mesa's OpenGL driver there is its `llvmpipe` software rasterizer, and Akamai refuses that renderer outright: homedepot.com under Xvfb (fetchaller's image, Chrome for Testing 154) answered every llvmpipe launch's sensor with a 403 block page within 3s (6 of 6), with or without mouse replay, and passed every SwiftShader launch (4 of 4; then `get()` 200 897KB and `render()` 200 919KB end to end, 2026-10-08). No WebGL at all (`gl=none`, `--disable-3d-apis`) was refused too. `--enable-unsafe-swiftshader` because Chrome no longer falls back to SwiftShader for WebGL on its own. `BrowserSolver` also reads the launched renderer and relaunches on SwiftShader when a render node still led to llvmpipe. | Linux |
| `--use-angle=metal` | Selects Metal backend on macOS. Only on `sys.platform == "darwin"`. | Both (macOS) |
| `--disable-quic` + `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` | Disables page-controlled UDP paths that would bypass the TCP-only proxy. Omitted for direct browsers so their launch fingerprint stays unchanged. | Proxied only |
| `--start-maximized` | Headed browsers run under a real window manager; gives screen, outer-window and viewport geometry one coherent envelope instead of JWM's half-screen tiling. | Headed (Linux) |
| `--headless=new` | Chrome 112+ new headless mode. Uses real compositor pipeline - fixes `performance.now` timer resolution (old `--headless` clamps to 100us, detectable via timing loop). | Headless |
| `--force-color-profile=scrgb-linear` | Makes the rendering pipeline report 10-bit color (`(color: 10)` true, `(color: 8)` false) and HDR (`(dynamic-range: high)` true). Without this, headless Chrome on macOS reports 8-bit sRGB. Kasada cross-checks CSS computed styles against `screen.colorDepth` to detect headless. macOS only. | Headless |
| `--force-device-scale-factor=<scale>` | Every frame reports the display's devicePixelRatio (its AppKit backing scale; 2 on any Retina Mac). Playwright's `device_scale_factor` reaches only the top frame: without this a cross-site iframe reports 1 under a top document reporting 2, and an A->B->A page drags the top document to 1 (measured on Chrome 154). macOS only. | Headless |
| `--screen-info={0,0 WxH colorDepth=C workAreaTop=... workAreaBottom=... workAreaLeft=... workAreaRight=...}` | The Mac's main display, from AppKit, in device pixels: size, menu bar and Dock insets, `colorDepth` 30 on a P3 display (24 otherwise). Every frame of a `no_viewport` context then reports headed Chrome's screen, available area and `colorDepth` natively. macOS only. | Headless |
| `--window-size=W,H` | The page size (`viewport=`, default the largest common size fitting the work area) plus Chrome's 87px toolbar, so `outerWidth == innerWidth` and `outerHeight - innerHeight == 87`, as in headed Chrome. macOS only. | Headless |
| `--user-agent=<browser UA, HeadlessChrome scrubbed>` | Only when `user_agent=` is passed. Chromium puts `HeadlessChrome` in its default UA whenever `--headless` is present, and service and shared workers read that default before any CDP session can change it. Costs the default high-entropy client hints, which per-target CDP overrides restore. | Headless |

## Stripped Patchright Defaults

Passed via `ignore_default_args=[...]`.

| Stripped Arg | Why it's stripped | Mode |
|---|---|---|
| `--enable-automation` | Primary DD detection signal. Removes `chrome.runtime`, sets internal automation state, triggers infobar. | Both |
| `--force-color-profile=srgb` | Real Chrome uses system profile (Display P3 on modern Macs). Alters canvas fingerprint hash. | Both |
| `--headless` | Replaced with `--headless=new` for better fingerprint fidelity. | Headless |

## CDP Scripts (both modes)

Registered via `Page.addScriptToEvaluateOnNewDocument` (requires `Page.enable` first), on the page and on every out-of-process iframe through auto-attach while the iframe is paused. The CDP session must NOT be detached after registration.

### screenX/screenY mouse event fix

**Chromium bug #40280325:** CDP `Input.dispatchMouseEvent` sets `screenX = clientX` and `screenY = clientY` instead of adding the window position offset. DataDome compares screenX/Y vs clientX/Y to detect CDP-dispatched events.

Applied to both `MouseEvent.prototype` and `PointerEvent.prototype`.

The replacement is authorized only by `_probe_screenxy_patch`, a real-input
probe that clicks a button and compares the observed `screenX/Y` against
`clientX/Y + window.screenX/Y + chrome height`. It is a `Function.prototype.toString`-visible
override, so it is installed only when the probe positively shows the bug.

Three outcomes: `screen == client` installs it; the additive relation holds
and it stays off; anything else leaves it off with a warning. That third case
is real, not hypothetical - headless Chrome 150 on macOS reports
`client=(100,100) screen=(122,209) window=(22,22) chrome_y=0`, where the Y
offset is unexplained by `window.screenY`/`outerHeight`. Treating that as
fatal disabled every headless solve, so it must stay non-fatal: the
coordinates are still offset from the client origin, which is the case the
patch exists to repair.

## CDP Scripts (headless only)

Self-guards with `navigator.platform === 'MacIntel'`. `harden_page` and the solver inject it with one fixed geometry computed from the viewport (`_headless_geometry`), the same in the page and every iframe, and it skips a document it has already patched. The derived form shipped in `HardenedLaunch.init_scripts` computes the geometry from its own window and also guards on `outerWidth > innerWidth` (not `!==`, because `outerWidth === 0` during early document load on cross-origin navigation); it is only meaningful in a top-level document, since an iframe's native `outerWidth` is the window's.

### Window property patches

| Property | Headless default | Patched value |
|---|---|---|
| `window.outerWidth` | `== innerWidth` | viewport width + 2, in every frame |
| `window.outerHeight` | `== innerHeight` | viewport height + 80, in every frame |
| `window.screenY` | ~22 | 56 |
| `window.screenTop` | ~22 | 56 |

### Screen dimension patches

Headless reports `screen.width == viewport width` - impossible on real hardware.

| Property | Headless default | Patched value |
|---|---|---|
| `screen.width` | Viewport width | Plausible macOS resolution |
| `screen.height` | Viewport height | Plausible macOS resolution |
| `screen.availWidth` | Viewport width | Same as `screen.width` |
| `screen.availHeight` | Viewport height | `screen.height - 37` (menu bar) |
| `screen.availTop` | 0 | 37 |
| `screen.availLeft` | 0 | 0 |

Resolution lookup table (common macOS CSS-pixel resolutions):
```
[1440, 900], [1512, 982], [1710, 1107], [1728, 1117], [2560, 1440]
```

### Color depth patches

| Property | Headless default | Patched value |
|---|---|---|
| `screen.colorDepth` | 24 | 30 |
| `screen.pixelDepth` | 24 | 30 |

These are safe to patch because `--force-color-profile=scrgb-linear` makes the CSS media queries match (`(color: 10)` true, `(dynamic-range: high)` true), so there's no cross-check inconsistency. Previously left unpatched because the CSS queries couldn't be fixed.

**Kasada exception (viewport emulation only since 2026-10-06; native pages need no script, see "The real display, natively"):** The `_HEADLESS_FIX_SCRIPT` (which includes colorDepth patches) is **skipped** for Kasada challenges. Kasada's ips.js detects the `Function.prototype.toString` wrapper used for getter reflection hardening. scrgb-linear alone suffices for Kasada - the CSS media queries pass and Kasada accepts colorDepth=24 when the rendering pipeline reports 10-bit color.

### Getter reflection hardening

All patched getters are hardened:

- **`Function.name`** - Set to match original (e.g. `"get outerWidth"`). DD checks this.
- **`Function.prototype.toString()`** - Map-backed override returns original native getter's toString result.
- **Setter preservation** - Window properties have setters natively. Missing setter is detectable. `orig.set` preserved.

## CDP Emulation (both modes)

### `Emulation.setUserAgentOverride` with `userAgentMetadata`

Applied in both headed and headless, to the page and, through auto-attach on the page's CDP session, to every iframe, dedicated worker and service worker it starts (`Network.setUserAgentOverride` too, for workers), and to shared workers from a browser session. Without `userAgentMetadata`, the CDP call strips `sec-ch-ua` HTTP headers entirely.

| Field | Value | Purpose |
|---|---|---|
| `userAgent` | Native (headed) or HeadlessChrome replaced (headless) | Remove headless identifier |
| `acceptLanguage` | `"en-US,en"` | Fix `navigator.languages` from `["en-US"]` to `["en-US", "en"]` |
| `brands` | Generated from sec-ch-ua algorithm | Ensure brand shuffling matches HTTP headers |
| `fullVersionList` | Real version from `browser.version` | See version consistency below |
| `fullVersion` | Real version from `browser.version` | Sets `getHighEntropyValues().uaFullVersion` |
| `architecture` | Real arch (e.g. `"arm"`) | High-entropy Client Hints |
| `platformVersion` | Real macOS version (e.g. `"26.3.0"`) | Frozen `10.15.7` is a headless tell |

### `Emulation.setEmulatedMedia` (headless macOS)

| Feature | Value | Status |
|---|---|---|
| `color-gamut` | `p3` | Works - fixes `matchMedia('(color-gamut: p3)')` |

`dynamic-range` was previously attempted but ineffective (rendering pipeline limitation). Now handled natively by `--force-color-profile=scrgb-linear`.

## Version consistency

Chrome's UA Reduction changes the UA string to `MAJOR.0.0.0`, but `getHighEntropyValues()` returns the real version. The `fullVersionList` in CDP metadata MUST use `browser.version` (e.g. `145.0.7632.117`), NOT the UA string.

**Before fix:** `uaFullVersion: 145.0.7632.117` vs `fullVersionList: 145.0.7632.46` (stale table lookup). This mismatch was a major DD detection signal - fixing it dropped headless from interactive captcha to WASM PoW auto-resolve.

## Context-level overrides

| Setting | Headed | Headless |
|---|---|---|
| `user_agent` | Not set | Not set (the launch's `--user-agent` and per-target CDP overrides carry it; a context-level UA adds Playwright's `x86` / `10.15.7` metadata to every cross-site iframe) |
| `viewport` | Not set (`no_viewport=True`) | macOS: not set (`no_viewport=True`; the launch's `--window-size` holds one common size per solver that fits the display). Elsewhere: random common resolution |
| `device_scale_factor` | Not set (display DPR) | macOS: not set (`--force-device-scale-factor` carries the display's scale). Elsewhere: 1 |
| `no_viewport` | `True` | `True` on macOS; not set elsewhere |

## Gotchas

- **Patchright `evaluate` is not the page** - it defaults to `isolated_context=True`, an isolated world page scripts cannot see, and Playwright sends every evaluation with `userGesture: true`. Read or patch page state through CDP `Runtime.evaluate` instead.
- **Playwright's default headless binary is chrome-headless-shell** - `headless=True` with no `channel` or `executable_path` launches it, and it ignores `--headless=new`, brands its workers `HeadlessChrome` and reports no plugins. Launch a full Chrome.
- **`Page.enable` required** - CDP `Page.addScriptToEvaluateOnNewDocument` silently fails without it.
- **Don't detach CDP session** - Removes registered scripts. GC-safe via Playwright channel registry.
- **Extensions don't load in `new_context()`** - Only in default persistent context. Use CDP injection instead.
- **`page.add_init_script()` breaks DNS** in Patchright - causes `ERR_NAME_NOT_RESOLVED`.
- **`chrome.runtime` absent** in fresh profiles (no extensions). Not a major detection vector after `--enable-automation` fix.
- **outerHeight formula** - Must be `innerHeight + 80` (title + tab + toolbar). An earlier `innerHeight - 62` produced `outerHeight < innerHeight` - impossible in real Chrome.
- **Playwright IIFE gotcha** - JS starting with `() =>` or `function` gets auto-wrapped. Use `(function(){...})()`.
- **Never use `networkidle`** with PX iframes - persistent connections, always times out.

## Research log (failed approaches)

1. **CDP `Page.addScriptToEvaluateOnNewDocument` without site isolation disable** - Only reaches main frame, not cross-origin iframes (OOPIFs are separate targets). Solved since 2026-10-05 by auto-attaching each OOPIF, paused, and registering the scripts on its own session.

2. **Chrome extension with `all_frames: true, world: MAIN`** - Extensions work in `--headless=new` since Chrome 112, but only in default persistent context, not `new_context()`. Also, `--load-extension` removed from branded Chrome 137+.

3. **`context.add_init_script()` / `page.add_init_script()`** - Breaks DNS. Patchright implements via route interception which interferes with navigation.

4. **Route interception for DD iframe HTML** - `page.route()` doesn't intercept cross-origin iframe document requests.

5. **CDP `Emulation.setDeviceMetricsOverride` with `screenColorDepth`** - Accepted but does not change `screen.colorDepth` in JS.

6. **JS `matchMedia` proxy override** - Replacing `window.matchMedia` with a Proxy that returns `{matches: true}` for `(color: 10)` and `(dynamic-range: high)`. JS-level checks pass but CSS `getComputedStyle()` on media-query-styled elements still reveals the real rendering pipeline state. Kasada creates `@media (color: 10) { .test { color: green } }` rules and checks computed styles as a cross-check.

7. **`--force-color-profile=display-p3-d65`** - Fixes `matchMedia('(color-gamut: p3)')` but NOT `(color: 10)` or `(dynamic-range: high)`. scrgb-linear fixes all three.

6. **`page.on("framenavigated")` for DD iframe** - Did not fire for cross-origin DD iframe.

7. **CDP `Target.setAutoAttach` with `waitForDebuggerOnStart`** - Detects targets but Patchright's CDP doesn't support flattened child sessions.

8. **`--window-position=-32000,-32000` (headed, hidden off-screen)** - macOS constrains to screen bounds.

9. **`--start-minimized`** - Did not minimize on macOS.

10. **CDP `Browser.setWindowBounds` with minimized state** - Works but launches visible window briefly. Not acceptable for `headless=True`.

4. **`--user-agent` alone** (2026-10-05) - removes `HeadlessChrome` from every target, but Chromium then sends only low-entropy client hints by default: `architecture`, `platformVersion` and the full version list come back empty everywhere CDP does not override them.

5. **Per-target UA override without `--user-agent`** (2026-10-05) - fixes a service worker's fetches but not its `navigator.userAgent` or the `sw.js` request, which take the browser default before the worker can be paused.

6. **Browser-level auto-attach to shared workers, unflattened** (2026-10-05) - refused: "Only flatten protocol is supported with browser level auto-attach". A flattened child cannot be messaged from Playwright's Python `CDPSession` either ("When using flat protocol, messages are routed to the target via the sessionId attribute"); hence the pause, second-session, release dance.

7. **Pausing workers on start** (2026-10-05) - `waitForDebuggerOnStart` on wafer's unflattened sessions, page-level or browser-level, holds no service or shared worker: Patchright's immediate resume or detach releases it, and waiting for the overrides to be acknowledged before resuming changes nothing. What does hold a service worker is a *flattened* page-level session, through the main-script throttle (see above). A shared worker is held by its script fetch, intercepted from the browser session, and fully once Patchright is kept off it (`hardened_driver_env`): then the pause on start is wafer's alone, and wafer resumes it after the override (see above).

8. **Matching held shared-worker fetches by URL** (2026-10-06) - a per-URL credit count released one held fetch per finished override, so with several workers on one script URL a fetch could be released by another worker's override. Chrome reports the script's `networkId` as the worker's target id, which matches each fetch to its own worker.

9. **Re-pausing a shared worker from wafer's session** (2026-10-06) - `Debugger.enable` + `Debugger.pause`, or `Debugger.setInstrumentationBreakpoint` (`beforeScriptExecution`, sent before or after the override), on the worker's unflattened session. They paused the worker in 85-99% of runs and left the residual unchanged (5 of 400 each): in the losing runs the script reads its hints before any wafer message is processed, because Patchright's queued resume is flushed first.

10. **Dropping `--user-agent` in headless** (2026-10-06) - high-entropy hints become natively full in every shared worker (0 of 300 empty), and `navigator.userAgent` says `HeadlessChrome` in 300 of 300.
