# Browser Fingerprint Overrides

Every override BrowserSolver applies to Patchright/Chrome, organized by mechanism. Includes research log of failed approaches at the end.

## CDP init scripts do not execute - re-applied on navigation (2026-07-27)

Measured against Patchright with system Chrome 150.0.7871.182 on macOS.
`Page.addScriptToEvaluateOnNewDocument` accepts the registration and returns
an identifier, and the CDP session is live (`Runtime.evaluate` works on the
same session), but the registered script never executes -- verified with a
script whose only job was to set `window.__probe`, which stayed `undefined`
across two navigations. `page.add_init_script()` and
`context.add_init_script()` are not alternatives: both break navigation
outright under Patchright.

`Frame.evaluate` does work, so `BrowserSolver._install_init_script_fallback`
re-applies the same scripts on `framenavigated`. One navigation is one fresh
document, so each script runs exactly once per document. This lands just
after document-start rather than before it, so a WAF that fingerprints at
document-start could still read pre-patch values; it is a fallback for an
injection that was otherwise doing nothing at all.

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

DataDome is the case the after-document-start limitation actually bites: its
`tag.js` fingerprints at document start, so it reads the pre-patch values
before `framenavigated` fires. The WAFs that fingerprint later see the patched
window. Use `headless=False` for DataDome; headed passes it in ~6s.

Closing that gap needs injection that genuinely runs before first script
execution, which is the thing Patchright is currently preventing.

## Launch Args

Passed to `chromium.launch(args=[...])`.

Built by `hardened_launch_config(headless=…, proxied=…)` in `wafer/browser/_solver.py`,
which `_ensure_browser` consumes and which is exported from `wafer.browser` for
callers driving their own Playwright. This table and that function must agree;
`tests/test_hardened_launch.py` asserts the solver launches with exactly what
the function returns.

### Removed

`--disable-site-isolation-trials` and its companion
`--disable-features=IsolateOrigins,site-per-process` were dropped. They forced
all frames into one process so CDP scripts reached cross-origin iframes, but
Cloudflare detects the flag and Turnstile would not resolve while it was set
(researchgate.net, 2026-03-06 -see `docs/site-list.md`). Cross-origin frames are
now reached with `patch_frame_headless()` / `patch_frame_screenxy()` instead.

| Arg | Purpose | Mode |
|---|---|---|
| `--disable-blink-features=AutomationControlled` | Makes `navigator.webdriver` return `false` via native getter. | Both |
| `--enable-gpu` | Forces real GPU. Without it, WebGL exposes `"SwiftShader"` as renderer. | Both |
| `--use-gl=angle` | Uses ANGLE for GPU rendering (pairs with `--enable-gpu`). | Both |
| `--use-angle=gl` + `--ignore-gpu-blocklist` | On Linux/Xvfb, selects Mesa OpenGL explicitly; automatic ANGLE selection can yield `gl=none` and remove WebGL. | Linux |
| `--use-angle=metal` | Selects Metal backend on macOS. Only on `sys.platform == "darwin"`. | Both (macOS) |
| `--disable-quic` + `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` | Disables page-controlled UDP paths that would bypass the TCP-only proxy. Omitted for direct browsers so their launch fingerprint stays unchanged. | Proxied only |
| `--start-maximized` | Headed browsers run under a real window manager; gives screen, outer-window and viewport geometry one coherent envelope instead of JWM's half-screen tiling. | Headed (Linux) |
| `--headless=new` | Chrome 112+ new headless mode. Uses real compositor pipeline - fixes `performance.now` timer resolution (old `--headless` clamps to 100us, detectable via timing loop). | Headless |
| `--force-color-profile=scrgb-linear` | Makes the rendering pipeline report 10-bit color (`(color: 10)` true, `(color: 8)` false) and HDR (`(dynamic-range: high)` true). Without this, headless Chrome on macOS reports 8-bit sRGB. Kasada cross-checks CSS computed styles against `screen.colorDepth` to detect headless. macOS only. | Headless |

## Stripped Patchright Defaults

Passed via `ignore_default_args=[...]`.

| Stripped Arg | Why it's stripped | Mode |
|---|---|---|
| `--enable-automation` | Primary DD detection signal. Removes `chrome.runtime`, sets internal automation state, triggers infobar. | Both |
| `--force-color-profile=srgb` | Real Chrome uses system profile (Display P3 on modern Macs). Alters canvas fingerprint hash. | Both |
| `--headless` | Replaced with `--headless=new` for better fingerprint fidelity. | Headless |

## CDP Scripts (both modes)

Registered via `Page.addScriptToEvaluateOnNewDocument` (requires `Page.enable` first). The CDP session must NOT be detached after registration.

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

Self-guards with `navigator.platform === 'MacIntel'` and `outerWidth > innerWidth` check - only activates on macOS headless. Uses `outerWidth > innerWidth` (not `!==`) because `outerWidth === 0` during early document load on cross-origin navigation.

### Window property patches

| Property | Headless default | Patched value |
|---|---|---|
| `window.outerWidth` | `== innerWidth` | `innerWidth + 2` |
| `window.outerHeight` | `== innerHeight` | `innerHeight + 80` |
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

**Kasada exception:** The `_HEADLESS_FIX_SCRIPT` (which includes colorDepth patches) is **skipped** for Kasada challenges. Kasada's ips.js detects the `Function.prototype.toString` wrapper used for getter reflection hardening. scrgb-linear alone suffices for Kasada - the CSS media queries pass and Kasada accepts colorDepth=24 when the rendering pipeline reports 10-bit color.

### Getter reflection hardening

All patched getters are hardened:

- **`Function.name`** - Set to match original (e.g. `"get outerWidth"`). DD checks this.
- **`Function.prototype.toString()`** - Map-backed override returns original native getter's toString result.
- **Setter preservation** - Window properties have setters natively. Missing setter is detectable. `orig.set` preserved.

## CDP Emulation (both modes)

### `Emulation.setUserAgentOverride` with `userAgentMetadata`

Applied in both headed and headless. Without `userAgentMetadata`, the CDP call strips `sec-ch-ua` HTTP headers entirely.

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
| `user_agent` | Not set | HeadlessChrome replaced |
| `viewport` | Not set (`no_viewport=True`) | Random common resolution |
| `device_scale_factor` | Not set (display DPR) | 2 on macOS, 1 elsewhere |
| `no_viewport` | `True` | Not set |

## Gotchas

- **`Page.enable` required** - CDP `Page.addScriptToEvaluateOnNewDocument` silently fails without it.
- **Don't detach CDP session** - Removes registered scripts. GC-safe via Playwright channel registry.
- **Extensions don't load in `new_context()`** - Only in default persistent context. Use CDP injection instead.
- **`page.add_init_script()` breaks DNS** in Patchright - causes `ERR_NAME_NOT_RESOLVED`.
- **`chrome.runtime` absent** in fresh profiles (no extensions). Not a major detection vector after `--enable-automation` fix.
- **outerHeight formula** - Must be `innerHeight + 80` (title + tab + toolbar). An earlier `innerHeight - 62` produced `outerHeight < innerHeight` - impossible in real Chrome.
- **Playwright IIFE gotcha** - JS starting with `() =>` or `function` gets auto-wrapped. Use `(function(){...})()`.
- **Never use `networkidle`** with PX iframes - persistent connections, always times out.

## Research log (failed approaches)

1. **CDP `Page.addScriptToEvaluateOnNewDocument` without site isolation disable** - Only reaches main frame, not cross-origin iframes (OOPIFs are separate targets).

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
