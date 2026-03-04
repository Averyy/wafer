# Browser Fingerprint Overrides

Every override BrowserSolver applies to Patchright/Chrome, organized by mechanism. Includes research log of failed approaches at the end.

## Launch Args

Passed to `chromium.launch(args=[...])`.

| Arg | Purpose | Mode |
|---|---|---|
| `--disable-blink-features=AutomationControlled` | Makes `navigator.webdriver` return `false` via native getter. | Both |
| `--enable-gpu` | Forces real GPU. Without it, WebGL exposes `"SwiftShader"` as renderer. | Both |
| `--use-gl=angle` | Uses ANGLE for GPU rendering (pairs with `--enable-gpu`). | Both |
| `--use-angle=metal` | Selects Metal backend on macOS. Only on `sys.platform == "darwin"`. | Both (macOS) |
| `--disable-site-isolation-trials` | Forces all frames into one process so CDP scripts reach cross-origin iframes (e.g. DataDome's `geo.captcha-delivery.com`). | Both |
| `--disable-features=IsolateOrigins,site-per-process` | Companion to site isolation disable. | Both |
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
