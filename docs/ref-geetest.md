# GeeTest v4 Slide CAPTCHA Solver

## Status

**Detection**: Done. Browser-level: `.geetest_slider`, `.geetest_btn_click`, `window.initGeetest4` in DOM (`_drag.py::detect_drag_vendor`).

**Browser solve**: Done. **12/12 consecutive solves** on live GeeTest demo (Feb 2026). Full pipeline: network intercept → CV notch detection → mousse replay → verify.

**CV**: `find_notch(bg_png, piece_png)` in `_cv.py`. Multi-blur edge voting + HSV brightness-invariant matching. 16 unit tests.

**Dispatch**: `challenge_type="geetest"` routes to `solve_drag()` in `_solver.py`.

## Architecture

```
wafer/browser/
  _drag.py            # GeeTest-specific: detect_drag_vendor, setup_image_intercept,
                      #   _extract_images_from_dom, _wait_for_puzzle, _get_geometry,
                      #   _check_result, solve_drag
  _cv.py              # CV notch detection: find_notch (Canny + HSV + confidence voting)
  _recordings/
    drags/            # 26 variable-width drags (32-301px)
    paths/            # 27 approach paths (shared with other solvers)
    idles/            # 9 idle recordings (shared)
```

## GeeTest Demo Interaction

**URL**: `https://www.geetest.com/en/adaptive-captcha-demo` -Next.js React app.

1. Navigate to demo URL, wait for load (5s)
2. **Select "Slide CAPTCHA"** -defaults to "No CAPTCHA" otherwise (nothing appears)
3. Select animation style: Float, Popup, or **Bind** (only Bind reliably shows puzzle -Float/Popup auto-pass invisible check)
4. Click `aria-label="Click to verify"` button
5. Wait ~3s for puzzle widget to render

**Critical**: Tab selection uses `.tab-item.tab-item-1` div (not the button inside -div intercepts pointer events). Scroll 400px down to avoid sticky header.

## Widget Structure

- **No iframes, no shadow DOM** -widget injected directly into host page DOM
- CSS classes use hash suffixes: `geetest_slider_<hash>` (e.g., `geetest_slider_1fb54cb8`)
- Puzzle images served as PNGs from `static.geetest.com` CDN, set as `background-image` on `<div>` elements (NOT canvas, NOT `<img>`)
- Background: 300×200px RGB PNG (50-130KB). Piece: 80×80px RGBA PNG with alpha (8-10KB).

### Selectors

```
.geetest_bg          -background image div
.geetest_slice_bg    -puzzle piece div
.geetest_btn         -drag handle
.geetest_track       -slider track
.geetest_box         -widget container
.geetest_result_tips -success/fail message (class includes "success" or "fail")
```

### Outer Wrapper by Style

- **Popup**: `geetest_popup_wrap` → ghost overlay (first child) + `geetest_box_wrap`
- **Bind**: `geetest_captcha geetest_bind` → `geetest_box_wrap` (first child) + ghost overlay (LAST child)
- **Float**: Same as popup but `position: relative`, no ghost overlay

### Widget Dimensions (Bind)

Container 340px, window 302×201px, track 302×60px.

## CV Notch Detection

Algorithm in `_cv.py::find_notch`:
- Binary alpha composite: alpha>128→RGB, shadow→gray128 (eliminates spurious edges from semi-transparent drop shadow)
- Multi-blur edge voting: 5 Gaussian blur levels, Canny + matchTemplate on each, vote for best x-offset
- HSV brightness-invariant matching: GeeTest darkens notch with semi-transparent black overlay. Matching on H+S channels only makes darkening invisible.
- B&W detection: skip HSV when piece mean saturation < 15 (no hue signal)
- x0_crop midpoint: piece shadow boundary midpoint between alpha>0 and alpha>128
- Confidence-weighted scoring: `conf_sum * 5 + contrast * 3`

## Network Flow

```
1. Host page loads gt4.js → defines window.initGeetest4
2. initGeetest4(config, callback) → JSONP to gcaptcha4.geetest.com/load
   → returns captcha_type, image paths, lot_number, payload
3. Injects gcaptcha4.js (widget) + gct4.<hash>.js (telemetry)
4. User clicks trigger → CDN fetches bg.png + slice.png
5. User drags → JSONP /verify with behavioral fingerprint (w= param)
```

## Test Infrastructure

- **Mock**: `tests/mocks/geetest/slide.html` -all 3 styles, procedural puzzles, real DOM structure, loading animation, solve detection
- **Test images**: `tests/mocks/geetest/images/` -5 bg/piece pairs for CV validation
- **Unit tests**: `tests/test_cv.py` -16 tests
- **Demo**: `tests/demo_cv_solve.py` -offline E2E solve against mock
- **Live test**: `tests/live_geetest_demo.py` -12/12 on real demo
