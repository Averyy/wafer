# PerimeterX Press-and-Hold Solver

## Overview

PerimeterX (HUMAN Security) uses a "press and hold" challenge: hold a button for 6-10 seconds while PX collects behavioral telemetry (80+ data points). Solver replays recorded human mouse movements via CDP `Input.dispatchMouseEvent` (`isTrusted: true`).

## Architecture

```
wafer/browser/
  _solver.py          # BrowserSolver: lifecycle, recording management, mouse replay, dispatch
  _perimeterx.py      # PX-specific: _find_px_button, progress bar monitoring, solve verification
  _extensions/screenxy/  # Chrome extension fixing CDP screenX/screenY bug
  _recordings/
    idles/             # Pre-interaction page scanning (shared across solvers)
    paths/             # Mouse paths to button (shared across solvers)
    holds/             # Micro-tremor during hold (PX-specific)
```

## Key Decisions

| Question | Answer | Why |
|---|---|---|
| Mouse input? | **Recorded human paths/holds** | Real tremor/wobble undetectable; PX samples 80+ points during hold |
| Button detection? | **DOM frame scanning** | `role="button"` in visible PX frames only (decoy frames are 0x0) |
| Pre-interaction idle? | **Required** | PX monitors all mouse events from page load; no prior movement is a flag |
| screenX/screenY? | **Browser extension** | Fixes CDP bug #40280325. Runs in separate content script world (invisible to PX integrity checks) |

## Real PX Structure

Captured from wayfair.com and zillow.com (2026-02-20). Full dumps in `tests/px_frame_dumps/ANALYSIS.md`.

### Frame Tree

```
Frame 0: main page
├── Frame 1: about:blank (empty placeholder)
├── Frame 2: about:blank (decoy button -"Press & Hold")
├── Frame 3: about:blank (decoy button -"Press & Hold")
├── Frame 4: about:blank (REAL button -has accessibility text)
├── Frame 5: about:blank (decoy button -"Press & Hold")
└── Frame 6: about:blank (decoy button -"Press & Hold")
```

PX creates 5-6 `about:blank` iframes inside `#px-captcha`. All have identical `<title>Human verification challenge</title>` and `role="button"` elements. **Only one** has elements with a visible bounding box (> 10px). The rest are decoys (0x0 invisible elements). This is the single biggest trap in PX solving.

### Main Page DOM

```html
<div id="px-captcha-wrapper" dir="auto">
  <div class="px-captcha-container">    <!-- centered modal, 530px wide -->
    <div class="px-captcha-header">     <!-- "Before we continue..." -->
    <div class="px-captcha-message">    <!-- "Press & Hold to confirm..." -->
    <div id="px-captcha"                <!-- THE CLICK TARGET -530x100 -->
         style="display: block; min-width: 253px;">
      <iframe title="Human verification challenge" ...>
      <!-- captcha.js creates nested about:blank sub-frames -->
    </div>
  </div>
</div>
```

### Button Element (inside each iframe)

All IDs are obfuscated random strings. The real button is a 253px pill shape with a progress bar as an absolutely-positioned child at `z-index: -1`.

```html
<div role="button" tabindex="0" style="display: block; margin: auto;">
  <!-- Progress bar: position:absolute; z-index:-1; growing width -->
</div>
```

Both wayfair and zillow use identical PX structure (different app IDs only).

Recording format details in `wafer/browser/mousse/README.md`.

## Solve Flow

```
1. Wait 1.5-3.0s for challenge page to render
2. _find_px_button: scan frames for role="button" with visible bounding box
   → returns (x, y, frame) -frame reference needed for progress monitoring
3. _replay_idle: 2-4s of casual page scanning from random origin
4. _replay_path: move from idle endpoint to button (direction-matched recording)
5. Brief hover: 0.3-0.8s (human reads button text)
6. _replay_hold: mousedown + tremor replay, watching progress bar in PX frame
   → releases 300-600ms after bar reaches 100%
7. _wait_for_px_solve: poll for #px-captcha removal (success) or "try again" (fail)
8. Retry up to 3 times on failure
```

### Timing from live tests

| Phase | Duration |
|---|---|
| Idle | 2-4s |
| Path to button | 0.5-1.5s |
| Hover | 0.3-0.8s |
| Hold (PX-determined) | 6.5-9.4s observed |
| Post-solve redirect | ~2.5s |
| **Total (first attempt success)** | **~20s** |

Time scaling (+/-15%) on all recordings gives hundreds of effective variations from 79 base recordings.

## Critical Bugs Found

### 1. Decoy Frames

PX creates multiple iframes with identical `<title>Human verification challenge</title>` and `role="button"`. Only ONE has visible elements (bounding_box > 10px). Reading the progress bar from a decoy frame always returns 0% -the hold runs to max duration and PX rejects it.

**Fix**: `_find_px_button` checks `bounding_box > 10px` on each frame's button element. Returns `(x, y, frame)` -the frame reference is passed to progress monitoring.

### 2. Honeypot Fast Fill

The `#px-captcha` div itself is clickable and passes through to the iframes. But clicking the div center might hit a decoy iframe. Frame scanning ensures we target the real button's coordinates.

### 3. networkidle Trap

`page.wait_for_load_state("networkidle")` times out at 30s on every attempt because PX iframes maintain persistent WebSocket/XHR connections. They never reach "idle".

**Fix**: Poll `_find_px_button` for button visibility instead of waiting for network idle.

### 4. IIFE Double-Invocation

Progress bar JS starting with `() =>` or `function` gets auto-wrapped as a callable by Playwright's `frame.evaluate()`. The function runs once as definition, once as invocation.

**Fix**: Use `(function(){...})()` IIFE expression form.

### 5. screenX/screenY CDP Bug

Chromium bug #40280325: `Input.dispatchMouseEvent` sets `screenX = clientX` instead of adding window position offset. PX collects screenX/screenY and checks consistency.

**Fix**: Browser extension patches `MouseEvent.prototype` getters in a separate content script world (invisible to PX's native function integrity checks). Based on `CDP-bug-MouseEvent-screenX-screenY-patcher` (252 stars).

### 6. Progress Bar Reversal

PX can reject a hold mid-way -the bar fills to 17-37% then shrinks back to 0%. Normal behavior (suspected: click position too extreme, or behavioral scoring). Retry succeeds within 1-3 attempts.

### 7. Solve Detection False Positive

`page.content()` string search for "px-captcha" matched CSS class names even after the `#px-captcha` element was removed.

**Fix**: Use `page.locator("#px-captcha").count()` for exact element presence.

## Live Test Results (Feb 2026)

**wayfair.com**: PX triggered after 7 refreshes. First-attempt solve: 3.3% → 99.3% in 9.4s, released 0.48s after 100%. ~20s total from trigger to solve.

**Local mock**: `tests/px_captcha_local.html` -random delays, decoy frames, honeypot. Solver passes reliably.

## Testing

### How to Trigger PX

**Method 1: Repeat refreshes** -7-10 refreshes on `wayfair.com/v/account/authentication/login` triggers the challenge.

**Method 2: Suspicious User-Agent** -Set UA to `HeadlessChrome` or `PhantomJS` for immediate bot classification.

**Tips**: Clear cookies between attempts. If solved recently, wait 5-10 minutes or append random string to UA.

### Test Sites

| Site | URL | Reliability |
|---|---|---|
| Wayfair | `wayfair.com/v/account/authentication/login` | HIGH -confirmed + solved |
| Zillow | `zillow.com` | HIGH -captured frame dumps |
| Walmart | `walmart.com/blocked` | HIGH -has reCAPTCHA fallback |
| DigiKey | `digikey.com` | HIGH -PX + Cloudflare |
| StockX | `stockx.com` | MEDIUM -may pass without challenge |

### Local Mock

`tests/px_captcha_local.html` -realistic PX mock matching real frame structure. Random load delay, random hold duration, decoy frames, honeypot, progress bar, overshoot detection.

```bash
uv run python tests/test_px_captcha_local.py   # visual mock test
uv run python tests/test_px_live_wayfair.py    # live site test
uv run pytest tests/ -x -q                     # 459 unit tests
```

