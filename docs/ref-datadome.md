# DataDome Solver

## Status

**Detection**: Done. Header-based (`x-datadome` on 403/429) and cookie-based (`datadome` cookie).

**What we solve**:

| Challenge Type | Status | How |
|---|---|---|
| WASM PoW auto-resolve (plv3) | **Works** | DD's JS runs in browser, sets `datadome` cookie automatically. No interaction needed. Most common path. |
| Confirm button | **Works** | "Confirm you are human" button in `captcha-delivery` iframe. Clicked with mousse replay path. |
| Puzzle slider (ArgoZhang jigsaw) | **Broken** | CV notch detection works, drag works, DD rejects the answer. |
| Slide-right slider | **Broken** | Drag to end works, DD rejects the answer. |
| Audio captcha (6 digits) | **Broken** | Whisper transcription works, digits entered correctly, DD rejects the answer. |

**What we don't solve** (and why):

DD's interactive challenges (slider, audio, slide-right) all fail even when the answer is correct. The issue is not accuracy - it's that DD's behavioral analysis detects CDP-dispatched input events. This happens in both headless and headful mode because the detection is on the input event pattern, not browser fingerprinting.

Specifically, when DD escalates beyond WASM PoW, it runs deeper behavioral checks on mouse/keyboard events inside the `captcha-delivery` iframe. CDP `Input.dispatchMouseEvent` and `Input.dispatchKeyEvent` produce events that DD can distinguish from real hardware input. The `_SCREENXY_FIX_SCRIPT` patches `screenX`/`screenY` on mouse events, but DD likely checks additional signals (event timing distribution, pressure, movement entropy, trusted event internals).

Evidence:
- Audio captcha: correct 6 digits transcribed and entered, verify clicked, DD rejects (cookie changes but iframe persists - "rejection, not clearance")
- Puzzle slider: correct notch position, drag replayed with mousse recording, DD rejects
- Slide-right: handle dragged to correct end position, DD rejects
- All three fail identically in both headless and headful mode
- WASM PoW (no interaction) works consistently

## Architecture

The solver (`wafer/browser/_datadome.py`) does:

1. Navigate browser to challenged URL
2. Wait for DD `captcha-delivery` iframe or WASM PoW auto-resolve
3. If confirm button visible, click it with mousse replay
4. If WASM PoW runs, detect `datadome` cookie change + iframe disappearing
5. If DD escalates to interactive challenge (audio/slider), bail out immediately (saves 15-30s of wasted time)
6. If no `captcha-delivery` iframe appears within 8s, the browser met no challenge. When the displayed document is a 2xx (its own navigation timing status, not the newest response seen) and a `datadome` cookie is set for the page's host, DD let it through on the first request (that response sets the cookie, so there is no change to see); this counts as solved, the page is passed through and the session pins to the browser, as after any DD solve. Without both, it fails as before.

The bail-out was added March 2026. Previously the solver spent 15-30s on audio transcription or slider solving that always got rejected.

**Let through on the first request** (mouser.com, macOS, 2026-11-04, 1 of 16 solves): the plain client drew the 403 and the browser's navigation got the 200 page with DD's cookie. The handler reported it as a failed solve, so the page and cookie were dropped, the rotations were refused, and the request failed in 14s. The solver's return-cookies-anyway fallback for a failed handler went in July 2026, which turned this case from a replay into a failure.

**A mouse move Chrome never answers** (mouser.com): DD's interstitial is a full-page iframe, removed when the cleared page reloads; a `mouseMoved` in flight at that commit was never answered, and the solve waited in `mouse.move` until its timeout. The driver preload now bounds input (see `docs/ref-headless.md`).

## Cookie Replay

DataDome cookies can be replayed via TLS. Requirements:
- OS must match (DD's `plv3` fingerprint includes OS)
- TLS fingerprint must be consistent (wreq Emulation handles this)
- IP doesn't need to match exactly (DD allows IP changes within reason)

Cookie TTL is ~4 hours. After initial browser solve, subsequent TLS requests reuse the `datadome` cookie without re-challenging.

## Verified Sites

Sites where WASM PoW auto-resolve works:
- `etsy.com` - auto-resolve, 238KB (Mar 2026)
- `allegro.pl` - auto-resolve, 1.3MB (Feb 2026)
- `tripadvisor.com` - auto-resolve (intermittent, sometimes TLS-only)
- `idealista.com` - auto-resolve, 89KB (Feb 2026)
- `mouser.com` - auto-resolve, 172KB, about 6s on macOS (Nov 2026); now and then lets the browser through with no challenge

Sites where DD escalates to interactive challenge (unsolvable):
- `neimanmarcus.com` - escalates to audio captcha, always rejected (Mar 2026)

## Future Work

To solve DD's interactive challenges, we'd need to bypass CDP input detection. Possible approaches:
- Native input injection via OS-level APIs (CGEventPost on macOS) instead of CDP
- X11/Wayland input injection on Linux
- Hardware input simulation (USB HID device emulation)

All of these are significantly more complex than CDP dispatch and would require platform-specific code.
