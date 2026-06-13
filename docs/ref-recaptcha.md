# reCAPTCHA Solvers (v2 grid + v3 mint)

wafer handles the two reCAPTCHA variants with two unrelated mechanisms:

- **v2** (visible checkbox + image grid) -solved in a real browser via
  `BrowserSolver` (`challenge_type="recaptcha"`). The bulk of this doc.
- **v3** (invisible *score* token) -minted **browser-free** over plain HTTP via
  `session.mint_recaptcha_v3(...)`. See [reCAPTCHA v3 token minting](#recaptcha-v3-token-minting-browser-free)
  at the bottom.

---

# reCAPTCHA v2 Image Grid Solver

## Status

**Detection**: Done. Browser-level: `#recaptcha-anchor` checkbox or `rc-imageselect` grid in DOM (`_recaptcha.py`). HTTP-level: `google.com/recaptcha` in response body (`_challenge.py`).

**Browser solve**: Done. Live-solved on `google.com/recaptcha/api2/demo` (Feb 2026). Checkbox click + image grid classification/detection.

**Dispatch**: `challenge_type="recaptcha"` routes to `solve_recaptcha()` in `_solver.py`.

## Architecture

```
wafer/browser/
  _recaptcha.py         # Checkbox click, grid detection, solve orchestration
  _recaptcha_grid.py    # ONNX inference, keyword mapping, tile/grid collection
  _recordings/
    grid_hops/          # 45 short tile-to-tile mouse paths for natural clicking
```

## Grid Types

**3x3 static**: Image split into 9 independent tiles. Each tile classified individually via CLS model. One round - select matching tiles and verify.

**3x3 dynamic**: Same as static, but clicking correct tiles triggers replacement tiles. New tiles classified individually as they appear. Continues until no more replacements.

**4x4 multi-round**: One photo divided into 16 cells. DET model runs object detection on full image, maps bounding boxes to grid cells. Google shows 2-4 grids in sequence ("Next" for intermediate, "Verify" on final). Pass/fail only known after final verify.

Grid type auto-detected via DOM: `.rc-imageselect-table-44` = 4x4, `.rc-imageselect-desc-no-canonical` = dynamic 3x3.

## Keyword Matching

`KEYWORD_TO_CLASS` maps reCAPTCHA prompt text (e.g. "Select all images with **bicycles**") to model class indices. Covers 16 object classes in 9 languages.

**CLS classes** (14 live, 2 collection-only): Bicycle, Bridge, Bus, Car, Chimney, Crosswalk, Hydrant, Motorcycle, Mountain, Other, Palm, Stair, Tractor, Traffic Light, Boat*, Parking Meter*. (* = collection-only until retrain)

**DET coverage**: 8 of 16 classes have COCO equivalents (bicycle, bus, car, fire hydrant, motorcycle, traffic light, boat, parking meter). Non-COCO keywords (bridge, chimney, crosswalk, mountain, palm, stairs, tractor) on 4x4 grids trigger a reload for a 3x3 grid.

Unknown keywords log a warning and reload.

## Models

Two ONNX models from HuggingFace (`Averyyyyyy/wafer-models`), downloaded on first use via `huggingface_hub`. Not bundled in pip package.

- **CLS** (`wafer_cls_s.onnx`, ~21 MB): EfficientNet-B0, 14-class tile classifier, 92.1% accuracy
- **DET** (`wafer_det_s.onnx`, ~42 MB): D-FINE-S, COCO object detector, confidence threshold 0.25

Models loaded independently - one can work without the other. First inference has ~2-3s warmup (background thread). All `session.run()` calls wrapped in `_inference_lock` for thread safety.

If `onnxruntime` or `huggingface_hub` not installed, or download fails: solver returns False, challenge escalation continues normally. No exception raised.

See `docs/ref-models.md` for model training, data collection pipeline, and retraining instructions.

## Behavioral Evasion

- Mouse replay: 45 recorded human grid-hop paths (short tile-to-tile movements)
- Random click position within each tile (not center)
- Human-like delays between tile clicks
- Checkbox click uses recorded mouse path, not direct click

## Known Limitations

- DET model sometimes over-selects (9-11 of 16 cells) due to low confidence threshold
- Non-COCO keywords on 4x4 grids cause a reload (wastes one round)
- Boat and Parking Meter classes are collection-only (model outputs 14 classes, not 16)
- First request downloads ~63 MB of models (cached after that)

## Test Infrastructure

- **Live test**: `google.com/recaptcha/api2/demo` (always triggers image grid)
- **Bulk data collection**: `uv run python training/recaptcha/collect.py --workers 3` (headless, ~18 img/min per worker, both 3x3 and 4x4)
- **Annotation**: `uv run python -m wafer.browser.mousse` (DET and CLS labeling modes)
- **Recordings**: 45 grid hops in `_recordings/grid_hops/`

---

# reCAPTCHA v3 token minting (browser-free)

A completely separate path from the v2 grid solver above. reCAPTCHA **v3**
issues an invisible *score* token rather than a visible challenge, so there is
nothing to click. wafer mints the token over plain HTTP -**no browser, no
`[browser]` extra, no JS execution** -via `session.mint_recaptcha_v3(...)`.
Implementation: `wafer/_recaptcha_v3.py` (entry points `mint_sync` / `mint_async`);
session methods in `wafer/_sync.py` / `wafer/_async.py`.

## Status

**Done.** Browser-free minting via two cross-origin requests to Google's
reCAPTCHA endpoints, run under the session's own TLS-emulated client (so the
token rides a real browser fingerprint). Distinct from the v2 grid solver -no
DOM, no ONNX models, no `BrowserSolver`.

## Flow

The token is produced by two requests to `www.google.com` (no browser):

1. **`GET .../anchor`** (`/recaptcha/api2/anchor`, or `/recaptcha/enterprise/anchor`
   for enterprise) -returns an HTML page carrying a hidden `recaptcha-token`
   `<input>`, the anchor (`c`) token. Parsed two-pass (locate the input tag, then
   read its `value=`) so attribute order/quote style don't matter.
2. **`POST .../reload`** (`/recaptcha/api2/reload`) -exchanges the anchor token
   for the final response token, embedded in the JSON-ish body as
   `["rresp","<token>"]`. The action rides in the `sa` param; `reason=q`.

The reload call is sent as an XHR would be (`Accept: */*`, `Origin` + `Referer`
= google), not a navigation.

## API

```python
token = session.mint_recaptcha_v3(
    sitekey,                        # the site's reCAPTCHA key (readable from the page)
    action,                         # action name, rides in the reload `sa` param
    *,
    origin=None,                    # scheme+host the sitekey is bound to
    referer=None,                   # embedding page URL; defaults to origin
    v=None,                         # api.js release hash; None -> auto-scraped + cached
    enterprise=False,               # True -> enterprise anchor/reload paths + enterprise.js
)  # -> str (the response token; raises TokenMintFailed, never returns None)
```

Identical signature on `SyncSession` (returns `str`) and `AsyncSession`
(returns a coroutine).

- **`origin` / `referer`:** pass at least one. If only `referer` is given,
  `origin` is derived from it; if only `origin`, `referer` defaults to it; if
  neither, `TokenMintFailed(stage="anchor")`.
- **`co` param:** computed for you as `base64url(scheme://host:port)` in Google's
  `.`-padded form (`compute_co`), using the origin's actual port (explicit, or
  the scheme default).
- **`v` (release hash) auto-scrape:** when `v=None`, wafer fetches Google's
  `api.js` (or `enterprise.js`), scrapes the release hash from the
  `releases/<v>/` path in the loader, and **caches it on the session**
  (`self._recaptcha_v`, keyed `"std"`/`"ent"`) -so repeat mints don't refetch
  and minting keeps working when Google ships a new api.js. Pass `v=` only if you
  already know it.
- **Embed-mode safe:** in an `embed="xhr"` / `"xhr-jquery"` / `"iframe"` session,
  minting suspends embed mode for the Google requests (`_embed_suspended`), so the
  embed `Accept` / `X-Requested-With` / `Origin` never leak to or duplicate
  against google.com. No separate non-embed session needed.

## Score caveat (read this)

Minting **always produces a token**, but the *score* Google assigns it depends
on **request reputation** -IP, TLS fingerprint, cookies. wafer mints the token;
it **cannot guarantee** the site's score threshold passes. A clean residential IP
with the session's real-browser TLS fingerprint scores best; a flagged datacenter
IP may mint a token the site still rejects on score. This is why minting is
HTTP-only and site-agnostic -it keys solely off page-readable values (sitekey,
action, origin), not on solving anything.

## Errors

Raises `TokenMintFailed` (a `WaferError`) -never silently returns None -when a
token can't be extracted: a missing anchor token, a missing reload token, or a
non-200 from Google. `.stage` is `"anchor"`, `"reload"`, or `"apijs"`;
`.status_code` is the failing HTTP status when one was in hand.
