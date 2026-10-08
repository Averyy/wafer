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

**Dispatch**: `challenge_type="recaptcha"` routes to `wait_for_recaptcha()` in `_recaptcha.py`, which escalates to `solve_image_grid()` in `_recaptcha_grid.py` when Google shows a grid.

## Under TMD (AliExpress MTop)

`challenge_type="tmd"` also lands here when the issued punishment URL, or a vendor punishment frame on a rendered page, carries `action=captcharecaptcha`. That call passes `protocol_completion_is_intermediate=True`: the widget is no longer the authority, because `BrowserSolver`'s outer gate requires a new target-scoped `x5sec` before reporting success. Under that flag the solver hands off (returns True) as soon as TMD has what it needs:

- **Checkbox:** our click happened and the bound anchor frame detached. TMD consumes the auto-passed token and tears the widget down about a second later, before `aria-checked` can be read, so waiting for a token there spent the whole budget.
- **Grid, after a submitted Verify:** an accepted `uvresp` (`protocol_solved`), or a widget teardown (the `torn_down` outcome, watched in both the 10s and 30s post-Verify windows). Live, a `continued` uvresp was followed by a teardown and the gate found a new `x5sec`.

The hand-off log names Google's last verdict since the click (`google_verdict=`, or `not_observed`); it is diagnostic only, since the body read can lose the race with the teardown. A generic `recaptcha` caller never takes these paths and keeps waiting for a token it can prove. Running out of budget in the checkbox phase is a timeout (False), never a fall-through into the image phase. The TMD side (retry targets, render dialog, measurements) is in `docs/ref-baxia.md`.

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

Grid size comes from the one grid table on screen: `.rc-imageselect-table-44` = 4x4, `-33` = 3x3. Detection first waits (up to 4s) until exactly one table is present and none carries an `rc-imageselect-carousel-*` class, because Google slides the next round of a multi-round challenge in with a carousel and for a moment both tables exist. For a 3x3 grid, instructions that continue after the keyword ("Click verify once there are none left") mark it dynamic; the text itself is never compared. That is only a first guess: the first clicks settle it. A static tile keeps its image and takes `rc-imageselect-tileselected` (acknowledged as `selected`); a dynamic tile fades and is replaced. If every click was acknowledged `selected` the grid is handled as static, otherwise as dynamic. Downgrading a grid the prompt called dynamic also needs the clicked tiles still showing their own images, selected, with no replacement arriving, 0.8s after the last click.

## Round handling (live, 2026-10-08)

Measured on AliExpress MTop reCAPTCHA punishments (`challenge_type="tmd"`, 150s budget), with per-poll DOM and network instrumentation. Five defects lost rounds or whole solves:

- **Mid-carousel reads.** On a 4x4 "Next" the button turned to "Skip" 45 ms after the click while the old image was still on screen. Any marker change counted as a new round, the next attempt read the grid mid-carousel (two `table-44`s; the old strict `table-44` locator raised), called it `dynamic_3x3`, could not find a `tile-33` image and reloaded, throwing away a valid round. Seen in all three baseline runs. A new round now needs a new image or prompt (`_new_round`), and detection waits for the carousel to settle.
- **Grid type from `rc-imageselect-desc-no-canonical`.** By its name that class marks a prompt without a canonical example image, and it did not track dynamic grids in either direction. A dynamic "cars" grid without the class was read as static: Verify was pressed while its clicked tiles were still being replaced, no userverify went out, and the solve gave up at 89s of 150s. A static grid with it was read as dynamic and waited 8s for replacements that never came. Fixed by the click-behaviour check above.
- **Reload after "Please try again".** Google answers a wrong submission with a new grid (new image, sometimes a new keyword). The solver clicked reload on top of it. It now continues on Google's grid when one appears within 3s and reloads only when the grid did not change.
- **Stale error messages.** A "try again" or "select all" message still showing from an earlier round is read before Verify and ignored as this round's verdict until it disappears; if it comes back, that is the verdict. One still showing after a userverify and 40s of no change reloads.
- **Giving up on a grid nothing was submitted for.** A lost tile click, unresolved dynamic replacements, a grid that never settled, a Verify that did not dispatch, and a Verify that sent no userverify (counted when the request is sent, so an answer in flight is still waited for) each ended the whole solve. Nothing reached Google in any of them, so no verdict can arrive late; they now reload for a fresh grid while budget remains. A userverify that went out and got no visible result after 40s still ends the solve, leaving the page to the caller's check.

Before (3 cold sessions, old code): solved in 2 of 3 (50.1s, 81.4s; one gave up at 88.9s), 4-5 rounds each, 5 avoidable reloads. After (6 cold sessions): solved in 6 of 6 (103.8s/7 rounds, 63.0s/4, 20.3s/1, 80.8s/6, 18.5s/1, 97.3s/4), no avoidable reloads, Google's own replacement grid used 5 times. The number of rounds is Google's call; long runs were chains of five 4x4 rounds. Under TMD a missing anchor now waits 20s instead of 5s before deciding the browser passed through, since the issued URL already names a reCAPTCHA. This one is inferred, not observed: the anchor appeared within 3s in all 9 runs, but the 5s path ends a solve roughly 15-25s after the call (launch, navigation, browse, grace, then the 8s x5sec poll), which fits a consumer's unexplained 26s failure. An exception inside the solver now logs at WARNING with its type; it used to end the solve with a DEBUG line only.

## Tile score floor

A 3x3 tile (grid or dynamic replacement) is clicked when the target is its top class and scores at least `_MIN_TILE_CONFIDENCE = 0.70` (was 0.10, a leftover from a nano model whose softmax was spread thin). Checked against the unlabeled demo-page tiles in `training/recaptcha/collected_cls` (never in a training set): the shipped classifier scored all 33,485 "cars" tiles, and samples of its Car picks were labeled by eye, about 30 per score band:

| p(Car) band | Share of picks | Cars / labeled |
|---|---|---|
| 0.30-0.50 | 5.1% | 2 / 30 |
| 0.50-0.60 | 5.4% | 1 / 29 |
| 0.60-0.70 | 5.1% | 9 / 29 |
| 0.70-0.80 | 5.4% | 11 / 28 |
| 0.80-0.97 | 16.6% | 30 / 58 |
| 0.97-1.00 | 62.1% | 29 / 29 |

A tile that is more likely wrong than right fails the grid whether clicked or not, so it is better left alone; below 0.70 every band's 95% interval stays under even odds. Bus and hydrant picks at 0.50-0.80 agreed (9/19, 3/18). Car-ish tiles whose top class was something else held no cars (0/29 at 0.05-0.50), so the argmax rule costs little there. Live grids were mixed and few: picks at 0.641 and 0.653 were wrong, one at 0.697 right, and one solve was accepted with a true car at 0.563 left out (the new floor at work). The floor does not explain every wrong verdict: on clean (noise-free) live grids most misses were tiles where another class won (a cyclist on a crosswalk at 0.162, a small white hydrant at 0.063).

## Keyword Matching

`KEYWORD_TO_CLASS` maps reCAPTCHA prompt text (e.g. "Select all images with **bicycles**") to model class indices. Covers 16 object classes in 9 languages.

**CLS classes** (14 live, 2 collection-only): Bicycle, Bridge, Bus, Car, Chimney, Crosswalk, Hydrant, Motorcycle, Mountain, Other, Palm, Stair, Tractor, Traffic Light, Boat*, Parking Meter*. (* = collection-only until retrain)

**DET coverage**: 8 of 16 classes have COCO equivalents (bicycle, bus, car, fire hydrant, motorcycle, traffic light, boat, parking meter). Non-COCO keywords (bridge, chimney, crosswalk, mountain, palm, stairs, tractor) on 4x4 grids trigger a reload for a 3x3 grid.

Unknown keywords log a warning and reload.

## Detection gating

HTTP-layer detection only fires on **403/429** responses. A 200 page that merely embeds a reCAPTCHA widget is not a challenge - gating on the marker alone would classify every contact form and login page as one. A site that serves reCAPTCHA behind a 200 therefore never reaches the solver via `detect_challenge`; exercising the solver against such a page (including Google's own `api2/demo`, which returns 200) means calling `wait_for_recaptcha(solver, page, timeout_ms)` directly.

One 200 page is a challenge regardless: Google's "unusual traffic" page (`/sorry/index`), recognized structurally by `form#captcha-form` holding a `g-recaptcha` widget and a hidden `continue` input (`is_google_sorry_page`). It is served as 429 after a redirect, but `render()` captured it under a 200 document after an in-place solve and returned it as the search results (2026-10-06). `render()` also classifies the captured DOM by the status of the document it came from, not the first navigation's: Google's `/search` answered 200 and then moved the page on to `/sorry/` (429), so its reCAPTCHA was never solved in place.

Live, 2026-10-06 (system Chrome 154): the solve was working and wafer reported it as a failure. A headless trace of a Google search showed the whole sequence: Verify, `userverify` 200 classified `protocol_solved`, the sorry page's own callback posting `POST /sorry/index`, a 302 to the search with `google_abuse=GOOGLE_ABUSE_EXEMPTION...`, a 302 to the plain search URL and 200 with 2.5MB of results, with the `GOOGLE_ABUSE_EXEMPTION` cookie set. The solver meanwhile kept watching a widget the page had already left for a token, for 40s, and returned False. A teardown after Verify only counted for the TMD wrapper. Now, for every caller, a widget torn down after an accepted answer (`_has_new_protocol_solved_response`, with up to 3s for that answer to be read) is solved, and one torn down with no accepted answer is a failure; a checkbox whose widget is torn down after the click hands off the same way. The caller still classifies the page the browser lands on. After the fix `render()` returned the results page (200, 2.4MB, "best mechanical keyboard - Google Search") in 61.6s after two image rounds. A real Chrome with no cookies (an Incognito window) also gets the sorry page first; a checkbox click passes it there. wafer's checkbox passed it the same way in a later run (`widget torn down after checkbox (google_verdict=protocol_solved)`), returning results in 15.8s. Since an image-grid solve outruns the session's 30s default, `session.render()` without a `timeout=` lets a render that lands on a reCAPTCHA run up to 150s from the call (`_RENDER_CHALLENGE_BUDGET`, the solver's `challenge_budget`); an explicit `timeout=` always wins.

## Models

Two ONNX models from HuggingFace (`Averyyyyyy/wafer-models`), downloaded on first use via `huggingface_hub`. Not bundled in pip package.

- **CLS** (`wafer_cls_s.onnx`, ~21 MB): EfficientNet-B0, 14-class tile classifier, 92.1% accuracy
- **DET** (`wafer_det_s.onnx`, ~42 MB): D-FINE-S, COCO object detector, confidence threshold 0.25

Models loaded independently - one can work without the other. First inference has ~2-3s warmup (background thread). All `session.run()` calls wrapped in `_inference_lock` for thread safety.

Loading runs on a daemon thread so a cold install cannot pin BrowserSolver's single worker. The waiting solve holds back part of its budget (`min(10s, half the remaining deadline)`) rather than waiting to the deadline: models returned with no time left to use them are useless, and the loader keeps running either way, so the next challenge still gets warm models. Deployments that must not pay this on the first challenge should call `preload_recaptcha_models(timeout=...)` (returns bool) or `preflight_recaptcha_models(timeout=...)` (raises) at startup.

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
- A tile holding two classes is skipped when the other one wins (live misses: a cyclist on a crosswalk, a hydrant beside a wall)
- "Please select all matching images" still reloads; the selection is not extended
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
