# Mousse -Mouse Movement Recorder

Dev tool for recording human mouse movements and labeling reCAPTCHA training data. Records idles, paths, holds, drags, slide_drags, grids, and browses as CSV files consumed at runtime by `_solver.py`. Also provides DET (detection) and CLS (classification) annotation modes for labeling collected reCAPTCHA grid images and tiles.

## Usage

```bash
uv run python -m wafer.browser.mousse
# Opens http://localhost:8377 in your browser
```

Optional flags:
- `--port 9000` to use a different port
- `--collected-det PATH` to set the DET grids directory (default: `training/recaptcha/collected_det`)
- `--collected-cls PATH` to set the CLS tiles directory (default: `training/recaptcha/collected_cls`)

## Recording Modes

### Idle (30 needed)
Natural mouse movement -pretend you're reading a page. Press Space, move around for 1-4 seconds (randomized per recording). Stored as `t,dx,dy` pixel deltas.

### Path (26 needed across 6 directions)
Move from a green start zone to a red end zone. Press Space, enter green zone, hold 500ms, move to red zone, hold 500ms. Stored as `t,rx,ry` normalized fractions (resolution-independent).

| Direction | Count |
|-----------|-------|
| UL → Center | 8 |
| UR → Center | 5 |
| L → Center | 4 |
| BL → Center | 3 |
| BR → Center | 3 |
| UL → Lower | 3 |

### Hold (20 needed)
Click and hold inside the red target circle for up to 12 seconds. Captures micro-tremor. Stored as `t,dx,dy` pixel deltas from mousedown point.

### Drag (20 needed)
Simulate solving a slider puzzle. Press Space to see the puzzle, then:

1. **Approach**: Move cursor to the slider handle (recording starts when you enter the handle zone)
2. **Pause**: Hover near the handle naturally -look at the puzzle, decide where to drag. This pre-drag dwell (0.5-2s) is captured in the recording and replayed before mousedown, replacing synthetic sleep timers
3. **Drag**: Click and drag horizontally to the notch position, release when placed

The pause before clicking is critical -it captures real human "thinking time" and micro-jitter that WAF behavioral models check for. Don't rush it.

Stored as `t,rx,ry` normalized fractions with `mousedown_t` in metadata marking when the drag phase begins. Pre-drag events have `rx ≈ 0` (hovering near handle).

### Slide (15 needed)
Simulate a "slide to verify" CAPTCHA -a confident full-width left-to-right drag. The slider matches real Baxia/AliExpress NoCaptcha dimensions (300px track, 42px handle, 34px height). Press Space to see the slider, then:

1. **Approach**: Move cursor to the handle (recording starts when you enter the handle zone)
2. **Pause**: Hover briefly near the handle -quick natural pause, no puzzle to study
3. **Slide**: Click and drag all the way to the right edge, release at the end

Unlike puzzle drags (which require careful placement), slides should be confident and fast -the real CAPTCHA checks behavioral signals, not positional accuracy.

Stored as `t,rx,ry` normalized fractions (same format as puzzle drags) with `mousedown_t` in metadata. Saved to `slide_drags/` directory.

### Grid (30 needed - 10 sessions x 3 segments)
Short mouse hops between grid tiles for reCAPTCHA image grid solving. Press Space to see a 3x3 tile grid with 3 randomly highlighted targets. Click each target tile in order (1, 2, 3). After the 3rd click, the recording auto-finishes.

Each accepted session produces **3 separate CSV files** - one per tile-to-tile hop:

1. **Segment 1**: cursor start -> first tile click (approach + dwell)
2. **Segment 2**: first tile click -> second tile click (pause + move + dwell)
3. **Segment 3**: second tile click -> third tile click (pause + move + dwell)

Each segment captures the full natural cycle between clicks - post-click pause, scanning, movement, and pre-click dwell are all baked into the timing data.

Targets are randomized each session (never all in the same row or column) so recordings cover all 8 directions naturally. Stored as `t,rx,ry` normalized fractions (same format as paths). Typical segment duration: 0.4-1.2s.

### Browse (20 needed)
Simulate exploring a page -move mouse around naturally AND scroll up/down. Press Space, then move and scroll for 8 seconds. The fake page has randomized content length (3-12 sections) per recording to capture different scroll behaviors for short vs long pages. Section count is saved in metadata for page-length matching during replay. Captures both mouse movement and scroll wheel events. Stored as `t,dx,dy,scroll_y` where `scroll_y` is the wheel deltaY (0 for mouse-only events, positive for scroll-down, negative for scroll-up).

## Labeling Modes

### DET (Detection Grid Annotation)

Annotate 4x4 (and 3x3) reCAPTCHA grid images collected during live solves or the bulk collector. DET mode shows each grid with the original keyword, and you click cells to mark the ground truth.

- Click cells to toggle, or click+drag across multiple cells
- Green cells = your picks, red cells = model-only picks, amber = both agree
- Class override dropdown lets you correct the keyword if Google's label is wrong (e.g. image shows a bicycle but keyword says "motorcycles")
- Enter = save annotation, Esc = skip
- On annotation:
  1. Grid copied to `datasets/wafer_det/{ClassName}/`, ground truth saved to `datasets/wafer_det/annotations.jsonl`
  2. Grid also copied to `datasets/wafer_cls/{ClassName}/` for CLS retraining
  3. Grid removed from `collected_det/` queue

- **Priority ordering**: grids are sorted by labeled class count (ascending) so underrepresented classes appear first
- **Stats table** at the bottom shows per-class labeled/pending counts with color coding (green/yellow/red)

Tab is disabled when no grids are available. Populate by running the collector (`uv run python training/collect.py`) or the reCAPTCHA solver with collection enabled (`WAFER_COLLECT_DET` env var or default path).

### CLS (Classification Tile Labeling)

Label individual 3x3 reCAPTCHA tiles collected during live solves or the bulk collector. CLS mode shows each tile with confidence bars and 16 emoji-labeled class buttons (Other is last, for tiles that don't match any category).

The bulk collector (`training/collect.py`) auto-splits 3x3 grids into individual tiles on save, so collected tiles are ready for CLS annotation immediately. Run `predict_cls.py` after collecting to add model predictions.

- **Auto-suggest**: model's predicted class is pre-selected (half-opacity green). Press Enter/Space to approve, or click a different button to override (full green, accepts immediately).
- S = skip tile, D = delete tile
- 3-item pending buffer: the last 3 labels stay pending (yellow border in history) before being transferred. Click a pending item to undo instantly without an API call. Already-transferred items can still be undone (calls the undo API).
- "Save N pending" button appears below history when items are buffered, hidden when empty
- Pending labels also flush automatically on tab switch or page close
- Labeled tiles are moved to `datasets/wafer_cls/{ClassName}/`
- **Priority ordering**: tiles are sorted by labeled class count (ascending) so underrepresented classes appear first
- **Stats table** at the bottom shows per-class labeled/pending counts with color coding (green/yellow/red)

Tab is disabled when no tiles are available.

## Output

CSV files saved to `wafer/browser/_recordings/{idles,paths,holds,drags,slide_drags,grids,browses}/`.

Each CSV has a metadata comment line, header row, then data:

```csv
# type=paths viewport=1280x720 start=64,36 end=640,396 direction=to_center_from_ul
t,rx,ry
0.000,0.0000,0.0000
0.016,0.0230,0.0150
...
```

Browse recordings include a scroll column:

```csv
# type=browses viewport=1280x720
t,dx,dy,scroll_y
0.000,0.0,0.0,0
0.016,3.2,-1.1,0
0.500,2.1,1.5,-120
```

## Controls

| Key | Action |
|-----|--------|
| Space | Start recording / confirm CLS label / save DET annotation |
| Enter | Accept recording / confirm CLS label / save DET annotation |
| Escape | Discard / close modal / skip DET grid / skip CLS tile |
| S | Skip CLS tile |
| D | Delete CLS tile |

Gear icon (⚙) in the header opens bulk delete controls.

## Architecture

```
wafer/browser/mousse/
  __init__.py    # package docstring
  __main__.py    # CLI: parse port, open browser, run server
  _server.py     # stdlib HTTP server + JSON API
  _static/
    index.html   # single-page recording UI
    recorder.js  # mouse capture, normalization, API calls
    style.css    # dark theme
```

Zero external dependencies -stdlib `http.server` + vanilla JS.

## Browse Replay in Solvers

All browser solver wait loops must use `_replay_browse_chunk()` instead of bare `time.sleep()`. This replays recorded mouse movement and scrolling during idle waits, preventing WAF VMs from detecting zero-activity bot signals. Pattern:

1. `state = solver._start_browse(page, x, y)` at solver start
2. `solver._replay_browse_chunk(page, state, N)` replacing each `time.sleep(N)`

Falls back to `time.sleep` transparently when no browse recordings are loaded.
