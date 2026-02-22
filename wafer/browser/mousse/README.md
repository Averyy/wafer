# Mousse — Mouse Movement Recorder

Dev tool for recording human mouse movements used by wafer's browser solver. Records idles, paths, holds, drags, and browses as CSV files consumed at runtime by `_solver.py`.

## Usage

```bash
uv run python -m wafer.browser.mousse
# Opens http://localhost:8377 in your browser
```

Optional: `--port 9000` to use a different port.

## Recording Modes

### Idle (30 needed)
Natural mouse movement — pretend you're reading a page. Press Space, move around for 1-4 seconds (randomized per recording). Stored as `t,dx,dy` pixel deltas.

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
Horizontal drag from left green zone to right red zone. Same flow as paths (Space, enter start zone, dwell, drag to end). Stored as `t,rx,ry` normalized fractions.

### Browse (20 needed)
Simulate exploring a page — move mouse around naturally AND scroll up/down. Press Space, then move and scroll for 8 seconds. The fake page has randomized content length (3-12 sections) per recording to capture different scroll behaviors for short vs long pages. Section count is saved in metadata for page-length matching during replay. Captures both mouse movement and scroll wheel events. Stored as `t,dx,dy,scroll_y` where `scroll_y` is the wheel deltaY (0 for mouse-only events, positive for scroll-down, negative for scroll-up).

## Output

CSV files saved to `wafer/browser/_recordings/{idles,paths,holds,drags,browses}/`.

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
| Space | Start recording |
| Enter | Accept recording |
| Escape | Discard / close modal |

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

Zero external dependencies — stdlib `http.server` + vanilla JS.
