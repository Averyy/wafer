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
- **Bulk data collection**: `uv run python training/collect.py --workers 3` (headless, ~18 img/min per worker, both 3x3 and 4x4)
- **Annotation**: `uv run python -m wafer.browser.mousse` (DET and CLS labeling modes)
- **Recordings**: 45 grid hops in `_recordings/grid_hops/`
