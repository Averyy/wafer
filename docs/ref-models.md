# reCAPTCHA Vision Models - Architecture & Training Reference

Current state of the local ONNX models used by `wafer/browser/_recaptcha_grid.py`.

## Two Model Types

### CLS - Tile Classification (3x3 grids)

EfficientNet fine-tuned from scratch on 57k reCAPTCHA tiles. Currently classifies individual tiles into 14 object classes (expanding to 16 on retrain).

| Variant | Architecture | Input | Output | Size | Status |
|---------|-------------|-------|--------|------|--------|
| `wafer_cls_s.onnx` | EfficientNet-B0 | (B,3,224,224) | (B,14) logits | ~21 MB | Live (default) |
| `wafer_cls_x.onnx` | EfficientNet-B1 | (B,3,224,224) | (B,14) logits | ~31 MB | Live (backup) |

Only "s" is loaded at runtime - "x" is 40% larger with <1% accuracy gain (92.1% vs 92.5%). Both are on HuggingFace.

**16 classes** (index order): Bicycle, Bridge, Bus, Car, Chimney, Crosswalk, Hydrant, Motorcycle, Mountain, Other, Palm, Stair, Tractor, Traffic Light, Boat, Parking Meter. Current live model outputs 14 classes (indices 0-13); Boat (14) and Parking Meter (15) are collection-only until retrain.

**How it works:**
1. 3x3 grid image split into 9 tiles (100x100 collected, resized to 224x224 for inference)
2. Batch-classify all 9 tiles -> softmax probabilities per tile
3. Tiles matching the target keyword class are selected
4. Dynamic 3x3: replacement tiles appear after clicking correct ones, re-classified individually

### DET - Object Detection (4x4 grids)

D-FINE (DETR variant) pretrained on Objects365+COCO. General-purpose COCO detector, NOT fine-tuned on reCAPTCHA images.

| Variant | Architecture | Input | Output | Size | Status |
|---------|-------------|-------|--------|------|--------|
| `wafer_det_s.onnx` | D-FINE-S obj2coco | (1,3,640,640) + (1,2) | labels+boxes+scores | 42 MB | Live (default) |
| `wafer_det_x.onnx` | D-FINE-X obj2coco | (1,3,640,640) + (1,2) | labels+boxes+scores | 248 MB | HF only (not auto-downloaded) |

Only "s" is downloaded at runtime. "x" is on HuggingFace as a backup but not auto-downloaded (248 MB vs 42 MB, unbenchmarked on reCAPTCHA grids).

**How it works:**
1. Full 4x4 grid image (one photo divided into 16 cells) letterboxed to 640x640
2. D-FINE outputs up to 300 detections: COCO class labels, bounding boxes (x1,y1,x2,y2), confidence scores
3. Filter by target COCO class + confidence threshold (0.25)
4. Map bounding boxes to grid cells via overlap, requiring min 15% cell area coverage (`min_cell_coverage=0.15`)
5. Click matching cells

**Keyword-to-COCO mapping** (8 of 16 reCAPTCHA classes have COCO equivalents):

| reCAPTCHA keyword | CLS index | COCO80 class |
|-------------------|-----------|-------------|
| bicycle | 0 | 1 |
| bus | 2 | 5 |
| car | 3 | 2 |
| fire hydrant | 6 | 10 |
| motorcycle | 7 | 3 |
| traffic light | 13 | 9 |
| boat | 14 | 8 |
| parking meter | 15 | 12 |

**Non-COCO keywords** (bridge, chimney, crosswalk, mountain, palm tree, stairs, tractor) have no COCO mapping. When these appear on 4x4 grids, the solver collects the image for training then reloads for a 3x3 grid. The Phase 3 cell classifier will handle these directly.

**Unknown keywords**: If Google introduces a new keyword, the solver logs a warning, collects the grid image with outcome "unknown_keyword" for review, then reloads.

## Hosting & Loading

ONNX models hosted on Hugging Face (`Averyyyyyy/wafer-models`), not bundled in the pip package. Downloaded once on first use via `huggingface_hub.hf_hub_download()`.

Thread safety: `_inference_lock` (threading.Lock) wraps all `session.run()` calls so multiple browser workers share the same ONNX sessions safely.

## reCAPTCHA Grid Types

**3x3 static**: Image split into 9 independent tiles. Each classified separately. One round.

**3x3 dynamic**: Same as static, but clicking correct tiles triggers replacements. New single tiles classified individually as they appear.

**4x4 multi-round**: One full photo divided into 16 cells. Google shows 2-4 grids in sequence. "Next" for intermediate rounds, "Verify" on the final one. Pass/fail only known after Verify.

## Keyword Support

`KEYWORD_TO_CLASS` maps reCAPTCHA prompt text to CLS class index. Covers 16 object classes in 9 languages: English, Spanish, French, German, Italian, Portuguese, Dutch, Russian, Chinese. Boat (14) and Parking Meter (15) are English-only until translations are confirmed from live captures.

## Training Infrastructure

All training scripts live in `training/recaptcha/`. Separate venv from wafer (`training/recaptcha/.venv`).

### CLS Training (complete)

Both CLS models are trained, exported, uploaded to HuggingFace, and live in production.

**Base dataset**: `DannyLuna/recaptcha-classification-57k` (57k tiles, 14 classes, MIT license). Downloaded via `download_dataset.py` to `datasets/dataset_cls_full_57k/`.

**Training script**: `train_mps.py` - EfficientNet on Apple Silicon MPS GPU.

```bash
cd training/recaptcha
python train_mps.py --sizes s,x --epochs 30 --batch 64 --lr 1e-3
```

- ImageNet-pretrained backbone, fine-tuned with AdamW + cosine annealing
- Augmentation: RandomResizedCrop, HorizontalFlip, ColorJitter
- Early stopping (patience=10), auto-resume from checkpoint
- Outputs: `runs/cls_{s,x}/weights/best.pth.tar` + `results.json`

**ONNX export**: `export.py`

```bash
python export.py --cls-model runs/cls_s/weights/best.pth.tar --size s
python export.py --cls-model runs/cls_x/weights/best.pth.tar --size x --deliver
```

To retrain with new data, merge reviewed tiles into the base dataset (see Offline Dedup & Merge below) and re-run `train_mps.py` with `--data datasets/dataset_cls_merged`.

### DET Models (off-the-shelf)

D-FINE models are used as-is from the D-FINE project (pretrained on Objects365+COCO). No custom training - ONNX files were exported from the D-FINE repo and uploaded to HuggingFace. See `todo-modeltraining.md` for the plan to replace these with a custom cell classifier.

## Data Collection Pipeline

### Bulk Collection

`training/collect.py` runs headless browser workers against Google's reCAPTCHA demo page, collecting both 3x3 and 4x4 grids. No inference, no solving - just image + keyword capture. ~18 img/min per worker.

```bash
uv run python training/collect.py --workers 3
```

3x3 grids split into 9 individual 100x100 tiles on save, written to `collected_cls/_unlabeled/`. 4x4 grids saved as full images to `collected_det/_unlabeled/`.

### Hot Path Collection

The solver also collects training data during live reCAPTCHA solves (zero overhead to the user):

**CLS tiles** (`_collect_single_tile`):
- Every 3x3 tile (both grid splits and dynamic replacements) saved as 100x100 JPEG
- Metadata: predicted_class, confidence, top-3 predictions, keyword, target_class, is_selected, dhash, pixhash
- Cross-session dedup via dHash (loads existing hashes from metadata.jsonl on first collection)
- Env var: `WAFER_COLLECT_CLS` (default: `training/recaptcha/collected_cls`)

**DET grids** (`_collect_det_grid`):
- Full 4x4 grid images saved at native resolution (~400-450px) with solve outcome
- Metadata: keyword, grid_type, outcome, cells_selected, dhash
- Cross-session dedup via dHash (same mechanism as CLS)
- All 10 outcome paths logged (solved, failed, no_coco_class, etc.)
- Env var: `WAFER_COLLECT_DET` (default: `training/recaptcha/collected_det`)

### Mousse Labeler (annotation UI)

`python -m wafer.browser.mousse` includes DET and CLS annotation tabs:

**DET mode**: Shows full grid images with model cell selections overlaid. Click cells to mark ground truth. On annotation:
1. Grid moved to `collected_det/{ClassName}/` (Title Case, e.g. `Bicycle/`, `Traffic Light/`)
2. Ground truth saved to `annotations.jsonl`
3. Full grid image copied to `reviewed/{ClassName}/` for CLS retraining (450x450 scene photo = valid CLS training data)

**CLS mode**: Shows individual tiles with model predictions and top-3 confidence bars. Click one of 17 class buttons (16 classes + None for distractors) to label. Labeled tiles moved to `reviewed/{ClassName}/`.

### Offline Dedup & Merge

`training/recaptcha/dedup.py` handles dedup against the base 57k dataset:

```bash
python dedup.py build-index                    # pixel SHA256 + dHash of 57k tiles
python dedup.py dedup --threshold 4            # remove matches from reviewed/
python dedup.py merge --output datasets/dataset_cls_merged  # base + reviewed -> train/
```

Two-tier dedup: exact pixel hash match, then perceptual dHash with hamming distance <= 4.

## Data Directories

| Directory | Contents |
|-----------|----------|
| `training/recaptcha/collected_cls/` | CLS tiles - individual 100x100 tiles from hot path and collector |
| `training/recaptcha/collected_det/` | DET grid images (`_unlabeled/` + annotated class folders) |
| `training/recaptcha/reviewed/` | Labeled images ready for training merge (all classes) |
| `training/recaptcha/datasets/dataset_cls_full_57k/` | 57k base tiles (train + val splits) |

## Known DET Issues

- **Over-selection**: D-FINE sometimes detects 9-11 cells out of 16
- `conf_thresh` (0.25) and `min_cell_coverage` (0.15) may need tuning
- The model is general COCO, not adapted to reCAPTCHA's image style (low-res, specific crops, Google's JPEG compression)
- bbox-to-cell mapping is a lossy intermediate step

## Reference

| Project | License | Used for |
|---------|---------|----------|
| [D-FINE](https://github.com/Peterande/D-FINE) | Apache 2.0 | COCO detection (det models) |
| [timm](https://github.com/huggingface/pytorch-image-models) | Apache 2.0 | EfficientNet training (cls models) |
| [DannyLuna/recaptcha-classification-57k](https://huggingface.co/DannyLuna/recaptcha-classification-57k) | MIT | Base CLS dataset |
| [Breaking reCAPTCHAv2](https://github.com/aplesner/Breaking-reCAPTCHAv2) | Academic | Mouse curves, 4x4 strategy |
