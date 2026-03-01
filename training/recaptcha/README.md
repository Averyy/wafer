# reCAPTCHA Model Training

Train EfficientNet classification models for automated reCAPTCHA solving.

## Models

| Variant | Architecture | Params | ONNX size | Status |
|---------|-------------|--------|-----------|--------|
| `wafer_cls_s.onnx` | EfficientNet-B0 | 5.3M | ~21 MB | Live (default) |
| `wafer_cls_x.onnx` | EfficientNet-B1 | 7.8M | ~31 MB | Backup (HuggingFace only) |

Only "s" is loaded at runtime. Both are Apache 2.0 licensed via [timm](https://github.com/huggingface/pytorch-image-models).

## Requirements

- Python 3.10+
- Apple Silicon Mac (MPS) or NVIDIA GPU (CUDA)
- ~2 GB disk for dataset, ~1 GB for training runs

## Data Collection

Collect reCAPTCHA grid images from Google's demo page:

```bash
# Single worker (recommended - Google rate-limits after ~30-60 min)
uv run python training/collect.py

# Headful if headless stops getting challenges
uv run python training/collect.py --headful
```

3x3 grids are auto-split into 9 individual 100x100 tiles on save (`collected_cls/`). 4x4 grids go to `collected_det/` as full images. 3-6s delay between grid reloads, 10-16s between rounds. Auto-backoff on rate limiting (8h, 12h).

After collecting, add model predictions for faster CLS labeling:

```bash
uv run python training/recaptcha/predict_cls.py
```

Label with Mousse: `uv run python -m wafer.browser.mousse`

## Directory Structure

```
training/recaptcha/
  collected_cls/              # Raw unlabeled CLS tiles (staging queue)
    *.jpg
    metadata.jsonl
  collected_det/              # Raw unlabeled DET grids (staging queue)
    *.jpg
    metadata.jsonl
  datasets/
    wafer_cls_classic/        # Deduplicated base dataset (46,753 tiles, 14 classes)
    wafer_cls/{ClassName}/    # Our labeled CLS tiles (Mousse output)
    wafer_det/{ClassName}/    # Our labeled DET grids (Mousse output)
    wafer_det/annotations.jsonl  # Cell-level ground truth
```

## Training

```bash
cd training/recaptcha
pip install -r requirements.txt

# 1. Train (s ~4-6 hr on M4, x ~6-8 hr)
nohup python train_mps.py --sizes s,x --epochs 30 > train.log 2>&1 &

# 2. Export to ONNX
python export.py --cls-model runs/cls_s/weights/best.pth.tar --size s

# 3. Deliver ONNX files to wafer
python export.py --cls-model runs/cls_s/weights/best.pth.tar --size s --deliver
```

To retrain with our collected data, dedup first then point at both data sources:

```bash
python dedup.py build-index       # index the classic dataset
python dedup.py dedup             # remove duplicates from datasets/wafer_cls/
python train_mps.py --data datasets/wafer_cls_classic --extra-data datasets/wafer_cls
```

## Base Dataset

`datasets/wafer_cls_classic/` - 46,753 deduplicated tiles across 14 classes. Originally from [DannyLuna/recaptcha-classification-57k](https://huggingface.co/DannyLuna/recaptcha-classification-57k) (MIT license), deduplicated from 57k to remove ~11k byte-identical duplicates and train/val data leakage.

Classes: bicycle, bridge, bus, car, chimney, crosswalk, fire hydrant, motorcycle, mountain, other, palm tree, stairs, tractor, traffic light

## Training Options

```
python train_mps.py --help

--sizes   Model sizes to train (default: s,x)
--epochs  Training epochs (default: 30)
--imgsz   Image size (default: 224)
--batch   Batch size (default: 64)
--lr      Learning rate (default: 1e-3)
--data    Dataset path (default: datasets/wafer_cls_classic)
--patience Early stopping patience (default: 10)
```

## Export Options

```
python export.py --help

--cls-model  Path to trained .pth.tar (required)
--size       Model size suffix: s or x (default: s)
--deliver    Copy ONNX files to wafer/browser/models/
```
