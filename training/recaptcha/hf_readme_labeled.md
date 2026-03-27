---
license: cc-by-nc-sa-4.0
task_categories:
- image-classification
- object-detection
tags:
- recaptcha
- captcha
size_categories:
- 10K<n<100K
configs:
- config_name: wafer_cls_classic
  data_files:
    - split: train
      path: "wafer_cls_classic/train-*"
- config_name: wafer_cls
  data_files:
    - split: train
      path: "wafer_cls/train-*"
- config_name: wafer_det
  data_files:
    - split: train
      path: "wafer_det/train-*"
---

# wafer-recaptcha

Labeled training data for [wafer](https://github.com/Averyy/wafer) reCAPTCHA grid solvers.

## Configs

### wafer_cls_classic

~46,753 deduplicated tiles from [DannyLuna/recaptcha-classification-57k](https://huggingface.co/datasets/DannyLuna/recaptcha-classification-57k) (MIT license). 14 classes as Parquet with `image` and `label` columns. The original 57k had ~11k byte-identical duplicates.

### wafer_cls

Our collected and labeled CLS tiles. 15 classes (same 14 as classic plus Boat). Parquet with `image` and `label` columns.

### wafer_det

4x4 grid images with cell-level ground truth. Each row has:
- `image` - the grid image
- `keyword` - reCAPTCHA prompt keyword (e.g. "bicycles")
- `grid_type` - always "4x4"
- `ground_truth` - list of cell indices (0-15) containing the target object
- `keyword_folder` - class name (e.g. "Bicycle")

Cell indices map to a 4x4 grid left-to-right, top-to-bottom:
```
 0  1  2  3
 4  5  6  7
 8  9 10 11
12 13 14 15
```

## Usage

```python
from datasets import load_dataset

cls = load_dataset("Averyyyyyy/wafer-recaptcha", "wafer_cls_classic")
det = load_dataset("Averyyyyyy/wafer-recaptcha", "wafer_det")
```

## License

- wafer_cls_classic: MIT (derived from DannyLuna/recaptcha-classification-57k)
- wafer_cls, wafer_det: CC BY-NC-SA 4.0
