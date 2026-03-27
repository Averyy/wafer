---
license: cc-by-nc-sa-4.0
task_categories:
- image-classification
- object-detection
tags:
- recaptcha
- captcha
size_categories:
- 100K<n<1M
configs:
- config_name: cls
  data_files:
    - split: train
      path: "cls/train-*"
- config_name: det
  data_files:
    - split: train
      path: "det/train-*"
---

# wafer-recaptcha-unlabeled

Raw, unlabeled reCAPTCHA images collected by [wafer](https://github.com/Averyy/wafer). Backup of the collection pipeline output before manual labeling.

For labeled, curated data see [Averyyyyyy/wafer-recaptcha](https://huggingface.co/datasets/Averyyyyyy/wafer-recaptcha).

## Configs

### cls

Raw 3x3 CLS tiles (100x100 JPEG). Each row has:
- `image` - the tile image
- `file` - original filename
- `keyword` - reCAPTCHA prompt keyword
- `keyword_folder` - class name
- `phash` / `dhash` - perceptual hashes (hex) used for deduplication

### det

Raw 4x4 DET grid images. Each row has:
- `image` - the full grid image
- `file` - original filename
- `keyword` - reCAPTCHA prompt keyword
- `keyword_folder` - class name

## Usage

```python
from datasets import load_dataset

cls = load_dataset("Averyyyyyy/wafer-recaptcha-unlabeled", "cls")
det = load_dataset("Averyyyyyy/wafer-recaptcha-unlabeled", "det")
```

## License

CC BY-NC-SA 4.0
