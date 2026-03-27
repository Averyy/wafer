# HuggingFace Dataset Upload Plan

Two private repos. Models already live at `Averyyyyyy/wafer-models`.

## Repos

### `Averyyyyyy/wafer-recaptcha` (labeled, curated)

Parquet shards via `push_to_hub()`. All configs use `image` + `label`/metadata columns.

| Local path | HF config | Description | Images |
|---|---|---|---|
| `datasets/wafer_cls_classic/` | `wafer_cls_classic` | Deduplicated DannyLuna 57k (MIT) | ~46,753 |
| `datasets/wafer_cls/` | `wafer_cls` | Our labeled CLS tiles from Mousse | ~877 (growing) |
| `datasets/wafer_det/` | `wafer_det` | Our labeled DET grids from Mousse | ~322 (growing) |

### `Averyyyyyy/wafer-recaptcha-unlabeled` (raw, backup)

Parquet shards via `push_to_hub()`. No file limit concerns.

| Local path | HF config | Description | Images |
|---|---|---|---|
| `collected_cls/` | `cls` | Raw 3x3 tiles (100x100 JPEG) | ~110k (growing) |
| `collected_det/` | `det` | Raw 4x4 grid images | ~15k (growing) |

## Pre-upload changes

### 1. Migrate DET annotations to HF-compatible format

HF's ImageFolder loader auto-reads `metadata.jsonl` and links rows to images via `file_name`.
Our `annotations.jsonl` uses `file` instead. Rename the file and the field:

```bash
cd training/recaptcha/datasets/wafer_det

# Rename field and file
python3 -c "
import json, pathlib
lines = pathlib.Path('annotations.jsonl').read_text().strip().split('\n')
out = []
for line in lines:
    row = json.loads(line)
    row['file_name'] = row['keyword_folder'] + '/' + row.pop('file')
    out.append(json.dumps(row))
pathlib.Path('metadata.jsonl').write_text('\n'.join(out) + '\n')
"

# Verify
head -2 metadata.jsonl
# Should show: {"file_name": "Motorcycle/xxx.jpg", "keyword": "...", "ground_truth": [...], ...}

# Delete old file
rm annotations.jsonl
```

After this, `load_dataset("imagefolder", data_dir="wafer_det")` will return:
- `image` column (PIL images, auto-loaded from `file_name`)
- `keyword`, `grid_type`, `ground_truth`, `keyword_folder` columns (from metadata.jsonl)

We do NOT convert to COCO bbox format - cell indices are the natural representation for
4x4 grids and that's what our solver uses.

### 2. Update Mousse write side

`wafer/browser/mousse/_server.py` DET annotation endpoint (around line 448-459):
- Write `file_name` instead of `file` as the key, with subdirectory prefix: `f"{class_name}/{bare}"`
- Write to `metadata.jsonl` instead of `annotations.jsonl`

CLS and collected_* dirs are unaffected - CLS uses ImageFolder (no metadata needed),
and collected dirs use their own `metadata.jsonl` with `file` key (not uploaded as ImageFolder).

### 3. Verify no read-side changes needed

Investigated: Mousse never reads back from `datasets/wafer_det/`. All `"file"` reads
in `_server.py` are from collected_* dirs (lines 183, 228, 309), which keep `"file"`.
The POST body fields (lines 410, 475, 529) are UI request params, not stored format.
No read-side changes needed.

`_recaptcha_grid.py` writes `"file"` to `collected_*/metadata.jsonl` (staging dirs).
These don't go to HF as ImageFolder and Mousse reads them correctly. No changes needed.

### 4. Update docs

These files reference `annotations.jsonl` and need updating to say `metadata.jsonl`:
- `docs/ref-models.md` (lines 149, 175)
- `wafer/browser/mousse/README.md` (line 86)
- `training/recaptcha/README.md` (line 56)

### 5. Validate before upload

```bash
cd training/recaptcha/datasets

# CLS classic: image count
find wafer_cls_classic \( -name '*.jpg' -o -name '*.png' \) | wc -l

# CLS: image count should match dir listing
find wafer_cls -name '*.jpg' | wc -l

# DET: image count should match metadata line count
find wafer_det -name '*.jpg' | wc -l
wc -l wafer_det/metadata.jsonl

# DET: every file_name in metadata should exist on disk
python3 -c "
import json, pathlib
meta = pathlib.Path('wafer_det/metadata.jsonl')
missing = []
for line in meta.read_text().strip().split('\n'):
    row = json.loads(line)
    path = pathlib.Path('wafer_det') / row['file_name']
    if not path.is_file():
        missing.append(row['file_name'])
if missing:
    print(f'{len(missing)} missing files!')
    for f in missing[:10]:
        print(f'  {f}')
else:
    print('All files present')
"
```

## Dataset cards

### wafer-recaptcha (labeled)

Source file: `hf_readme_labeled.md` (uploaded as `README.md` to HF).

### wafer-recaptcha-unlabeled

Source file: `hf_readme_unlabeled.md` (uploaded as `README.md` to HF).

## Upload commands

### First time setup

```bash
# Login (one-time, already done)
hf auth login

# Verify
hf auth whoami
```

### Labeled repo (wafer-recaptcha)

```bash
cd training/recaptcha

# First time: create private repo
hf repos create Averyyyyyy/wafer-recaptcha --type dataset --private

# Upload dataset card
hf upload Averyyyyyy/wafer-recaptcha hf_readme_labeled.md README.md --repo-type dataset

# Upload all configs as Parquet (re-uploads all shards each time)
uv run --with datasets python3 -c "
from pathlib import Path
from datasets import Dataset, Image, ClassLabel, Features
import json

# CLS classic (ImageFolder -> Parquet)
base = Path('datasets/wafer_cls_classic')
rows, labels = [], set()
for d in sorted(base.iterdir()):
    if not d.is_dir() or d.name.startswith('.'): continue
    labels.add(d.name)
    for f in d.iterdir():
        if f.is_file() and not f.name.startswith('.'):
            rows.append({'image': str(f), 'label': d.name})
feat = Features({'image': Image(), 'label': ClassLabel(names=sorted(labels))})
Dataset.from_list(rows, features=feat).push_to_hub(
    'Averyyyyyy/wafer-recaptcha', 'wafer_cls_classic', private=True, max_shard_size='500MB')
print(f'cls_classic: {len(rows)}')

# CLS (ImageFolder -> Parquet)
base = Path('datasets/wafer_cls')
rows, labels = [], set()
for d in sorted(base.iterdir()):
    if not d.is_dir() or d.name.startswith('.'): continue
    labels.add(d.name)
    for f in d.iterdir():
        if f.is_file() and not f.name.startswith('.'):
            rows.append({'image': str(f), 'label': d.name})
feat = Features({'image': Image(), 'label': ClassLabel(names=sorted(labels))})
Dataset.from_list(rows, features=feat).push_to_hub(
    'Averyyyyyy/wafer-recaptcha', 'wafer_cls', private=True, max_shard_size='500MB')
print(f'cls: {len(rows)}')

# DET (metadata.jsonl + images -> Parquet)
d = Path('datasets/wafer_det')
rows = []
for line in (d / 'metadata.jsonl').read_text().strip().split('\n'):
    entry = json.loads(line)
    img = d / entry['file_name']
    if img.is_file():
        entry['image'] = str(img)
        rows.append(entry)
Dataset.from_list(rows).cast_column('image', Image()).push_to_hub(
    'Averyyyyyy/wafer-recaptcha', 'wafer_det', private=True, max_shard_size='500MB')
print(f'det: {len(rows)}')
"
```

### Unlabeled repo (wafer-recaptcha-unlabeled)

```bash
cd training/recaptcha

# First time: create private repo
hf repos create Averyyyyyy/wafer-recaptcha-unlabeled --type dataset --private

# Upload collected CLS tiles as Parquet
# (collected dirs use 'file' key, not 'file_name', so we load manually)
uv run --with datasets python3 -c "
import json
from pathlib import Path
from datasets import Dataset, Image

d = Path('collected_cls')
rows = []
with open(d / 'metadata.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        img = d / entry['file']
        if img.is_file():
            entry['image'] = str(img)
            rows.append(entry)

ds = Dataset.from_list(rows).cast_column('image', Image())
ds.push_to_hub(
    'Averyyyyyy/wafer-recaptcha-unlabeled',
    'cls',
    private=True,
    max_shard_size='500MB',
)
print(f'Pushed {len(ds)} CLS tiles')
"

# Upload collected DET grids as Parquet
uv run --with datasets python3 -c "
import json
from pathlib import Path
from datasets import Dataset, Image

d = Path('collected_det')
rows = []
with open(d / 'metadata.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        img = d / entry['file']
        if img.is_file():
            entry['image'] = str(img)
            rows.append(entry)

ds = Dataset.from_list(rows).cast_column('image', Image())
ds.push_to_hub(
    'Averyyyyyy/wafer-recaptcha-unlabeled',
    'det',
    private=True,
    max_shard_size='500MB',
)
print(f'Pushed {len(ds)} DET grids')
"
```

Note: `push_to_hub()` re-uploads all Parquet shards for the config each time (not row-level
diffing). For ~110k small tiles this takes a few minutes. Run whenever you want a backup.

## Ongoing workflow

1. Collect images with `collect.py` (runs continuously)
2. Periodically back up raw data: re-run the unlabeled upload commands
3. Label with Mousse (`uv run python -m wafer.browser.mousse`)
4. Dedup new CLS tiles: `uv run python manual_dedup.py --delete`
5. Push labeled data to HF: re-run the labeled upload script above

## Making public

When datasets are large enough to be useful:

```bash
hf repos settings Averyyyyyy/wafer-recaptcha --repo-type dataset --public
hf repos settings Averyyyyyy/wafer-recaptcha-unlabeled --repo-type dataset --public
```
