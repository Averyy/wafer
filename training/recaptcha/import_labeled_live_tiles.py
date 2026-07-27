"""Import human-reviewed live reCAPTCHA tiles with immutable provenance.

The two known decision-boundary tiles remain held out forever.  The remaining
tiles were reviewed from the same live grid and are eligible as supplemental
training examples.  Every source byte digest is pinned before copying.
"""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ARTIFACTS = Path("/tmp/ae-final-live-artifacts.b78Ac7/recaptcha-cls")

TRAINING_TILES = {
    "d97bf719-33a8-4881-a908-139cbef408b3.jpg": (
        "Traffic Light",
        "3cf1b55686d271c32bf12efd232717ef54586bfc655534cd7461b988297305b4",
    ),
    "4406c20d-f96e-4b69-907c-ac2a0edac0b9.jpg": (
        "Car",
        "f9f4bb582833b36241dcc59270cb2db2e16e71494387229a092b20e267be1484",
    ),
    "38e71301-e704-438a-acb3-52e533987c3e.jpg": (
        "Car",
        "987073bf1c0aaadc2eb4fa24a04c21624a97ea01cb0a08477bc14cb944b6e262",
    ),
    "6a3ae05d-4659-4ce1-a4b0-e1ad0c40909b.jpg": (
        "Crosswalk",
        "baadba686d57c3abb3b18463cd5ec9e4c708efb72ddbb4cf799cd8876c3d1ec0",
    ),
    "27b782a6-4df6-4e82-a646-a2f4b197f764.jpg": (
        "Crosswalk",
        "f6d7697164ec95bb100b468638db90d2be9aff3c4758df9eb2407d7f9543ddf4",
    ),
    "acf9fd87-0c5d-416d-8a7c-e17b28783703.jpg": (
        "Motorcycle",
        "e8a46d28851e61af983e5ad4f40f389ef69620e624da23e44247a47fa6322b12",
    ),
    "23984e95-9ed3-4095-b6fb-c1629f112868.jpg": (
        "Motorcycle",
        "9b1683528101f67a175a7802f7b92486e9e946ff36e18f3f70fed67219d71897",
    ),
}

HELDOUT_TILES = {
    "d36de213-6235-40e4-b453-4bc21e75211c.jpg": (
        "Crosswalk",
        "f17d3b9c115b4b0cc6cffd60cad37dfcfaff2678ab710a615756a73834e1cc83",
        "human-reviewed false negative from live AliExpress grid",
    ),
    "4a91f9d7-b8ab-49f3-9401-9cf19780e870.jpg": (
        "Traffic Light",
        "bcbebc3549f85262121428955e085fc85a5cb004043d4434c847df43d4dd0f21",
        "human-reviewed non-crosswalk boundary negative from live grid",
    ),
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy_checked(source: Path, target: Path, expected_digest: str) -> None:
    observed = _digest(source)
    if observed != expected_digest:
        raise ValueError(f"Source digest mismatch for {source.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if _digest(target) != expected_digest:
            raise ValueError(f"Refusing to overwrite different file: {target}")
        return
    shutil.copy2(source, target)
    if _digest(target) != expected_digest:
        raise RuntimeError(f"Copied digest mismatch for {target}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    parser.add_argument(
        "--training-root",
        type=Path,
        default=SCRIPT_DIR / "datasets" / "wafer_cls",
    )
    parser.add_argument(
        "--heldout-root",
        type=Path,
        default=SCRIPT_DIR / "datasets" / "wafer_cls_live_holdout",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    provenance = {"schema_version": 1, "training": [], "heldout": []}
    for name, (label, digest) in TRAINING_TILES.items():
        source = args.artifacts / name
        target = args.training_root / label / name
        if args.dry_run:
            if _digest(source) != digest:
                raise ValueError(f"Source digest mismatch for {source.name}")
        else:
            _copy_checked(source, target, digest)
        provenance["training"].append(
            {"file": name, "label": label, "sha256": digest}
        )
    for name, (label, digest, reason) in HELDOUT_TILES.items():
        source = args.artifacts / name
        target = args.heldout_root / label / name
        if args.dry_run:
            if _digest(source) != digest:
                raise ValueError(f"Source digest mismatch for {source.name}")
        else:
            _copy_checked(source, target, digest)
        provenance["heldout"].append(
            {"file": name, "label": label, "sha256": digest, "reason": reason}
        )
    if not args.dry_run:
        provenance_path = args.heldout_root / "provenance.json"
        provenance_path.parent.mkdir(parents=True, exist_ok=True)
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    print(
        f"Verified {len(TRAINING_TILES)} training and "
        f"{len(HELDOUT_TILES)} held-out live tiles"
    )


if __name__ == "__main__":
    main()
