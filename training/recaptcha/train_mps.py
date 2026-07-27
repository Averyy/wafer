"""Train EfficientNet on MPS (Apple Silicon GPU) with checkpoint resume support."""

import argparse
import random
import time
from pathlib import Path

import numpy as np
import timm
import torch
import torch.nn as nn
from PIL import Image
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms

try:
    from classes import NUM_CLASSES
    from dataset_manifest import build_manifest, write_manifest
    from durable_io import atomic_write, atomic_write_json
    from training_contract import (
        SIZES,
        best_checkpoint_name,
        build_checkpoint,
        publish_epoch_checkpoints,
        size_seed,
        state_dict_sha256,
        validate_best_checkpoint,
        validate_class_contract,
        validate_resume_checkpoint,
        validate_training_request,
    )
except ModuleNotFoundError:
    from training.recaptcha.classes import NUM_CLASSES
    from training.recaptcha.dataset_manifest import build_manifest, write_manifest
    from training.recaptcha.durable_io import atomic_write, atomic_write_json
    from training.recaptcha.training_contract import (
        SIZES,
        best_checkpoint_name,
        build_checkpoint,
        publish_epoch_checkpoints,
        size_seed,
        state_dict_sha256,
        validate_best_checkpoint,
        validate_class_contract,
        validate_resume_checkpoint,
        validate_training_request,
    )

LOG_INTERVAL = 50  # log every N batches


class ManifestDataset(Dataset):
    """Load exactly the reviewed records selected by a split manifest."""

    def __init__(self, records, class_to_idx, transform):
        self.records = records
        self.class_to_idx = class_to_idx
        self.transform = transform

    def __len__(self):
        return len(self.records)

    def __getitem__(self, index):
        record = self.records[index]
        with Image.open(record["path"]) as image:
            image = image.convert("RGB")
        return self.transform(image), self.class_to_idx[record["label"]]


def get_transforms(img_size, is_train):
    if is_train:
        return transforms.Compose(
            [
                transforms.RandomResizedCrop(img_size, scale=(0.8, 1.0)),
                transforms.RandomHorizontalFlip(),
                transforms.ColorJitter(brightness=0.2, contrast=0.2, saturation=0.2),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]
                ),
            ]
        )
    return transforms.Compose(
        [
            # Validation must represent the shipped predictor, not timm's
            # generic ImageNet evaluation crop.  The reCAPTCHA tiles are
            # already exact cell crops; resizing to 255 then center-cropping
            # discards their borders and materially disagrees with production.
            # The direct bilinear production contract measured 93.24% on the
            # 1,258-tile labeled corpus and also beat the center-crop variant
            # in the focused comparison, so keep validation identical to
            # predict_cls.py and wafer's ONNX inference path.
            transforms.Resize(
                (img_size, img_size),
                interpolation=transforms.InterpolationMode.BILINEAR,
                antialias=True,
            ),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
        ]
    )


def train_one_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0
    num_batches = len(loader)
    for batch_idx, (images, labels) in enumerate(loader):
        images = images.to(device, non_blocking=True)
        labels = labels.to(device, non_blocking=True)
        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * images.size(0)
        _, predicted = outputs.max(1)
        correct += predicted.eq(labels).sum().item()
        total += labels.size(0)
        if (batch_idx + 1) % LOG_INTERVAL == 0 or batch_idx == num_batches - 1:
            acc = correct / total
            print(
                f"    batch {batch_idx + 1}/{num_batches}  "
                f"loss={loss.item():.4f}  acc={acc:.4f}",
                flush=True,
            )
        # Prevent MPS memory buildup (pytorch/pytorch#145374)
        if (batch_idx + 1) % 10 == 0:
            torch.mps.empty_cache()
    return total_loss / total, correct / total


@torch.no_grad()
def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    for images, labels in loader:
        images = images.to(device, non_blocking=True)
        labels = labels.to(device, non_blocking=True)
        outputs = model(images)
        loss = criterion(outputs, labels)
        total_loss += loss.item() * images.size(0)
        _, predicted = outputs.max(1)
        correct += predicted.eq(labels).sum().item()
        total += labels.size(0)
    return total_loss / total, correct / total


def evaluate_selected_checkpoint(model, checkpoint_path, loader, criterion, device):
    """Evaluate held-out data once, after validation chooses the checkpoint."""

    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    model.load_state_dict(checkpoint["state_dict"])
    model = model.to(device)
    return evaluate(model, loader, criterion, device)


def select_validation_winner(results):
    """Choose one candidate solely by validation accuracy and size tie-break."""

    if not results:
        raise RuntimeError("No valid model sizes were selected")
    return sorted(
        results,
        key=lambda size: (-results[size]["best_val_acc"], size),
    )[0]


def evaluate_heldout_selected_winner(
    results,
    heldout_loader,
    model_factory,
    criterion,
    device,
    *,
    defer_heldout=False,
):
    """Select by validation, optionally deferring the one held-out evaluation."""

    selected_size = select_validation_winner(results)
    selected = results[selected_size]
    selected["heldout_loss"] = None
    selected["heldout_acc"] = None
    if heldout_loader is not None and not defer_heldout:
        model = model_factory(selected_size)
        selected["heldout_loss"], selected["heldout_acc"] = (
            evaluate_selected_checkpoint(
                model,
                selected["checkpoint"],
                heldout_loader,
                criterion,
                device,
            )
        )
    return selected_size


def _training_run_config(args) -> dict:
    """Return every CLI value that changes optimizer or loader continuity."""

    return {
        "batch": args.batch,
        "epochs": args.epochs,
        "imgsz": args.imgsz,
        "lr": args.lr,
        "patience": args.patience,
        "seed": args.seed,
        "workers": args.workers,
    }


def _seed_size_run(run_seed: int) -> None:
    """Reset every training RNG before constructing one size candidate."""

    random.seed(run_seed)
    np.random.seed(run_seed % (2**32))
    torch.manual_seed(run_seed)
    torch.mps.manual_seed(run_seed)


def _capture_rng_state(loader_generator) -> dict:
    """Capture all RNG streams needed to continue at the next epoch."""

    return {
        "python": random.getstate(),
        "numpy": np.random.get_state(),
        "torch_cpu": torch.get_rng_state(),
        "torch_mps": torch.mps.get_rng_state(),
        "loader_generator": loader_generator.get_state(),
    }


def _restore_rng_state(rng_state: dict, loader_generator) -> None:
    """Restore the exact post-epoch RNG state from a checkpoint."""

    random.setstate(rng_state["python"])
    np.random.set_state(rng_state["numpy"])
    torch.set_rng_state(rng_state["torch_cpu"])
    torch.mps.set_rng_state(rng_state["torch_mps"])
    loader_generator.set_state(rng_state["loader_generator"])


def _save_checkpoint(checkpoint: dict, path: Path) -> None:
    """Durably replace one checkpoint."""

    atomic_write(path, lambda handle: torch.save(checkpoint, handle))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="s,x", help="Comma-separated sizes: s,x")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--imgsz", type=int, default=224)
    parser.add_argument("--batch", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument(
        "--seed", type=int, default=20260726, help="Training and loader RNG seed"
    )
    parser.add_argument("--data", default="datasets/wafer_cls_classic")
    parser.add_argument(
        "--extra-data",
        action="append",
        default=[],
        help="Additional class-directory tree; merged through the manifest",
    )
    parser.add_argument(
        "--heldout-data",
        action="append",
        default=[],
        help="Class-directory tree reserved for final evaluation only",
    )
    parser.add_argument(
        "--defer-heldout",
        action="store_true",
        help=(
            "Select and freeze the validation winner without evaluating held-out "
            "data; use for pre-export review"
        ),
    )
    parser.add_argument(
        "--validation-fraction",
        type=float,
        default=0.1,
        help="Per-class deterministic validation fraction",
    )
    parser.add_argument(
        "--split-seed",
        type=int,
        default=20260726,
        help="Stable seed used only for manifest split assignment",
    )
    parser.add_argument(
        "--manifest",
        default="runs/training_manifest.json",
        help="Where to write the exact reviewed split manifest",
    )
    parser.add_argument(
        "--run-root",
        default="runs",
        help="Root for this run's size-specific checkpoints and metrics",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and validate the manifest without requiring MPS or training",
    )
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument(
        "--resume", default=None, help="Resume from checkpoint (path to .pth.tar)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        help="DataLoader workers (uses spawn context for MPS safety)",
    )
    args = parser.parse_args()

    sizes, resume_path = validate_training_request(
        args.sizes.split(","),
        args.resume,
    )
    data = Path(args.data)
    roots = [data, *(Path(path) for path in args.extra_data)]
    heldout_roots = [Path(path) for path in args.heldout_data]
    manifest = build_manifest(
        roots,
        heldout_roots,
        validation_fraction=args.validation_fraction,
        seed=args.split_seed,
    )
    validate_class_contract(manifest["classes"])
    manifest_path = Path(args.manifest)
    write_manifest(manifest, manifest_path)
    print(f"Manifest: {manifest_path} ({manifest['manifest_sha256']})")
    print(
        "Manifest splits: "
        f"train={len(manifest['splits']['train'])}, "
        f"validation={len(manifest['splits']['validation'])}, "
        f"heldout={len(manifest['splits']['heldout'])}, "
        f"excluded_duplicates={len(manifest['excluded_duplicates'])}"
    )
    if args.dry_run:
        return
    if not torch.backends.mps.is_available():
        raise RuntimeError("MPS not available - this script requires Apple Silicon GPU")

    device = torch.device("mps")
    # Fail instead of silently using an operation PyTorch marks
    # nondeterministic. Backend-level floating-point reproducibility is still
    # bounded by PyTorch/MPS itself; see the training README.
    torch.use_deterministic_algorithms(True)
    run_config = _training_run_config(args)

    print(f"Device: {device}")
    print(f"Sizes: {sizes}")
    print(
        f"Epochs: {args.epochs}, imgsz: {args.imgsz}, "
        f"batch: {args.batch}, lr: {args.lr}"
    )
    print(f"Workers: {args.workers} (spawn)")
    print(f"Training RNG seed: {args.seed}")
    print()

    classes = manifest["classes"]
    class_to_idx = {label: index for index, label in enumerate(classes)}
    heldout_ds = ManifestDataset(
        manifest["splits"]["heldout"],
        class_to_idx,
        get_transforms(args.imgsz, is_train=False),
    )
    mp_ctx = torch.multiprocessing.get_context("spawn") if args.workers > 0 else None
    heldout_loader = (
        DataLoader(
            heldout_ds,
            batch_size=args.batch,
            shuffle=False,
            num_workers=args.workers,
            pin_memory=False,
            multiprocessing_context=mp_ctx,
            persistent_workers=False,
        )
        if len(heldout_ds)
        else None
    )
    results = {}

    for size in sizes:
        run_seed = size_seed(args.seed, size)
        _seed_size_run(run_seed)
        model_name = SIZES[size]
        run_dir = Path(args.run_root) / f"cls_{size}"
        run_dir.mkdir(parents=True, exist_ok=True)
        weights_dir = run_dir / "weights"
        weights_dir.mkdir(exist_ok=True)

        print(f"{'=' * 60}")
        print(f"Training {model_name} (size={size}) -> {run_dir}")
        print(f"{'=' * 60}")

        # Data loaders - source trees stay immutable; manifest membership is
        # the only authority for train/validation/held-out inclusion.
        train_ds = ManifestDataset(
            manifest["splits"]["train"],
            class_to_idx,
            get_transforms(args.imgsz, is_train=True),
        )
        val_ds = ManifestDataset(
            manifest["splits"]["validation"],
            class_to_idx,
            get_transforms(args.imgsz, is_train=False),
        )
        print(f"Classes ({len(classes)}): {classes}")
        print(
            f"Train: {len(train_ds)}, Val: {len(val_ds)}, Held-out: {len(heldout_ds)}"
        )

        loader_generator = torch.Generator().manual_seed(run_seed)
        train_loader = DataLoader(
            train_ds,
            batch_size=args.batch,
            shuffle=True,
            num_workers=args.workers,
            pin_memory=False,
            multiprocessing_context=mp_ctx,
            # New workers each epoch receive seeds from the checkpointed
            # generator. Persistent workers have opaque RNG state and make an
            # interrupted run impossible to reproduce exactly.
            persistent_workers=False,
            generator=loader_generator,
        )
        val_loader = DataLoader(
            val_ds,
            batch_size=args.batch,
            shuffle=False,
            num_workers=args.workers,
            pin_memory=False,
            multiprocessing_context=mp_ctx,
            persistent_workers=False,
        )

        # Model
        # A resume checkpoint completely replaces model parameters. Avoid
        # making resume depend on a pretrained-weight cache or network fetch.
        model = timm.create_model(
            model_name,
            pretrained=resume_path is None,
            num_classes=NUM_CLASSES,
        )
        model = model.to(device)
        print(f"Params: {sum(p.numel() for p in model.parameters()):,}")

        # Training setup
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=args.epochs
        )

        # Resume from checkpoint
        start_epoch = 1
        best_acc = -1.0
        patience_counter = 0
        history = []
        best_checkpoint_path = None
        best_artifact_name = None
        best_state_digest = None

        if resume_path is not None:
            print(f"Resuming from {resume_path}")
            ck = torch.load(resume_path, map_location="cpu", weights_only=False)
            validate_resume_checkpoint(
                ck,
                size,
                manifest["manifest_sha256"],
                run_config,
            )
            model.load_state_dict(ck["state_dict"])
            model = model.to(device)
            optimizer.load_state_dict(ck["optimizer_state_dict"])
            scheduler.load_state_dict(ck["scheduler_state_dict"])
            start_epoch = ck["epoch"] + 1
            best_acc = ck["best_val_acc"]
            patience_counter = ck["patience_counter"]
            history = ck["history"]
            best_artifact_name = ck["best_checkpoint_name"]
            best_state_digest = ck["best_state_dict_sha256"]
            source_best_path = resume_path.parent / best_artifact_name
            if not source_best_path.is_file():
                raise FileNotFoundError(
                    "Resume checkpoint requires its immutable matching "
                    f"best checkpoint: {source_best_path}"
                )
            best_checkpoint = torch.load(
                source_best_path,
                map_location="cpu",
                weights_only=False,
            )
            validate_best_checkpoint(
                best_checkpoint,
                ck,
                size,
                manifest["manifest_sha256"],
                run_config,
            )
            best_checkpoint_path = weights_dir / best_artifact_name
            if source_best_path.resolve() != best_checkpoint_path.resolve():
                _save_checkpoint(best_checkpoint, best_checkpoint_path)
            _save_checkpoint(
                best_checkpoint,
                weights_dir / "best.pth.tar",
            )
            _restore_rng_state(ck["rng_state"], loader_generator)
            print(
                f"Resuming from epoch {start_epoch}, best_acc={best_acc:.4f}, "
                f"lr={optimizer.param_groups[0]['lr']:.6f}"
            )

        last_checkpoint = None
        for epoch in range(start_epoch, args.epochs + 1):
            t0 = time.time()
            train_loss, train_acc = train_one_epoch(
                model, train_loader, criterion, optimizer, device
            )
            val_loss, val_acc = evaluate(model, val_loader, criterion, device)
            scheduler.step()
            elapsed = time.time() - t0

            lr = optimizer.param_groups[0]["lr"]
            print(
                f"  [{epoch:02d}/{args.epochs}] "
                f"train_loss={train_loss:.4f} train_acc={train_acc:.4f}  "
                f"val_loss={val_loss:.4f} val_acc={val_acc:.4f}  "
                f"lr={lr:.6f}  {elapsed:.1f}s"
            )

            history.append(
                {
                    "epoch": epoch,
                    "train_loss": train_loss,
                    "train_acc": train_acc,
                    "val_loss": val_loss,
                    "val_acc": val_acc,
                    "lr": lr,
                }
            )

            improved = val_acc > best_acc
            if improved:
                best_acc = val_acc
                patience_counter = 0
            else:
                patience_counter += 1

            current_state = model.state_dict()
            current_state_digest = state_dict_sha256(current_state)
            if improved:
                best_state_digest = current_state_digest
                best_artifact_name = best_checkpoint_name(
                    epoch,
                    best_state_digest,
                )
            if best_state_digest is None or best_artifact_name is None:
                raise RuntimeError("Training has no selected best state")
            last_checkpoint = build_checkpoint(
                size=size,
                manifest_sha256=manifest["manifest_sha256"],
                run_config=run_config,
                state_dict=current_state,
                optimizer_state_dict=optimizer.state_dict(),
                scheduler_state_dict=scheduler.state_dict(),
                patience_counter=patience_counter,
                history=history,
                val_acc=val_acc,
                best_val_acc=best_acc,
                epoch=epoch,
                rng_state=_capture_rng_state(loader_generator),
                best_state_dict_sha256=best_state_digest,
                best_checkpoint_name=best_artifact_name,
            )
            best_checkpoint_path = publish_epoch_checkpoints(
                last_checkpoint,
                weights_dir,
                improved=improved,
                save_checkpoint=_save_checkpoint,
            )
            if improved:
                print(f"    -> new best: {val_acc:.4f}")
            if not improved and patience_counter >= args.patience:
                print(
                    f"    -> early stopping (no improvement for {args.patience} epochs)"
                )
                break

        # Save last weights
        if last_checkpoint is None:
            raise RuntimeError("Training produced no checkpoint")
        if best_checkpoint_path is None:
            raise RuntimeError("Training produced no best checkpoint")

        atomic_write_json(run_dir / "results.json", history)

        results[size] = {
            "best_val_acc": best_acc,
            "checkpoint": str(best_checkpoint_path),
        }
        print(f"\n{model_name} (size={size}): best val_acc = {best_acc:.4f}\n")

    selected_size = evaluate_heldout_selected_winner(
        results,
        heldout_loader,
        lambda size: timm.create_model(
            SIZES[size], pretrained=False, num_classes=NUM_CLASSES
        ),
        nn.CrossEntropyLoss(),
        device,
        defer_heldout=args.defer_heldout,
    )
    selected = results[selected_size]
    if args.defer_heldout:
        print(
            f"Selected size by validation only: {selected_size}; "
            "held-out evaluation deferred for checkpoint review"
        )
    else:
        heldout_accuracy = (
            selected["heldout_acc"] if selected["heldout_acc"] is not None else "n/a"
        )
        print(
            f"Selected size by validation only: {selected_size}; "
            "held-out evaluated once after selection: "
            f"{heldout_accuracy}"
        )

    # Summary
    print(f"\n{'=' * 60}")
    print(
        f"{'Size':>6s}  {'Model':>20s}  {'Best Val Acc':>12s}  "
        f"{'Held-out Acc':>12s}  {'Weights'}"
    )
    print(f"{'-' * 60}")
    for size in sizes:
        if size in results:
            model_name = SIZES[size]
            result = results[size]
            weights = result["checkpoint"]
            heldout = result.get("heldout_acc")
            print(
                f"{size:>6s}  {model_name:>20s}  "
                f"{result['best_val_acc']:12.4f}  "
                f"{heldout if heldout is not None else 'n/a':>12}  {weights}"
            )
    print()


if __name__ == "__main__":
    main()
