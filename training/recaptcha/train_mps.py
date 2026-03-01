"""Train EfficientNet on MPS (Apple Silicon GPU) with checkpoint resume support."""

import argparse
import json
import time
from pathlib import Path

import timm
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torchvision import datasets, transforms

SIZES = {
    "s": "efficientnet_b0",
    "x": "efficientnet_b1",
}

NUM_CLASSES = 14
LOG_INTERVAL = 50  # log every N batches


def get_transforms(img_size, is_train):
    if is_train:
        return transforms.Compose([
            transforms.RandomResizedCrop(img_size, scale=(0.8, 1.0)),
            transforms.RandomHorizontalFlip(),
            transforms.ColorJitter(brightness=0.2, contrast=0.2, saturation=0.2),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                                 std=[0.229, 0.224, 0.225]),
        ])
    return transforms.Compose([
        transforms.Resize(int(img_size * 1.14)),
        transforms.CenterCrop(img_size),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406],
                             std=[0.229, 0.224, 0.225]),
    ])


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
            print(f"    batch {batch_idx + 1}/{num_batches}  "
                  f"loss={loss.item():.4f}  acc={acc:.4f}", flush=True)
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="s,x", help="Comma-separated sizes: s,x")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--imgsz", type=int, default=224)
    parser.add_argument("--batch", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--data", default="datasets/wafer_cls_classic")
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--resume", default=None,
                        help="Resume from checkpoint (path to .pth.tar)")
    parser.add_argument("--workers", type=int, default=2,
                        help="DataLoader workers (uses spawn context for MPS safety)")
    args = parser.parse_args()

    if not torch.backends.mps.is_available():
        raise RuntimeError("MPS not available - this script requires Apple Silicon GPU")

    device = torch.device("mps")
    sizes = [s.strip() for s in args.sizes.split(",")]
    data = Path(args.data)

    if not (data / "train").exists():
        raise FileNotFoundError(f"Dataset not found at {data}. Run download_dataset.py first.")

    print(f"Device: {device}")
    print(f"Sizes: {sizes}")
    print(f"Epochs: {args.epochs}, imgsz: {args.imgsz}, batch: {args.batch}, lr: {args.lr}")
    print(f"Workers: {args.workers} (spawn)")
    print()

    results = {}

    for size in sizes:
        if size not in SIZES:
            print(f"Unknown size '{size}', available: {list(SIZES.keys())}")
            continue

        model_name = SIZES[size]
        run_dir = Path(f"runs/cls_{size}")
        run_dir.mkdir(parents=True, exist_ok=True)
        weights_dir = run_dir / "weights"
        weights_dir.mkdir(exist_ok=True)

        print(f"{'=' * 60}")
        print(f"Training {model_name} (size={size}) -> {run_dir}")
        print(f"{'=' * 60}")

        # Data loaders - spawn context avoids fork+MPS deadlocks
        train_ds = datasets.ImageFolder(
            str(data / "train"), transform=get_transforms(args.imgsz, is_train=True))
        val_ds = datasets.ImageFolder(
            str(data / "val"), transform=get_transforms(args.imgsz, is_train=False))

        print(f"Classes ({len(train_ds.classes)}): {train_ds.classes}")
        print(f"Train: {len(train_ds)}, Val: {len(val_ds)}")

        mp_ctx = torch.multiprocessing.get_context("spawn") if args.workers > 0 else None
        train_loader = DataLoader(train_ds, batch_size=args.batch, shuffle=True,
                                  num_workers=args.workers, pin_memory=False,
                                  multiprocessing_context=mp_ctx,
                                  persistent_workers=args.workers > 0)
        val_loader = DataLoader(val_ds, batch_size=args.batch, shuffle=False,
                                num_workers=args.workers, pin_memory=False,
                                multiprocessing_context=mp_ctx,
                                persistent_workers=args.workers > 0)

        # Model
        model = timm.create_model(model_name, pretrained=True, num_classes=NUM_CLASSES)
        model = model.to(device)
        print(f"Params: {sum(p.numel() for p in model.parameters()):,}")

        # Training setup
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)

        # Resume from checkpoint
        start_epoch = 1
        best_acc = 0.0
        patience_counter = 0
        history = []

        resume_path = args.resume
        if resume_path is None:
            # Auto-detect: check if a best checkpoint exists for this size
            auto = weights_dir / "best.pth.tar"
            if auto.exists():
                resume_path = str(auto)

        if resume_path and Path(resume_path).exists():
            print(f"Resuming from {resume_path}")
            ck = torch.load(resume_path, map_location="cpu", weights_only=False)
            model.load_state_dict(ck["state_dict"])
            model = model.to(device)
            start_epoch = ck["epoch"] + 1
            best_acc = ck.get("val_acc", 0.0)
            # Advance scheduler to correct position
            for _ in range(start_epoch - 1):
                scheduler.step()
            # Load existing history if available
            hist_path = run_dir / "results.json"
            if hist_path.exists():
                history = json.loads(hist_path.read_text())
            print(f"Resuming from epoch {start_epoch}, best_acc={best_acc:.4f}, "
                  f"lr={optimizer.param_groups[0]['lr']:.6f}")

        for epoch in range(start_epoch, args.epochs + 1):
            t0 = time.time()
            train_loss, train_acc = train_one_epoch(model, train_loader, criterion,
                                                    optimizer, device)
            val_loss, val_acc = evaluate(model, val_loader, criterion, device)
            scheduler.step()
            elapsed = time.time() - t0

            lr = optimizer.param_groups[0]["lr"]
            print(f"  [{epoch:02d}/{args.epochs}] "
                  f"train_loss={train_loss:.4f} train_acc={train_acc:.4f}  "
                  f"val_loss={val_loss:.4f} val_acc={val_acc:.4f}  "
                  f"lr={lr:.6f}  {elapsed:.1f}s")

            history.append({
                "epoch": epoch, "train_loss": train_loss, "train_acc": train_acc,
                "val_loss": val_loss, "val_acc": val_acc, "lr": lr,
            })

            if val_acc > best_acc:
                best_acc = val_acc
                patience_counter = 0
                torch.save({
                    "model_name": model_name,
                    "num_classes": NUM_CLASSES,
                    "state_dict": model.state_dict(),
                    "val_acc": val_acc,
                    "epoch": epoch,
                }, weights_dir / "best.pth.tar")
                print(f"    -> new best: {val_acc:.4f}")
            else:
                patience_counter += 1
                if patience_counter >= args.patience:
                    print(f"    -> early stopping (no improvement for {args.patience} epochs)")
                    break

        # Save last weights
        torch.save({
            "model_name": model_name,
            "num_classes": NUM_CLASSES,
            "state_dict": model.state_dict(),
            "val_acc": val_acc,
            "epoch": epoch,
        }, weights_dir / "last.pth.tar")

        with open(run_dir / "results.json", "w") as f:
            json.dump(history, f, indent=2)

        results[size] = best_acc
        print(f"\n{model_name} (size={size}): best val_acc = {best_acc:.4f}\n")

    # Summary
    print(f"\n{'=' * 60}")
    print(f"{'Size':>6s}  {'Model':>20s}  {'Best Val Acc':>12s}  {'Weights'}")
    print(f"{'-' * 60}")
    for size in sizes:
        if size in results:
            model_name = SIZES[size]
            weights = f"runs/cls_{size}/weights/best.pth.tar"
            print(f"{size:>6s}  {model_name:>20s}  {results[size]:12.4f}  {weights}")
    print()


if __name__ == "__main__":
    main()
