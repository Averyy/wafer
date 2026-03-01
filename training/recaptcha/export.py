"""Export trained EfficientNet models to ONNX and verify output shapes."""

import argparse
import shutil
from pathlib import Path

import numpy as np
import onnxruntime as ort
import timm
import torch

NUM_CLASSES = 14


def verify_cls(onnx_path: Path):
    """Verify classification ONNX output shapes with batch=1 and batch=9."""
    sess = ort.InferenceSession(str(onnx_path))
    input_name = sess.get_inputs()[0].name

    for batch in (1, 9):
        dummy = np.random.randn(batch, 3, 224, 224).astype(np.float32)
        outputs = sess.run(None, {input_name: dummy})
        shape = outputs[0].shape
        expected = (batch, NUM_CLASSES)
        assert shape == expected, f"cls shape mismatch: got {shape}, expected {expected}"
        print(f"  cls batch={batch}: {shape} OK")


def export_cls(checkpoint_path: Path, size: str, deliver_dir: Path | None):
    """Export a trained EfficientNet classifier to ONNX."""
    print(f"Loading checkpoint: {checkpoint_path}")
    ckpt = torch.load(str(checkpoint_path), map_location="cpu", weights_only=False)

    model_name = ckpt["model_name"]
    num_classes = ckpt["num_classes"]
    val_acc = ckpt.get("val_acc", "unknown")
    print(f"  model={model_name}, num_classes={num_classes}, val_acc={val_acc}")

    model = timm.create_model(model_name, pretrained=False, num_classes=num_classes)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    onnx_path = checkpoint_path.parent / f"wafer_cls_{size}.onnx"
    dummy = torch.randn(1, 3, 224, 224)
    torch.onnx.export(
        model, dummy, str(onnx_path),
        opset_version=17,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={"input": {0: "batch"}, "output": {0: "batch"}},
    )
    print(f"  -> {onnx_path} ({onnx_path.stat().st_size / 1024:.0f} KB)")

    print("Verifying classification ONNX...")
    verify_cls(onnx_path)

    if deliver_dir:
        dest = deliver_dir / f"wafer_cls_{size}.onnx"
        shutil.copy2(onnx_path, dest)
        print(f"  Delivered to: {dest}")

    return onnx_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cls-model", required=True, help="Path to cls best.pth.tar")
    parser.add_argument("--size", default="s", choices=["s", "x"],
                        help="Model size suffix for naming (default: s)")
    parser.add_argument("--deliver", action="store_true",
                        help="Copy ONNX files to wafer/browser/models/")
    args = parser.parse_args()

    cls_pt = Path(args.cls_model)
    if not cls_pt.exists():
        raise FileNotFoundError(f"Classification model not found: {cls_pt}")

    deliver_dir = None
    if args.deliver:
        deliver_dir = Path(__file__).resolve().parent.parent.parent / "wafer" / "browser" / "models"
        deliver_dir.mkdir(parents=True, exist_ok=True)

    export_cls(cls_pt, args.size, deliver_dir)

    print("\nExport complete.")
    if not args.deliver:
        print("Run with --deliver to copy ONNX files to wafer/browser/models/")


if __name__ == "__main__":
    main()
