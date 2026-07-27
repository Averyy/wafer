import ast
import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from training.recaptcha import durable_io
from training.recaptcha.durable_io import atomic_write, atomic_write_json
from training.recaptcha.training_contract import (
    CHECKPOINT_REQUIRED_KEYS,
    RNG_STATE_KEYS,
    best_checkpoint_name,
    build_checkpoint,
    publish_epoch_checkpoints,
    size_seed,
    state_dict_sha256,
    validate_best_checkpoint,
    validate_resume_checkpoint,
    validate_training_request,
)

MANIFEST_SHA256 = "a" * 64
RUN_CONFIG = {
    "batch": 64,
    "epochs": 10,
    "imgsz": 224,
    "lr": 0.001,
    "patience": 3,
    "seed": 7,
    "workers": 2,
}
RNG_STATE = {
    "python": ("python",),
    "numpy": ("numpy",),
    "torch_cpu": "torch-cpu",
    "torch_mps": "torch-mps",
    "loader_generator": "loader",
}


def _checkpoint(history=None):
    history = history or [
        {"epoch": 1, "val_acc": 0.8},
        {"epoch": 2, "val_acc": 0.7},
    ]
    history_metrics = [item["val_acc"] for item in history]
    best_val_acc = max(history_metrics)
    best_epoch_index = history_metrics.index(best_val_acc)
    best_state = {"model": b"best-state"}
    current_state = (
        best_state
        if best_epoch_index == len(history) - 1
        else {"model": b"current-state"}
    )
    best_digest = state_dict_sha256(best_state)
    return build_checkpoint(
        size="s",
        manifest_sha256=MANIFEST_SHA256,
        run_config=RUN_CONFIG,
        state_dict=current_state,
        optimizer_state_dict={"optimizer": "state"},
        scheduler_state_dict={"scheduler": "state"},
        patience_counter=len(history) - best_epoch_index - 1,
        history=history,
        val_acc=history_metrics[-1],
        best_val_acc=best_val_acc,
        epoch=len(history),
        rng_state=RNG_STATE,
        best_state_dict_sha256=best_digest,
        best_checkpoint_name=best_checkpoint_name(
            best_epoch_index + 1,
            best_digest,
        ),
    )


@pytest.fixture
def trainer():
    pytest.importorskip("timm")
    pytest.importorskip("torch")
    pytest.importorskip("torchvision")
    from training.recaptcha import train_mps

    return train_mps


def test_heldout_is_loaded_from_selected_checkpoint_once(monkeypatch, trainer):
    checkpoint = {"state_dict": {"weight": "selected-on-validation"}}
    model = MagicMock()
    evaluate = MagicMock(return_value=(0.25, 0.75))
    monkeypatch.setattr(trainer.torch, "load", MagicMock(return_value=checkpoint))
    monkeypatch.setattr(trainer, "evaluate", evaluate)

    result = trainer.evaluate_selected_checkpoint(
        model, "best.pth.tar", "heldout-loader", "criterion", "mps"
    )

    assert result == (0.25, 0.75)
    model.load_state_dict.assert_called_once_with(checkpoint["state_dict"])
    evaluate.assert_called_once_with(
        model.to.return_value, "heldout-loader", "criterion", "mps"
    )


def test_epoch_history_contract_has_no_heldout_metrics(trainer):
    source = trainer.Path(trainer.__file__).read_text()

    loop_start = source.index("for epoch in range")
    last_weights = source.index("# Save last weights")
    epoch_loop = source[loop_start:last_weights]
    assert "heldout_loader" not in epoch_loop
    assert "heldout_acc" not in epoch_loop
    assert source.rindex("evaluate_heldout_selected_winner") > last_weights


def test_validation_winner_is_deterministic_and_heldout_is_evaluated_once(
    monkeypatch, trainer
):
    results = {
        "x": {"best_val_acc": 0.9, "checkpoint": "x-best"},
        "s": {"best_val_acc": 0.9, "checkpoint": "s-best"},
    }
    evaluate_selected = MagicMock(return_value=(0.1, 0.8))
    model_factory = MagicMock(return_value=MagicMock())
    monkeypatch.setattr(trainer, "evaluate_selected_checkpoint", evaluate_selected)

    selected = trainer.evaluate_heldout_selected_winner(
        results, "heldout", model_factory, "criterion", "mps"
    )

    assert selected == "s"
    model_factory.assert_called_once_with("s")
    evaluate_selected.assert_called_once_with(
        model_factory.return_value, "s-best", "heldout", "criterion", "mps"
    )
    assert results["s"]["heldout_acc"] == 0.8
    assert "heldout_acc" not in results["x"]


def test_validation_winner_can_freeze_without_touching_heldout(
    monkeypatch,
    trainer,
):
    results = {
        "x": {"best_val_acc": 0.8, "checkpoint": "x-best"},
        "s": {"best_val_acc": 0.9, "checkpoint": "s-best"},
    }
    evaluate_selected = MagicMock()
    model_factory = MagicMock()
    monkeypatch.setattr(trainer, "evaluate_selected_checkpoint", evaluate_selected)

    selected = trainer.evaluate_heldout_selected_winner(
        results,
        object(),
        model_factory,
        "criterion",
        "mps",
        defer_heldout=True,
    )

    assert selected == "s"
    assert results["s"]["heldout_loss"] is None
    assert results["s"]["heldout_acc"] is None
    model_factory.assert_not_called()
    evaluate_selected.assert_not_called()


def test_cpu_interrupted_resume_matches_uninterrupted_training_exactly(trainer):
    """CPU proves pipeline/RNG continuity; MPS kernel determinism is not assumed."""

    torch = trainer.torch
    config = dict(RUN_CONFIG, batch=4, epochs=3, imgsz=2, workers=0)
    manifest_sha256 = MANIFEST_SHA256
    run_seed = size_seed(config["seed"], "s")
    inputs = torch.arange(48, dtype=torch.float32).reshape(12, 4) / 10
    labels = torch.tensor([0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2])

    def initialize():
        trainer.random.seed(run_seed)
        trainer.np.random.seed(run_seed % (2**32))
        torch.manual_seed(run_seed)
        model = torch.nn.Sequential(
            torch.nn.Linear(4, 8),
            torch.nn.ReLU(),
            torch.nn.Dropout(p=0.25),
            torch.nn.Linear(8, 3),
        )
        optimizer = torch.optim.AdamW(model.parameters(), lr=0.01)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer,
            T_max=config["epochs"],
        )
        generator = torch.Generator().manual_seed(run_seed)
        return model, optimizer, scheduler, generator

    def train_epoch(model, optimizer, scheduler, generator):
        dataset = torch.utils.data.TensorDataset(inputs, labels)
        loader = torch.utils.data.DataLoader(
            dataset,
            batch_size=config["batch"],
            shuffle=True,
            num_workers=0,
            generator=generator,
        )
        model.train()
        for batch_inputs, batch_labels in loader:
            # Exercise every restored CPU-side training RNG, not just the
            # sampler generator and torch's dropout stream.
            jitter = trainer.random.random() + float(trainer.np.random.random())
            batch_inputs = batch_inputs + jitter / 100
            optimizer.zero_grad()
            loss = torch.nn.functional.cross_entropy(
                model(batch_inputs),
                batch_labels,
            )
            loss.backward()
            optimizer.step()
        scheduler.step()

    uninterrupted = initialize()
    for _epoch in range(1, 4):
        train_epoch(*uninterrupted)

    interrupted = initialize()
    history = []
    for epoch in range(1, 3):
        train_epoch(*interrupted)
        history.append({"epoch": epoch, "val_acc": 0.5 + epoch / 10})
    model, optimizer, scheduler, generator = interrupted
    selected_digest = state_dict_sha256(model.state_dict())
    rng_state = {
        "python": trainer.random.getstate(),
        "numpy": trainer.np.random.get_state(),
        "torch_cpu": torch.get_rng_state(),
        "torch_mps": b"not-used-by-cpu-contract-test",
        "loader_generator": generator.get_state(),
    }
    checkpoint = build_checkpoint(
        size="s",
        manifest_sha256=manifest_sha256,
        run_config=config,
        state_dict=model.state_dict(),
        optimizer_state_dict=optimizer.state_dict(),
        scheduler_state_dict=scheduler.state_dict(),
        patience_counter=0,
        history=history,
        val_acc=0.7,
        best_val_acc=0.7,
        epoch=2,
        rng_state=rng_state,
        best_state_dict_sha256=selected_digest,
        best_checkpoint_name=best_checkpoint_name(2, selected_digest),
    )
    serialized = io.BytesIO()
    torch.save(checkpoint, serialized)
    serialized.seek(0)
    checkpoint = torch.load(
        serialized,
        map_location="cpu",
        weights_only=False,
    )

    resumed = initialize()
    model, optimizer, scheduler, generator = resumed
    model.load_state_dict(checkpoint["state_dict"])
    optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
    scheduler.load_state_dict(checkpoint["scheduler_state_dict"])
    trainer.random.setstate(checkpoint["rng_state"]["python"])
    trainer.np.random.set_state(checkpoint["rng_state"]["numpy"])
    torch.set_rng_state(checkpoint["rng_state"]["torch_cpu"])
    generator.set_state(checkpoint["rng_state"]["loader_generator"])
    train_epoch(*resumed)

    uninterrupted_model, uninterrupted_optimizer, uninterrupted_scheduler, _ = (
        uninterrupted
    )
    assert state_dict_sha256(model.state_dict()) == state_dict_sha256(
        uninterrupted_model.state_dict()
    )
    assert scheduler.state_dict() == uninterrupted_scheduler.state_dict()
    for parameter, uninterrupted_parameter in zip(
        model.parameters(),
        uninterrupted_model.parameters(),
        strict=True,
    ):
        assert torch.equal(parameter, uninterrupted_parameter)
    for resumed_state, uninterrupted_state in zip(
        optimizer.state_dict()["state"].values(),
        uninterrupted_optimizer.state_dict()["state"].values(),
        strict=True,
    ):
        assert resumed_state.keys() == uninterrupted_state.keys()
        for key in resumed_state:
            assert torch.equal(resumed_state[key], uninterrupted_state[key])


def test_state_digest_supports_scalar_buffers_and_real_efficientnet(trainer):
    torch = trainer.torch
    scalar_digest = state_dict_sha256({"counter": torch.tensor(0)})
    assert len(scalar_digest) == 64

    model = trainer.timm.create_model(
        "efficientnet_b0",
        pretrained=False,
        num_classes=14,
    )
    scalar_buffers = [value for value in model.state_dict().values() if value.ndim == 0]
    assert scalar_buffers
    assert state_dict_sha256(model.state_dict()) == state_dict_sha256(
        model.state_dict()
    )


@pytest.mark.parametrize(
    ("resume", "expected_pretrained"),
    [(False, True), (True, False)],
)
def test_model_construction_uses_pretraining_only_for_fresh_runs(
    trainer,
    tmp_path,
    monkeypatch,
    resume,
    expected_pretrained,
):
    from training.recaptcha.classes import CLS_NAMES

    class ConstructionReached(RuntimeError):
        pass

    checkpoint_path = tmp_path / "source" / "last.pth.tar"
    args = [
        "train_mps.py",
        "--sizes",
        "s",
        "--data",
        str(tmp_path / "unused-data"),
        "--manifest",
        str(tmp_path / "manifest.json"),
        "--run-root",
        str(tmp_path / "runs"),
        "--workers",
        "0",
    ]
    if resume:
        checkpoint_path.parent.mkdir()
        checkpoint_path.write_bytes(b"checkpoint")
        args.extend(["--resume", str(checkpoint_path)])

    record = {"path": str(tmp_path / "unused.jpg"), "label": CLS_NAMES[0]}
    manifest = {
        "classes": list(CLS_NAMES),
        "manifest_sha256": MANIFEST_SHA256,
        "splits": {
            "train": [record],
            "validation": [record],
            "heldout": [],
        },
        "excluded_duplicates": [],
    }
    create_model = MagicMock(side_effect=ConstructionReached)
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.setattr(trainer, "build_manifest", MagicMock(return_value=manifest))
    monkeypatch.setattr(trainer, "write_manifest", MagicMock())
    monkeypatch.setattr(trainer, "_seed_size_run", MagicMock())
    monkeypatch.setattr(trainer.torch.backends.mps, "is_available", lambda: True)
    monkeypatch.setattr(
        trainer.torch,
        "use_deterministic_algorithms",
        MagicMock(),
    )
    monkeypatch.setattr(trainer.timm, "create_model", create_model)

    with pytest.raises(ConstructionReached):
        trainer.main()

    create_model.assert_called_once_with(
        "efficientnet_b0",
        pretrained=expected_pretrained,
        num_classes=14,
    )


def test_class_contract_requires_exact_production_index_order(trainer):
    from training.recaptcha.classes import CLS_NAMES

    trainer.validate_class_contract(CLS_NAMES)
    with pytest.raises(ValueError, match="index order"):
        trainer.validate_class_contract(tuple(reversed(CLS_NAMES)))


def test_training_labels_match_runtime_classifier_order():
    from training.recaptcha.classes import CLS_NAMES, NUM_CLASSES
    from wafer.browser._recaptcha_grid import _CLS_NAMES

    assert CLS_NAMES == tuple(_CLS_NAMES[:NUM_CLASSES])
    assert _CLS_NAMES[NUM_CLASSES:] == ["Boat", "Parking Meter"]


def test_trainer_source_compiles_without_optional_training_dependencies():
    path = Path("training/recaptcha/train_mps.py")
    source = path.read_text()

    ast.parse(source, filename=str(path))
    compile(source, str(path), "exec")


def test_checkpoint_contains_every_state_needed_for_exact_resume():
    checkpoint = _checkpoint()

    assert set(checkpoint) == CHECKPOINT_REQUIRED_KEYS
    assert set(checkpoint["rng_state"]) == RNG_STATE_KEYS
    assert checkpoint["optimizer_state_dict"] == {"optimizer": "state"}
    assert checkpoint["scheduler_state_dict"] == {"scheduler": "state"}
    assert checkpoint["patience_counter"] == 1
    assert checkpoint["history"][-1] == {"epoch": 2, "val_acc": 0.7}
    assert checkpoint["val_acc"] == 0.7
    assert checkpoint["best_val_acc"] == 0.8
    validate_resume_checkpoint(
        checkpoint,
        "s",
        MANIFEST_SHA256,
        RUN_CONFIG,
    )


def test_state_digest_rejects_non_string_keys_and_best_name_scales_past_9999():
    with pytest.raises(RuntimeError, match="keys must be strings"):
        state_dict_sha256({"valid": b"value", 1: b"invalid"})

    digest = "f" * 64
    assert best_checkpoint_name(10_000, digest) == (
        "best-epoch-10000-ffffffffffffffff.pth.tar"
    )


@pytest.mark.parametrize("missing", sorted(CHECKPOINT_REQUIRED_KEYS))
def test_resume_rejects_every_missing_checkpoint_field(missing):
    checkpoint = _checkpoint()
    checkpoint.pop(missing)

    with pytest.raises(RuntimeError, match="missing required state"):
        validate_resume_checkpoint(
            checkpoint,
            "s",
            MANIFEST_SHA256,
            RUN_CONFIG,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda checkpoint: checkpoint.update(model_name="efficientnet_b1"),
            "architecture",
        ),
        (lambda checkpoint: checkpoint.update(best_val_acc=0.7), "best_val_acc"),
        (lambda checkpoint: checkpoint.update(val_acc=0.6), "val_acc"),
        (lambda checkpoint: checkpoint.update(patience_counter=0), "patience counter"),
        (
            lambda checkpoint: checkpoint["history"].append(
                {"epoch": 4, "val_acc": 0.6}
            ),
            "epoch history",
        ),
        (
            lambda checkpoint: checkpoint["rng_state"].pop("torch_mps"),
            "RNG state",
        ),
    ],
)
def test_resume_rejects_internally_inconsistent_state(mutation, message):
    checkpoint = _checkpoint()
    mutation(checkpoint)

    with pytest.raises(RuntimeError, match=message):
        validate_resume_checkpoint(
            checkpoint,
            "s",
            MANIFEST_SHA256,
            RUN_CONFIG,
        )


def test_resume_restores_best_accuracy_not_last_epoch_accuracy():
    checkpoint = _checkpoint()

    assert checkpoint["best_val_acc"] == 0.8
    assert checkpoint["val_acc"] == 0.7


def test_resume_checkpoint_requires_matching_best_model_artifact():
    resume = _checkpoint()
    best = _checkpoint([{"epoch": 1, "val_acc": 0.8}])

    validate_best_checkpoint(
        best,
        resume,
        "s",
        MANIFEST_SHA256,
        RUN_CONFIG,
    )

    best["state_dict"] = {"model": b"state-only-substitution"}
    with pytest.raises(RuntimeError, match="state_dict digest"):
        validate_best_checkpoint(
            best,
            resume,
            "s",
            MANIFEST_SHA256,
            RUN_CONFIG,
        )


def test_completed_or_early_stopped_checkpoint_cannot_resume():
    completed = _checkpoint()
    completed["run_config"] = dict(RUN_CONFIG, epochs=2)
    with pytest.raises(RuntimeError, match="completed configured epochs"):
        validate_resume_checkpoint(
            completed,
            "s",
            MANIFEST_SHA256,
            dict(RUN_CONFIG, epochs=2),
        )

    stopped = _checkpoint(
        [
            {"epoch": 1, "val_acc": 0.8},
            {"epoch": 2, "val_acc": 0.7},
            {"epoch": 3, "val_acc": 0.6},
            {"epoch": 4, "val_acc": 0.5},
        ]
    )
    with pytest.raises(RuntimeError, match="early stopping"):
        validate_resume_checkpoint(
            stopped,
            "s",
            MANIFEST_SHA256,
            RUN_CONFIG,
        )


def test_epoch_publication_is_transactional_and_last_is_immediately_current(tmp_path):
    first = _checkpoint([{"epoch": 1, "val_acc": 0.8}])
    second = _checkpoint(
        [
            {"epoch": 1, "val_acc": 0.8},
            {"epoch": 2, "val_acc": 0.7},
        ]
    )
    published = {}
    order = []

    def save(checkpoint, path):
        order.append(Path(path).name)
        published[Path(path)] = checkpoint

    selected = publish_epoch_checkpoints(
        first,
        tmp_path,
        improved=True,
        save_checkpoint=save,
    )
    assert order == [
        first["best_checkpoint_name"],
        "best.pth.tar",
        "last.pth.tar",
    ]
    assert published[tmp_path / "last.pth.tar"]["epoch"] == 1
    assert selected == tmp_path / first["best_checkpoint_name"]

    # A non-best epoch durably advances only ``last``. If the process is
    # interrupted immediately afterward, exact optimizer/scheduler/RNG/history
    # state for epoch 2 is already the published resume point.
    order.clear()
    publish_epoch_checkpoints(
        second,
        tmp_path,
        improved=False,
        save_checkpoint=save,
    )
    assert order == ["last.pth.tar"]
    resumed = published[tmp_path / "last.pth.tar"]
    assert resumed["epoch"] == 2
    assert resumed["optimizer_state_dict"] == second["optimizer_state_dict"]
    assert resumed["scheduler_state_dict"] == second["scheduler_state_dict"]
    assert resumed["rng_state"] == second["rng_state"]
    assert resumed["history"] == second["history"]
    validate_resume_checkpoint(
        resumed,
        "s",
        MANIFEST_SHA256,
        RUN_CONFIG,
    )


def test_durable_write_survives_interruption_and_uses_unique_tempfiles(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"old")

    def interrupted(handle):
        handle.write(b"partial-new")
        raise RuntimeError("interrupted")

    with pytest.raises(RuntimeError, match="interrupted"):
        atomic_write(target, interrupted)
    assert target.read_bytes() == b"old"
    assert list(tmp_path.glob(".artifact.bin.*.tmp")) == []

    sources = []
    real_replace = os.replace

    def replace(source, destination):
        sources.append(Path(source).name)
        real_replace(source, destination)

    monkeypatch.setattr(durable_io.os, "replace", replace)
    atomic_write(target, lambda handle: handle.write(b"first"))
    atomic_write(target, lambda handle: handle.write(b"second"))

    assert target.read_bytes() == b"second"
    assert len(set(sources)) == 2
    assert all(name != ".artifact.bin.tmp" for name in sources)


def test_durable_write_fsyncs_file_and_directory_and_json_is_complete(
    tmp_path,
    monkeypatch,
):
    fsync_calls = []
    monkeypatch.setattr(
        durable_io.os,
        "fsync",
        lambda descriptor: fsync_calls.append(descriptor),
    )
    output = tmp_path / "results.json"

    atomic_write_json(output, [{"epoch": 1, "val_acc": 0.8}])

    assert json.loads(output.read_text()) == [{"epoch": 1, "val_acc": 0.8}]
    assert len(fsync_calls) == 2
    assert list(tmp_path.glob(".results.json.*.tmp")) == []


def test_resume_path_is_explicit_existing_and_single_size(tmp_path):
    checkpoint = tmp_path / "last.pth.tar"
    checkpoint.write_bytes(b"checkpoint")

    assert validate_training_request(["s"], checkpoint) == (
        ("s",),
        checkpoint,
    )
    with pytest.raises(ValueError, match="exactly one"):
        validate_training_request(["s", "x"], checkpoint)
    with pytest.raises(FileNotFoundError, match="does not exist"):
        validate_training_request(["s"], tmp_path / "missing.pth.tar")


@pytest.mark.parametrize(
    "sizes",
    [
        [],
        [""],
        ["s", ""],
        ["s", "s"],
        ["unknown"],
    ],
)
def test_invalid_size_selection_fails_before_training(sizes):
    with pytest.raises(ValueError):
        validate_training_request(sizes, None)


def test_per_size_seed_and_trainer_wiring_are_order_independent():
    assert size_seed(7, "s") == size_seed(7, "s")
    assert size_seed(7, "s") != size_seed(7, "x")

    source = Path("training/recaptcha/train_mps.py").read_text()
    assert "run_seed = size_seed(args.seed, size)" in source
    assert "_seed_size_run(run_seed)" in source
    assert "torch.use_deterministic_algorithms(True)" in source
    assert "torch.Generator().manual_seed(run_seed)" in source
    assert "pretrained=resume_path is None" in source
    assert "persistent_workers=False" in source
    assert 'best_acc = ck["best_val_acc"]' in source
    assert '_restore_rng_state(ck["rng_state"], loader_generator)' in source
    assert "optimizer_state_dict=optimizer.state_dict()" in source
    assert "scheduler_state_dict=scheduler.state_dict()" in source
    assert "rng_state=_capture_rng_state(loader_generator)" in source
    assert "publish_epoch_checkpoints(" in source
    assert "validate_best_checkpoint(" in source


def test_export_rejects_checkpoint_architecture_or_class_contract_mismatch():
    pytest.importorskip("onnxruntime")
    pytest.importorskip("timm")
    pytest.importorskip("torch")
    from training.recaptcha.classes import CLS_NAMES, NUM_CLASSES
    from training.recaptcha.export import validate_checkpoint_contract

    checkpoint = {
        "model_name": "efficientnet_b0",
        "num_classes": NUM_CLASSES,
        "classes": list(CLS_NAMES),
    }
    validate_checkpoint_contract(checkpoint, "s")
    with pytest.raises(ValueError, match="architecture"):
        validate_checkpoint_contract(checkpoint, "x")
