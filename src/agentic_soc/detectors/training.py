"""Training of the detectors from the time-split feature tables built by ``soc etl build``."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc

from agentic_soc.detectors.base import table_matrix
from agentic_soc.detectors.m1 import M1Detector
from agentic_soc.etl.training import load_features
from agentic_soc.features import Profiles


def load_splits(features_root: Path) -> dict[str, Any]:
    return json.loads((Path(features_root) / "splits.json").read_text())


def benign(table: pa.Table) -> pa.Table:
    return table.filter(pc.invert(table.column("label")))


def after(table: pa.Table, when: datetime) -> pa.Table:
    return table.filter(
        pc.greater_equal(
            table.column("window_start"), pa.scalar(when, pa.timestamp("us", tz="UTC"))
        )
    )


def labels_of(table: pa.Table) -> np.ndarray:
    return np.asarray(table.column("label").to_pylist(), dtype=bool)


def train_m1(features_root: Path, seed: int = 0) -> tuple[M1Detector, dict[str, Any]]:
    """Forests on benign history (scored against early baselines, no leakage) plus benign
    training weeks; thresholds at the target FPR on the validation week."""
    root = Path(features_root)
    splits = load_splits(root)
    split = datetime.fromisoformat(splits["profile_split"])
    train: dict[str, np.ndarray] = {}
    validation: dict[str, np.ndarray] = {}
    report: dict[str, Any] = {"train_rows": {}, "validation": {}}
    for kind in M1Detector.kinds:
        history = after(load_features(root, splits["history"], kind), split)
        weeks = benign(load_features(root, splits["train"], kind))
        train[kind] = np.vstack([table_matrix(history, kind), table_matrix(weeks, kind)])
        report["train_rows"][kind] = len(train[kind])
    detector = M1Detector.fit(train, Profiles.load(root / "profiles.json"), seed=seed)
    for kind in M1Detector.kinds:
        table = load_features(root, splits["validation"], kind)
        validation[kind] = table_matrix(benign(table), kind)
        y = labels_of(table)
        scores = detector.raw_scores(kind, table_matrix(table, kind))
        report["validation"][kind] = {
            "rows": len(y),
            "positives": int(y.sum()),
            "scores": scores,
            "labels": y,
        }
    detector.calibrate(validation)
    for kind, info in report["validation"].items():
        scores, y = info.pop("scores"), info.pop("labels")
        alerts = scores >= detector.thresholds[kind]
        info["threshold"] = detector.thresholds[kind]
        info["false_positives"] = int((alerts & ~y).sum())
        info["true_positives"] = int((alerts & y).sum())
    detector.meta["validation"] = report["validation"]
    return detector, report
