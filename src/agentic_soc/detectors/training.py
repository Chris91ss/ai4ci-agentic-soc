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


def train_m2(
    features_root: Path, seed: int = 0, fpr: float | None = None
) -> tuple[Any, dict[str, Any]]:
    """LightGBM on the labelled training weeks, early stopping and thresholds on validation."""
    from agentic_soc.detectors.m2 import DEFAULT_FPR, KIND, M2Detector

    root = Path(features_root)
    splits = load_splits(root)
    train = load_features(root, splits["train"], KIND)
    validation = load_features(root, splits["validation"], KIND)
    X, y = table_matrix(train, KIND), labels_of(train)
    X_val, y_val = table_matrix(validation, KIND), labels_of(validation)
    detector = M2Detector.fit(X, y, X_val, y_val, seed=seed)
    detector.calibrate(X_val[~y_val], fpr or DEFAULT_FPR)
    scores = detector.raw_scores(X_val)
    alerts = scores >= detector.thresholds[KIND]
    report = {
        "train_rows": len(y),
        "train_positives": int(y.sum()),
        "validation": {
            "rows": len(y_val),
            "positives": int(y_val.sum()),
            "threshold": detector.thresholds[KIND],
            "true_positives": int((alerts & y_val).sum()),
            "false_positives": int((alerts & ~y_val).sum()),
        },
    }
    detector.meta["validation"] = report["validation"]
    return detector, report


def _m3_windows(table: pa.Table) -> list[tuple[str, list[tuple[str, str]]]]:
    windows = []
    for context in table.column("context").to_pylist():
        data = json.loads(context) if context else {}
        windows.append(
            (data.get("host_class", "unknown"), [tuple(p) for p in data.get("pairs", [])])
        )
    return windows


def train_m3(
    features_root: Path, lake_root: Path, fpr: float | None = None
) -> tuple[Any, dict[str, Any]]:
    """Host-day launch frequencies from the benign history in the lake; calibration on benign
    windows of the training weeks; thresholds on the validation week."""
    from collections import Counter

    from agentic_soc.detectors.m3 import DEFAULT_FPR, KIND, M3Detector, PairRarity
    from agentic_soc.etl import duck
    from agentic_soc.etl.lake import Lake
    from agentic_soc.features.extract import host_class_of

    root = Path(features_root)
    splits = load_splits(root)
    history = splits["history"][0]
    inventory = Lake(lake_root).inventory(history)
    classes = {host_id: host_class_of(inventory, host_id) for host_id in inventory.hosts}
    con = duck.connect(lake_root)
    host_days = duck.rows(
        con,
        "SELECT host_id, count(DISTINCT CAST(event_time AS DATE)) AS n FROM process "
        "WHERE run = ? AND host_id IS NOT NULL GROUP BY ALL",
        [history],
    )
    launches = duck.rows(
        con,
        "SELECT host_id, parent_name, process_name, count(DISTINCT CAST(event_time AS DATE)) AS n "
        "FROM process WHERE run = ? AND host_id IS NOT NULL GROUP BY ALL",
        [history],
    )
    con.close()
    days_by_class: Counter[str] = Counter()
    for row in host_days:
        days_by_class[classes.get(row["host_id"], "unknown")] += int(row["n"])
    df: Counter[tuple[str, str, str]] = Counter()
    for row in launches:
        df[(classes.get(row["host_id"], "unknown"), row["parent_name"], row["process_name"])] += (
            int(row["n"])
        )
    model = PairRarity()
    model.add_counts(dict(days_by_class), ((c, p, ch, n) for (c, p, ch), n in df.items()))
    train = benign(load_features(root, splits["train"], KIND))
    detector = M3Detector.fit(model, _m3_windows(train))
    validation = load_features(root, splits["validation"], KIND)
    y_val = labels_of(validation)
    detector.calibrate(_m3_windows(benign(validation)), fpr or DEFAULT_FPR)
    scores = detector.window_scores(_m3_windows(validation))
    alerts = scores >= detector.thresholds[KIND]
    report = {
        "host_days": model.days,
        "validation": {
            "rows": len(y_val),
            "positives": int(y_val.sum()),
            "threshold": detector.thresholds[KIND],
            "true_positives": int((alerts & y_val).sum()),
            "false_positives": int((alerts & ~y_val).sum()),
        },
    }
    detector.meta["validation"] = report["validation"]
    return detector, report
