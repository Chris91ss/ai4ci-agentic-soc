"""Model-level evaluation of M1-M3 on the time-ordered test weeks (TESSERACT-style splits).

For each detector kind: PR-AUC, ROC-AUC, recall at 1% FPR and at the operating threshold, false
positives per day, recall per attack stage, and detection delay (from the start of each attack
stage in the run's ground truth to the end of the first alerting window that covers it).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from agentic_soc.detectors.base import table_matrix
from agentic_soc.detectors.registry import ModelRegistry
from agentic_soc.detectors.training import _m3_windows, labels_of, load_splits
from agentic_soc.etl.lake import Lake
from agentic_soc.etl.training import load_features
from agentic_soc.evaluation.metrics import parse_time

KINDS = ("M1-user", "M1-ip", "M2", "M3")


def _scores(detectors: Any, kind: str, table: Any) -> np.ndarray:
    if kind.startswith("M1"):
        return detectors.detectors["M1"].raw_scores(kind, table_matrix(table, kind))
    if kind == "M2":
        return detectors.detectors["M2"].raw_scores(table_matrix(table, kind))
    return detectors.detectors["M3"].window_scores(_m3_windows(table))


def evaluate_models(features_root: Path, models_root: Path, lake_root: Path) -> dict[str, Any]:
    root = Path(features_root)
    splits = load_splits(root)
    detectors = ModelRegistry(models_root).load_set()
    thresholds = detectors.thresholds()
    lake = Lake(lake_root)
    truths = {
        run: json.loads((lake.meta(run) / "truth.json").read_text()) for run in splits["test"]
    }
    hours = sum(
        (parse_time(t["run"]["end"]) - parse_time(t["run"]["start"])).total_seconds() / 3600  # type: ignore[operator]
        for t in truths.values()
    )
    days = max(hours, 1.0) / 24
    out: dict[str, Any] = {"test_runs": splits["test"], "test_days": round(days, 2), "kinds": {}}
    for kind in KINDS:
        table = load_features(root, splits["test"], kind)
        y = labels_of(table)
        scores = _scores(detectors, kind, table)
        threshold = thresholds[kind]
        negatives = scores[~y]
        cut = float(np.quantile(negatives, 0.99)) if len(negatives) else 1.0
        alerts = scores >= threshold
        row: dict[str, Any] = {
            "rows": len(y),
            "positives": int(y.sum()),
            "pr_auc": round(float(average_precision_score(y, scores)), 4) if y.any() else None,
            "roc_auc": round(float(roc_auc_score(y, scores)), 4)
            if y.any() and (~y).any()
            else None,
            "recall_at_1pct_fpr": round(float((scores[y] >= cut).mean()), 4) if y.any() else None,
            "threshold": round(float(threshold), 5),
            "recall_at_threshold": round(float(alerts[y].mean()), 4) if y.any() else None,
            "fpr_at_threshold": round(float(alerts[~y].mean()), 6) if (~y).any() else None,
            "false_positives_per_day": round(float((alerts & ~y).sum()) / days, 2),
            "precision_at_threshold": round(float((alerts & y).sum() / max(1, alerts.sum())), 4),
        }
        stages = table.column("stage").to_pylist()
        runs = table.column("run").to_pylist()
        ends = table.column("window_end").to_pylist()
        row["recall_by_stage"] = {
            stage: round(float(alerts[np.array([s == stage for s in stages])].mean()), 3)
            for stage in sorted({s for s in stages if s})
        }
        delays: dict[str, list[float]] = {}
        for run, truth in truths.items():
            stage_times = truth["campaign"].get("stage_times", {})
            for stage, started in stage_times.items():
                begun = parse_time(started)
                hits = [
                    parse_time(ends[i]) for i in np.where(alerts)[0]
                    if runs[i] == run and stages[i] == stage
                ]  # fmt: skip
                if hits and begun is not None:
                    first = min(hits)
                    delays.setdefault(stage, []).append(
                        round((first - begun).total_seconds() / 60, 1)
                    )
        row["detection_delay_min"] = {stage: values for stage, values in sorted(delays.items())}
        out["kinds"][kind] = row
    return out
