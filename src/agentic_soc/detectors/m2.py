"""M2: network-flow classifier (LightGBM) over conversation windows.

Supervised on labelled weeks of the simulated company. Beacon-periodicity features (interval
regularity and persistence over the last hour), volume asymmetry, destination rarity and the
source's fan-out let it separate C2 beacons, bulk uploads, sweeps and lateral SMB/RDP from
their benign look-alikes (EDR cloud sync, heartbeats, backups, developer deployments).
Per-row explanations are LightGBM's SHAP contributions.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, ClassVar

import lightgbm as lgb
import numpy as np

from agentic_soc.detectors.base import (
    Detector,
    Score,
    fmt_bytes,
    matrix,
    new_version,
    threshold_for_fpr,
)
from agentic_soc.features import FEATURES, FeatureRow

KIND = "M2"
DEFAULT_FPR = 2e-4
PARAMS: dict[str, Any] = {
    "objective": "binary",
    "learning_rate": 0.03,
    "num_leaves": 31,
    "min_child_samples": 50,
    "feature_fraction": 0.85,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    "verbose": -1,
    "num_threads": 0,
}


class M2Detector(Detector):
    name: ClassVar[str] = "M2"
    kinds: ClassVar[tuple[str, ...]] = (KIND,)

    def __init__(
        self, booster: lgb.Booster, version: str, thresholds: dict[str, float], meta: dict[str, Any]
    ) -> None:
        super().__init__(version, thresholds, meta)
        self.booster = booster

    @classmethod
    def fit(
        cls,
        X: np.ndarray,
        y: np.ndarray,
        X_val: np.ndarray | None = None,
        y_val: np.ndarray | None = None,
        seed: int = 0,
        rounds: int = 500,
        pos_weight: float = 20.0,
    ) -> M2Detector:
        """Fixed number of rounds; the validation week is only monitored (average precision)."""
        positives = max(1, int(y.sum()))
        params = PARAMS | {
            "seed": seed,
            "scale_pos_weight": pos_weight,
            "metric": "average_precision",
        }
        names = FEATURES[KIND]
        train = lgb.Dataset(X, label=y.astype(int), feature_name=names, free_raw_data=False)
        valid_sets, history = [], {}
        callbacks = [lgb.log_evaluation(0), lgb.record_evaluation(history)]
        if X_val is not None and y_val is not None and y_val.sum() > 0:
            valid_sets = [lgb.Dataset(X_val, label=y_val.astype(int), reference=train)]
        booster = lgb.train(
            params, train, num_boost_round=rounds, valid_sets=valid_sets, callbacks=callbacks
        )
        curve = next(iter(history.values()), {}).get("average_precision", [])
        importance = dict(
            zip(names, booster.feature_importance("gain").round(1).tolist(), strict=True)
        )
        meta = {
            "training_rows": len(y),
            "training_positives": positives,
            "rounds": rounds,
            "validation_ap_curve": [round(v, 4) for v in curve[::50]],
            "feature_importance": dict(sorted(importance.items(), key=lambda kv: -kv[1])[:15]),
            "seed": seed,
        }
        return cls(booster, new_version("m2"), {KIND: 0.5}, meta)

    def raw_scores(self, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.zeros(0)
        return self.booster.predict(X, num_iteration=self.booster.best_iteration or None)

    def calibrate(self, benign: np.ndarray, fpr: float = DEFAULT_FPR) -> dict[str, float]:
        self.thresholds[KIND] = threshold_for_fpr(self.raw_scores(benign), fpr, floor=0.5)
        self.meta["threshold_fpr"] = fpr
        return self.thresholds

    def explain(self, X: np.ndarray, k: int = 5) -> list[list[dict[str, Any]]]:
        contrib = self.booster.predict(
            X, pred_contrib=True, num_iteration=self.booster.best_iteration or None
        )
        names = FEATURES[KIND]
        out = []
        for i in range(len(X)):
            values = contrib[i, :-1]
            order = np.argsort(-values)[:k]
            out.append(
                [
                    {
                        "name": names[j],
                        "value": round(float(X[i, j]), 4),
                        "contribution": round(float(values[j]), 3),
                    }
                    for j in order
                    if values[j] > 0
                ]
            )
        return out

    def score(self, rows: list[FeatureRow]) -> list[Score]:
        rows = [r for r in rows if r.detector == KIND]
        if not rows:
            return []
        X = matrix(rows, KIND)
        probabilities = self.raw_scores(X)
        threshold = self.thresholds[KIND]
        alerting = [i for i, p in enumerate(probabilities) if p >= threshold]
        explanations = (
            dict(zip(alerting, self.explain(X[alerting]), strict=True)) if alerting else {}
        )
        scores = []
        for i, row in enumerate(rows):
            score = Score(
                self.name, KIND, float(probabilities[i]), threshold, explanations.get(i, [])
            )
            if score.alert:
                score.techniques, score.summary = self.describe(row)
            scores.append(score)
        return scores

    @staticmethod
    def describe(row: FeatureRow) -> tuple[list[str], str]:
        f, ctx = row.features, row.context
        src_ip, dst_ip, port = row.key.split("|")
        src = f"{ctx.get('src_host') or src_ip}"
        dst = f"{dst_ip}:{port}" + (f" ({ctx['dst_org']})" if ctx.get("dst_org") else "")
        out_bytes = math.expm1(f["log_bytes_out"])
        if f["dir_outbound"] and f["hist_regularity"] >= 0.6 and f["hist_n"] >= 6:
            interval = math.expm1(f["hist_interval_log"])
            return (
                ["T1071.001", "T1573"] if f["port_web"] else ["T1071.001"],
                f"Regular beacon from {src} to {dst}: {int(f['hist_n'])} connections in the last hour, "
                f"median interval {interval:.0f}s, CV {f['hist_interval_cv']:.2f}",
            )
        if f["dir_outbound"] and out_bytes >= 5e7:
            return (
                ["T1041"],
                f"Large upload from {src} to {dst}: {fmt_bytes(out_bytes)} in {int(f['n_flows'])} flows",
            )
        if f["src_distinct_dsts"] >= 20 and f["src_small_share"] >= 0.3:
            return (
                ["T1018"],
                f"Network sweep from {src}: {int(f['src_distinct_dsts'])} destinations, "
                f"{int(f['src_distinct_ports'])} ports, {f['src_small_share']:.0%} tiny flows",
            )
        if f["dir_inbound"]:
            return (
                ["T1133"],
                f"Repeated inbound connections from {src} to {dst}: {int(f['n_flows'])} flows, "
                f"{f['src_distinct_dsts']:.0f} internal targets",
            )
        if f["dir_internal"] and (f["port_smb"] or f["port_rpc"]):
            return (
                ["T1021.002"],
                f"Unusual SMB/RPC session from {src} to {dst}: {fmt_bytes(out_bytes)} sent",
            )
        if f["dir_internal"] and f["port_rdp"]:
            return (["T1021.001"], f"Unusual RDP session from {src} to {dst}")
        return (
            ["T1071.001"],
            f"Suspicious connection from {src} to {dst}: {int(f['n_flows'])} flows, {fmt_bytes(out_bytes)} sent",
        )

    def save(self, directory: Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(directory / "model.txt"))
        self._write_meta(directory, {})

    @classmethod
    def load(cls, directory: Path) -> M2Detector:
        directory = Path(directory)
        meta = cls._read_meta(directory)
        booster = lgb.Booster(model_file=str(directory / "model.txt"))
        version, thresholds = meta.pop("version"), meta.pop("thresholds")
        meta.pop("detector", None)
        return cls(booster, version, thresholds, meta)
