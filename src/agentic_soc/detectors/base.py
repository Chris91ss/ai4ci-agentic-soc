"""Shared detector machinery: scores, calibration, thresholds, explanations and artifacts."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import numpy as np

from agentic_soc.features import FEATURES, FeatureRow


@dataclass(slots=True)
class Score:
    detector: str
    kind: str
    score: float
    threshold: float
    top_features: list[dict[str, Any]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    summary: str = ""

    @property
    def alert(self) -> bool:
        return self.score >= self.threshold

    @property
    def severity(self) -> str:
        if not self.alert:
            return "low"
        margin = (self.score - self.threshold) / max(1e-9, 1.0 - self.threshold)
        if margin < 0.5:
            return "medium"
        if margin < 0.9:
            return "high"
        return "critical"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "kind": self.kind,
            "score": self.score,
            "threshold": self.threshold,
            "alert": self.alert,
            "severity": self.severity,
            "top_features": self.top_features,
            "techniques": self.techniques,
            "summary": self.summary,
        }


class TailCalibrator:
    """Raw anomaly score -> [0, 1]: empirical CDF of benign training scores, with an
    exponential tail beyond the training maximum so that extreme windows stay rankable."""

    def __init__(self, quantiles: np.ndarray, n: int, scale: float) -> None:
        self.quantiles = np.asarray(quantiles, dtype=float)
        self.n = int(n)
        self.scale = float(scale)

    @classmethod
    def fit(cls, raw: np.ndarray, grid: int = 2001) -> TailCalibrator:
        raw = np.asarray(raw, dtype=float)
        quantiles = np.quantile(raw, np.linspace(0, 1, grid))
        top = raw[raw >= np.quantile(raw, 0.99)]
        scale = float(np.std(top)) or float(np.std(raw)) or 1.0
        return cls(quantiles, len(raw), scale)

    def __call__(self, raw: np.ndarray) -> np.ndarray:
        raw = np.asarray(raw, dtype=float)
        grid = np.linspace(0, 1, len(self.quantiles))
        # np.interp needs increasing x; ties in the quantiles are fine but we de-duplicate
        xs, idx = np.unique(self.quantiles, return_index=True)
        cdf = np.interp(raw, xs, grid[idx]) * (self.n / (self.n + 1))
        top = xs[-1]
        beyond = raw > top
        if beyond.any():
            cdf[beyond] = 1.0 - np.exp(-(raw[beyond] - top) / self.scale) / (self.n + 1)
        return cdf

    def to_json(self) -> dict[str, Any]:
        return {"quantiles": self.quantiles.tolist(), "n": self.n, "scale": self.scale}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> TailCalibrator:
        return cls(np.asarray(data["quantiles"]), data["n"], data["scale"])


def threshold_for_fpr(benign_scores: np.ndarray, fpr: float, floor: float = 0.5) -> float:
    """Score threshold whose false-positive rate on benign validation windows is ``fpr``."""
    if len(benign_scores) == 0:
        return max(floor, 1.0 - fpr)
    return float(max(floor, np.quantile(benign_scores, 1.0 - fpr)))


class RobustStats:
    """Per-feature median and spread of benign training data, for explanations."""

    def __init__(self, names: list[str], median: np.ndarray, spread: np.ndarray) -> None:
        self.names = names
        self.median = np.asarray(median, dtype=float)
        self.spread = np.asarray(spread, dtype=float)

    @classmethod
    def fit(cls, names: list[str], X: np.ndarray) -> RobustStats:
        median = np.median(X, axis=0)
        q75, q25 = np.percentile(X, [75, 25], axis=0)
        spread = (q75 - q25) / 1.349
        std = X.std(axis=0)
        spread = np.where(spread > 1e-9, spread, np.where(std > 1e-9, std, 1.0))
        return cls(names, median, spread)

    def explain(self, x: np.ndarray, k: int = 5) -> list[dict[str, Any]]:
        z = (np.asarray(x, dtype=float) - self.median) / self.spread
        order = np.argsort(-np.abs(z))[:k]
        return [
            {
                "name": self.names[i],
                "value": round(float(x[i]), 4),
                "baseline": round(float(self.median[i]), 4),
                "contribution": round(float(abs(z[i])), 3),
                "direction": "higher" if z[i] > 0 else "lower",
            }
            for i in order
            if abs(z[i]) > 0.5
        ]

    def to_json(self) -> dict[str, Any]:
        return {"names": self.names, "median": self.median.tolist(), "spread": self.spread.tolist()}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RobustStats:
        return cls(data["names"], np.asarray(data["median"]), np.asarray(data["spread"]))


def matrix(rows: list[FeatureRow], kind: str) -> np.ndarray:
    names = FEATURES[kind]
    if not rows:
        return np.zeros((0, len(names)))
    return np.array([[row.features[n] for n in names] for row in rows], dtype=float)


def table_matrix(table: Any, kind: str) -> np.ndarray:
    """Feature matrix of a feature table (pyarrow) in the canonical column order."""
    names = FEATURES[kind]
    if table.num_rows == 0:
        return np.zeros((0, len(names)))
    return np.column_stack(
        [table.column(f"f_{n}").to_numpy(zero_copy_only=False) for n in names]
    ).astype(float)


def new_version(prefix: str) -> str:
    return f"{prefix}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"


class Detector:
    """Interface of the three detectors (scores windows of the kinds it handles)."""

    name: ClassVar[str] = ""
    kinds: ClassVar[tuple[str, ...]] = ()

    def __init__(self, version: str, thresholds: dict[str, float], meta: dict[str, Any]) -> None:
        self.version = version
        self.thresholds = thresholds
        self.meta = meta

    def score(self, rows: list[FeatureRow]) -> list[Score]:
        raise NotImplementedError

    def save(self, directory: Path) -> None:
        raise NotImplementedError

    def _write_meta(self, directory: Path, extra: dict[str, Any]) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        meta = (
            {"detector": self.name, "version": self.version, "thresholds": self.thresholds}
            | self.meta
            | extra
        )
        (directory / "meta.json").write_text(json.dumps(meta, indent=1, default=str) + "\n")

    @staticmethod
    def _read_meta(directory: Path) -> dict[str, Any]:
        return json.loads((directory / "meta.json").read_text())


def fmt_bytes(value: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    return f"{value:.1f} {units[i]}"


def expm1(value: float) -> float:
    return math.expm1(value)
