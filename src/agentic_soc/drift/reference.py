"""Reference distributions of detector features and the drift statistics against them.

The population stability index (PSI) compares binned proportions: bins are the deciles of the
reference, plus an "above the reference" bin for features the reference saw as constant. A PSI
above 0.1 is usually read as a moderate shift and above 0.25 as a significant one. The
two-sample Kolmogorov-Smirnov test complements it on a sample of the reference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy.stats import ks_2samp

EPS = 1e-4


def _bin(edges: np.ndarray, values: np.ndarray) -> np.ndarray:
    counts = np.bincount(np.searchsorted(edges, values, side="right"), minlength=len(edges) + 1)
    return counts / max(1, len(values))


def psi(expected: np.ndarray, actual: np.ndarray) -> float:
    e = np.maximum(expected, EPS)
    a = np.maximum(actual, EPS)
    return float(np.sum((a - e) * np.log(a / e)))


@dataclass
class FeatureReference:
    features: list[str]
    edges: list[np.ndarray]
    props: list[np.ndarray]
    sample: np.ndarray  # rows of the reference, for KS tests
    rows: int

    @classmethod
    def fit(
        cls, features: list[str], X: np.ndarray, sample: int = 600, seed: int = 0
    ) -> FeatureReference:
        X = np.asarray(X, dtype=float)
        edges, props = [], []
        for j in range(X.shape[1]):
            column = X[:, j]
            cut = (
                np.unique(np.quantile(column, np.linspace(0.1, 0.9, 9)))
                if len(column)
                else np.zeros(0)
            )
            if len(cut) <= 1:  # (nearly) constant: one bin for the value, one above it
                top = float(column.max()) if len(column) else 0.0
                cut = np.array([np.nextafter(top, np.inf)])
            edges.append(cut)
            props.append(_bin(cut, column))
        rng = np.random.default_rng(seed)
        keep = rng.choice(len(X), size=min(sample, len(X)), replace=False) if len(X) else []
        return cls(list(features), edges, props, X[np.sort(keep)] if len(X) else X, len(X))

    def psi(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        return np.array(
            [psi(self.props[j], _bin(self.edges[j], X[:, j])) for j in range(len(self.features))]
        )

    def ks_pvalues(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        out = np.ones(len(self.features))
        if len(self.sample) < 20 or len(X) < 20:
            return out
        for j in range(len(self.features)):
            a, b = self.sample[:, j], X[:, j]
            if np.ptp(a) == 0 and np.ptp(b) == 0 and a[0] == b[0]:
                continue
            out[j] = float(ks_2samp(a, b).pvalue)
        return out

    def to_json(self) -> dict[str, Any]:
        return {
            "features": self.features,
            "edges": [e.tolist() for e in self.edges],
            "props": [p.tolist() for p in self.props],
            "sample": np.round(self.sample, 5).tolist(),
            "rows": self.rows,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> FeatureReference:
        return cls(
            list(data["features"]),
            [np.asarray(e, dtype=float) for e in data["edges"]],
            [np.asarray(p, dtype=float) for p in data["props"]],
            np.asarray(data["sample"], dtype=float).reshape(-1, len(data["features"])),
            int(data["rows"]),
        )
