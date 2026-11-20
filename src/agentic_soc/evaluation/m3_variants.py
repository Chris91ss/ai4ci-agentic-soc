"""M3 ablation: would the window features of M3's rows improve its launch rarity score?

The promoted M3 scores a host window only by the rarity of its parent->child launches. Its feature
rows also carry nine window features that the score ignores (launches, distinct pairs, longest
command line, encoded commands, LOLBins, integrity, SYSTEM and admin shares, users). Each variant
below adds information in one way. Its weight is chosen on the validation week, the threshold is set
at M3's false positive rate on the benign validation windows, and the result is reported on the
test weeks. A variant should replace M3 only if it is better on the validation week.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score

from agentic_soc.detectors.base import table_matrix
from agentic_soc.detectors.m3 import DEFAULT_FPR, FLOOR_BITS, window_raw
from agentic_soc.detectors.registry import ModelRegistry
from agentic_soc.detectors.training import _m3_windows, labels_of, load_splits
from agentic_soc.etl import duck
from agentic_soc.etl.training import load_features
from agentic_soc.features.extract import FEATURES

ENCODED = FEATURES["M3"].index("encoded_cmds")
LOLBINS = FEATURES["M3"].index("lolbins")


@dataclass
class Split:
    raw: np.ndarray  # the promoted score: excess launch surprisal in bits
    X: np.ndarray
    y: np.ndarray
    classes: list[str]
    hosts: list[str]
    windows: list[tuple[str, list[tuple[str, str]]]]


def _load(root: Path, runs: list[str], model: Any) -> Split:
    table = load_features(root, runs, "M3")
    windows = _m3_windows(table)
    return Split(
        raw=np.array([window_raw(model, c, pairs)[0] for c, pairs in windows]),
        X=table_matrix(table, "M3"),
        y=labels_of(table),
        classes=[c for c, _ in windows],
        hosts=[h[0] if h else "" for h in table.column("hosts").to_pylist()],
        windows=windows,
    )


def _excess(bits: np.ndarray) -> np.ndarray:
    return np.maximum(bits - FLOOR_BITS, 0.0)


def _indicator_bits(train: Split, column: int) -> Callable[[Split], np.ndarray]:
    """Surprisal of a window having the indicator at all, per host class (benign windows)."""
    benign = ~train.y
    present = train.X[:, column] > 0
    prior = (present[benign].sum() + 0.5) / (benign.sum() + 1)
    classes = np.array(train.classes)
    bits = {
        c: -math.log2((present[benign & (classes == c)].sum() + prior) / ((benign & (classes == c)).sum() + 1))
        for c in set(train.classes)
    }  # fmt: skip

    def score(split: Split) -> np.ndarray:
        b = np.array([bits.get(c, -math.log2(prior)) for c in split.classes])
        return np.where(split.X[:, column] > 0, b, 0.0)

    return score


def _forest_bits(train: Split) -> Callable[[Split], np.ndarray]:
    """Tail probability of an isolation forest's anomaly score among benign windows, in bits."""
    forest = IsolationForest(n_estimators=200, random_state=0, n_jobs=1).fit(train.X[~train.y])
    reference = np.sort(-forest.score_samples(train.X[~train.y]))

    def score(split: Split) -> np.ndarray:
        above = len(reference) - np.searchsorted(reference, -forest.score_samples(split.X))
        return -np.log2((above + 1) / (len(reference) + 1))

    return score


def _per_host(lake_root: Path, history: str, model: Any) -> Callable[[Split, float], np.ndarray]:
    """Launch rarity on the host itself, with its peer group's probability as the prior."""
    con = duck.connect(lake_root)
    days = {
        r["host_id"]: int(r["n"])
        for r in duck.rows(con, "SELECT host_id, count(DISTINCT CAST(event_time AS DATE)) AS n FROM process "
                                "WHERE run = ? AND host_id IS NOT NULL GROUP BY ALL", [history])
    }  # fmt: skip
    seen: Counter[tuple[str, str, str]] = Counter()
    for r in duck.rows(con, "SELECT host_id, parent_name, process_name, count(DISTINCT CAST(event_time AS DATE)) "
                            "AS n FROM process WHERE run = ? AND host_id IS NOT NULL GROUP BY ALL", [history]):  # fmt: skip
        seen[(r["host_id"], r["parent_name"], r["process_name"])] += int(r["n"])
    con.close()

    def score(split: Split, beta: float) -> np.ndarray:
        out = np.zeros(len(split.y))
        for i, (host, (cls, pairs)) in enumerate(zip(split.hosts, split.windows, strict=True)):
            for parent, child in {tuple(p) for p in pairs}:
                prior = model.probability(cls, parent, child)
                p = (seen[(host, parent, child)] + beta * prior) / (days.get(host, 0) + beta)
                out[i] += max(0.0, -math.log2(min(p, 1.0)) - FLOOR_BITS)
        return out

    return score


def _metrics(scores: np.ndarray, y: np.ndarray, threshold: float, days: float) -> dict[str, Any]:
    alerts = scores >= threshold
    return {
        "pr_auc": round(float(average_precision_score(y, scores)), 4),
        "recall_at_threshold": round(float(alerts[y].mean()), 4),
        "false_positives_per_day": round(float((alerts & ~y).sum()) / days, 2),
        "precision_at_threshold": round(float((alerts & y).sum() / max(1, alerts.sum())), 4),
    }


def evaluate_m3_variants(
    features_root: Path, models_root: Path, lake_root: Path, test_days: float
) -> dict[str, Any]:
    root = Path(features_root)
    splits = load_splits(root)
    model = ModelRegistry(models_root).load_set().detectors["M3"].model
    train, val, test = (_load(root, splits[s], model) for s in ("train", "validation", "test"))
    encoded, lolbins = _indicator_bits(train, ENCODED), _indicator_bits(train, LOLBINS)
    forest = _forest_bits(train)
    host = _per_host(Path(lake_root), splits["history"][0], model)
    # (name, parameter, values tried on the validation week, score)
    families: list[tuple[str, str, list[float], Callable[[Split, float], np.ndarray]]] = [
        ("Launch rarity (promoted M3)", "", [0.0], lambda s, w: s.raw),
        ("+ encoded commands and LOLBins, in bits", "weight", [0.25, 0.5, 1.0, 2.0],
         lambda s, w: s.raw + w * (_excess(encoded(s)) + _excess(lolbins(s)))),
        ("+ isolation forest on the 9 window features", "weight", [0.25, 0.5, 1.0],
         lambda s, w: s.raw + w * _excess(forest(s))),
        ("Rarity on the host itself, peer group as prior", "prior strength", [1.0, 4.0, 16.0], host),
    ]  # fmt: skip
    variants = []
    for name, parameter, values, fn in families:
        grid = {v: float(average_precision_score(val.y, fn(val, v))) for v in values}
        value = max(values, key=lambda v: (round(grid[v], 4), -v))
        val_scores = fn(val, value)
        threshold = float(np.quantile(val_scores[~val.y], 1 - DEFAULT_FPR))
        variants.append({
            "name": name,
            "parameter": f"{parameter} {value:g}" if parameter else "",
            "validation_pr_auc": round(grid[value], 4),
            "validation_false_positives": int(((val_scores >= threshold) & ~val.y).sum()),
            "test": _metrics(fn(test, value), test.y, threshold, test_days),
        })  # fmt: skip
    return {
        "validation_runs": splits["validation"],
        "test_runs": splits["test"],
        "positives": {"validation": int(val.y.sum()), "test": int(test.y.sum())},
        "variants": variants,
    }
