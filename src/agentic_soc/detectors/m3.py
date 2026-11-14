"""M3: endpoint process-sequence rarity with n-grams over parent->child process pairs.

The model is a bigram language over process launches (parent -> child), weighted by how often
a launch occurs on a *host-day* of the host's peer group (workstations by their owner's role,
servers by role), i.e. a document frequency rather than a per-launch frequency. Bursty but
daily behaviour such as logon trees or Intune scripts is therefore not rare, while a launch no
peer host performs on a normal day is, whatever the volume of other activity:

    P(pair on a host-day | class) = (df(class, pair) + a * P_global(pair)) / (days(class) + a)
    P_global(pair)                = (df(pair) + 0.5) / (days + 1)

The rarity of a launch is its surprisal -log2 P in bits. A host window scores the excess
surprisal of its distinct launches above a floor (launches seen on more than 1/8 of the peer
host-days add nothing), calibrated on benign windows.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any, ClassVar

import numpy as np

from agentic_soc.detectors.base import (
    Detector,
    Score,
    TailCalibrator,
    new_version,
    threshold_for_fpr,
)
from agentic_soc.features import FeatureRow

KIND = "M3"
DEFAULT_FPR = 5e-4
ALPHA = 1.0
FLOOR_BITS = 3.0

TECHNIQUE_HINTS: list[tuple[str, str]] = [
    ("psexesvc.exe", "T1569.002"),
    ("7za.exe", "T1560.001"),
    ("rar.exe", "T1560.001"),
    ("sqlcmd.exe", "T1560.001"),
    ("robocopy.exe", "T1560.001"),
    ("nltest.exe", "T1018"),
    ("net.exe", "T1087.002"),
    ("whoami.exe", "T1087.002"),
    ("powershell.exe", "T1059.001"),
    ("rundll32.exe", "T1218.011"),
]

Pair = tuple[str, str]


class PairRarity:
    def __init__(self) -> None:
        self.days_class: Counter[str] = Counter()
        self.df_class: Counter[tuple[str, str, str]] = Counter()
        self.df: Counter[Pair] = Counter()
        self.days = 0

    def add_host_day(self, host_class: str, pairs: Iterable[Pair]) -> None:
        self.days_class[host_class] += 1
        self.days += 1
        for parent, child in set(pairs):
            self.df_class[(host_class, parent, child)] += 1
            self.df[(parent, child)] += 1

    def add_counts(
        self, days_by_class: dict[str, int], df_rows: Iterable[tuple[str, str, str, int]]
    ) -> None:
        """Pre-aggregated host-day counts: (class, parent, child, host-days with the launch)."""
        for host_class, n in days_by_class.items():
            self.days_class[host_class] += n
            self.days += n
        for host_class, parent, child, n in df_rows:
            self.df_class[(host_class, parent, child)] += n
            self.df[(parent, child)] += n

    def probability(self, host_class: str, parent: str, child: str) -> float:
        p_global = (self.df[(parent, child)] + 0.5) / (self.days + 1)
        p = (self.df_class[(host_class, parent, child)] + ALPHA * p_global) / (
            self.days_class[host_class] + ALPHA
        )
        return min(p, 1.0)

    def rarity(self, host_class: str, parent: str, child: str) -> float:
        return -math.log2(self.probability(host_class, parent, child))

    def to_json(self) -> dict[str, Any]:
        return {
            "days_class": dict(self.days_class),
            "df_class": [[c, p, ch, n] for (c, p, ch), n in self.df_class.items()],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> PairRarity:
        model = cls()
        model.add_counts(data["days_class"], (tuple(r) for r in data["df_class"]))  # type: ignore[misc]
        return model


def window_raw(
    model: PairRarity, host_class: str, pairs: Iterable[Pair]
) -> tuple[float, list[tuple[float, str, str]]]:
    ranked = sorted(
        ((model.rarity(host_class, p, c), p, c) for p, c in {tuple(x) for x in pairs}), reverse=True
    )
    return float(sum(r - FLOOR_BITS for r, _, _ in ranked if r > FLOOR_BITS)), ranked


class M3Detector(Detector):
    name: ClassVar[str] = "M3"
    kinds: ClassVar[tuple[str, ...]] = (KIND,)

    def __init__(
        self,
        model: PairRarity,
        calibrator: TailCalibrator,
        version: str,
        thresholds: dict[str, float],
        meta: dict[str, Any],
    ) -> None:
        super().__init__(version, thresholds, meta)
        self.model = model
        self.calibrator = calibrator

    @classmethod
    def fit(cls, model: PairRarity, benign_windows: list[tuple[str, list[Pair]]]) -> M3Detector:
        raw = (
            np.array([window_raw(model, c, pairs)[0] for c, pairs in benign_windows])
            if benign_windows
            else np.zeros(1)
        )
        meta = {
            "host_days": model.days,
            "distinct_pairs": len(model.df),
            "host_classes": len(model.days_class),
            "calibration_windows": len(benign_windows),
        }
        return cls(model, TailCalibrator.fit(raw), new_version("m3"), {KIND: 0.999}, meta)

    def window_scores(self, windows: list[tuple[str, list[Pair]]]) -> np.ndarray:
        if not windows:
            return np.zeros(0)
        return self.calibrator(
            np.array([window_raw(self.model, c, pairs)[0] for c, pairs in windows])
        )

    def calibrate(
        self, benign_windows: list[tuple[str, list[Pair]]], fpr: float = DEFAULT_FPR
    ) -> dict[str, float]:
        self.thresholds[KIND] = threshold_for_fpr(self.window_scores(benign_windows), fpr)
        self.meta["threshold_fpr"] = fpr
        return self.thresholds

    def score(self, rows: list[FeatureRow]) -> list[Score]:
        out = []
        for row in rows:
            if row.detector != KIND:
                continue
            host_class = row.context.get("host_class", "unknown")
            raw, ranked = window_raw(self.model, host_class, row.context.get("pairs", []))
            score = Score(
                self.name, KIND, float(self.calibrator(np.array([raw]))[0]), self.thresholds[KIND]
            )
            score.top_features = [
                {
                    "name": f"{parent} -> {child}",
                    "value": round(r, 2),
                    "contribution": round(max(0.0, r - FLOOR_BITS), 2),
                    "peer_host_days": self.model.df_class[(host_class, parent, child)],
                    "all_host_days": self.model.df[(parent, child)],
                }
                for r, parent, child in ranked[:5]
            ]
            if score.alert:
                score.techniques, score.summary = self.describe(row, ranked)
            out.append(score)
        return out

    def describe(
        self, row: FeatureRow, ranked: list[tuple[float, str, str]]
    ) -> tuple[list[str], str]:
        host = row.hosts[0] if row.hosts else row.key
        host_class = row.context.get("host_class", "unknown")
        rare = [x for x in ranked if x[0] > FLOOR_BITS][:4] or ranked[:2]
        names = {c for _, _, c in rare} | {p for _, p, _ in rare}
        techniques = list(dict.fromkeys(t for name, t in TECHNIQUE_HINTS if name in names))
        if row.features.get("encoded_cmds", 0) > 0 and "T1059.001" not in techniques:
            techniques.append("T1059.001")
        days = self.model.days_class[host_class]
        launches = "; ".join(
            f"{p} -> {c} (on {self.model.df_class[(host_class, p, c)]}/{days} peer host-days)"
            for _, p, c in rare
        )
        users = ", ".join(row.users) if row.users else "SYSTEM"
        return techniques or [
            "T1059.001"
        ], f"Rare process launches on {host} ({host_class}) by {users}: {launches}"

    def save(self, directory: Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "pairs.json").write_text(json.dumps(self.model.to_json()))
        self._write_meta(directory, {"calibrator": self.calibrator.to_json()})

    @classmethod
    def load(cls, directory: Path) -> M3Detector:
        directory = Path(directory)
        meta = cls._read_meta(directory)
        model = PairRarity.from_json(json.loads((directory / "pairs.json").read_text()))
        calibrator = TailCalibrator.from_json(meta.pop("calibrator"))
        version, thresholds = meta.pop("version"), meta.pop("thresholds")
        meta.pop("detector", None)
        return cls(model, calibrator, version, thresholds, meta)
