"""Drift monitor: PSI and KS of live M1 feature windows against the training reference.

Windows are kept for a full day so that the time-of-day mix matches the reference; a check
whose shifted features reach the alarm rule on consecutive checks raises an alarm.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from agentic_soc.drift.reference import FeatureReference
from agentic_soc.features import FeatureRow
from agentic_soc.features.extract import FEATURES


@dataclass
class DriftCheck:
    time: datetime
    kind: str
    rows: int
    psi: dict[str, float]
    ks_p: dict[str, float]
    drifted: list[str]
    max_psi: float

    @property
    def shifted(self) -> bool:
        return bool(self.drifted)

    def to_dict(self, top: int = 6) -> dict[str, Any]:
        worst = sorted(self.psi.items(), key=lambda kv: -kv[1])[:top]
        return {
            "time": self.time,
            "kind": self.kind,
            "rows": self.rows,
            "max_psi": round(self.max_psi, 4),
            "drifted": self.drifted,
            "top_psi": {k: round(v, 4) for k, v in worst},
            "ks_p": {k: round(self.ks_p[k], 6) for k, _ in worst},
        }


@dataclass
class DriftConfig:
    window_h: float = 24.0
    min_rows: int = 300
    psi_alarm: float = 0.25  # per feature
    min_features: int = 2  # features beyond psi_alarm for a shifted check
    consecutive: int = 2  # shifted checks in a row for an alarm
    ks_alpha: float = 0.001
    # Calendar and account-age features move with the calendar, not with behaviour (a window
    # of weekdays differs from a reference spanning whole weeks).
    ignore: tuple[str, ...] = ("weekend", "maturity")


@dataclass
class DriftMonitor:
    references: dict[str, FeatureReference]
    cfg: DriftConfig = field(default_factory=DriftConfig)

    def __post_init__(self) -> None:
        self.rows: dict[str, deque[tuple[datetime, np.ndarray]]] = {
            k: deque() for k in self.references
        }
        self.history: list[DriftCheck] = []
        self.streak: dict[str, int] = dict.fromkeys(self.references, 0)
        self.alarm_since: datetime | None = None

    @property
    def alarm(self) -> bool:
        return self.alarm_since is not None

    def reset(self, references: dict[str, FeatureReference] | None = None) -> None:
        """New baseline (after retraining): forget the windows seen against the old one."""
        if references is not None:
            self.references = references
        self.__post_init__()

    def observe(self, rows: list[FeatureRow]) -> None:
        for row in rows:
            buffer = self.rows.get(row.detector)
            if buffer is not None:
                vector = np.array(
                    [row.features[name] for name in FEATURES[row.detector]], dtype=float
                )
                buffer.append((row.window_end, vector))

    def _trim(self, now: datetime) -> None:
        cutoff = now - timedelta(hours=self.cfg.window_h)
        for buffer in self.rows.values():
            while buffer and buffer[0][0] < cutoff:
                buffer.popleft()

    def ready(self, now: datetime) -> bool:
        """A full window of observations exists (otherwise the hour-of-day mix is skewed)."""
        firsts = [b[0][0] for b in self.rows.values() if b]
        return bool(firsts) and now - min(firsts) >= timedelta(hours=self.cfg.window_h * 0.95)

    def check(self, now: datetime) -> list[DriftCheck]:
        self._trim(now)
        out = []
        if not self.ready(now):
            return out
        for kind, reference in self.references.items():
            buffer = self.rows[kind]
            if len(buffer) < self.cfg.min_rows:
                continue
            X = np.vstack([v for _, v in buffer])
            names = reference.features
            keep = np.array([name not in self.cfg.ignore for name in names])
            values = np.where(keep, reference.psi(X), 0.0)
            pvalues = np.where(keep, reference.ks_pvalues(X), 1.0)
            drifted = [names[j] for j in np.argsort(-values) if values[j] > self.cfg.psi_alarm]
            check = DriftCheck(
                now,
                kind,
                len(X),
                dict(zip(names, map(float, values), strict=True)),
                dict(zip(names, map(float, pvalues), strict=True)),
                drifted,
                float(values.max()),
            )
            shifted = len(drifted) >= self.cfg.min_features
            self.streak[kind] = self.streak[kind] + 1 if shifted else 0
            if self.streak[kind] >= self.cfg.consecutive and self.alarm_since is None:
                self.alarm_since = now
            self.history.append(check)
            out.append(check)
        return out
