"""Offline retraining of M1 after drift.

The per-account baselines are refreshed with the recent sign-ins (so new home networks and
working hours stop looking novel), the feature windows of that period are recomputed against
the refreshed baselines, and new forests are fitted and calibrated on them. Events of incidents
judged malicious are left out, so the attack does not become part of "normal".
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from agentic_soc.detectors.base import matrix
from agentic_soc.detectors.m1 import M1Detector
from agentic_soc.features import FeaturePipeline, FeatureRow, WindowConfig
from agentic_soc.ingestion import Inventory, NormSignin
from agentic_soc.ingestion.models import from_row
from agentic_soc.storage import Store


def recent_signins(store: Store, end: datetime, window_h: float) -> list[NormSignin]:
    rows = store.events_between("signin", end - timedelta(hours=window_h), end, by="ingest_time")
    return [from_row(r) for r in rows]  # type: ignore[misc]


def retrain_m1(
    current: M1Detector,
    signins: Iterable[NormSignin],
    inventory: Inventory,
    exclude_event_ids: set[str] | None = None,
    windows: WindowConfig | None = None,
    seed: int = 0,
    calibration_share: float = 0.3,
) -> tuple[M1Detector, dict[str, Any]]:
    exclude = exclude_event_ids or set()
    events = sorted((e for e in signins if e.event_id not in exclude), key=lambda e: e.ingest_time)
    if not events:
        raise ValueError("no sign-ins to retrain on")
    profiles = current.profiles.updated(events)
    pipeline = FeaturePipeline(inventory, profiles, windows, detectors=set(M1Detector.kinds))
    rows: list[FeatureRow] = []
    for i in range(0, len(events), 2000):
        pipeline.add(events[i : i + 2000])
        rows += pipeline.advance().rows()
    rows += pipeline.flush().rows()
    rows = [r for r in rows if not exclude.intersection(r.event_ids)]
    rows.sort(key=lambda r: r.window_end)
    train: dict[str, np.ndarray] = {}
    calibration: dict[str, np.ndarray] = {}
    for kind in M1Detector.kinds:
        kind_rows = [r for r in rows if r.detector == kind]
        if len(kind_rows) < 50:
            raise ValueError(f"too few {kind} windows to retrain on ({len(kind_rows)})")
        split = int(len(kind_rows) * (1 - calibration_share))
        train[kind] = matrix(kind_rows[:split], kind)
        calibration[kind] = matrix(kind_rows[split:], kind)
    detector = M1Detector.fit(train, profiles, seed=seed)
    detector.calibrate(calibration, current.meta.get("threshold_fpr"))
    report = {
        "parent": current.version,
        "version": detector.version,
        "signins": len(events),
        "excluded_events": len(exclude),
        "train_rows": {k: len(v) for k, v in train.items()},
        "calibration_rows": {k: len(v) for k, v in calibration.items()},
        "thresholds": {k: round(v, 5) for k, v in detector.thresholds.items()},
        "accounts": len(profiles.accounts),
    }
    detector.meta["retrained"] = report
    return detector, report
