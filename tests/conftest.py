"""Shared fixtures: a small but complete SOC stack built from one simulated run."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import numpy as np
import pytest

from agentic_soc.actions import ActionManager, PolicyGate
from agentic_soc.correlation import CorrelationEngine
from agentic_soc.detectors import M1Detector, M2Detector, M3Detector
from agentic_soc.detectors.base import matrix
from agentic_soc.detectors.m3 import PairRarity
from agentic_soc.detectors.registry import DetectorSet
from agentic_soc.detectors.service import LocalDetectorClient
from agentic_soc.features import FeaturePipeline, FeatureRow, Profiles
from agentic_soc.features.extract import host_class_of
from agentic_soc.ingestion import IngestionStage, Inventory, NormSignin
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.storage import Store

MINI = {
    "org": {"users": 50},
    "duration_h": 10,
    "campaign": {
        "start_offset_h": 3,
        "start_jitter_h": 0,
        "dwell_scale": 0.35,
        "spray_targets": 30,
    },
}


@dataclass
class MiniSoc:
    sim: Simulator
    inventory: Inventory
    store: Store
    profiles: Profiles
    pipeline: FeaturePipeline
    detectors: DetectorSet
    correlation: CorrelationEngine
    actions: ActionManager
    rows: list[FeatureRow]
    malicious: set[str]
    clock: datetime

    def client(self) -> LocalDetectorClient:
        return LocalDetectorClient(self.detectors)

    def top_incident(self):
        return max(self.correlation.incidents.values(), key=lambda s: s.risk.risk)


def _labels(sim: Simulator) -> set[str]:
    return sim.labels.malicious_ids()


@pytest.fixture(scope="session")
def mini_soc() -> MiniSoc:
    sim = Simulator(load_config(overrides=MINI))
    inventory = Inventory.from_enterprise(sim.ent)
    stage = IngestionStage(inventory)
    store = Store.memory()
    events = []
    for batch in sim.run():
        result = stage.process_batch((d.topic, d.value, d.key, d.deliver_at) for d in batch)
        events += result.events
        store.write_events(result.events)
    malicious = _labels(sim)
    start = sim.campaign.start
    profiles = Profiles.build(
        (e for e in events if isinstance(e, NormSignin) and e.event_time < start),
        inventory.timezone,
    )
    pipeline = FeaturePipeline(inventory, profiles)
    rows: list[FeatureRow] = []
    for i in range(0, len(events), 2000):
        pipeline.add(events[i : i + 2000])
        rows += pipeline.advance().rows()
    rows += pipeline.flush().rows()

    def label(row: FeatureRow) -> bool:
        return any(e in malicious for e in row.event_ids)

    by_kind = {k: [r for r in rows if r.detector == k] for k in ("M1-user", "M1-ip", "M2", "M3")}
    m1 = M1Detector.fit(
        {k: matrix([r for r in by_kind[k] if not label(r)], k) for k in M1Detector.kinds},
        profiles,
        n_estimators=50,
    )
    m1.calibrate(
        {k: matrix([r for r in by_kind[k] if not label(r)], k) for k in M1Detector.kinds},
        {"M1-user": 0.01, "M1-ip": 0.02},
    )
    X2 = matrix(by_kind["M2"], "M2")
    y2 = np.array([label(r) for r in by_kind["M2"]])
    m2 = M2Detector.fit(X2, y2, rounds=60)
    m2.calibrate(X2[~y2], fpr=0.001)
    rarity = PairRarity()
    days: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for e in events:
        if e.stream == "process" and e.host_id and e.event_time < start:
            days.setdefault((e.host_id, e.event_time.date().isoformat()), set()).add(
                (e.parent_name, e.process_name)
            )
    for (host, _), pairs in days.items():
        rarity.add_host_day(host_class_of(inventory, host), pairs)
    benign_m3 = [
        (r.context["host_class"], r.context["pairs"]) for r in by_kind["M3"] if not label(r)
    ]
    m3 = M3Detector.fit(rarity, benign_m3)
    m3.calibrate(benign_m3, fpr=0.01)
    detectors = DetectorSet({"M1": m1, "M2": m2, "M3": m3})
    correlation = CorrelationEngine(inventory)
    rows.sort(key=lambda r: r.window_end)
    for i in range(0, len(rows), 3000):
        chunk = rows[i : i + 3000]
        correlation.ingest(detectors.score(chunk), chunk[-1].window_end)
    actions = ActionManager(PolicyGate(inventory), None, store)
    return MiniSoc(
        sim,
        inventory,
        store,
        profiles,
        pipeline,
        detectors,
        correlation,
        actions,
        rows,
        malicious,
        sim.clock,
    )
