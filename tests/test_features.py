from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import numpy as np
import pyarrow.parquet as pq
import pytest

from agentic_soc.features import FEATURES, FeaturePipeline, Profiles, Windower
from agentic_soc.features.history import ConversationHistory
from agentic_soc.ingestion import IngestionStage, Inventory, NormSignin, replay_run
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.simulator.run_io import simulate_to_dir

T0 = datetime(2026, 3, 2, 10, 0, tzinfo=UTC)


def ev(minutes: float, key: str = "a") -> SimpleNamespace:
    return SimpleNamespace(event_time=T0 + timedelta(minutes=minutes), key=key)


def test_windows_fire_on_the_watermark_and_refire_late_events() -> None:
    w = Windower("t", size_s=600, allowed_delay_s=60, keys=lambda e: [e.key], retention_s=1800)
    w.add(ev(1))
    w.add(ev(5, "b"))
    w.add(ev(12))
    assert w.advance(T0 + timedelta(minutes=10)) == []  # watermark 09:59 + 10 min - 1
    fired = w.advance(T0 + timedelta(minutes=11, seconds=1))
    assert sorted((x.key, len(x.events)) for x in fired) == [("a", 1), ("b", 1)]
    w.add(ev(3))  # late: its window already fired
    refired = w.advance(T0 + timedelta(minutes=12))
    assert [(x.key, len(x.events), x.late, x.fired) for x in refired] == [("a", 2, True, 2)]
    w.advance(T0 + timedelta(hours=2))
    w.add(ev(2))  # beyond retention
    assert w.stats.dropped == 1 and w.stats.refired == 1
    assert w.flush() == []


def test_late_event_for_a_window_that_never_opened_fires_as_late() -> None:
    w = Windower("t", size_s=600, allowed_delay_s=0, keys=lambda e: [e.key], retention_s=3600)
    w.advance(T0 + timedelta(minutes=30))
    w.add(ev(1, "x"))
    fired = w.advance(T0 + timedelta(minutes=31))
    assert [(x.key, x.late) for x in fired] == [("x", True)]


def test_conversation_history_detects_regular_beacons() -> None:
    history = ConversationHistory(horizon_s=3600)
    rng = np.random.default_rng(1)
    t = 0.0
    for _ in range(40):
        t += 60 * rng.uniform(0.85, 1.15)
        history.observe(SimpleNamespace(src_ip="10.0.0.1", dst_ip="1.2.3.4", dst_port=443,
                                        event_time=T0 + timedelta(seconds=t), bytes_out=500))  # fmt: skip
    beacon = history.stats("10.0.0.1|1.2.3.4|443", T0 + timedelta(seconds=t + 1))
    assert beacon["hist_regularity"] > 0.9 and beacon["hist_interval_cv"] < 0.15
    assert history.stats("nope", T0)["hist_n"] == 0


FAST = {
    "org": {"users": 60},
    "duration_h": 8,
    "campaign": {"start_offset_h": 4, "start_jitter_h": 0, "dwell_scale": 0.3, "spray_targets": 30},
}


@pytest.fixture(scope="module")
def featurised(tmp_path_factory):
    sim = Simulator(load_config(overrides=FAST))
    out = tmp_path_factory.mktemp("run")
    simulate_to_dir(sim, out)
    inv = Inventory.from_file(out / "inventory.json")
    events = IngestionStage(inv).process_batch(replay_run(out)).events
    start = sim.campaign.start
    profiles = Profiles.build(
        (e for e in events if isinstance(e, NormSignin) and e.event_time < start), inv.timezone
    )
    pipeline = FeaturePipeline(inv, profiles)
    rows = []
    for i in range(0, len(events), 1000):
        pipeline.add(events[i : i + 1000])
        rows += pipeline.advance().rows()
    rows += pipeline.flush().rows()
    labels = pq.read_table(out / "labels.parquet").to_pylist()
    malicious = {r["event_id"] for r in labels if r["malicious"]}
    return sim, inv, pipeline, rows, malicious


def test_rows_have_complete_feature_vectors(featurised) -> None:
    _, _, _, rows, _ = featurised
    by_detector = {d: [r for r in rows if r.detector == d] for d in FEATURES}
    assert all(by_detector.values())
    for detector, detector_rows in by_detector.items():
        matrix = np.array([r.vector() for r in detector_rows])
        assert matrix.shape[1] == len(FEATURES[detector]) and np.isfinite(matrix).all(), detector


def test_campaign_windows_stand_out(featurised) -> None:
    sim, _, _, rows, malicious = featurised
    truth = sim.truth()["campaign"]
    spray = [r for r in rows if r.detector == "M1-ip" and r.ips[0] in truth["spray_ips"]]
    assert spray and max(r.features["n_users_failed"] for r in spray) >= 5
    beacons = [
        r
        for r in rows
        if r.detector == "M2" and truth["c2_ips"][0] in r.ips and r.features["n_flows"] >= 3
    ]
    assert beacons and max(r.features["hist_regularity"] for r in beacons) > 0.5
    compromised = {truth["workstation"], truth["staging_host"]}
    assert all(set(r.hosts) <= compromised for r in beacons)
    m3 = [r for r in rows if r.detector == "M3" and any(e in malicious for e in r.event_ids)]
    pairs = {p for r in m3 for p in r.context["pairs"]}
    assert ("services.exe", "psexesvc.exe") in pairs and ("cmd.exe", "7za.exe") in pairs


def test_entity_resolution_links_workstation_addresses(featurised) -> None:
    sim, _, pipeline, _, _ = featurised
    resolver = pipeline.resolver
    t = sim.config.start + timedelta(hours=7)
    resolved = 0
    for host in sim.ent.workstations:
        user = sim.ent.users_by_id[host.owner]
        plan = sim.ctx.planner.plan(user, 0)
        if plan.works and not plan.remote and plan.start < t:
            ip = sim.ent.dhcp_ip(host.host_id, t)
            assert resolver.host_for_ip(ip, t) == host.host_id
            assert resolver.user_for_ip(ip, t) == user.user_id
            assert ip in resolver.ips_for_host(host.host_id, t - timedelta(hours=1), t)
            resolved += 1
    assert resolved >= 5
    server = sim.ent.servers[0]
    assert resolver.host_for_ip(server.static_ip, t) == server.host_id
    assert pipeline.stats()["flow-src"]["fired"] > 0
