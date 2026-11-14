from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text, update

from agentic_soc.ingestion import (
    IngestionStage,
    Inventory,
    NormFlow,
    NormProcess,
    NormSignin,
    replay_run,
)
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.simulator.run_io import simulate_to_dir
from agentic_soc.storage import ColdStore, StorageSink, Store, read_table
from agentic_soc.storage import schema as s

FAST = {
    "org": {"users": 60},
    "duration_h": 4,
    "campaign": {
        "start_offset_h": 0.5,
        "start_jitter_h": 0,
        "dwell_scale": 0.3,
        "spray_targets": 30,
    },
}


@pytest.fixture(scope="module")
def ingested(tmp_path_factory):
    sim = Simulator(load_config(overrides=FAST))
    out = tmp_path_factory.mktemp("run")
    simulate_to_dir(sim, out)
    stage = IngestionStage(Inventory.from_file(out / "inventory.json"))
    result = stage.process_batch(replay_run(out))
    return sim, result


def fill(store: Store, result) -> None:
    store.write_events(result.events)
    store.write_dead_letters(result.dead_letters)


def check_store(store: Store, sim, result) -> None:
    by_stream = {"signin": 0, "flow": 0, "process": 0}
    for e in result.events:
        by_stream[e.stream] += 1
    assert {k: store.count_events(k) for k in by_stream} == by_stream
    store.write_events(result.events[:100])  # idempotent re-delivery
    assert store.count_events("signin") == by_stream["signin"]

    start, end = sim.config.start, sim.config.start + timedelta(hours=6)
    truth = sim.truth()["campaign"]
    victim, ws = truth["victim"], truth["workstation"]
    user_tl = store.timeline("user", victim, start, end)
    assert user_tl and {r["stream"] for r in user_tl} >= {"signin", "process"}
    assert all(r["event_time"].tzinfo is not None for r in user_tl)
    assert [r["event_time"] for r in user_tl] == sorted(
        (r["event_time"] for r in user_tl), reverse=True
    )
    host_tl = store.timeline("host", ws, start, end, streams=["process"])
    assert host_tl and all(r["host_id"] == ws for r in host_tl)
    spray_ip = truth["spray_ips"][0]
    ip_tl = store.timeline("ip", spray_ip, start, end)
    assert ip_tl and all(spray_ip in (r.get("src_ip"), r.get("dst_ip")) for r in ip_tl)
    ids = [ip_tl[0]["event_id"], host_tl[0]["event_id"]]
    assert [r["event_id"] for r in store.events_by_ids(ids)] == ids
    counts = store.stream_counts(start, end, bucket_s=3600)
    assert sum(c["count"] for c in counts) == sum(by_stream.values())
    assert {c["bucket"].minute for c in counts} == {0}
    summary = store.dead_letter_summary()
    assert sum(r["n"] for r in summary) == len(result.dead_letters)


def test_sqlite_store(ingested) -> None:
    sim, result = ingested
    store = Store.memory()
    fill(store, result)
    check_store(store, sim, result)


def test_audit_log_is_tamper_evident() -> None:
    store = Store.memory()
    t0 = datetime(2026, 3, 2, 21, tzinfo=UTC)
    first = store.audit("agent", "propose_action", "action", "A-1", {"type": "isolate_host"}, ts=t0)
    second = store.audit(
        "analyst:dana", "approve", "action", "A-1", {"at": t0}, ts=t0 + timedelta(minutes=1)
    )
    assert second["prev_hash"] == first["hash"]
    assert store.verify_audit_chain() == (True, None)
    assert [e["action"] for e in store.audit_entries("A-1")] == ["approve", "propose_action"]
    with store.engine.begin() as conn:
        conn.execute(update(s.audit_log).where(s.audit_log.c.seq == 1).values(actor="attacker"))
    assert store.verify_audit_chain() == (False, 1)


def test_cold_store_partitions_by_stream_and_date(ingested, tmp_path) -> None:
    _, result = ingested
    cold = ColdStore(tmp_path / "lake", flush_rows=10_000)
    sink = StorageSink(cold=cold)
    sink.write_events(result.events)
    sink.write_dead_letters(result.dead_letters)
    sink.close()
    for stream, cls in (("signin", NormSignin), ("flow", NormFlow), ("process", NormProcess)):
        table = read_table(tmp_path / "lake", stream)
        assert table.num_rows == sum(isinstance(e, cls) for e in result.events)
        assert str(table.schema.field("event_time").type) == "timestamp[us, tz=UTC]"
    assert (tmp_path / "lake" / "flow" / "date=2026-03-02").is_dir()
    assert read_table(tmp_path / "lake", "dead_letter").num_rows == len(result.dead_letters)
    assert cold.files_written >= 4


PG_URL = os.environ.get("SOC_PG_URL")


@pytest.mark.integration
@pytest.mark.skipif(not PG_URL, reason="set SOC_PG_URL (make up)")
def test_timescaledb_store(ingested) -> None:
    sim, result = ingested
    store = Store(PG_URL)
    store.reset()
    fill(store, result)
    check_store(store, sim, result)
    with store.engine.connect() as conn:
        hypertables = {
            r[0]
            for r in conn.execute(
                text("SELECT hypertable_name FROM timescaledb_information.hypertables")
            )
        }
    assert {"signin_events", "flow_events", "process_events"} <= hypertables
    store.audit("system", "test", "run", "x")
    assert store.verify_audit_chain() == (True, None)
