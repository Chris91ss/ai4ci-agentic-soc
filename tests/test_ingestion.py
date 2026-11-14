from __future__ import annotations

from datetime import UTC, datetime

import orjson
import pytest

from agentic_soc.broker import InMemoryBroker
from agentic_soc.ingestion import (
    Deduplicator,
    IngestionService,
    IngestionStage,
    IngestResult,
    Inventory,
    NormFlow,
    NormProcess,
    NormSignin,
    canonical_account,
    replay_run,
)
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.simulator.live import LiveSimulator
from agentic_soc.simulator.run_io import simulate_to_dir

FAST = {
    "org": {"users": 60},
    "duration_h": 5,
    "campaign": {
        "start_offset_h": 0.5,
        "start_jitter_h": 0,
        "dwell_scale": 0.3,
        "spray_targets": 30,
    },
}
NOW = datetime(2026, 3, 2, 10, tzinfo=UTC)


@pytest.fixture(scope="module")
def replay(tmp_path_factory):
    sim = Simulator(load_config(overrides=FAST))
    out = tmp_path_factory.mktemp("run")
    simulate_to_dir(sim, out)
    inventory = Inventory.from_file(out / "inventory.json")
    stage = IngestionStage(inventory)
    result = stage.process_batch(replay_run(out))
    return sim, inventory, stage, result


def test_every_message_is_accounted_for(replay) -> None:
    sim, _, stage, result = replay
    stats = sim.delivery.stats
    summary = stage.summary()
    received = sum(s["received"] for s in summary.values())
    assert received == stats.delivered
    assert (
        sum(s["invalid"] for s in summary.values()) == stats.malformed == len(result.dead_letters)
    )
    assert sum(s["duplicates"] for s in summary.values()) == stats.duplicates == result.duplicates
    assert len(result.events) == stats.submitted - stats.malformed
    assert sum(s["legacy"] for s in summary.values()) == stats.legacy
    assert summary["flow"]["delay_p50_s"] > summary["signin"]["delay_p50_s"]


def test_identities_are_resolved_across_streams(replay) -> None:
    _, inventory, _, result = replay
    signins = [e for e in result.events if isinstance(e, NormSignin)]
    forms: dict[str, set[str]] = {}
    for e in signins:
        if e.user_kind == "user":
            forms.setdefault(e.user_id, set()).add(e.user_raw.split("@")[-1])
    assert any(f == {"corp.example", "CORP.EXAMPLE"} for f in forms.values())
    admins = [e for e in signins if e.user_kind == "admin"]
    assert admins and all(e.person == inventory.admin_owner[e.user_id] for e in admins)
    assert any(e.user_kind == "service" for e in signins)
    assert any(e.user_kind == "unknown" and e.user_id == "admin" for e in signins)  # sprayed
    spray = [e for e in signins if e.src_category == "hosting" and e.outcome == "failure"]
    assert spray and all(e.src_zone == "external" for e in spray)
    processes = [e for e in result.events if isinstance(e, NormProcess)]
    assert all(e.host_id in inventory.hosts for e in processes)
    assert any(e.user_id == "system" and e.user_kind == "system" for e in processes)
    assert all(e.process_name == e.process_name.lower() for e in processes)


def test_flows_are_enriched(replay) -> None:
    _, inventory, _, result = replay
    flows = [e for e in result.events if isinstance(e, NormFlow)]
    outbound = [e for e in flows if e.direction == "outbound"]
    assert outbound and all(e.dst_zone == "external" for e in outbound)
    assert any(e.dst_org == "Microsoft" for e in outbound)
    servers = [e for e in flows if e.src_host and e.src_host.startswith("SRV-")]
    assert servers and all(inventory.hosts[e.src_host].static_ip == e.src_ip for e in servers)
    assert any(e.service == "smb" for e in flows) and any(e.service == "edr" for e in flows)
    assert {e.schema_version for e in flows} == {"1.0", "0.9"}


def test_dead_letters_keep_the_raw_payload() -> None:
    inventory = Inventory.from_enterprise(
        Simulator(load_config(overrides={"org": {"users": 20}})).ent
    )
    stage = IngestionStage(inventory)
    result = IngestResult()
    stage.process("signin", b'{"event_id": "x' + b"y" * 9000, "k", NOW, result)
    stage.process("flow", orjson.dumps({"schema_version": "9.9"}), None, NOW, result)
    codes = [d.error_code for d in result.dead_letters]
    assert codes == ["invalid_json", "unknown_version"]
    assert len(result.dead_letters[0].raw) == 4096 and result.dead_letters[0].key == "k"
    assert stage.stats["signin"].errors == {"invalid_json": 1}


def test_deduplicator_window() -> None:
    dedupe = Deduplicator(window_s=60)
    assert not dedupe.seen("a", 0)
    assert dedupe.seen("a", 30)
    assert not dedupe.seen("b", 61)
    assert not dedupe.seen("a", 100)  # forgotten after the window
    assert len(dedupe) == 2


def test_canonical_accounts() -> None:
    assert canonical_account("CORP\\Ana.Pop") == "ana.pop"
    assert canonical_account("ana.pop@CORP.EXAMPLE") == "ana.pop"
    assert canonical_account("NT AUTHORITY\\SYSTEM") == "system"
    assert canonical_account(" root ") == "root"


def test_service_consumes_the_broker_and_publishes_dead_letters() -> None:
    cfg = load_config(
        overrides={
            "org": {"users": 40},
            "duration_h": 1,
            "campaign": {"enabled": False},
            "delivery": {
                "signin": {
                    "median_delay_s": 2,
                    "late_prob": 0,
                    "late_delay_s": [1, 2],
                    "duplicate_prob": 0,
                    "malformed_prob": 0.2,
                },
                "flow": {
                    "median_delay_s": 15,
                    "late_prob": 0,
                    "late_delay_s": [1, 2],
                    "duplicate_prob": 0.05,
                },
                "process": {
                    "median_delay_s": 4,
                    "late_prob": 0,
                    "late_delay_s": [1, 2],
                    "duplicate_prob": 0,
                },
            },
        }
    )
    sim = Simulator(cfg)
    broker = InMemoryBroker()
    LiveSimulator(sim, broker, speed=0).run()
    inventory = Inventory.from_enterprise(sim.ent)
    service = IngestionService(broker, IngestionStage(inventory))
    events = dead = 0
    while True:
        result = service.poll_once(timeout=0)
        if not result.events and not result.dead_letters and not result.duplicates:
            break
        events += len(result.events)
        dead += len(result.dead_letters)
    assert dead == sim.delivery.stats.malformed > 0
    assert broker.size("dead-letter") == dead
    letter = orjson.loads(broker.messages("dead-letter")[0].value)
    assert letter["topic"] == "signin" and letter["error_code"]
    assert events == sim.delivery.stats.submitted - dead
    assert broker.lag("ingestion", ["signin", "flow", "process"]) == {
        "signin": 0,
        "flow": 0,
        "process": 0,
    }

    # Dead letters still buffered by the producer are delivered when the service stops.
    flushes = []
    service.producer.flush = lambda timeout=10.0: flushes.append(timeout)
    service.close()
    assert flushes
