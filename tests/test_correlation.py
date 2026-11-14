from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentic_soc.correlation import CorrelationEngine, incident_risk, priority_of
from agentic_soc.detectors.base import Score
from agentic_soc.features import FEATURES, FeatureRow
from agentic_soc.ingestion import Inventory
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.storage import Store

T0 = datetime(2026, 3, 2, 20, tzinfo=UTC)


@pytest.fixture(scope="module")
def inventory() -> Inventory:
    return Inventory.from_enterprise(Simulator(load_config(overrides={"org": {"users": 40}})).ent)


def scored(
    kind: str,
    key: str,
    minute: float,
    users=(),
    hosts=(),
    ips=(),
    score=0.999,
    techniques=("T1078",),
):
    start = T0 + timedelta(minutes=minute)
    row = FeatureRow(kind, key, start, start + timedelta(minutes=15), list(users), list(hosts), list(ips),
                     [f"e-{key}-{minute}"], dict.fromkeys(FEATURES[kind], 0.0))  # fmt: skip
    return row, Score(kind.split("-")[0], kind, score, 0.99, [{"name": "n", "value": 1.0, "contribution": 2.0}],
                      list(techniques), f"{kind} alert on {key}")  # fmt: skip


def test_alerts_sharing_entities_form_one_incident(inventory) -> None:
    engine = CorrelationEngine(inventory)
    ws = next(h for h in inventory.hosts.values() if h.kind == "workstation")
    user = ws.owner
    updates = engine.ingest(
        [scored("M1-user", f"user:{user}", 0, users=[user], hosts=[ws.host_id], ips=["45.32.1.1"])],
        T0,
    )
    assert updates[0].created
    engine.ingest([scored("M2", "c2", 30, users=[user], hosts=[ws.host_id], ips=["10.10.1.1", "95.216.1.1"],
                          techniques=["T1071.001"])], T0 + timedelta(minutes=45))  # fmt: skip
    engine.ingest(
        [scored("M1-ip", "ip:45.32.1.1", 5, ips=["45.32.1.1"], techniques=["T1110.003"])], T0
    )
    assert len(engine.incidents) == 1
    incident = next(iter(engine.incidents.values()))
    assert incident.detectors == ["M1", "M2"] and len(incident.alerts) == 3
    record = incident.to_record()
    assert f" user:{user} " in record["entity_keys"] and record["priority"] <= 2


def test_infrastructure_and_time_horizon_do_not_link(inventory) -> None:
    engine = CorrelationEngine(inventory)
    dc = next(h for h in inventory.hosts.values() if h.role == "dc")
    engine.ingest(
        [scored("M2", "a", 0, hosts=["WS-0001", dc.host_id], ips=["10.10.1.1", dc.static_ip])], T0
    )
    engine.ingest(
        [scored("M2", "b", 0, hosts=["WS-0002", dc.host_id], ips=["10.10.1.2", dc.static_ip])], T0
    )
    assert len(engine.incidents) == 2
    engine.ingest(
        [scored("M2", "c", 60 * 10, hosts=["WS-0001"], ips=["10.10.1.1"])], T0 + timedelta(hours=10)
    )
    assert len(engine.incidents) == 3
    assert (
        f"host:{dc.host_id}" in engine.stop
        and f"ip:{next(iter(inventory.office_egress.values()))}" in engine.stop
    )


def test_spray_targets_link_through_the_source_only(inventory) -> None:
    engine = CorrelationEngine(inventory)
    spray = "45.32.9.9"
    engine.ingest([scored("M1-ip", f"ip:{spray}", 0, ips=[spray], techniques=["T1110.003"])], T0)
    engine.ingest(
        [scored("M1-user", "user:a", 0, users=["a"], ips=[spray], techniques=["T1110"])], T0
    )
    assert len(engine.incidents) == 1
    # The targeted account's own (unrelated) activity starts a separate incident...
    engine.ingest([scored("M3", "host:WS-0009", 20, users=["a"], hosts=["WS-0009"])], T0)
    assert len(engine.incidents) == 2
    # ...unless the account is actually used by the attacker (a successful sign-in).
    engine.ingest(
        [scored("M1-user", "user:a", 30, users=["a"], ips=[spray], techniques=["T1110", "T1078"])],
        T0,
    )
    assert len(engine.incidents) == 1


def test_alerts_of_an_incident_merged_in_the_same_batch_are_reported(inventory) -> None:
    engine = CorrelationEngine(inventory)
    engine.ingest([scored("M1-user", "user:a", 0, users=["a"])], T0)
    batch = [
        scored("M3", "host:WS-0009", 5, users=["b"], hosts=["WS-0009"]),
        scored("M2", "bridge", 10, users=["a"], hosts=["WS-0009"]),
    ]
    updates = engine.ingest(batch, T0)
    assert len(engine.incidents) == 1 and len(updates) == 1
    update = updates[0]
    assert update.merged == ["INC-00002"] and len(update.new_alerts) == 2
    assert {a.alert_id for a in update.new_alerts} | {
        next(iter(engine.incidents["INC-00001"].alerts))
    } == set(engine.incidents["INC-00001"].alerts)


def test_bridging_alert_merges_incidents_and_refires_update_in_place(inventory) -> None:
    engine = CorrelationEngine(inventory)
    engine.ingest([scored("M1-user", "user:a", 0, users=["a"])], T0)
    engine.ingest([scored("M3", "host:WS-0009", 0, users=["b"], hosts=["WS-0009"])], T0)
    assert len(engine.incidents) == 2
    updates = engine.ingest([scored("M2", "bridge", 10, users=["a"], hosts=["WS-0009"])], T0)
    assert len(engine.incidents) == 1 and updates[0].merged == ["INC-00002"]
    before = len(engine.alert_incident)
    engine.ingest([scored("M2", "bridge", 10, users=["a"], hosts=["WS-0009"], score=0.9999)], T0)
    assert len(engine.alert_incident) == before
    assert engine.stats()["alert_to_incident_ratio"] == 3.0


def test_risk_rewards_corroboration_and_late_tactics() -> None:
    single = incident_risk({"M1-user": 0.1}, {"T1078"}, 2, False)
    spray = incident_risk({"M1-ip": 1.0}, {"T1110.003"}, 2, False)
    chain = incident_risk(
        {"M1-user": 0.8, "M2": 1.0, "M3": 0.9},
        {"T1078", "T1071.001", "T1003.001", "T1041"},
        4,
        True,
    )
    assert single.risk < 0.5 < spray.risk < chain.risk < 1.0
    assert priority_of(single.risk) == 4 and priority_of(chain.risk) == 1
    assert chain.corroboration == pytest.approx(0.5) and chain.stakes == pytest.approx(0.15)


def test_store_round_trip_for_alerts_and_incidents(inventory) -> None:
    engine = CorrelationEngine(inventory)
    updates = engine.ingest([scored("M1-user", "user:z", 0, users=["z"], hosts=["WS-0003"])], T0)
    store = Store.memory()
    incident = updates[0].incident
    for alert in incident.alerts.values():
        store.upsert_alert(alert.model_dump() | {"incident_id": incident.incident_id, "entity_keys": " user:z host:WS-0003 ",
                                                 "created_at": T0, "entities": alert.entities.model_dump(),
                                                 "top_features": [f.model_dump() for f in alert.top_features]})  # fmt: skip
    store.upsert_incident(incident.to_record())
    store.upsert_incident(incident.to_record() | {"status": "queued"})
    assert store.get_incident(incident.incident_id)["status"] == "queued"
    assert store.list_incidents(entity="user:z")[0]["incident_id"] == incident.incident_id
    assert (
        len(store.list_alerts(incident_id=incident.incident_id)) == 1 and store.count_alerts() == 1
    )
