from __future__ import annotations

from datetime import timedelta

import pyarrow.parquet as pq
import pytest

from agentic_soc.evidence import EvidenceBuilder, FeedbackService
from agentic_soc.schemas import Decision, EvidenceRef, ProposedAction


def _malicious(agent_run):
    store = agent_run.pipeline.store
    return next(d for d in store.recent_decisions(500) if d["verdict"] == "malicious")


def test_every_decision_stores_its_evidence(agent_run) -> None:
    pipeline = agent_run.pipeline
    stats = agent_run.summary["stats"]
    assert stats["evidence_items"] > 0 and stats.get("evidence_missing", 0) == 0
    decision = _malicious(agent_run)
    items = pipeline.store.list_evidence(decision["incident_id"], limit=5000)
    kinds = {item["kind"] for item in items}
    assert kinds == {"alert", "event", "baseline", "tool_call"}
    cited = {ref["id"] for ref in decision["decision"]["evidence"]}
    flagged = {item["ref_id"] for item in items if item["cited"]}
    assert cited and cited <= flagged | {item["ref_id"] for item in items}
    assert cited & flagged
    alert = next(item for item in items if item["kind"] == "alert")
    assert alert["detector"] in {"M1", "M2", "M3"} and alert["data"]["top_features"]
    calls = [item for item in items if item["kind"] == "tool_call"]
    assert calls[0]["data"]["tool"] == "get_incident" and calls[0]["ref_id"].startswith("D")


def test_baselines_describe_the_entities(agent_run) -> None:
    store = agent_run.pipeline.store
    incidents = {
        d["incident_id"] for d in store.recent_decisions(500) if d["verdict"] == "malicious"
    }
    baselines = [
        b for i in sorted(incidents) for b in store.list_evidence(i, kind="baseline", limit=500)
    ]
    users = [b for b in baselines if b["entity"].startswith("user:") and "local_hours" in b["data"]]
    assert users and len(users[0]["data"]["local_hours"]) == 24
    hosts = [b for b in baselines if b["entity"].startswith("host:")]
    assert hosts and {"traffic_before", "traffic_during"} <= set(hosts[0]["data"])
    ips = [b for b in baselines if b["entity"].startswith("ip:")]
    assert ips and ips[0]["data"]["geo"] is not None


def test_evidence_filters_by_entity_stream_detector_and_time(agent_run) -> None:
    store = agent_run.pipeline.store
    incident_id = _malicious(agent_run)["incident_id"]
    every = store.list_evidence(incident_id, limit=5000)
    events = [e for e in every if e["kind"] == "event"]
    entity = events[0]["entity"]
    by_entity = store.list_evidence(incident_id, entity=entity, limit=5000)
    assert by_entity and all(e["entity"] == entity for e in by_entity)
    flows = store.list_evidence(incident_id, stream="flow", limit=5000)
    assert all(e["stream"] == "flow" for e in flows)
    m2 = store.list_evidence(incident_id, detector="M2", limit=5000)
    assert all(e["detector"] == "M2" for e in m2)
    times = sorted(e["time"] for e in events)
    middle = times[len(times) // 2]
    window = store.list_evidence(incident_id, kind="event", start=middle,
                                 end=middle + timedelta(hours=1), limit=5000)  # fmt: skip
    assert window and all(middle <= e["time"] < middle + timedelta(hours=1) for e in window)
    cited = store.list_evidence(incident_id, cited=True, limit=5000)
    assert cited and all(e["cited"] for e in cited)


def test_rebuilding_a_bundle_refreshes_without_duplicates(agent_run) -> None:
    pipeline = agent_run.pipeline
    state = max(pipeline.correlation.incidents.values(), key=lambda s: s.risk.risk)
    builder = EvidenceBuilder(pipeline.store, pipeline.inv, pipeline.features.profiles,
                              pipeline.features.resolver)  # fmt: skip
    alert = max(state.alerts.values(), key=lambda a: a.score)
    decision = Decision(
        incident_id=state.incident_id,
        verdict="malicious",
        evidence=[
            EvidenceRef(id=alert.alert_id, kind="alert"),
            EvidenceRef(id="AL-doesnotexist", kind="alert"),
        ],
        action=ProposedAction(type="none"),
        confidence=0.9,
    )
    bundle = builder.build(state, decision, decision_id=999)
    assert bundle.missing == ["AL-doesnotexist"]

    def keys(items):
        return [(i["kind"], i["ref_id"]) for i in items]

    before = set(keys(pipeline.store.list_evidence(state.incident_id, limit=10_000)))
    pipeline.store.upsert_evidence(bundle.items)
    pipeline.store.upsert_evidence(bundle.items)
    after = pipeline.store.list_evidence(state.incident_id, limit=10_000)
    assert len(keys(after)) == len(set(keys(after)))  # one row per (kind, reference)
    assert set(keys(after)) == before | set(keys(bundle.items))
    refreshed = next(i for i in after if i["ref_id"] == alert.alert_id)
    assert refreshed["cited"]


def test_analyst_feedback_drives_false_positive_statistics(agent_run, tmp_path) -> None:
    pipeline = agent_run.pipeline
    service = FeedbackService(pipeline.store)
    now = pipeline.now()
    truth = agent_run.truth["campaign"]["entities"]
    attack = {f"user:{u}" for u in truth["users"]} | {f"host:{h}" for h in truth["hosts"]}
    attack |= {f"ip:{i}" for i in truth["ips"]}
    incidents = pipeline.store.list_incidents(limit=1000)
    benign = next(i for i in incidents if not set(i["entity_keys"].split()) & attack)
    hostile = next(i for i in incidents if set(i["entity_keys"].split()) & attack)
    n_fp = service.record(benign["incident_id"], "false_positive", "ana", now, "travel")
    n_tp = service.record(hostile["incident_id"], "true_positive", "ana", now)
    assert n_fp == len(benign["alert_ids"]) and n_tp == len(hostile["alert_ids"])
    stats = service.detector_stats()
    reviewed = sum(row["reviewed"] for row in stats)
    assert reviewed == len({*benign["alert_ids"], *hostile["alert_ids"]})
    assert sum(row["false_positive"] for row in stats) >= 1
    for row in stats:
        if row["reviewed"]:
            assert row["false_positive_share"] + row["precision"] <= 1.0
    path = tmp_path / "labels.parquet"
    assert service.export_labels(path) == reviewed
    table = pq.read_table(path).to_pylist()
    assert {r["label"] for r in table} == {0, 1}
    audit = pipeline.store.audit_entries(object_id=benign["incident_id"])
    assert any(e["action"] == "feedback" for e in audit)
    assert pipeline.store.verify_audit_chain() == (True, None)
    with pytest.raises(ValueError):
        service.record(benign["incident_id"], "maybe", "ana", now)
