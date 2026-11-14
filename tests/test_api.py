from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentic_soc.api import ConsoleService, create_app


@pytest.fixture(scope="module")
def live(agent_run) -> TestClient:
    service = ConsoleService(agent_run.pipeline.store, pipeline=agent_run.pipeline,
                             run={"name": "test"})  # fmt: skip
    return TestClient(create_app(service))


@pytest.fixture(scope="module")
def recorded(agent_run) -> TestClient:
    pipeline = agent_run.pipeline
    service = ConsoleService(pipeline.store, pipeline.inv, pipeline.features.profiles)
    return TestClient(create_app(service))


def _top(client: TestClient) -> dict:
    return client.get("/api/incidents").json()[0]


def test_health_and_stream_health(live, recorded) -> None:
    health = live.get("/api/health").json()
    assert health["live"] and health["mode"] == "agent" and health["now"].endswith("Z")
    assert recorded.get("/api/health").json()["live"] is False
    stream = recorded.get("/api/stream-health", params={"hours": 15}).json()
    assert {c["stream"] for c in stream["counts"]} == {"signin", "flow", "process"}
    assert stream["totals"]["flow"] > 10_000
    assert "ingestion" in live.get("/api/stream-health").json()


def test_incident_queue_detail_trace_and_evidence(live) -> None:
    incidents = live.get("/api/incidents").json()
    assert incidents and [i["priority"] for i in incidents] == sorted(
        i["priority"] for i in incidents
    )
    contained = live.get("/api/incidents", params={"status": ["contained"]}).json()
    assert all(i["status"] == "contained" for i in contained)
    agent_decided = next(i for i in incidents if i["decided_by"] == "agent")
    detail = live.get(f"/api/incidents/{agent_decided['incident_id']}").json()
    assert detail["alerts"] and detail["decisions"] and detail["evidence_counts"]["alert"] > 0
    trace = live.get(f"/api/incidents/{agent_decided['incident_id']}/trace").json()
    assert trace["tool_calls"][0]["tool"] == "get_incident"
    evidence = live.get(f"/api/incidents/{agent_decided['incident_id']}/evidence",
                        params={"kind": "event", "stream": "signin"}).json()  # fmt: skip
    assert all(e["kind"] == "event" and e["stream"] == "signin" for e in evidence)
    assert live.get("/api/incidents/INC-NOPE").status_code == 404


def test_entities_and_timelines(recorded, agent_run) -> None:
    host = agent_run.truth["campaign"]["workstation"]
    detail = recorded.get(f"/api/entities/host:{host}").json()
    assert detail["host"]["kind"] == "workstation" and detail["incidents"]
    timeline = recorded.get(f"/api/entities/host:{host}/timeline",
                            params={"start": "2026-03-02T08:00:00Z", "end": "2026-03-02T15:00:00Z"}).json()  # fmt: skip
    assert timeline["addresses"] and {e["stream"] for e in timeline["events"]} >= {
        "process",
        "flow",
    }
    user = agent_run.truth["campaign"]["victim"]
    assert "baseline" in recorded.get(f"/api/entities/user:{user}").json()
    assert recorded.get("/api/entities/nonsense").status_code == 422


def test_approve_and_reject_held_actions_live_only(live, recorded, agent_run) -> None:
    pipeline = agent_run.pipeline
    gate = pipeline.actions.gate
    workstations = [h.host_id for h in pipeline.inv.hosts.values() if h.kind == "workstation"]
    taken = {a.target for a in pipeline.actions.actions.values()}
    first, second = [h for h in workstations if h not in taken][:2]
    gate.cfg.auto_approve_high_impact = False
    try:
        held = [pipeline.actions.propose("INC-00001", "isolate_host", host, "agent", pipeline.now(),
                                         "beaconing implant") for host in (first, second)]  # fmt: skip
    finally:
        gate.cfg.auto_approve_high_impact = True
    assert all(a.status == "pending_approval" for a in held)
    pending = live.get("/api/actions", params={"status": ["pending_approval"]}).json()
    assert {a.action_id for a in held} <= {a["action_id"] for a in pending}
    blocked = recorded.post(f"/api/actions/{held[0].action_id}/approve", json={"analyst": "ana"})
    assert blocked.status_code == 409
    approved = live.post(
        f"/api/actions/{held[0].action_id}/approve", json={"analyst": "ana"}
    ).json()
    assert approved["status"] == "executed" and approved["approved_by"] == "ana"
    rejected = live.post(f"/api/actions/{held[1].action_id}/reject",
                         json={"analyst": "ana", "reason": "server owner confirmed"}).json()  # fmt: skip
    assert rejected["status"] == "rejected"
    again = live.post(f"/api/actions/{held[1].action_id}/approve", json={"analyst": "ana"})
    assert again.status_code == 409
    assert live.post("/api/actions/ACT-nope/approve", json={"analyst": "ana"}).status_code == 404
    audit = live.get("/api/audit", params={"object_id": held[0].action_id}).json()
    assert any(e["actor"] == "analyst:ana" and e["action"] == "approve" for e in audit)
    assert live.get("/api/audit/verify").json() == {"ok": True, "first_broken": None}


def test_feedback_and_metrics(live) -> None:
    incident = _top(live)
    response = live.post(f"/api/incidents/{incident['incident_id']}/feedback",
                         json={"analyst": "ana", "verdict": "true_positive"})  # fmt: skip
    assert response.status_code == 200 and response.json()["alerts"] == incident["alerts"]
    bad = live.post(f"/api/incidents/{incident['incident_id']}/feedback",
                    json={"analyst": "ana", "verdict": "maybe"})  # fmt: skip
    assert bad.status_code == 422
    missing = live.post(
        "/api/incidents/INC-NOPE/feedback", json={"analyst": "a", "verdict": "false_positive"}
    )
    assert missing.status_code == 404
    metrics = live.get("/api/metrics").json()
    assert metrics["incidents"] > 0 and metrics["alerts"] >= metrics["incidents"]
    assert metrics["agent"]["decisions"] > 0 and metrics["agent"]["invalid_tool_call_rate"] == 0
    assert any(row["reviewed"] for row in metrics["detector_feedback"])
    assert metrics["pipeline"]["breaker"] == "closed"


def test_server_sent_events_stream_pipeline_events(live, recorded) -> None:
    with live.stream("GET", "/api/events", params={"max_s": 0.2, "interval_s": 0.1}) as response:
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())
    assert body.startswith("event: hello")
    for kind in ("incident", "alert", "decision", "metrics"):
        assert f"event: {kind}\n" in body
    with recorded.stream(
        "GET", "/api/events", params={"max_s": 0.1, "interval_s": 0.1}
    ) as response:
        quiet = "".join(response.iter_text())
    assert "event: hello" in quiet and "event: decision" not in quiet
