from __future__ import annotations

import json

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


def test_recorded_runs_replay_their_log_and_hide_merged_incidents(agent_run) -> None:
    pipeline = agent_run.pipeline
    log = [{"time": "2026-03-02T09:00:00Z", "kind": "incident", "incident_id": "INC-00001"},
           {"time": "2026-03-02T09:05:00Z", "kind": "decision", "incident_id": "INC-00001"}]  # fmt: skip
    client = TestClient(create_app(ConsoleService(pipeline.store, log=log)))
    assert [e["kind"] for e in client.get("/api/log").json()] == ["incident", "decision"]
    assert client.get("/api/log", params={"kinds": ["decision"]}).json() == log[1:]
    merged = [e["merged"] for e in pipeline.log if e["kind"] == "merge"]
    listed = {i["incident_id"] for i in client.get("/api/incidents", params={"limit": 5000}).json()}
    assert merged and not set(merged) & listed
    assert client.get("/api/metrics").json()["incidents"] == len(pipeline.correlation.incidents)


def test_evaluation_results_with_thinned_load_samples(agent_run, tmp_path) -> None:
    pipeline = agent_run.pipeline
    service = ConsoleService(pipeline.store, pipeline.inv, evaluation_dir=tmp_path)
    client = TestClient(create_app(service))
    assert client.get("/api/evaluation").status_code == 404
    (tmp_path / "results.json").write_text(
        json.dumps({"generated": "now", "s2": [{"llm_slowdown": 4}]})
    )
    samples = [{"wall_s": i, "sim_t": 60 * i, "stream_lag_s": 30} for i in range(3000)]
    (tmp_path / "s2-samples-x4.json").write_text(json.dumps(samples))
    found = client.get("/api/evaluation").json()
    assert found["generated"] == "now" and found["s2"][0]["llm_slowdown"] == 4
    assert (
        500 <= len(found["s2_samples"]["4"]) <= 600 and found["s2_samples"]["4"][0]["wall_s"] == 0
    )


def test_static_export_matches_the_console_files(agent_run, tmp_path) -> None:
    from agentic_soc.api.export import entity_file, export_static

    pipeline = agent_run.pipeline
    service = ConsoleService(pipeline.store, pipeline.inv, pipeline.features.profiles,
                             run={"name": "test"}, log=pipeline.log)  # fmt: skip
    result = export_static(service, tmp_path, timeline_limit=20, alert_limit=5)
    names = {p.name for p in tmp_path.iterdir()}
    assert {"health.json", "stream-health.json", "incidents.json", "actions.json", "metrics.json",
            "audit.json", "audit-verify.json", "log.json", "incidents", "entities"} <= names  # fmt: skip
    assert "evaluation.json" not in names  # no evaluation directory configured
    incidents = json.loads((tmp_path / "incidents.json").read_text())
    assert len(incidents) == result["incidents"] > 0
    first = json.loads((tmp_path / "incidents" / f"{incidents[0]['incident_id']}.json").read_text())
    assert set(first) == {"detail", "evidence", "trace"} and first["detail"]["alerts"]
    for action in json.loads((tmp_path / "actions.json").read_text()):
        kind = {"block_ip": "ip", "isolate_host": "host"}.get(action["type"], "user")
        path = tmp_path / "entities" / f"{entity_file(f'{kind}:{action["target"]}')}.json"
        entity = json.loads(path.read_text())
        assert len(entity["timeline"]["events"]) <= 20 and len(entity["timeline"]["alerts"]) <= 5
        assert all(v is not None for e in entity["timeline"]["events"] for v in e.values())
    assert entity_file("ip:10.0.0.1") == "ip_10.0.0.1" and entity_file("user:a b") == "user_a_b"
