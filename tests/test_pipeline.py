from __future__ import annotations

import pytest

from agentic_soc.pipeline import InProcessRun, PipelineConfig, RunOutcome
from agentic_soc.pipeline.staging import StagedActions
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.storage import Store
from conftest import MINI, RUN, closed_loop


@pytest.fixture(scope="module")
def playbook_run(mini_soc) -> RunOutcome:
    return closed_loop(mini_soc, mode="detectors")


def _truth_entities(outcome: RunOutcome) -> set[str]:
    entities = outcome.truth["campaign"]["entities"]
    return {*entities["users"], *entities["hosts"], *entities["ips"]}


def test_agent_contains_the_campaign_through_the_actions_topic(agent_run) -> None:
    summary, truth = agent_run.summary, agent_run.truth
    assert summary["events"] > 50_000 and summary["incidents"] < summary["alerts"]
    executed = [a for a in summary["actions"] if a["status"] == "executed"]
    assert executed and all(a["requested_by"] == "agent" for a in executed)
    attack = _truth_entities(agent_run)
    assert any(a["target"] in attack for a in executed)
    applied = {(a["type"], a["target"]) for a in truth["actions"] if a["applied"]}
    assert applied == {(a["type"], a["target"]) for a in executed}
    campaign = truth["campaign"]
    assert campaign["status"] == "stalled" and campaign["exfil_bytes"] == 0


def test_agent_decisions_and_traces_are_persisted(agent_run) -> None:
    pipeline = agent_run.pipeline
    store: Store = pipeline.store
    decisions = store.recent_decisions(limit=500)
    assert len(decisions) == summary_decisions(agent_run) > 0
    malicious = next(d for d in decisions if d["verdict"] == "malicious")
    calls = store.tool_calls_for(malicious["incident_id"])
    assert calls[0]["tool"] == "get_incident" and any(c["tool"] == "decision" for c in calls)
    incident = store.get_incident(malicious["incident_id"])
    assert incident["decided_by"] == "agent" and incident["status"] in {
        "contained",
        "awaiting_approval",
        "open",
    }
    assert store.list_alerts(incident_id=malicious["incident_id"])
    assert store.verify_audit_chain() == (True, None)
    stats = agent_run.summary["stats"]
    assert stats["agent_runs"] == len(decisions) and stats["agent_invalid_tool_calls"] == 0


def summary_decisions(outcome: RunOutcome) -> int:
    return sum(outcome.summary["decisions"].values())


def test_agent_latency_is_charged_in_simulated_time(agent_run) -> None:
    decisions = [d for d in agent_run.pipeline.decisions if d["decided_by"] == "agent"]
    assert all(15 <= d["latency_s"] <= 180 for d in decisions)
    # Agent actions take effect only after the triage finished.
    for action in agent_run.summary["actions"]:
        if action["requested_by"] == "agent":
            decided = [
                d["created_at"].isoformat()
                for d in decisions
                if d["incident_id"] == action["incident_id"]
            ]
            assert action["created_at"] in decided


def test_detector_baseline_decides_with_playbooks(playbook_run) -> None:
    summary = playbook_run.summary
    assert summary["mode"] == "detectors" and set(summary["decisions"]) == {"playbook"}
    assert "agent" not in summary["routes"]
    assert any(a["status"] == "executed" for a in summary["actions"])
    assert all(a["requested_by"] == "playbook" for a in summary["actions"])


def test_slow_agent_times_out_to_playbook_and_trips_the_breaker(mini_soc) -> None:
    config = load_config(overrides=RUN | {"duration_h": 12})
    run = InProcessRun(
        Simulator(config),
        mini_soc.detectors,
        PipelineConfig(mode="agent", seconds_per_llm_call=60.0),
    )
    outcome = run.run()
    stats = outcome.summary["stats"]
    assert stats["agent_timeouts"] >= 3 and outcome.summary["breaker_trips"] >= 1
    assert outcome.summary["decisions"].get("playbook", 0) >= stats["agent_timeouts"]


def test_staged_agent_proposals_wait_for_the_decision(mini_soc) -> None:
    staged = StagedActions(mini_soc.actions)
    staged.staging = True
    ws = next(h for h in mini_soc.inventory.hosts.values() if h.kind == "workstation")
    before = len(mini_soc.actions.actions)
    action = staged.propose(
        "INC-X", "isolate_host", ws.host_id, "agent", mini_soc.clock, "implant beaconing"
    )
    assert action.status == "pending_approval" and len(mini_soc.actions.actions) == before
    dc = next(h for h in mini_soc.inventory.hosts.values() if h.role == "dc")
    denied = staged.propose("INC-X", "isolate_host", dc.host_id, "agent", mini_soc.clock, "x" * 12)
    assert denied.status == "denied"
    proposals = staged.take()
    assert [(p.action_type, p.target) for p in proposals] == [("isolate_host", ws.host_id)]
    assert staged.take() == [] and staged.gate is mini_soc.actions.gate


def test_soc_run_cli_writes_a_run_directory(mini_soc, tmp_path) -> None:
    import json

    import yaml
    from typer.testing import CliRunner

    from agentic_soc.cli import app
    from agentic_soc.detectors.registry import ModelRegistry

    registry = ModelRegistry(tmp_path / "models")
    for detector in mini_soc.detectors.detectors.values():
        registry.save(detector)
    scenario = tmp_path / "mini.yaml"
    scenario.write_text(yaml.safe_dump({k: v for k, v in MINI.items() if k != "duration_h"}))
    out = tmp_path / "run"
    result = CliRunner().invoke(app, [
        "run", "--scenario", str(scenario), "--seed", "11", "--org-seed", "7",
        "--start", "2026-03-02T00:00:00Z", "--hours", "12", "--mode", "detectors",
        "--models", str(tmp_path / "models"), "--out", str(out),
    ])  # fmt: skip
    assert result.exit_code == 0, result.output
    summary = json.loads((out / "summary.json").read_text())
    assert summary["mode"] == "detectors" and summary["incidents"] > 0
    assert (out / "truth.json").exists() and (out / "soc.db").stat().st_size > 0
    kinds = {json.loads(line)["kind"] for line in (out / "log.jsonl").read_text().splitlines()}
    assert {"alert", "incident", "route", "decision"} <= kinds


def test_live_mode_on_the_broker_with_a_threaded_agent(mini_soc) -> None:
    import json
    import threading

    from agentic_soc.broker import InMemoryBroker
    from agentic_soc.detectors.service import LocalDetectorClient
    from agentic_soc.ingestion import Inventory
    from agentic_soc.pipeline import SocPipeline
    from agentic_soc.pipeline.service import run_live
    from agentic_soc.routing import RouterConfig
    from agentic_soc.simulator.live import LiveSimulator

    broker = InMemoryBroker()
    sim = Simulator(load_config(overrides=RUN | {"duration_h": 12}))
    live = LiveSimulator(sim, broker, speed=7200)
    config = PipelineConfig(mode="agent", worker="threaded",
                            router=RouterConfig(agent_timeout_s=6 * 3600))  # fmt: skip
    soc = SocPipeline(Inventory.from_enterprise(sim.ent), LocalDetectorClient(mini_soc.detectors),
                      mini_soc.profiles, Store.memory(), broker, config)  # fmt: skip
    assert soc.ctx.lock is soc.lock
    producer = threading.Thread(target=live.run)
    producer.start()
    stop = threading.Event()
    consumer = threading.Thread(
        target=run_live, args=(soc,), kwargs={"stop": stop, "poll_timeout": 0.05}
    )
    consumer.start()
    producer.join(timeout=120)
    while broker.lag("ingestion", ["signin", "flow", "process"]) != dict.fromkeys(
        ["signin", "flow", "process"], 0
    ) or (soc.worker is not None and soc.worker.busy):
        threading.Event().wait(0.2)
    stop.set()
    consumer.join(timeout=60)
    summary = soc.summary()
    assert summary["events"] > 50_000 and summary["incidents"] > 0
    assert summary["decisions"].get("agent", 0) > 0 and soc.worker.completed
    assert summary["stats"].get("agent_failures", 0) == 0
    # Which containment lands depends on thread timing; whatever executed reached the topic.
    published = {json.loads(m.value)["action_id"] for m in broker.messages("actions")}
    executed = {a["action_id"] for a in summary["actions"] if a["status"] == "executed"}
    assert executed <= published
