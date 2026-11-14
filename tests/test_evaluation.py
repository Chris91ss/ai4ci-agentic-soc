"""Evaluation harness: run metrics, aggregation, paired Wilcoxon tests and the report."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from agentic_soc.evaluation import STAGES, aggregate, compare, render, run_metrics
from agentic_soc.evaluation.e2e import RunSpec, seed_start, specs_for
from agentic_soc.evaluation.metrics import percentile, prf

START = datetime(2026, 3, 16, 10, tzinfo=UTC)


def _outcome(actions: list[SimpleNamespace]) -> SimpleNamespace:
    """The parts of a RunOutcome that run_metrics reads, for a campaign starting at START."""
    campaign = {
        "start": START.isoformat(),
        "status": "stalled",
        "exfil_bytes": 0,
        "stage_times": {
            "spray": START.isoformat(),
            "initial_access": (START + timedelta(hours=1)).isoformat(),
        },
        "entities": {"users": ["alice"], "hosts": ["WS-0001"], "ips": ["203.0.113.9"]},
    }
    pipeline = SimpleNamespace(
        store=SimpleNamespace(list_alerts=lambda **_: []),
        actions=SimpleNamespace(actions={a.action_id: a for a in actions}),
        correlation=SimpleNamespace(incidents={}, alert_incident={}),
        cfg=SimpleNamespace(mode="detectors"),
        stats={"events": 100},
        decisions=[],
        log=[],
    )
    return SimpleNamespace(truth={"campaign": campaign, "run": {"seed": 1}}, pipeline=pipeline)


def _action(target: str, at: datetime, status: str = "executed") -> SimpleNamespace:
    return SimpleNamespace(action_id=f"A-{target}-{at:%H%M}", type="revoke_sessions", target=target,
                           status=status, executed_at=at, requested_by="playbook")  # fmt: skip


def test_containment_counts_only_after_the_campaign_started() -> None:
    early = _action("alice", START - timedelta(hours=2))  # the future victim, before the attack
    row = run_metrics(_outcome([early]), set())
    assert row["false_containments"] == 1 and not row["contained"] and row["mttc_min"] is None

    late = _action("alice", START + timedelta(minutes=30))
    bystander = _action("bob", START + timedelta(minutes=5))
    pending = _action("WS-0001", START + timedelta(minutes=1), status="pending_approval")
    row = run_metrics(_outcome([early, late, bystander, pending]), set())
    assert row["contained"] and row["mttc_min"] == 30.0
    assert row["actions_executed"] == 3 and row["actions_on_attack"] == 1
    assert row["false_containments"] == 2
    assert row["furthest_stage"] == "initial_access" and row["furthest_stage_index"] == 2
    assert row["stopped_before_exfiltration"]


def test_decisions_on_merged_incidents_count_for_the_survivor() -> None:
    outcome = _outcome([])
    pipeline = outcome.pipeline
    hostile = {"alert_id": "AL-1", "event_ids": ["ev-1"], "created_at": START + timedelta(minutes=12),
               "model_version": "M1-ip", "detector": "M1"}  # fmt: skip
    pipeline.store = SimpleNamespace(list_alerts=lambda **_: [hostile])
    survivor = SimpleNamespace(incident_id="INC-2", alerts={"AL-1": object()})
    pipeline.correlation = SimpleNamespace(
        incidents={"INC-2": survivor}, alert_incident={"AL-1": "INC-2"}
    )
    pipeline.cfg = SimpleNamespace(mode="agent")
    pipeline.log = [{"kind": "merge", "incident_id": "INC-2", "merged": "INC-3"},
                    {"kind": "merge", "incident_id": "INC-3", "merged": "INC-4"}]  # fmt: skip

    def decision(incident_id: str, verdict: str) -> dict:
        return {"incident_id": incident_id, "decided_by": "agent", "verdict": verdict,
                "latency_s": 60.0, "decision": {}}  # fmt: skip

    pipeline.decisions = [decision("INC-4", "malicious")]  # absorbed twice, into INC-3 then INC-2
    verdict = run_metrics(outcome, {"ev-1"})["agent"]["verdict"]
    assert (verdict["tp"], verdict["fp"], verdict["fn"]) == (1, 0, 0)
    pipeline.decisions.append(decision("INC-2", "suspicious"))  # the survivor's later decision wins
    verdict = run_metrics(outcome, {"ev-1"})["agent"]["verdict"]
    assert (verdict["tp"], verdict["fp"], verdict["fn"]) == (0, 0, 1)


def test_run_metrics_on_the_closed_loop(agent_run) -> None:
    row = run_metrics(agent_run, agent_run.simulator.labels.malicious_ids())
    assert row["mode"] == "agent" and row["furthest_stage"] in STAGES
    assert row["detected"] and row["mttd_min"] >= 0
    assert row["actions_executed"] == row["actions_on_attack"] + row["false_containments"]
    assert row["mttc_min"] is None or row["mttc_min"] >= 0
    assert 0 < row["incidents"] <= row["alerts"]
    agent = row["agent"]
    assert agent["decisions"] > 0 and agent["verdict"]["tp"] + agent["verdict"]["fn"] > 0
    assert agent["latency_mean_s"] > 0


def _row(config: str, seed: int, **values) -> dict:
    row = {
        "config": config, "seed": seed, "furthest_stage": "discovery", "furthest_stage_index": 3,
        "detected": True, "mttd_min": 10.0, "contained": True, "mttc_min": 20.0,
        "stopped_before_exfiltration": True, "exfil_gb": 0.0, "false_containments": 0,
        "actions_executed": 2, "alerts": 100, "incidents": 10, "alert_reduction": 0.9, "wall_s": 60.0,
    }  # fmt: skip
    return row | values


def test_aggregate_and_paired_tests() -> None:
    rows = [_row("agent", s) for s in range(8)]
    rows += [
        _row("detectors", s, false_containments=3 + s % 2, mttc_min=12.0 + s) for s in range(8)
    ]
    rows.append({"config": "detectors", "seed": 99, "error": "boom"})
    summary = aggregate(rows)
    assert summary["agent"]["runs"] == 8 and summary["detectors"]["runs"] == 8
    assert summary["agent"]["false_containments_total"] == 0
    assert summary["detectors"]["false_containments_mean"] == 3.5
    assert summary["agent"]["stopped_before_exfiltration"] == 1.0
    assert summary["agent"]["furthest_stage"] == {"discovery": 8}

    tests = compare(rows)["agent_vs_detectors"]
    assert tests["false_containments"]["n"] == 8
    assert tests["false_containments"]["median_difference"] == -3.5
    assert tests["false_containments"]["p_value"] < 0.05
    assert tests["exfil_gb"]["p_value"] is None  # no differences at all


def test_report_renders_every_section() -> None:
    rows = [_row("agent", s) for s in range(3)] + [_row("rules", s) for s in range(3)]
    results = {
        "generated": "now",
        "e2e": {"runs": rows, "summary": aggregate(rows), "tests": compare(rows)},
    }
    text = render(results)
    assert "# " in text and "results.json" in text
    assert "Agent" in text and "rules" in text.lower()


def test_seeds_start_on_successive_mondays() -> None:
    specs = specs_for(["agent", "rules"], [401, 402], hours=24)
    assert [s.name for s in specs] == [
        "agent-seed401",
        "rules-seed401",
        "agent-seed402",
        "rules-seed402",
    ]
    starts = [datetime.fromisoformat(seed_start(i)) for i in range(3)]
    assert all(t.weekday() == 0 for t in starts) and starts[1] - starts[0] == timedelta(days=7)
    assert (
        RunSpec(mode="agent", seed=1, llm="ollama:gpt-oss:20b", retrain_on_drift=True).label
        == "agent:gpt-oss:20b+retrain"
    )


def test_metric_helpers() -> None:
    assert percentile([], 0.5) is None
    assert percentile([1, 2, 3, 4, 5], 0.95) == 5
    assert prf(0, 0, 0)["f1"] is None
    assert prf(3, 1, 1)["f1"] == pytest.approx(0.75)
