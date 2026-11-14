from __future__ import annotations

from collections import Counter

from agentic_soc.correlation import make_alert
from agentic_soc.ingestion.models import from_row
from agentic_soc.rules import RULES, RuleEngine
from conftest import closed_loop


def _replay(mini_soc) -> list:
    events = []
    for stream in ("signin", "flow", "process"):
        events += [
            from_row(r)
            for r in mini_soc.store.events_between(
                stream, mini_soc.sim.config.start, mini_soc.clock
            )
        ]
    events.sort(key=lambda e: e.ingest_time)
    engine = RuleEngine(mini_soc.inventory)
    found = []
    for i in range(0, len(events), 3000):
        engine.add(events[i : i + 3000])
        found += engine.advance(events[min(i + 2999, len(events) - 1)].ingest_time)
    return found + engine.flush()


def test_rules_catch_the_campaign_and_its_look_alikes(mini_soc) -> None:
    found = _replay(mini_soc)
    fired = Counter(row.context["rule"] for row, _ in found)
    malicious = {
        row.context["rule"] for row, _ in found if mini_soc.malicious.intersection(row.event_ids)
    }
    assert {"R01", "R06"} <= malicious  # the password spray and the LSASS dump
    assert fired["R05"] > 0  # encoded PowerShell also fires on benign Intune scripts
    spray = next(row for row, _ in found if row.context["rule"] == "R01")
    assert spray.ips and spray.detector == "rule:R01"
    alert = make_alert(*next((r, s) for r, s in found if r.context["rule"] == "R06"))
    assert alert.detector == "rule:R06" and alert.stream == "process"
    assert alert.techniques == list(RULES["R06"].techniques) and alert.severity == "critical"


def test_rules_baseline_runs_the_closed_loop_with_playbooks(mini_soc) -> None:
    outcome = closed_loop(mini_soc, mode="rules")
    pipeline = outcome.pipeline
    detectors = {
        a.detector for s in pipeline.correlation.incidents.values() for a in s.alerts.values()
    }
    assert detectors and all(d.startswith("rule:") for d in detectors)
    assert set(outcome.summary["decisions"]) <= {"playbook"}
    assert pipeline.drift is None or not pipeline.drift.history
    assert any(a["status"] == "executed" for a in outcome.summary["actions"])
