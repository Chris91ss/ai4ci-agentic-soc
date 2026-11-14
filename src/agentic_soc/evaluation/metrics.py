"""Metrics of one closed-loop run against the simulator's ground truth.

- Detection: time from the start of the attack to the first alert that contains a malicious
  event (as raised by the pipeline, so window and delivery delays count).
- Containment: time to the first executed action on an entity the attacker used, how far the
  attack got along the kill chain, whether it was stopped before exfiltration and how much data
  left, and false containments (executed actions on entities the attacker never used).
- Triage: alert-to-incident reduction; for the agent, verdict precision/recall/F1 on the
  incidents it decided (an incident is an attack if any of its alerts holds a malicious event),
  correctness of its actions, invalid tool-call rate and latency.
"""

from __future__ import annotations

import statistics
from collections import Counter
from datetime import UTC, datetime
from typing import Any

STAGES = [
    "spray",
    "initial_access",
    "discovery",
    "execution",
    "command_and_control",
    "credential_access",
    "lateral_movement",
    "collection",
    "exfiltration",
]


def parse_time(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def minutes(a: datetime | None, b: datetime | None) -> float | None:
    if a is None or b is None:
        return None
    return round((b - a).total_seconds() / 60, 1)


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))], 2)


def prf(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall
        else (0.0 if tp + fp + fn else None)
    )
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def run_metrics(outcome: Any, labels: set[str]) -> dict[str, Any]:
    """``outcome``: a RunOutcome; ``labels``: ids of the malicious events of the run."""
    truth = outcome.truth
    campaign = truth["campaign"]
    pipeline = outcome.pipeline
    store = pipeline.store
    start = parse_time(campaign.get("start"))
    entities = campaign.get("entities", {"users": [], "hosts": [], "ips": []})
    attack = set(entities["users"]) | set(entities["hosts"]) | set(entities["ips"])

    alerts = store.list_alerts(limit=10_000_000)
    hostile = [a for a in alerts if labels.intersection(a["event_ids"])]
    first_alert = min((parse_time(a["created_at"]) for a in hostile), default=None)
    detectors_on_attack = sorted({a["model_version"] or a["detector"] for a in hostile})

    executed = [a for a in pipeline.actions.actions.values() if a.status == "executed"]

    def contains_attack(action: Any) -> bool:
        # An action on a future victim before the campaign started was a false positive too.
        at = parse_time(action.executed_at)
        return action.target in attack and start is not None and at is not None and at >= start

    on_attack = [a for a in executed if contains_attack(a)]
    false = [a for a in executed if not contains_attack(a)]
    first_containment = min((a.executed_at for a in on_attack if a.executed_at), default=None)

    reached = [stage for stage in STAGES if stage in campaign.get("stage_times", {})]
    furthest = reached[-1] if reached else None

    incidents = list(pipeline.correlation.incidents.values())
    n_alerts = len(pipeline.correlation.alert_incident)
    hostile_ids = {a["alert_id"] for a in hostile}
    attack_incidents = [s for s in incidents if hostile_ids.intersection(s.alerts)]

    row: dict[str, Any] = {
        "mode": pipeline.cfg.mode,
        "seed": truth["run"]["seed"],
        "campaign_start": campaign.get("start"),
        "campaign_status": campaign.get("status"),
        "stall_reason": campaign.get("stall_reason"),
        "furthest_stage": furthest,
        "furthest_stage_index": STAGES.index(furthest) + 1 if furthest else 0,
        "detected": first_alert is not None,
        "mttd_min": minutes(start, first_alert),
        "detectors_on_attack": detectors_on_attack,
        "contained": first_containment is not None,
        "mttc_min": minutes(start, first_containment),
        # Stalled by containment with no data out (a run ending mid-attack does not count).
        "stopped_before_exfiltration": campaign.get("status") == "stalled"
        and not campaign.get("exfil_bytes"),
        "exfil_gb": round((campaign.get("exfil_bytes") or 0) / 1e9, 3),
        "actions_executed": len(executed),
        "actions_on_attack": len(on_attack),
        "false_containments": len(false),
        "false_containments_by_type": dict(Counter(a.type for a in false)),
        "alerts": n_alerts,
        "incidents": len(incidents),
        "attack_incidents": len(attack_incidents),
        "alert_to_incident_ratio": round(n_alerts / len(incidents), 2) if incidents else None,
        "alert_reduction": round(1 - len(incidents) / n_alerts, 4) if n_alerts else None,
        "events": pipeline.stats["events"],
        "drift_alarms": pipeline.stats.get("drift_alarms", 0),
        "retrains": pipeline.stats.get("retrains", 0),
    }

    decisions = pipeline.decisions
    # A merged incident lives on in the incident that absorbed it, so decisions taken before the
    # merge count for the survivor (whose own later decisions replace them).
    survivor = {e["merged"]: e["incident_id"] for e in pipeline.log if e["kind"] == "merge"}

    def final(incident_id: str) -> str:
        seen: set[str] = set()
        while incident_id in survivor and incident_id not in seen:
            seen.add(incident_id)
            incident_id = survivor[incident_id]
        return incident_id

    latest: dict[str, dict[str, Any]] = {}
    for record in decisions:
        incident_id = final(record["incident_id"])
        latest[incident_id] = record | {"incident_id": incident_id}
    attack_set = {s.incident_id for s in attack_incidents}
    agent = [d for d in latest.values() if d["decided_by"] == "agent"]
    if pipeline.cfg.mode == "agent":
        tp = sum(1 for d in agent if d["verdict"] == "malicious" and d["incident_id"] in attack_set)
        fp = sum(
            1 for d in agent if d["verdict"] == "malicious" and d["incident_id"] not in attack_set
        )
        fn = sum(1 for d in agent if d["verdict"] != "malicious" and d["incident_id"] in attack_set)
        flagged = sum(
            1 for d in agent if d["verdict"] != "benign" and d["incident_id"] in attack_set
        )
        dismissed_attacks = sum(
            1
            for d in agent
            if d["decision"].get("original_verdict") == "benign" and d["incident_id"] in attack_set
        )
        stats = pipeline.stats
        calls = stats.get("agent_tool_calls", 0) + stats.get("agent_invalid_tool_calls", 0)
        agent_actions = [a for a in executed if a.requested_by == "agent"]
        latencies = [d["latency_s"] for d in decisions if d["decided_by"] == "agent"]
        row["agent"] = {
            "decisions": len([d for d in decisions if d["decided_by"] == "agent"]),
            "incidents_decided": len(agent),
            "verdict": prf(tp, fp, fn),
            "attack_incidents_flagged": flagged,
            "attack_incidents_decided": sum(1 for d in agent if d["incident_id"] in attack_set),
            "attack_dismissals_escalated": dismissed_attacks,
            "action_correctness": round(
                sum(contains_attack(a) for a in agent_actions) / len(agent_actions), 4
            )
            if agent_actions
            else None,
            "invalid_tool_call_rate": round(stats.get("agent_invalid_tool_calls", 0) / calls, 4)
            if calls
            else None,
            "llm_calls": stats.get("agent_llm_calls", 0),
            "tool_calls": stats.get("agent_tool_calls", 0),
            "invalid_tool_calls": stats.get("agent_invalid_tool_calls", 0),
            "latency_mean_s": round(statistics.fmean(latencies), 1) if latencies else None,
            "latency_p95_s": percentile(latencies, 0.95),
            "timeouts": stats.get("agent_timeouts", 0),
            "failures": stats.get("agent_failures", 0),
            "escalated_dismissals": stats.get("dismissals_escalated", 0),
        }
    return row
