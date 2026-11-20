"""Render the evaluation results (results.json) as a Markdown report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONFIG_NAMES = {
    "agent": "Agent (scripted analyst) + M1-M3",
    "detectors": "Detectors M1-M3 + playbooks",
    "rules": "Rules + playbooks",
    "agent+retrain": "Agent, M1 retrained on drift",
}


def _name(config: str) -> str:
    if config in CONFIG_NAMES:
        return CONFIG_NAMES[config]
    base, *flags = config.split("+")
    name = (
        f"Agent ({base.split(':', 1)[1]}) + M1-M3"
        if base.startswith("agent:")
        else CONFIG_NAMES.get(base, base)
    )
    if "retrain" in flags:
        name += ", M1 retrained on drift"
    if "verifier" in flags:
        name += ", evidence verifier"
    if "fastblock" in flags:
        name += ", spray blocked before triage"
    return name


def _fmt(value: Any, digits: int = 1, pct: bool = False) -> str:
    if value is None:
        return "–"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if pct:
        return f"{value * 100:.0f}%"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(out)


def _models(models: dict[str, Any]) -> str:
    rows = []
    for kind, m in models["kinds"].items():
        rows.append([kind, str(m["rows"]), str(m["positives"]), _fmt(m["pr_auc"], 3), _fmt(m["roc_auc"], 3),
                     _fmt(m["recall_at_1pct_fpr"], 3), _fmt(m["recall_at_threshold"], 3),
                     _fmt(m["false_positives_per_day"], 1), _fmt(m["precision_at_threshold"], 3)])  # fmt: skip
    table = _table(["Detector", "Windows", "Attack windows", "PR-AUC", "ROC-AUC", "Recall @1% FPR",
                    "Recall @threshold", "FP / day", "Precision"], rows)  # fmt: skip
    delays = []
    for kind, m in models["kinds"].items():
        for stage, values in m["detection_delay_min"].items():
            delays.append([kind, stage, ", ".join(_fmt(v) for v in values)])
    return (
        f"Held-out test weeks {', '.join(models['test_runs'])} ({models['test_days']} days), scored by the "
        "promoted models at their operating thresholds.\n\n"
        + table
        + "\n\nDetection delay: minutes from the start of an attack stage (ground truth) to the end of "
        "the first alerting window covering it, per test week.\n\n"
        + _table(["Detector", "Stage", "Delay (min)"], delays)
    )


def _e2e(summary: dict[str, Any], order: list[str]) -> str:
    header = ["Configuration", "Runs", "Detected", "MTTD (min, median)", "Contained", "MTTC (min, median)",
              "Stopped before exfiltration", "Exfiltrated (GB, mean)", "Furthest stage (mean of 9)",
              "False containments (mean)", "Runs without false containment", "Alerts (mean)",
              "Incidents (mean)", "Alert reduction"]  # fmt: skip
    rows = []
    for config in order:
        s = summary.get(config)
        if not s:
            continue
        rows.append([_name(config), str(s["runs"]), _fmt(s["detected"], pct=True), _fmt(s["mttd_min_median"]),
                     _fmt(s["contained"], pct=True), _fmt(s["mttc_min_median"]),
                     _fmt(s["stopped_before_exfiltration"], pct=True), _fmt(s["exfil_gb_mean"], 2),
                     _fmt(s["furthest_stage_mean"]), _fmt(s["false_containments_mean"]),
                     _fmt(s["runs_without_false_containment"], pct=True), _fmt(s["alerts_mean"], 0),
                     _fmt(s["incidents_mean"], 0), _fmt(s["alert_reduction_mean"], 3)])  # fmt: skip
    return _table(header, rows)


def _tests(tests: dict[str, Any]) -> str:
    rows = []
    for pair, metrics in tests.items():
        for metric, t in metrics.items():
            rows.append([pair.replace("_vs_", " vs "), metric, str(t["n"]), _fmt(t["median_difference"], 2),
                         _fmt(t["p_value"], 4)])  # fmt: skip
    return _table(["Comparison", "Metric", "Paired runs", "Median difference", "Wilcoxon p"], rows)


def _agent(summary: dict[str, Any]) -> str:
    rows = []
    for config, s in summary.items():
        a = s.get("agent")
        if not a:
            continue
        v = a["verdict"]
        rows.append([_name(config), str(a["decisions"]), _fmt(v["precision"], 3), _fmt(v["recall"], 3), _fmt(v["f1"], 3),
                     f"{a['attack_incidents_flagged']}/{a['attack_incidents_decided']}",
                     _fmt(a["action_correctness_mean"], 3), _fmt(a["invalid_tool_call_rate"], 4),
                     _fmt(a["latency_mean_s"]), _fmt(a["latency_p95_s"]), str(a["timeouts"]),
                     str(a["escalated_dismissals"])])  # fmt: skip
    return _table(["Configuration", "Decisions", "Verdict precision", "Verdict recall", "Verdict F1",
                   "Attack incidents flagged", "Action correctness", "Invalid tool calls", "Latency mean (s)",
                   "Latency p95 (s)", "Timeouts", "Escalated dismissals"], rows)  # fmt: skip


def _s1(runs: list[dict[str, Any]]) -> str:
    rows = []
    for r in sorted(runs, key=lambda r: (r["config"], r["seed"])):
        d = r.get("drift") or {}
        rows.append([_name(r["config"]), str(r["seed"]), _fmt(d.get("alarm_delay_h")),
                     f"{_fmt(d.get('false_alerts_per_h_before'), 2)} / {_fmt(d.get('false_alerts_per_busy_h_before'), 2)}",
                     _fmt(d.get("false_alerts_per_h_first_6h"), 2),
                     f"{_fmt(d.get('false_alerts_per_h_next_day'), 2)} ({_fmt(d.get('next_day_vs_before'))}x)",
                     _fmt(d.get("recovery_h")),
                     str(len(d.get("retrains", []))), str(r["false_containments"]),
                     r["furthest_stage"] or "–", _fmt(r["exfil_gb"], 2)])  # fmt: skip
    return _table(["Configuration", "Seed", "Alarm after (h)", "False M1 alerts/h before (all / busy hours)", "…first 6 h",
                   "…next day", "Recovered after (h)", "Retrainings", "False containments", "Furthest stage",
                   "Exfiltrated (GB)"], rows)  # fmt: skip


def _s2(variants: list[dict[str, Any]]) -> str:
    rows = []
    for v in variants:
        for phase in ("before", "burst", "after"):
            p = v["phases"].get(phase)
            if not p:
                continue
            rows.append([f"LLM ×{v['llm_slowdown']:g} in burst", phase, _fmt(p["events_per_wall_s"], 0),
                         _fmt(p["stream_lag_s_p50"], 0), _fmt(p["stream_lag_s_p95"], 0),
                         _fmt(p["stream_lag_wall_s_p95"], 2), str(p["consumer_lag_max"]), str(p["agent_queue_max"])])  # fmt: skip
    table = _table(["Variant", "Phase", "Events consumed / wall s", "Stream lag p50 (sim s)", "Stream lag p95 (sim s)",
                    "Stream lag p95 (wall s)", "Consumer lag max (msgs)", "Agent queue max"], rows)  # fmt: skip
    shed = _table(["Variant", "Event rate in burst", "Routes (agent / playbook)", "Shed to playbooks", "Agent timeouts",
                   "Breaker trips", "Decisions (agent / playbook)", "Campaign"],
                  [[f"LLM ×{v['llm_slowdown']:g} in burst", f"×{_fmt(v['event_rate_multiplier'])}",
                    f"{v['routes'].get('agent', 0)} / {v['routes'].get('playbook', 0)}", str(v["shed_to_playbooks"]),
                    str(v["agent_timeouts"]), str(v["breaker_trips"]),
                    f"{v['decisions'].get('agent', 0)} / {v['decisions'].get('playbook', 0)}",
                    f"{v['campaign']['status']}{' (' + v['campaign']['stall_reason'] + ')' if v['campaign'].get('stall_reason') else ''}"]
                   for v in variants])  # fmt: skip
    return table + "\n\n" + shed


def render(results: dict[str, Any]) -> str:
    parts = ["# Evaluation", "",
             f"Generated {results.get('generated', '')}. Raw numbers: [results.json](results.json).", ""]  # fmt: skip
    if "models" in results:
        parts += ["## Model level (M1-M3)", "", _models(results["models"]), ""]
    if "e2e" in results:
        e2e = results["e2e"]
        configs = [c for c in ("agent", "detectors", "rules") if c in e2e["summary"]]
        configs += [c for c in e2e["summary"] if c not in configs]
        parts += ["## End to end", "",
                  f"{e2e['summary'][configs[0]]['runs']} seeded 48-hour closed-loop runs per configuration on the same "
                  "company (org_seed 7), one attack per run, on weeks after the dataset's test weeks. Times are "
                  "measured from the start of the attack; MTTD counts window and delivery delays, MTTC is the first "
                  "executed action on an entity the attacker used, after the attack started. False containments "
                  "are executed actions on anything else, or on a future victim before the attack.", "", _e2e(e2e["summary"], configs), ""]  # fmt: skip
        if e2e.get("tests"):
            parts += [
                "Paired comparisons over the same seeds (Wilcoxon signed-rank):",
                "",
                _tests(e2e["tests"]),
                "",
            ]
        parts += ["### Triage agent", "", _agent(e2e["summary"]), ""]
    if "llm" in results:
        llm = results["llm"]
        parts += ["### Local LLM (gpt-oss:20b via Ollama)", "", _e2e(llm["summary"], list(llm["summary"])), "",
                  _agent(llm["summary"]), ""]  # fmt: skip
    if "s1" in results:
        parts += [
            "## S1: drift (move to remote work over ZTNA)",
            "",
            "False M1 alerts are sign-in alerts without attack events. Busy hours have at least half the "
            "pre-shift peak sign-in volume. Recovered after: hours from the shift until the false-alert "
            "rate over the last three busy hours is back within twice the pre-shift busy-hour rate (or "
            "that rate plus one); – means not within the run. Next day: the rate 24-36 hours after the "
            "shift, and its ratio to the pre-shift busy-hour rate.",
            "",
            _s1(results["s1"]["runs"]),
            "",
        ]
    if "s2" in results:
        parts += ["## S2: high load (10x event burst)", "", _s2(results["s2"]), ""]
    return "\n".join(parts).rstrip() + "\n"


def write(results: dict[str, Any], out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=1, default=str) + "\n")
    (out / "README.md").write_text(render(results))
    return out / "README.md"
