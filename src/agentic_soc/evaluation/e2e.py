"""End-to-end evaluation: seeded closed-loop runs of the agent and of the two baselines.

Every configuration sees the same seeds (company org_seed 7, one attack per run on weeks after
the dataset's test weeks), so results can be compared run by run (paired Wilcoxon tests).
Runs execute in parallel worker processes.
"""

from __future__ import annotations

import os
import statistics
import tempfile
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agentic_soc.evaluation.metrics import percentile, prf

EVAL_START = datetime(2026, 3, 16, tzinfo=UTC)  # a Monday after the dataset's test weeks


@dataclass(frozen=True)
class RunSpec:
    mode: str
    seed: int
    hours: float = 48.0
    start: str = ""
    scenarios: tuple[str, ...] = ()
    llm: str = "scripted"
    retrain_on_drift: bool = False
    verifier: bool = False
    fast_block: bool = False
    models: str = "models"
    overrides: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """Configuration name: the scripted analyst is "agent", a real LLM "agent:<model>"."""
        base = self.mode
        if self.mode == "agent" and self.llm != "scripted":
            base = f"agent:{self.llm.split(':', 1)[-1]}"
        return (
            base
            + ("+retrain" if self.retrain_on_drift else "")
            + ("+verifier" if self.verifier else "")
            + ("+fastblock" if self.fast_block else "")
        )

    @property
    def name(self) -> str:
        return f"{self.label}-seed{self.seed}"


def seed_start(index: int) -> str:
    """Runs on successive Mondays, so the calendar position of the attack varies too."""
    return (EVAL_START + timedelta(days=7 * index)).isoformat()


def run_one(spec: RunSpec) -> dict[str, Any]:
    """Run one closed loop and return its metrics (executed in a worker process)."""
    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.evaluation.metrics import run_metrics
    from agentic_soc.pipeline import InProcessRun, PipelineConfig
    from agentic_soc.simulator import Simulator, load_config
    from agentic_soc.simulator.config import deep_merge
    from agentic_soc.storage import Store

    started = time.perf_counter()
    overrides = deep_merge(
        {"seed": spec.seed, "org_seed": 7, "duration_h": spec.hours}, dict(spec.overrides)
    )
    if spec.start:
        overrides["start"] = spec.start
    config = load_config(None, *spec.scenarios, overrides=overrides)
    sim = Simulator(config)
    with tempfile.TemporaryDirectory(prefix="soc-eval-") as tmp:
        store = Store(f"sqlite:///{Path(tmp) / 'soc.db'}")
        store.init_schema()
        pipeline_config = PipelineConfig(
            mode=spec.mode,
            llm=spec.llm,
            retrain_on_drift=spec.retrain_on_drift,
            verifier=spec.verifier,
            fast_block=spec.fast_block,
        )  # type: ignore[arg-type]
        runner = InProcessRun(sim, ModelRegistry(spec.models).load_set(), pipeline_config, store)
        outcome = runner.run()
        row = run_metrics(outcome, sim.labels.malicious_ids())
        row["drift"] = (
            drift_metrics(outcome, sim.labels.malicious_ids()) if config.drift.enabled else None
        )
        store.engine.dispose()
    row |= {
        "name": spec.name,
        "config": spec.label,
        "start": config.start.isoformat(),
        "wall_s": round(time.perf_counter() - started, 1),
    }
    return row


def drift_metrics(outcome: Any, labels: set[str]) -> dict[str, Any]:
    """Scenario S1: alarm delay, false M1 alerts per hour around the shift, recovery time."""
    from agentic_soc.evaluation.metrics import parse_time

    config = outcome.simulator.config
    onset = config.start + timedelta(hours=config.drift.at_h)
    store = outcome.pipeline.store
    benign = sorted(
        parse_time(a["created_at"])  # type: ignore[misc]
        for a in store.list_alerts(detector="M1", limit=10_000_000)
        if not labels.intersection(a["event_ids"])
    )
    end = outcome.simulator.end

    def rate(a: datetime, b: datetime) -> float:
        hours = max((b - a).total_seconds() / 3600, 1e-9)
        return round(sum(1 for t in benign if a <= t < b) / hours, 2)

    baseline = rate(config.start + timedelta(hours=6), onset)
    alarms = [parse_time(e["time"]) for e in outcome.pipeline.log if e["kind"] == "drift_alarm"]
    retrains = [parse_time(e["time"]) for e in outcome.pipeline.log if e["kind"] == "retrain"]
    first_alarm = next((t for t in alarms if t and t >= onset), None)
    # Recovery is judged on busy hours (sign-in volume at least half the pre-shift peak): at night
    # there is nothing to raise false alerts on, so a quiet night is not a recovery.
    signins: dict[datetime, int] = {}
    for row in store.stream_counts(config.start, end, bucket_s=3600):
        if row["stream"] == "signin":
            signins[row["bucket"]] = signins.get(row["bucket"], 0) + row["count"]
    peak = max((n for t, n in signins.items() if t < onset), default=0)
    busy = sorted(t for t, n in signins.items() if peak and n >= peak / 2)
    busy_before = [
        rate(t, t + timedelta(hours=1))
        for t in busy
        if config.start + timedelta(hours=6) <= t < onset
    ]
    busy_baseline = sum(busy_before) / len(busy_before) if busy_before else baseline
    limit = max(2 * busy_baseline, busy_baseline + 1)
    after = [t for t in busy if t >= onset]
    rates = [rate(t, t + timedelta(hours=1)) for t in after]
    # Recovered at the first busy hour whose trailing three busy hours are back within the limit;
    # whether that lasts shows in the next day's rate.
    recovered = next(
        (
            t
            for i, t in enumerate(after)
            if sum(rates[max(0, i - 2) : i + 1]) / len(rates[max(0, i - 2) : i + 1]) <= limit
        ),
        None,
    )
    next_day = rate(onset + timedelta(hours=24), onset + timedelta(hours=36))
    hourly = []
    t = config.start
    while t < end:
        hourly.append({"hour": t.isoformat(), "false_alerts": rate(t, t + timedelta(hours=1))})
        t += timedelta(hours=1)
    return {
        "onset": onset.isoformat(),
        "alarm_delay_h": round((first_alarm - onset).total_seconds() / 3600, 2)
        if first_alarm
        else None,
        "alarms": len(alarms),
        "retrains": [r.isoformat() for r in retrains if r],
        "false_alerts_per_h_before": baseline,
        "false_alerts_per_busy_h_before": round(busy_baseline, 2),
        "busy_hours_after": len(after),
        "false_alerts_per_h_first_6h": rate(onset, onset + timedelta(hours=6)),
        "false_alerts_per_h_next_day": next_day,
        "next_day_vs_before": round(next_day / busy_baseline, 1) if busy_baseline else None,
        "recovery_h": round((recovered - onset).total_seconds() / 3600, 1) if recovered else None,
        "hourly_false_alerts": hourly,
    }


THREAD_VARS = (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)


def run_many(specs: list[RunSpec], workers: int = 4, progress: Any = None) -> list[dict[str, Any]]:
    # One thread per worker: OpenMP (LightGBM) and BLAS otherwise start a thread per core in
    # every process, and N workers oversubscribe the machine many times over. Workers are
    # spawned while tasks are submitted and inherit the environment then.
    saved = {var: os.environ.get(var) for var in THREAD_VARS}
    os.environ.update(dict.fromkeys(THREAD_VARS, "1"))
    try:
        return _run_pool(specs, workers, progress)
    finally:
        for var, value in saved.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value


def _run_pool(specs: list[RunSpec], workers: int, progress: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_one, spec): spec for spec in specs}
        for future in as_completed(futures):
            spec = futures[future]
            try:
                row = future.result()
            except Exception as exc:  # a failed run is reported, not fatal
                row = {"name": spec.name, "config": spec.label, "mode": spec.mode,
                       "seed": spec.seed, "error": repr(exc)}  # fmt: skip
            rows.append(row)
            if progress is not None:
                progress(row, len(rows), len(specs))
    return sorted(rows, key=lambda r: (r.get("config", ""), r.get("seed", 0)))


def _mean(values: list[float | None]) -> float | None:
    clean = [v for v in values if v is not None]
    return round(statistics.fmean(clean), 2) if clean else None


def _median(values: list[float | None]) -> float | None:
    clean = [v for v in values if v is not None]
    return round(statistics.median(clean), 2) if clean else None


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per configuration: rates, central values and spreads over the seeds."""
    out: dict[str, Any] = {}
    for config in sorted({r["config"] for r in rows if "error" not in r}):
        runs = [r for r in rows if r["config"] == config and "error" not in r]
        n = len(runs)
        stages = Counter(r["furthest_stage"] or "none" for r in runs)
        summary: dict[str, Any] = {
            "runs": n,
            "detected": sum(r["detected"] for r in runs) / n,
            "mttd_min_median": _median([r["mttd_min"] for r in runs]),
            "mttd_min_mean": _mean([r["mttd_min"] for r in runs]),
            "contained": sum(r["contained"] for r in runs) / n,
            "mttc_min_median": _median([r["mttc_min"] for r in runs]),
            "mttc_min_mean": _mean([r["mttc_min"] for r in runs]),
            "stopped_before_exfiltration": sum(r["stopped_before_exfiltration"] for r in runs) / n,
            "exfil_gb_mean": _mean([r["exfil_gb"] for r in runs]),
            "furthest_stage_mean": _mean([r["furthest_stage_index"] for r in runs]),
            "furthest_stage": dict(stages),
            "false_containments_mean": _mean([r["false_containments"] for r in runs]),
            "false_containments_total": sum(r["false_containments"] for r in runs),
            "runs_without_false_containment": sum(r["false_containments"] == 0 for r in runs) / n,
            "actions_executed_mean": _mean([r["actions_executed"] for r in runs]),
            "alerts_mean": _mean([r["alerts"] for r in runs]),
            "incidents_mean": _mean([r["incidents"] for r in runs]),
            "alert_reduction_mean": _mean([r["alert_reduction"] for r in runs]),
            "wall_s_mean": _mean([r["wall_s"] for r in runs]),
        }
        agents = [r["agent"] for r in runs if r.get("agent")]
        if agents:
            tp = sum(a["verdict"]["tp"] for a in agents)
            fp = sum(a["verdict"]["fp"] for a in agents)
            fn = sum(a["verdict"]["fn"] for a in agents)
            calls = sum(a["tool_calls"] for a in agents)
            invalid = sum(a["invalid_tool_calls"] for a in agents)
            summary["agent"] = {
                "decisions": sum(a["decisions"] for a in agents),
                "verdict": prf(tp, fp, fn),
                "attack_incidents_flagged": sum(a["attack_incidents_flagged"] for a in agents),
                "attack_incidents_decided": sum(a["attack_incidents_decided"] for a in agents),
                "action_correctness_mean": _mean([a["action_correctness"] for a in agents]),
                "invalid_tool_call_rate": round(invalid / (calls + invalid), 4)
                if calls + invalid
                else None,
                "latency_mean_s": _mean([a["latency_mean_s"] for a in agents]),
                "latency_p95_s": percentile(
                    [a["latency_p95_s"] for a in agents if a["latency_p95_s"]], 0.95
                ),
                "timeouts": sum(a["timeouts"] for a in agents),
                "escalated_dismissals": sum(a["escalated_dismissals"] for a in agents),
            }
        out[config] = summary
    return out


def compare(rows: list[dict[str, Any]], reference: str = "agent") -> dict[str, Any]:
    """Paired Wilcoxon signed-rank tests of the reference configuration against each other one."""
    from scipy.stats import wilcoxon

    by = {(r["config"], r["seed"]): r for r in rows if "error" not in r}
    seeds = sorted({seed for config, seed in by if config == reference})
    out: dict[str, Any] = {}
    for other in sorted({config for config, _ in by if config != reference}):
        pairs = [(by[(reference, s)], by[(other, s)]) for s in seeds if (other, s) in by]
        tests = {}
        for metric in (
            "false_containments",
            "furthest_stage_index",
            "exfil_gb",
            "mttc_min",
            "incidents",
        ):
            a = [x[metric] for x, y in pairs if x[metric] is not None and y[metric] is not None]
            b = [y[metric] for x, y in pairs if x[metric] is not None and y[metric] is not None]
            diffs = [p - q for p, q in zip(a, b, strict=True)]
            if len(diffs) >= 5 and any(diffs):
                result = wilcoxon(a, b, zero_method="zsplit")
                tests[metric] = {
                    "n": len(diffs),
                    "median_difference": _median(diffs),
                    "p_value": round(float(result.pvalue), 4),
                }
            else:
                tests[metric] = {
                    "n": len(diffs),
                    "median_difference": _median(diffs) if diffs else None,
                    "p_value": None,
                }
        out[f"{reference}_vs_{other}"] = tests
    return out


def specs_for(
    modes: list[str], seeds: list[int], hours: float = 48.0, models: str = "models", **kwargs: Any
) -> list[RunSpec]:
    """``modes``: agent, detectors or rules, optionally with options such as agent+fastblock."""
    options = {"fastblock": "fast_block", "verifier": "verifier"}
    specs = []
    for i, seed in enumerate(seeds):
        for config in modes:
            mode, *extra = config.split("+")
            unknown = [o for o in extra if o not in options]
            if unknown:
                raise ValueError(f"unknown option {unknown[0]!r} in {config!r}")
            flags = {options[o]: True for o in extra}
            specs.append(RunSpec(mode=mode, seed=seed, hours=hours, start=seed_start(i),
                                 models=models, **(kwargs | flags)))  # fmt: skip
    return specs


def as_dict(spec: RunSpec) -> dict[str, Any]:
    return asdict(spec)
