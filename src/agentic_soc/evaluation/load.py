"""Scenario S2 (high load) on the event broker.

The simulator runs in its own process, publishing to Redpanda at a fixed speed, while the SOC
pipeline consumes the topics in this process with the agent on its worker thread. Every half
second a sampler records the consumer lag (messages), the stream lag (how far the pipeline's
view trails the simulation clock), throughput and the agent queue. A burst multiplies user
activity for an hour; the router sheds load to playbooks when the agent queue saturates.
"""

from __future__ import annotations

import multiprocessing as mp
import tempfile
import threading
import time
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any

from agentic_soc.evaluation.metrics import parse_time, percentile


def _simulate(
    config_json: str, broker_url: str, speed: float, clock: Any, done: Any, truth: Any
) -> None:
    import json

    from agentic_soc.broker import connect
    from agentic_soc.simulator import Simulator, SimulatorConfig
    from agentic_soc.simulator.live import LiveSimulator

    sim = Simulator(SimulatorConfig.model_validate_json(config_json))
    live = LiveSimulator(sim, connect(broker_url), speed=speed, group=f"s2-sim-{time.time_ns()}")
    wall0, sim0 = time.monotonic(), sim.clock
    while not sim.finished:
        live.step()
        clock.value = sim.clock.timestamp()
        delay = wall0 + (sim.clock - sim0).total_seconds() / speed - time.monotonic()
        if delay > 0:
            time.sleep(delay)
    live.publish(sim.drain())
    live.producer.flush()
    for _ in range(20):  # containment published at the very end still reaches the simulator
        live.apply_pending_actions()
        time.sleep(0.1)
    truth.put(json.dumps(sim.truth(), default=str))
    done.value = 1


def _phase(t: float, burst: tuple[float, float]) -> str:
    return "before" if t < burst[0] else "burst" if t < burst[1] else "after"


def run_s2(
    models: str = "models",
    broker_url: str = "kafka://localhost:19092",
    seed: int = 501,
    speed: float = 120.0,
    hours: float = 6.0,
    burst_at_h: float = 3.0,
    burst_h: float = 1.0,
    factor: float = 11.5,
    triage_s: float = 60.0,
    llm_slowdown: float = 1.0,
    calls_per_triage: int = 8,
    sample_s: float = 0.5,
    drain_timeout_s: float = 900.0,
) -> dict[str, Any]:
    from agentic_soc import topics
    from agentic_soc.broker import connect
    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.detectors.service import LocalDetectorClient
    from agentic_soc.ingestion import Inventory
    from agentic_soc.pipeline import PipelineConfig, SocPipeline
    from agentic_soc.pipeline.service import run_live
    from agentic_soc.simulator import Simulator, load_config
    from agentic_soc.storage import Store

    overrides = {
        "seed": seed,
        "org_seed": 7,
        "start": "2026-03-17T05:00:00Z",  # a Tuesday morning
        "duration_h": hours,
        "burst": {"enabled": True, "at_h": burst_at_h, "duration_h": burst_h, "factor": factor},
        "campaign": {"start_offset_h": 1.0, "start_jitter_h": 0.0},
    }
    config = load_config(overrides=overrides)
    inventory = Inventory.from_enterprise(Simulator(config).ent)
    detectors = ModelRegistry(models).load_set()
    broker = connect(broker_url)
    group = f"s2-soc-{seed}-{time.time_ns()}"
    # The agent's latency in simulated time is its wall-clock latency times the speed: a call
    # delay of triage_s / speed / calls makes a triage take about triage_s simulated seconds.
    llm_delay_s = triage_s / speed / calls_per_triage
    stream_topics = list(topics.STREAM_TOPICS.values())
    burst = (
        config.start + timedelta(hours=burst_at_h),
        config.start + timedelta(hours=burst_at_h + burst_h),
    )
    window_start, window_end = burst[0].timestamp(), burst[1].timestamp()
    with tempfile.TemporaryDirectory(prefix="soc-s2-") as tmp:
        store = Store(f"sqlite:///{Path(tmp) / 'soc.db'}")
        store.init_schema()
        pipeline_config = PipelineConfig(mode="agent", worker="threaded", llm="scripted", llm_delay_s=llm_delay_s,
                                         consumer_group=group, from_beginning=False)  # fmt: skip
        pipeline = SocPipeline(
            inventory,
            LocalDetectorClient(detectors),
            detectors.profiles,
            store,
            broker,
            pipeline_config,
        )
        stop = threading.Event()
        consumer = threading.Thread(
            target=run_live,
            args=(pipeline,),
            kwargs={"stop": stop, "poll_timeout": 0.2},
            daemon=True,
        )
        consumer.start()
        ctx = mp.get_context("spawn")
        clock, done, truth_queue = (
            ctx.Value("d", config.start.timestamp()),
            ctx.Value("i", 0),
            ctx.Queue(),
        )
        simulator = ctx.Process(
            target=_simulate,
            args=(config.model_dump_json(), broker_url, speed, clock, done, truth_queue),
        )
        simulator.start()
        samples: list[dict[str, Any]] = []
        wall0 = time.monotonic()
        finished_at = None
        llm = pipeline.worker.agent.llm if pipeline.worker is not None else None
        while True:
            time.sleep(sample_s)
            lag = sum(broker.lag(group, stream_topics).values())
            sim_t = clock.value
            if llm is not None:  # a local LLM sharing the host slows down under the burst
                busy = window_start <= sim_t < window_end
                llm.delay_s = llm_delay_s * (llm_slowdown if busy else 1.0)
            seen = pipeline.clock.timestamp() if pipeline.clock else None
            samples.append({
                "wall_s": round(time.monotonic() - wall0, 2), "sim_t": sim_t, "pipeline_t": seen,
                "stream_lag_s": round(sim_t - seen, 1) if seen else None, "lag_messages": lag,
                "events": pipeline.stats["events"], "queue": pipeline.router.queue_length,
                "agent_busy": bool(pipeline.worker and pipeline.worker.busy),
            })  # fmt: skip
            if not done.value and not simulator.is_alive():
                stop.set()
                raise RuntimeError(f"the simulator process died (exit code {simulator.exitcode})")
            if done.value and finished_at is None:
                finished_at = time.monotonic()
            if finished_at is not None and (
                lag == 0 or time.monotonic() - finished_at > drain_timeout_s
            ):
                break
        truth = __import__("json").loads(truth_queue.get(timeout=60))
        simulator.join(timeout=30)
        time.sleep(2)
        stop.set()
        consumer.join(timeout=60)
        worker = getattr(pipeline.worker, "pool", None)
        if worker is not None:
            worker.shutdown(wait=True)  # an abandoned triage still uses the store
        summary = _summarise(samples, burst, speed, pipeline, truth, config)
        store.engine.dispose()
    return summary | {
        "seed": seed,
        "speed": speed,
        "factor": factor,
        "triage_s": triage_s,
        "llm_slowdown": llm_slowdown,
        "samples": samples,
    }


def _summarise(samples: list[dict[str, Any]], burst: tuple[Any, Any], speed: float, pipeline: Any, truth: dict[str, Any],
               config: Any) -> dict[str, Any]:  # fmt: skip
    window = (burst[0].timestamp(), burst[1].timestamp())
    phases: dict[str, Any] = {}
    for phase in ("before", "burst", "after"):
        rows = [
            s
            for s in samples
            if _phase(s["sim_t"], window) == phase and s["stream_lag_s"] is not None
        ]
        if len(rows) < 2:
            continue
        lags = [s["stream_lag_s"] for s in rows]
        wall = rows[-1]["wall_s"] - rows[0]["wall_s"]
        phases[phase] = {
            "samples": len(rows),
            "stream_lag_s_p50": percentile(lags, 0.5),
            "stream_lag_s_p95": percentile(lags, 0.95),
            "stream_lag_s_max": max(lags),
            "stream_lag_wall_s_p95": round((percentile(lags, 0.95) or 0) / speed, 2),
            "consumer_lag_max": max(s["lag_messages"] for s in rows),
            "consumer_lag_p95": percentile([s["lag_messages"] for s in rows], 0.95),
            "events_per_wall_s": round(
                (rows[-1]["events"] - rows[0]["events"]) / max(wall, 1e-9), 1
            ),
            "agent_queue_max": max(s["queue"] for s in rows),
        }
    routes = [e for e in pipeline.log if e["kind"] == "route"]

    def in_burst(e: dict[str, Any]) -> bool:
        t = parse_time(e["time"])
        return t is not None and burst[0] <= t < burst[1] + timedelta(hours=1)

    shed = [
        e
        for e in routes
        if e["route"] == "playbook" and ("saturated" in e["reason"] or "breaker" in e["reason"])
    ]
    campaign = truth["campaign"]
    return {
        "phases": phases,
        "routes": dict(Counter(e["route"] for e in routes)),
        "routes_during_burst": dict(Counter(e["route"] for e in routes if in_burst(e))),
        "event_rate_multiplier": _multiplier(pipeline, burst),
        "shed_to_playbooks": len(shed),
        "shed_during_burst": sum(1 for e in shed if in_burst(e)),
        "agent_timeouts": pipeline.stats.get("agent_timeouts", 0),
        "breaker_trips": pipeline.router.breaker.trips,
        "decisions": {
            by: sum(1 for d in pipeline.decisions if d["decided_by"] == by)
            for by in {d["decided_by"] for d in pipeline.decisions}
        },
        "events": pipeline.stats["events"],
        "campaign": {
            "status": campaign.get("status"),
            "stall_reason": campaign.get("stall_reason"),
            "exfil_gb": round((campaign.get("exfil_bytes") or 0) / 1e9, 3),
        },
        "burst": {
            "start": burst[0].isoformat(),
            "end": burst[1].isoformat(),
            "factor": config.burst.factor,
        },
    }


def _multiplier(pipeline: Any, burst: tuple[Any, Any]) -> float | None:
    """Events in the burst hour over the mean of the two hours before it."""
    counts = pipeline.store.stream_counts(burst[0] - timedelta(hours=2), burst[1], bucket_s=3600)
    per_hour: dict[Any, int] = {}
    for row in counts:
        per_hour[row["bucket"]] = per_hour.get(row["bucket"], 0) + row["count"]
    before = [n for t, n in per_hour.items() if t < burst[0]]
    during = [n for t, n in per_hour.items() if burst[0] <= t < burst[1]]
    if not before or not during:
        return None
    return round(sum(during) / len(during) / (sum(before) / len(before)), 2)
