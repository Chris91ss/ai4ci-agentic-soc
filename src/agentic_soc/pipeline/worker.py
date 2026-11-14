"""Triage workers: run the agent on queued incidents and apply decisions after its latency.

The virtual-time worker is used when the pipeline drives the simulator itself (evaluation and
demo runs): the agent is called synchronously, but its decision only takes effect once the
simulation clock has advanced by the agent's latency (wall-clock latency for a real LLM, a
per-call cost for the scripted analyst). Meanwhile the attack goes on, as it would in reality.
A decision later than the router's timeout is discarded and a playbook decides instead.

The threaded worker is used in live mode against the broker, where time is the stream's.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from agentic_soc.agent import TriageAgent, TriageResult
from agentic_soc.correlation import priority_of
from agentic_soc.pipeline.staging import StagedProposal

if TYPE_CHECKING:
    from agentic_soc.pipeline.core import SocPipeline


@dataclass
class TriageJob:
    incident_id: str
    started: datetime
    done_at: datetime
    result: TriageResult
    timed_out: bool
    staged: list[StagedProposal] = field(default_factory=list)
    risk: float = 0.0  # what the agent saw when it started
    tactics: frozenset[str] = frozenset()


class VirtualTimeAgentWorker:
    def __init__(
        self,
        pipeline: SocPipeline,
        agent: TriageAgent,
        seconds_per_llm_call: float | None = None,
        wall_time_scale: float = 1.0,
    ) -> None:
        self.pipeline = pipeline
        self.agent = agent
        self.seconds_per_llm_call = seconds_per_llm_call
        self.wall_time_scale = wall_time_scale
        self.job: TriageJob | None = None
        self.completed: list[TriageJob] = []

    def simulated_latency(self, result: TriageResult) -> float:
        if self.seconds_per_llm_call is not None:
            tool_s = sum(s.latency_ms for s in result.steps) / 1000
            return result.llm_calls * self.seconds_per_llm_call + tool_s
        return result.latency_s * self.wall_time_scale

    def tick(self, now: datetime) -> None:
        if self.job is not None and now >= self.job.done_at:
            job, self.job = self.job, None
            self.completed.append(job)
            self.pipeline.finish_triage(job, now)
        while self.job is None:
            incident_id = self.pipeline.router.next()
            if incident_id is None:
                return
            state = self.pipeline.correlation.get(incident_id)
            if state is None or state.status in {"contained", "dismissed", "closed"}:
                continue
            state.status = "triaging"
            self.pipeline.persist_incident(state)
            risk = state.risk.risk if state.risk else 0.0
            staging = self.pipeline.staged_actions
            staging.staging = True
            try:
                result = asyncio.run(self.agent.triage(incident_id, risk, priority_of(risk), now))
            finally:
                staging.staging = False
            latency = self.simulated_latency(result)
            timeout = self.pipeline.router.cfg.agent_timeout_s
            timed_out = latency > timeout
            done_at = now + timedelta(seconds=min(latency, timeout))
            self.job = TriageJob(incident_id, now, done_at, result, timed_out, staging.take(),
                                 risk, state.tactics())  # fmt: skip

    @property
    def busy(self) -> bool:
        return self.job is not None


@dataclass
class _Running:
    incident_id: str
    started: datetime
    risk: float
    tactics: frozenset[str]
    future: Future[TriageResult]
    abandoned: bool = False


class ThreadedAgentWorker:
    """Live mode: the agent triages on a background thread in wall-clock time while the
    pipeline keeps ingesting. Its tool calls take the pipeline lock, so they see consistent
    state; its decision is applied by the pipeline thread on the next tick. A triage still
    running after the router's timeout (in stream time) is abandoned to a playbook."""

    def __init__(self, pipeline: SocPipeline, agent: TriageAgent) -> None:
        self.pipeline = pipeline
        self.agent = agent
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="triage")
        self.running: _Running | None = None
        self.completed: list[TriageJob] = []

    @property
    def busy(self) -> bool:
        return self.running is not None

    def tick(self, now: datetime) -> None:
        run = self.running
        if run is not None:
            timeout = self.pipeline.router.cfg.agent_timeout_s
            if run.future.done():
                self.running = None
                try:
                    result = run.future.result()
                except Exception as exc:  # a crashed triage counts as an agent failure
                    result = TriageResult(run.incident_id, self.agent.llm.name, error=repr(exc))
                if not run.abandoned:
                    timed_out = (now - run.started).total_seconds() > timeout
                    job = TriageJob(run.incident_id, run.started, now, result, timed_out, [],
                                    run.risk, run.tactics)  # fmt: skip
                    self.completed.append(job)
                    self.pipeline.finish_triage(job, now)
            elif not run.abandoned and (now - run.started).total_seconds() > timeout:
                run.abandoned = True  # let it finish in the background; a playbook decides now
                result = TriageResult(run.incident_id, self.agent.llm.name, error="timeout")
                job = TriageJob(run.incident_id, run.started, now, result, True, [], run.risk,
                                run.tactics)  # fmt: skip
                self.completed.append(job)
                self.pipeline.finish_triage(job, now)
        if self.running is not None:
            return  # one agent; an abandoned triage still holds it until it ends
        while True:
            incident_id = self.pipeline.router.next()
            if incident_id is None:
                return
            state = self.pipeline.correlation.get(incident_id)
            if state is None or state.status in {"contained", "dismissed", "closed"}:
                continue
            state.status = "triaging"
            self.pipeline.persist_incident(state)
            risk = state.risk.risk if state.risk else 0.0
            future = self.pool.submit(self._triage, incident_id, risk, now)
            self.running = _Running(incident_id, now, risk, state.tactics(), future)
            return

    def _triage(self, incident_id: str, risk: float, now: datetime) -> TriageResult:
        return asyncio.run(self.agent.triage(incident_id, risk, priority_of(risk), now))

    def close(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
