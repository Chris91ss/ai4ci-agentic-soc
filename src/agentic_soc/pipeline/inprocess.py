"""Closed-loop runs in one process: the simulator publishes to an in-memory broker, the SOC
pipeline consumes it, and containment flows back through the actions topic."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentic_soc.broker import InMemoryBroker
from agentic_soc.detectors.registry import DetectorSet
from agentic_soc.detectors.service import LocalDetectorClient
from agentic_soc.ingestion import Inventory
from agentic_soc.pipeline.core import PipelineConfig, SocPipeline
from agentic_soc.simulator import Simulator
from agentic_soc.simulator.live import LiveSimulator
from agentic_soc.storage import Store


@dataclass
class RunOutcome:
    truth: dict[str, Any]
    summary: dict[str, Any]
    wall_s: float
    pipeline: SocPipeline
    simulator: Simulator


class InProcessRun:
    def __init__(
        self,
        sim: Simulator,
        detectors: DetectorSet,
        config: PipelineConfig | None = None,
        store: Store | None = None,
    ) -> None:
        self.sim = sim
        self.broker = InMemoryBroker()
        self.live = LiveSimulator(sim, self.broker, speed=0)
        self.store = store or Store.memory()
        self.pipeline = SocPipeline(
            Inventory.from_enterprise(sim.ent),
            LocalDetectorClient(detectors),
            detectors.profiles,
            self.store,
            self.broker,
            config,
        )

    def run(
        self, progress: Callable[[SocPipeline, Simulator], None] | None = None, every: int = 60
    ) -> RunOutcome:
        started = time.perf_counter()
        ticks = 0
        while not self.sim.finished:
            self.live.step()
            self.pipeline.step(clock=self.sim.clock)
            ticks += 1
            if ticks % every == 0:
                self.broker.trim()
                if progress is not None:
                    progress(self.pipeline, self.sim)
        self.live.publish(self.sim.drain())
        self.pipeline.step(clock=self.sim.clock)
        self.pipeline.flush()
        self.live.apply_pending_actions()
        return RunOutcome(
            self.sim.truth(),
            self.pipeline.summary(),
            time.perf_counter() - started,
            self.pipeline,
            self.sim,
        )
