"""Live demo: the simulator, the SOC pipeline and the console API in one process.

The simulator publishes to an in-memory broker at a chosen speed while the pipeline consumes it
with the agent on a background thread, so incidents, agent traces and held actions appear in the
console as the attack unfolds, and an analyst can approve or reject containment.
"""

from __future__ import annotations

import threading

from agentic_soc.broker import InMemoryBroker
from agentic_soc.detectors.registry import DetectorSet
from agentic_soc.detectors.service import LocalDetectorClient
from agentic_soc.ingestion import Inventory
from agentic_soc.pipeline.core import PipelineConfig, SocPipeline
from agentic_soc.pipeline.service import run_live
from agentic_soc.simulator import Simulator
from agentic_soc.simulator.live import LiveSimulator
from agentic_soc.storage import Store


class LiveDemo:
    def __init__(
        self,
        sim: Simulator,
        detectors: DetectorSet,
        config: PipelineConfig,
        store: Store,
        speed: float = 120.0,
        pause_for_agent: bool = False,
    ) -> None:
        config.worker = "threaded"
        self.pause_for_agent = pause_for_agent
        self.sim = sim
        self.broker = InMemoryBroker()
        self.simulator = LiveSimulator(sim, self.broker, speed=speed)
        self.pipeline = SocPipeline(Inventory.from_enterprise(sim.ent), LocalDetectorClient(detectors),
                                    detectors.profiles, store, self.broker, config)  # fmt: skip
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []

    @property
    def paused(self) -> bool:
        """The simulation is waiting for the agent (``pause_for_agent``)."""
        worker = self.pipeline.worker
        return self.pause_for_agent and worker is not None and worker.busy

    def start(self) -> None:
        hold = (lambda: self.paused) if self.pause_for_agent else None
        self.threads = [
            threading.Thread(target=self.simulator.run, kwargs={"stop": self.stop, "hold": hold},
                             name="simulator", daemon=True),
            threading.Thread(target=run_live, args=(self.pipeline,), name="soc-pipeline", daemon=True,
                             kwargs={"stop": self.stop, "poll_timeout": 0.2, "report_every_s": 30.0,
                                     "on_report": lambda _: self.broker.trim()}),
        ]  # fmt: skip
        for thread in self.threads:
            thread.start()

    @property
    def finished(self) -> bool:
        return self.sim.finished

    def close(self, timeout: float = 10.0) -> None:
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout)
