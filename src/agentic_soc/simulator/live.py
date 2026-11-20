"""Live mode: publish deliveries to the broker at a chosen speed and apply containment actions
consumed from the ``actions`` topic (the feedback loop of the architecture).

Messages carry a ``sim_ts`` header with their arrival time on the simulation clock, so that
downstream services measure lag and latency in simulated time regardless of the replay speed.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

import orjson

from agentic_soc import topics
from agentic_soc.broker.base import Broker
from agentic_soc.simulator.delivery import Delivery
from agentic_soc.simulator.engine import Simulator
from agentic_soc.simulator.model import iso

log = logging.getLogger(__name__)
APPLICABLE_STATUSES = {"approved", "executed"}


class LiveSimulator:
    def __init__(
        self, sim: Simulator, broker: Broker, speed: float = 60.0, group: str = "simulator"
    ) -> None:
        self.sim = sim
        self.broker = broker
        self.speed = speed
        self.producer = broker.producer()
        self.actions = broker.consumer(group, [topics.ACTIONS], from_beginning=False)
        self.published = 0
        self.applied = 0

    def apply_pending_actions(self) -> int:
        messages = self.actions.poll(max_messages=200, timeout=0)
        applied = 0
        for message in messages:
            try:
                action = orjson.loads(message.value)
                if action.get("status") not in APPLICABLE_STATUSES:
                    continue
                if self.sim.apply_action(
                    action["type"], action["target"], action_id=action.get("action_id")
                ):
                    applied += 1
            except (orjson.JSONDecodeError, KeyError, TypeError) as exc:
                log.warning("ignoring malformed action message: %s", exc)
        if messages:
            self.actions.commit()
        self.applied += applied
        return applied

    def publish(self, deliveries: list[Delivery]) -> None:
        for d in deliveries:
            self.producer.send(d.topic, d.value, d.key, headers={"sim_ts": iso(d.deliver_at)})
        self.published += len(deliveries)

    def step(self) -> list[Delivery]:
        self.apply_pending_actions()
        batch = self.sim.tick()
        self.publish(batch)
        return batch

    def run(
        self,
        max_ticks: int | None = None,
        stop: threading.Event | None = None,
        hold: Callable[[], bool] | None = None,
    ) -> None:
        """Publish tick by tick at ``speed``. While ``hold()`` is true the simulation clock stands
        still (the demo pauses while the agent investigates)."""
        wall0, sim0, ticks = time.monotonic(), self.sim.clock, 0
        while not self.sim.finished and not (stop is not None and stop.is_set()):
            if hold is not None and hold():
                paused = time.monotonic()
                while hold() and not (stop is not None and stop.is_set()):
                    if stop is not None:
                        stop.wait(0.1)
                    else:
                        time.sleep(0.1)
                wall0 += (
                    time.monotonic() - paused
                )  # resume the pacing from here, without catching up
                continue
            self.step()
            ticks += 1
            if max_ticks is not None and ticks >= max_ticks:
                break
            if self.speed > 0:
                target = wall0 + (self.sim.clock - sim0).total_seconds() / self.speed
                delay = target - time.monotonic()
                if delay > 0:
                    if stop is not None:
                        stop.wait(delay)
                    else:
                        time.sleep(delay)
        if self.sim.finished:
            self.publish(self.sim.drain())
        self.apply_pending_actions()
        self.producer.flush()
