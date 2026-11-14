"""Simulation engine: drives benign activity, the campaign and the delivery model tick by tick.

It is also the control interface of the simulated environment: :meth:`Simulator.apply_action`
applies containment actions (from the ``actions`` topic in a live deployment), which changes
what the generators emit from then on.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any

from agentic_soc.simulator.calibration import Calibration
from agentic_soc.simulator.campaign import Campaign
from agentic_soc.simulator.config import SimulatorConfig
from agentic_soc.simulator.delivery import Delivery, DeliveryModel
from agentic_soc.simulator.generators import BenignActivity, build_context
from agentic_soc.simulator.labels import LabelStore
from agentic_soc.simulator.model import iso

Hook = Callable[["Simulator", datetime], None]
_FAR_FUTURE = datetime(9999, 1, 1, tzinfo=UTC)


class Simulator:
    def __init__(
        self,
        config: SimulatorConfig,
        calibration: Calibration | None = None,
        hooks: list[Hook] | None = None,
    ) -> None:
        self.config = config
        self.ctx = build_context(config, calibration)
        self.ent = self.ctx.ent
        self.activity = BenignActivity(self.ctx)
        self.campaign = Campaign(self.activity)
        self.delivery = DeliveryModel(config)
        self.labels = LabelStore()
        self.clock = config.start
        self.end = config.end
        self.counts: Counter[str] = Counter()
        self.actions: list[dict[str, Any]] = []
        self.hooks: list[Hook] = list(hooks or [])
        self._fqdn = {h.fqdn.lower(): h.host_id for h in self.ent.hosts}

    # ------------------------------------------------------------------ control interface
    def normalise_target(self, action_type: str, target: str) -> str:
        """Map a target as the SOC names it to the simulator's identifiers."""
        value = target.strip()
        if action_type in {"disable_account", "revoke_sessions"}:
            value = value.split("\\")[-1].split("@")[0]
            return value.lower()
        if action_type == "isolate_host":
            lowered = value.lower()
            if lowered in self._fqdn:
                return self._fqdn[lowered]
            return value.upper()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value

    def apply_action(
        self,
        action_type: str,
        target: str,
        at: datetime | None = None,
        action_id: str | None = None,
    ) -> bool:
        """Apply a containment action; returns False for unknown or repeated actions."""
        at = at or self.clock
        resolved = self.normalise_target(action_type, target)
        applied = self.ctx.control.apply(action_type, resolved, at, action_id)
        self.actions.append(
            {
                "time": iso(at),
                "type": action_type,
                "target": resolved,
                "action_id": action_id,
                "applied": applied,
            }
        )
        return applied

    # ------------------------------------------------------------------ simulation
    @property
    def finished(self) -> bool:
        return self.clock >= self.end

    def tick(self) -> list[Delivery]:
        """Advance one tick; returns the messages that reached the broker meanwhile."""
        t0, dt = self.clock, self.config.tick_s
        for hook in self.hooks:
            hook(self, t0)
        events = self.activity.step(t0, dt)
        events += self.campaign.step(t0, dt)
        for event in events:
            self.counts[event.stream] += 1
        self.labels.add(events)
        self.delivery.submit(events, t0)
        self.clock = t0 + timedelta(seconds=dt)
        return self.delivery.pop_ready(self.clock)

    def drain(self) -> list[Delivery]:
        """Release everything still in flight (end of run)."""
        return self.delivery.pop_ready(_FAR_FUTURE)

    def run(self) -> Iterator[list[Delivery]]:
        while not self.finished:
            yield self.tick()
        yield self.drain()

    # ------------------------------------------------------------------ ground truth
    def truth(self) -> dict[str, Any]:
        return {
            "run": {
                "seed": self.config.seed,
                "start": iso(self.config.start),
                "end": iso(self.end),
                "clock": iso(self.clock),
                "tick_s": self.config.tick_s,
                "events": dict(self.counts),
                "labelled_events": len(self.labels),
                "delivery": asdict(self.delivery.stats),
            },
            "campaign": self.campaign.truth(),
            "actions": list(self.actions),
        }
