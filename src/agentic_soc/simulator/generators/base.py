"""Shared state of the stream generators."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property

import numpy as np

from agentic_soc.simulator.activity import ActivityPlanner
from agentic_soc.simulator.calibration import Calibration
from agentic_soc.simulator.config import SimulatorConfig
from agentic_soc.simulator.control import ControlState
from agentic_soc.simulator.enterprise import Enterprise
from agentic_soc.simulator.model import IdFactory, Label
from agentic_soc.simulator.rng import rng_for


@dataclass(slots=True)
class RdpSession:
    """Interactive session opened by the sign-in generator; flows and processes follow it."""

    src_ip: str
    target: str  # host_id
    account: str  # DOMAIN-less account name (e.g. adm-ana.popescu)
    start: datetime
    duration_s: float
    label: Label | None = None


@dataclass
class GenContext:
    config: SimulatorConfig
    ent: Enterprise
    calibration: Calibration
    planner: ActivityPlanner
    control: ControlState
    ids: IdFactory
    rdp_sessions: list[RdpSession] = field(default_factory=list)

    @property
    def seed(self) -> int:
        return self.config.seed

    def tick_index(self, t0: datetime) -> int:
        return int((t0 - self.config.start).total_seconds() // self.config.tick_s)

    def tick_rng(self, stream: str, t0: datetime) -> np.random.Generator:
        """One generator per (stream, tick): containment only shifts randomness within a tick."""
        return rng_for(self.seed, stream, self.tick_index(t0))

    @cached_property
    def server_profile(self):
        return self.calibration.server_profile()

    def server_factor(self, t: datetime) -> float:
        return self.server_profile.factor(self.ent.local(t))
