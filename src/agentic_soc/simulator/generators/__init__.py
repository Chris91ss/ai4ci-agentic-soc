"""Benign activity generators for the three telemetry streams."""

from __future__ import annotations

from datetime import datetime, timedelta

from agentic_soc.simulator.activity import ActivityPlanner
from agentic_soc.simulator.calibration import Calibration, load_calibration
from agentic_soc.simulator.config import SimulatorConfig
from agentic_soc.simulator.control import ControlState
from agentic_soc.simulator.enterprise import Enterprise
from agentic_soc.simulator.generators.base import GenContext, RdpSession
from agentic_soc.simulator.generators.flow import FlowGenerator
from agentic_soc.simulator.generators.process import ProcessGenerator
from agentic_soc.simulator.generators.signin import SigninGenerator
from agentic_soc.simulator.model import IdFactory, SimEvent

__all__ = [
    "BenignActivity",
    "FlowGenerator",
    "GenContext",
    "ProcessGenerator",
    "RdpSession",
    "SigninGenerator",
    "build_context",
]


def build_context(
    config: SimulatorConfig,
    calibration: Calibration | None = None,
    control: ControlState | None = None,
    enterprise: Enterprise | None = None,
) -> GenContext:
    ent = enterprise or Enterprise.build(config)
    calibration = calibration or load_calibration(config.calibration)
    planner = ActivityPlanner(
        ent,
        calibration,
        attendance=config.activity.weekday_attendance,
        travel=config.lookalikes.travel,
    )
    return GenContext(
        config=config,
        ent=ent,
        calibration=calibration,
        planner=planner,
        control=control or ControlState(),
        ids=IdFactory(config.seed),
    )


class BenignActivity:
    """Runs the sign-in, flow and process generators tick by tick (sign-ins first, so that
    the sessions they open are visible to the flow and process generators)."""

    def __init__(self, ctx: GenContext) -> None:
        self.ctx = ctx
        self.signin = SigninGenerator(ctx)
        self.flow = FlowGenerator(ctx)
        self.process = ProcessGenerator(ctx)

    def step(self, t0: datetime, dt: float) -> list[SimEvent]:
        horizon = t0 - timedelta(seconds=dt)
        self.ctx.rdp_sessions = [s for s in self.ctx.rdp_sessions if s.start >= horizon]
        events = self.signin.generate(t0, dt)
        events += self.flow.generate(t0, dt)
        events += self.process.generate(t0, dt)
        return events

    def run(self, start: datetime, end: datetime, tick_s: int | None = None) -> list[SimEvent]:
        tick = tick_s or self.ctx.config.tick_s
        out: list[SimEvent] = []
        t = start
        while t < end:
            out.extend(self.step(t, tick))
            t += timedelta(seconds=tick)
        return out
