"""Risk router: what deserves the agent's attention, and what happens when it is slow or down.

Low-risk incidents are only logged. Others are queued for the triage agent by priority and
re-triaged when their risk jumps or a new late-stage tactic appears. When the queue is full or
the circuit breaker is open (repeated agent failures or timeouts), a deterministic playbook
decides instead.
"""

from __future__ import annotations

import heapq
import itertools
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from agentic_soc.correlation.engine import IncidentState, IncidentUpdate
from agentic_soc.correlation.risk import LATE_TACTICS, priority_of

Route = Literal["none", "log", "agent", "playbook"]
CLOSED_STATUSES = {"contained", "dismissed", "closed"}


@dataclass
class RouterConfig:
    log_below: float = 0.5
    retriage_delta: float = 0.15
    max_queue: int = 25
    agent_timeout_s: float = 180.0
    breaker_failures: int = 3
    breaker_cooldown_s: float = 900.0


@dataclass(frozen=True, slots=True)
class RouteDecision:
    incident_id: str
    route: Route
    reason: str


class CircuitBreaker:
    """closed -> open after N consecutive failures; half-open after a cooldown; closed on success."""

    def __init__(self, failures: int, cooldown_s: float) -> None:
        self.threshold = failures
        self.cooldown = timedelta(seconds=cooldown_s)
        self.state: Literal["closed", "open", "half_open"] = "closed"
        self.failures = 0
        self.opened_at: datetime | None = None
        self.trips = 0

    def allow(self, now: datetime) -> bool:
        if (
            self.state == "open"
            and self.opened_at is not None
            and now - self.opened_at >= self.cooldown
        ):
            self.state = "half_open"
        return self.state != "open"

    def record(self, ok: bool, now: datetime) -> None:
        if ok:
            self.state, self.failures = "closed", 0
            return
        self.failures += 1
        if self.state == "half_open" or self.failures >= self.threshold:
            if self.state != "open":
                self.trips += 1
            self.state, self.opened_at = "open", now


class RiskRouter:
    def __init__(self, config: RouterConfig | None = None) -> None:
        self.cfg = config or RouterConfig()
        self.breaker = CircuitBreaker(self.cfg.breaker_failures, self.cfg.breaker_cooldown_s)
        self._heap: list[tuple[int, float, int, str]] = []
        self._order = itertools.count()
        self._queued: dict[str, int] = {}  # incident -> sequence of its live heap entry
        self.stats: Counter[str] = Counter()

    # ------------------------------------------------------------------ routing
    def _escalated(self, state: IncidentState) -> bool:
        risk = state.risk.risk if state.risk else 0.0
        new_late = (state.tactics() - state.triaged_tactics) & LATE_TACTICS
        return risk >= state.triaged_risk + self.cfg.retriage_delta or bool(new_late)

    def route(self, update: IncidentUpdate, now: datetime) -> RouteDecision:
        state = update.incident
        risk = state.risk.risk if state.risk else 0.0
        iid = state.incident_id
        if iid in self._queued:
            self._push(state)  # refresh its priority
            return RouteDecision(iid, "none", "already queued")
        if state.status == "triaging":
            return RouteDecision(iid, "none", "being triaged")
        handled = state.route in {"agent", "playbook", "analyst"}
        if handled and not self._escalated(state):
            return RouteDecision(iid, "none", "already triaged")
        if risk < self.cfg.log_below and not handled:
            state.route, state.status = "log", "logged"
            self.stats["log"] += 1
            return RouteDecision(iid, "log", f"risk {risk:.2f} below {self.cfg.log_below}")
        if risk < self.cfg.log_below:
            return RouteDecision(iid, "none", "low risk")
        reason = "escalated" if handled else f"risk {risk:.2f}"
        if not self.breaker.allow(now):
            return self._playbook(state, f"{reason}; circuit breaker open")
        if len(self._queued) >= self.cfg.max_queue:
            return self._playbook(state, f"{reason}; agent queue saturated ({len(self._queued)})")
        state.route, state.status = "agent", "queued"
        self._push(state)
        self.stats["agent"] += 1
        return RouteDecision(iid, "agent", reason)

    def _playbook(self, state: IncidentState, reason: str) -> RouteDecision:
        state.route = "playbook"
        self.stats["playbook"] += 1
        return RouteDecision(state.incident_id, "playbook", reason)

    def mark_triaged(self, state: IncidentState) -> None:
        state.triaged_risk = state.risk.risk if state.risk else 0.0
        state.triaged_tactics = state.tactics()

    # ------------------------------------------------------------------ queue
    def _push(self, state: IncidentState) -> None:
        risk = state.risk.risk if state.risk else 0.0
        seq = next(self._order)
        self._queued[state.incident_id] = seq
        heapq.heappush(self._heap, (priority_of(risk), -risk, seq, state.incident_id))

    def next(self) -> str | None:
        while self._heap:
            _, _, seq, iid = heapq.heappop(self._heap)
            if self._queued.get(iid) == seq:
                del self._queued[iid]
                return iid
        return None

    def drop(self, incident_id: str) -> None:
        self._queued.pop(incident_id, None)

    @property
    def queue_length(self) -> int:
        return len(self._queued)

    def queued(self) -> list[str]:
        live = [(p, r, s, i) for p, r, s, i in self._heap if self._queued.get(i) == s]
        return [i for *_, i in sorted(live)]

    # ------------------------------------------------------------------ agent outcomes
    def agent_result(self, ok: bool, now: datetime) -> None:
        self.breaker.record(ok, now)
        self.stats["agent_ok" if ok else "agent_failed"] += 1

    def is_timeout(self, latency_s: float) -> bool:
        return latency_s > self.cfg.agent_timeout_s
