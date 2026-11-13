"""Simulation records: generated events with their ground-truth labels."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

STREAM_PREFIX = {"signin": "si", "flow": "fl", "process": "pr"}


@dataclass(slots=True)
class Label:
    """Ground truth for one event. Benign look-alikes carry a ``tag`` but ``malicious=False``."""

    malicious: bool
    stage: str | None = None
    technique: str | None = None
    campaign_id: str | None = None
    tag: str | None = None


@dataclass(slots=True)
class SimEvent:
    stream: str
    time: datetime  # true time of occurrence (UTC); the source clock may differ
    payload: dict[str, Any]
    key: str  # partition key on the broker
    label: Label | None = None

    @property
    def event_id(self) -> str:
        return self.payload["event_id"]


@dataclass
class IdFactory:
    """Deterministic, run-unique event identifiers."""

    seed: int
    counters: dict[str, int] = field(default_factory=lambda: dict.fromkeys(STREAM_PREFIX, 0))

    def next(self, stream: str) -> str:
        self.counters[stream] += 1
        return f"{STREAM_PREFIX[stream]}-{self.seed:04x}-{self.counters[stream]:09d}"


def iso(t: datetime) -> str:
    """UTC timestamp with millisecond precision, e.g. ``2026-03-02T09:30:00.123Z``."""
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
