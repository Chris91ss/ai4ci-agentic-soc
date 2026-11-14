"""Asynchronous delivery of telemetry: per-stream delays, stragglers, duplicates and dirt.

Each stream has its own transport: the identity provider pushes sign-ins within seconds, flow
exporters batch records every ~15 s and the EDR agents buffer while hosts are offline. Sources
also have their own clocks, so ``event_time`` carries a per-source skew. A small share of
payloads is malformed (exercising the dead-letter path) and two legacy producers still emit
schema 0.9.
"""

from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import orjson

from agentic_soc.simulator.config import DeliverySpec, SimulatorConfig
from agentic_soc.simulator.model import SimEvent, iso
from agentic_soc.simulator.rng import rng_for
from agentic_soc.topics import STREAM_TOPICS

_PROTO_NUMBER = {"tcp": 6, "udp": 17, "icmp": 1}


@dataclass(order=True, slots=True)
class Delivery:
    """A message as it reaches the broker."""

    deliver_at: datetime
    seq: int
    topic: str = field(compare=False)
    key: str = field(compare=False)
    value: bytes = field(compare=False)
    event_id: str = field(compare=False)
    true_time: datetime = field(compare=False)
    duplicate: bool = field(default=False, compare=False)
    malformed: str | None = field(default=None, compare=False)


@dataclass
class DeliveryStats:
    submitted: int = 0
    delivered: int = 0
    duplicates: int = 0
    malformed: int = 0
    legacy: int = 0
    late: int = 0


class DeliveryModel:
    """Turns generated events into broker messages that arrive late, out of order or twice."""

    def __init__(self, config: SimulatorConfig) -> None:
        self.config = config
        self.specs: dict[str, DeliverySpec] = config.delivery
        self.seed = config.seed
        self._heap: list[Delivery] = []
        self._seq = itertools.count()
        self._skews: dict[tuple[str, str], float] = {}
        self.stats = DeliveryStats()

    # ------------------------------------------------------------------ clocks
    def skew(self, stream: str, source: str) -> float:
        """Fixed clock offset (seconds) of one producer; a few clocks drift a lot."""
        key = (stream, source)
        if key not in self._skews:
            spec = self.specs[stream]
            rng = rng_for(self.seed, "skew", stream, source)
            offset = float(rng.normal(0.0, spec.clock_skew_s))
            if rng.random() < spec.drifted_clock_prob:
                offset += float(rng.choice([-1, 1]) * rng.uniform(30, 180))
            self._skews[key] = offset
        return self._skews[key]

    # ------------------------------------------------------------------ submission
    def submit(self, events: list[SimEvent], tick_t0: datetime) -> None:
        if not events:
            return
        rng = rng_for(self.seed, "delivery", int((tick_t0 - self.config.start).total_seconds()))
        n = len(events)
        u = rng.random((n, 5))
        normals = rng.standard_normal(n)
        for i, event in enumerate(events):
            spec = self.specs[event.stream]
            payload = dict(event.payload)
            source = payload["host"] if event.stream == "process" else payload["source"]
            observed = event.time + timedelta(seconds=self.skew(event.stream, source))
            payload["event_time"] = iso(observed)
            delay = spec.median_delay_s * float(np.exp(spec.sigma * normals[i]))
            late = u[i, 0] < spec.late_prob
            if late:
                lo, hi = spec.late_delay_s
                delay += lo + (hi - lo) * float(u[i, 1])
                self.stats.late += 1
            malformed = None
            if u[i, 2] < spec.malformed_prob:
                value, malformed = self._corrupt(payload, rng)
            else:
                if self._is_legacy(event.stream, payload, spec, float(u[i, 3])):
                    payload = self._to_legacy(event.stream, payload, observed)
                    self.stats.legacy += 1
                value = orjson.dumps(payload)
            topic = STREAM_TOPICS[event.stream]
            deliver_at = event.time + timedelta(seconds=delay)
            self._push(Delivery(deliver_at, next(self._seq), topic, event.key, value, event.event_id,
                                event.time, malformed=malformed))  # fmt: skip
            if u[i, 4] < spec.duplicate_prob and malformed is None:
                again = deliver_at + timedelta(seconds=float(rng.uniform(1, spec.duplicate_max_s)))
                self._push(Delivery(again, next(self._seq), topic, event.key, value, event.event_id,
                                    event.time, duplicate=True))  # fmt: skip
                self.stats.duplicates += 1
            self.stats.submitted += 1

    def _push(self, delivery: Delivery) -> None:
        heapq.heappush(self._heap, delivery)

    def pop_ready(self, now: datetime) -> list[Delivery]:
        """Messages whose delivery time has passed, in arrival order."""
        out: list[Delivery] = []
        while self._heap and self._heap[0].deliver_at <= now:
            out.append(heapq.heappop(self._heap))
        self.stats.delivered += len(out)
        return out

    def pending(self) -> int:
        return len(self._heap)

    # ------------------------------------------------------------------ legacy producers
    @staticmethod
    def _is_legacy(stream: str, payload: dict[str, Any], spec: DeliverySpec, u: float) -> bool:
        if stream == "signin":
            return payload.get("source") == "vpn" and u < spec.legacy_prob
        if stream == "flow":
            return payload.get("source") in spec.legacy_sources
        return False

    @staticmethod
    def _to_legacy(stream: str, payload: dict[str, Any], observed: datetime) -> dict[str, Any]:
        if stream == "signin":
            legacy = {
                "schema_version": "0.9",
                "event_id": payload["event_id"],
                "ts": int(observed.timestamp() * 1000),
                "username": payload["user"],
                "ip": payload["src_ip"],
                "result": "ok" if payload["outcome"] == "success" else "fail",
                "ua": payload.get("user_agent", ""),
            }
            for src, dst in (
                ("failure_reason", "reason"),
                ("country", "country"),
                ("assigned_ip", "vpn_ip"),
            ):
                if payload.get(src) is not None:
                    legacy[dst] = payload[src]
            return legacy  # fmt: skip
        start = observed.timestamp()
        return {
            "schema_version": "0.9",
            "event_id": payload["event_id"],
            "start": round(start, 3),
            "end": round(start + payload["duration_ms"] / 1000, 3),
            "src": payload["src_ip"],
            "sport": payload["src_port"],
            "dst": payload["dst_ip"],
            "dport": payload["dst_port"],
            "proto": _PROTO_NUMBER[payload["protocol"]],
            "bytes_fwd": payload["bytes_out"],
            "bytes_rev": payload["bytes_in"],
            "pkts_fwd": payload.get("packets_out", 0),
            "pkts_rev": payload.get("packets_in", 0),
            "sensor": "netflow-v5",
        }

    # ------------------------------------------------------------------ dirt
    @staticmethod
    def _corrupt(payload: dict[str, Any], rng: np.random.Generator) -> tuple[bytes, str]:
        kind = str(
            rng.choice(
                ["truncated", "missing_field", "bad_ip", "naive_time", "bad_type", "bad_version"]
            )
        )
        broken = dict(payload)
        if kind == "truncated":
            raw = orjson.dumps(broken)
            return raw[: max(1, len(raw) // 2)], kind
        if kind == "missing_field":
            broken.pop("event_time", None)
        elif kind == "bad_ip":
            for field_name in ("src_ip", "dst_ip"):
                if field_name in broken:
                    broken[field_name] = "10.300.1.1"
                    break
            else:
                broken["pid"] = -1
        elif kind == "naive_time":
            broken["event_time"] = str(broken.get("event_time", "")).rstrip("Z")
        elif kind == "bad_type":
            target = next((k for k in ("pid", "bytes_out", "mfa") if k in broken), "event_id")
            broken[target] = "not-a-number" if target != "event_id" else 12
        else:
            broken["schema_version"] = "2.0"
        return orjson.dumps(broken), kind  # fmt: skip
