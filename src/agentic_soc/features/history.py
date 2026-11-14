"""Rolling state of the flow stream: per-conversation history and destination popularity.

Beacons are recognised by regularity over a longer horizon than one window (RITA-style
persistence and interval statistics); rare external destinations by how few internal sources
contacted them recently.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from datetime import datetime

import numpy as np

from agentic_soc.ingestion.models import NormFlow


def conversation_key(flow: NormFlow) -> str:
    return f"{flow.src_ip}|{flow.dst_ip}|{flow.dst_port}"


class ConversationHistory:
    def __init__(self, horizon_s: float = 3600.0, keep_s: float = 3 * 3600.0) -> None:
        self.horizon_s = horizon_s
        self.keep_s = keep_s
        self._events: dict[str, list[tuple[float, float]]] = defaultdict(list)

    def observe(self, flow: NormFlow) -> None:
        bisect.insort(
            self._events[conversation_key(flow)],
            (flow.event_time.timestamp(), float(flow.bytes_out)),
        )

    def stats(self, key: str, end: datetime) -> dict[str, float]:
        items = self._events.get(key, [])
        hi = end.timestamp()
        lo = hi - self.horizon_s
        i = bisect.bisect_left(items, (lo, -1.0))
        j = bisect.bisect_left(items, (hi, -1.0))
        window = items[i:j]
        n = len(window)
        if n < 3:
            return {"hist_n": float(n), "hist_interval_log": 0.0, "hist_interval_cv": 1.0,
                    "hist_regularity": 0.0, "hist_bytes_cv": 1.0, "hist_span_h": 0.0}  # fmt: skip
        times = np.fromiter((t for t, _ in window), float, n)
        sizes = np.fromiter((b for _, b in window), float, n)
        intervals = np.diff(times)
        intervals = intervals[intervals > 0.5]
        if len(intervals) < 2:
            median, cv, regular = 0.0, 1.0, 0.0
        else:
            median = float(np.median(intervals))
            cv = float(np.std(intervals) / max(np.mean(intervals), 1e-9))
            regular = float(np.mean(np.abs(intervals - median) <= 0.35 * median))
        return {
            "hist_n": float(n),
            "hist_interval_log": float(np.log1p(median)),
            "hist_interval_cv": min(cv, 5.0),
            "hist_regularity": regular,
            "hist_bytes_cv": float(min(np.std(sizes) / max(np.mean(sizes), 1.0), 5.0)),
            "hist_span_h": float((times[-1] - times[0]) / 3600.0),
        }

    def trim(self, now: datetime) -> None:
        cutoff = now.timestamp() - self.keep_s
        for key in list(self._events):
            items = self._events[key]
            i = bisect.bisect_left(items, (cutoff, -1.0))
            if i >= len(items):
                del self._events[key]
            elif i:
                del items[:i]

    def __len__(self) -> int:
        return len(self._events)


class DestinationPopularity:
    """Distinct internal sources that contacted an external destination within ``horizon_s``."""

    def __init__(self, horizon_s: float = 24 * 3600.0) -> None:
        self.horizon_s = horizon_s
        self._seen: dict[str, dict[str, float]] = defaultdict(dict)

    def observe(self, flow: NormFlow) -> None:
        if flow.dst_zone == "external" and flow.src_zone != "external":
            ts = flow.event_time.timestamp()
            seen = self._seen[flow.dst_ip]
            if seen.get(flow.src_ip, 0.0) < ts:
                seen[flow.src_ip] = ts

    def popularity(self, dst_ip: str, at: datetime) -> int:
        cutoff = at.timestamp() - self.horizon_s
        return sum(1 for ts in self._seen.get(dst_ip, {}).values() if ts >= cutoff)

    def trim(self, now: datetime) -> None:
        cutoff = now.timestamp() - self.horizon_s
        for dst in list(self._seen):
            seen = {s: ts for s, ts in self._seen[dst].items() if ts >= cutoff}
            if seen:
                self._seen[dst] = seen
            else:
                del self._seen[dst]
