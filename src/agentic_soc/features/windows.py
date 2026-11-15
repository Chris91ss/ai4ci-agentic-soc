"""Event-time tumbling windows per key, with watermarks and late re-firing.

The watermark of a stream follows the pipeline clock (latest arrival time seen on any stream,
on the simulation clock) minus an allowed delay. A window fires once the watermark passes its
end. Events that arrive after their window fired are added to the retained window, which then
fires again with all its events (accumulating refinement, as in the Dataflow model). Events
older than the retention horizon are counted as dropped; they remain in storage.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


@dataclass(slots=True)
class Window:
    key: str
    start: datetime
    end: datetime
    events: list[Any] = field(default_factory=list)
    fired: int = 0
    late: bool = False


@dataclass
class WindowStats:
    events: int = 0
    late_events: int = 0
    dropped: int = 0
    fired: int = 0
    refired: int = 0


class Windower:
    def __init__(
        self,
        name: str,
        size_s: int,
        allowed_delay_s: float,
        keys: Callable[[Any], Iterable[str]],
        retention_s: float = 7200.0,
    ) -> None:
        self.name = name
        self.size = timedelta(seconds=size_s)
        self.allowed_delay = timedelta(seconds=allowed_delay_s)
        self.retention = timedelta(seconds=retention_s)
        self.keys = keys
        self.watermark: datetime | None = None
        self._open: dict[datetime, dict[str, Window]] = {}
        self._closed: dict[tuple[str, datetime], Window] = {}
        self._dirty: set[tuple[str, datetime]] = set()
        self.stats = WindowStats()

    def window_start(self, t: datetime) -> datetime:
        size = self.size.total_seconds()
        offset = (t - EPOCH).total_seconds()
        return EPOCH + timedelta(seconds=(offset // size) * size)

    def add(self, event: Any) -> None:
        start = self.window_start(event.event_time)
        end = start + self.size
        self.stats.events += 1
        for key in self.keys(event):
            bucket = self._open.get(start)
            if bucket is not None and key in bucket:
                bucket[key].events.append(event)
                continue
            closed = self._closed.get((key, start))
            if closed is not None:
                closed.events.append(event)
                self._dirty.add((key, start))
                self.stats.late_events += 1
                continue
            if self.watermark is not None and end <= self.watermark:
                if end <= self.watermark - self.retention:
                    self.stats.dropped += 1
                    continue
                window = Window(key, start, end, [event], late=True)
                self._closed[(key, start)] = window
                self._dirty.add((key, start))
                self.stats.late_events += 1
                continue
            self._open.setdefault(start, {})[key] = Window(key, start, end, [event])

    def advance(self, clock: datetime) -> list[Window]:
        """Move the watermark to ``clock - allowed_delay`` and return windows to evaluate."""
        mark = clock - self.allowed_delay
        if self.watermark is None or mark > self.watermark:
            self.watermark = mark
        return self._fire(self.watermark)

    def flush(self) -> list[Window]:
        """Fire everything (end of a replay)."""
        return self._fire(datetime.max.replace(tzinfo=UTC))

    def _fire(self, watermark: datetime) -> list[Window]:
        out: list[Window] = []
        for start in sorted(s for s in self._open if s + self.size <= watermark):
            for key, window in self._open.pop(start).items():
                window.fired += 1
                self._closed[(key, start)] = window
                self.stats.fired += 1
                out.append(window)
        # In a fixed order: a set's order changes with each process's hash seed.
        for item in sorted(self._dirty, key=lambda k: (k[1], k[0])):
            window = self._closed[item]
            if window.fired:
                self.stats.refired += 1
            window.fired += 1
            window.late = True
            out.append(window)
        self._dirty.clear()
        if watermark.year < 9999:
            horizon = watermark - self.retention
            for item in [k for k, w in self._closed.items() if w.end <= horizon]:
                del self._closed[item]
        return out

    @property
    def open_windows(self) -> int:
        return sum(len(bucket) for bucket in self._open.values())
