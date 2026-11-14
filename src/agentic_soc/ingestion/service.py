"""Ingestion: validate, dead-letter, de-duplicate, normalise and enrich raw telemetry."""

from __future__ import annotations

import heapq
import logging
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import numpy as np
import orjson

from agentic_soc import topics
from agentic_soc.broker.base import Broker, Message
from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.ingestion.models import NormEventT
from agentic_soc.ingestion.normalize import normalize
from agentic_soc.schemas import DeadLetter, SchemaError, parse_event_versioned

log = logging.getLogger(__name__)
RAW_LIMIT = 4096


class Deduplicator:
    """Exactly-once view over at-least-once delivery: drops event IDs seen within ``window_s``."""

    def __init__(self, window_s: float = 7200.0) -> None:
        self.window_s = window_s
        self._seen: dict[str, float] = {}
        self._order: deque[tuple[float, str]] = deque()

    def seen(self, event_id: str, now: float) -> bool:
        while self._order and self._order[0][0] < now - self.window_s:
            ts, old = self._order.popleft()
            if self._seen.get(old) == ts:
                del self._seen[old]
        if event_id in self._seen:
            return True
        self._seen[event_id] = now
        self._order.append((now, event_id))
        return False

    def __len__(self) -> int:
        return len(self._seen)


@dataclass
class StreamStats:
    received: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    legacy: int = 0
    last_ingest: datetime | None = None
    max_event_time: datetime | None = None
    errors: dict[str, int] = field(default_factory=dict)
    delays: deque[float] = field(default_factory=lambda: deque(maxlen=5000))

    def summary(self) -> dict[str, object]:
        delays = np.asarray(self.delays) if self.delays else np.zeros(1)
        return {
            "received": self.received,
            "valid": self.valid,
            "invalid": self.invalid,
            "duplicates": self.duplicates,
            "legacy": self.legacy,
            "errors": dict(self.errors),
            "delay_p50_s": round(float(np.percentile(delays, 50)), 2),
            "delay_p95_s": round(float(np.percentile(delays, 95)), 2),
            "last_ingest": self.last_ingest.isoformat() if self.last_ingest else None,
            "max_event_time": self.max_event_time.isoformat() if self.max_event_time else None,
        }


@dataclass
class IngestResult:
    events: list[NormEventT] = field(default_factory=list)
    dead_letters: list[DeadLetter] = field(default_factory=list)
    duplicates: int = 0


class IngestionStage:
    """Pure processing step (no I/O): raw message in, normalised event or dead letter out."""

    def __init__(self, inventory: Inventory, dedupe_window_s: float = 7200.0) -> None:
        self.inventory = inventory
        self.dedupe = Deduplicator(dedupe_window_s)
        self.stats = {stream: StreamStats() for stream in topics.STREAM_TOPICS}

    def process(
        self, topic: str, value: bytes, key: str | None, ingest_time: datetime, result: IngestResult
    ) -> None:
        stats = self.stats[topic]
        stats.received += 1
        stats.last_ingest = ingest_time
        try:
            event, version = parse_event_versioned(topic, value)
        except SchemaError as exc:
            stats.invalid += 1
            stats.errors[exc.code] = stats.errors.get(exc.code, 0) + 1
            result.dead_letters.append(
                DeadLetter(
                    topic=topic,
                    key=key,
                    raw=value[:RAW_LIMIT].decode("utf-8", "replace"),
                    error_code=exc.code,
                    error_detail=exc.detail[:500],
                    received_at=ingest_time,
                )
            )
            return
        if self.dedupe.seen(event.event_id, ingest_time.timestamp()):
            stats.duplicates += 1
            result.duplicates += 1
            return
        stats.valid += 1
        if version != "1.0":
            stats.legacy += 1
        stats.delays.append((ingest_time - event.event_time).total_seconds())
        if stats.max_event_time is None or event.event_time > stats.max_event_time:
            stats.max_event_time = event.event_time
        result.events.append(normalize(event, self.inventory, ingest_time, version))

    def process_batch(
        self, messages: Iterable[tuple[str, bytes, str | None, datetime]]
    ) -> IngestResult:
        result = IngestResult()
        for topic, value, key, ingest_time in messages:
            self.process(topic, value, key, ingest_time, result)
        return result

    def summary(self) -> dict[str, dict[str, object]]:
        return {stream: stats.summary() for stream, stats in self.stats.items()}


class EventSink(Protocol):
    def write_events(self, events: list[NormEventT]) -> None: ...

    def write_dead_letters(self, letters: list[DeadLetter]) -> None: ...


class NullSink:
    def write_events(self, events: list[NormEventT]) -> None:
        return None

    def write_dead_letters(self, letters: list[DeadLetter]) -> None:
        return None


def message_time(message: Message) -> datetime:
    """Arrival time on the simulation clock (``sim_ts`` header), else the broker timestamp."""
    sim_ts = message.headers.get("sim_ts")
    if sim_ts:
        return datetime.fromisoformat(sim_ts.replace("Z", "+00:00"))
    return datetime.fromtimestamp(message.timestamp_ms / 1000, tz=UTC)


class IngestionService:
    """Consumes the raw topics, publishes dead letters and writes events to the sink."""

    def __init__(
        self,
        broker: Broker,
        stage: IngestionStage,
        sink: EventSink | None = None,
        group: str = "ingestion",
        from_beginning: bool = True,
    ) -> None:
        self.stage = stage
        self.sink = sink or NullSink()
        self.group = group
        self.consumer = broker.consumer(group, list(topics.STREAM_TOPICS.values()), from_beginning)
        self.producer = broker.producer()

    def poll_once(self, max_messages: int = 5000, timeout: float = 0.2) -> IngestResult:
        messages = self.consumer.poll(max_messages=max_messages, timeout=timeout)
        result = self.stage.process_batch(
            (m.topic, m.value, m.key, message_time(m)) for m in messages
        )
        if result.dead_letters:
            for letter in result.dead_letters:
                self.producer.send(
                    topics.DEAD_LETTER, letter.model_dump_json().encode(), key=letter.topic
                )
            self.sink.write_dead_letters(result.dead_letters)
        if result.events:
            self.sink.write_events(result.events)
        if messages:
            self.consumer.commit()
        return result


def replay_run(run_dir: Path) -> Iterator[tuple[str, bytes, str | None, datetime]]:
    """Messages of an offline run directory, merged across topics in arrival order."""

    def read(topic: str) -> Iterator[tuple[str, str, bytes, str | None]]:
        path = Path(run_dir) / "raw" / f"{topic}.jsonl"
        with open(path, "rb") as handle:
            for line in handle:
                record = orjson.loads(line)
                yield record["ts"], topic, record["value"].encode(), record.get("key")

    streams = [read(topic) for topic in topics.STREAM_TOPICS.values()]
    for ts, topic, value, key in heapq.merge(*streams, key=lambda r: r[0]):
        yield topic, value, key, datetime.fromisoformat(ts.replace("Z", "+00:00"))
