"""Thread-safe in-memory broker with partitions, consumer groups and committed offsets.

Used by tests, offline replays and the single-process pipeline. Semantics follow Kafka where
it matters: per-partition order, keyed partitioning, at-least-once delivery for consumers
that crash before committing, and per-group lag.
"""

from __future__ import annotations

import threading
import time
import zlib
from itertools import count

from agentic_soc.broker.base import TOPIC_PARTITIONS, Message


class _Partition:
    __slots__ = ("base", "messages")

    def __init__(self) -> None:
        self.base = 0  # offset of messages[0]; grows when consumed messages are trimmed
        self.messages: list[Message] = []

    @property
    def end(self) -> int:
        return self.base + len(self.messages)


class InMemoryBroker:
    def __init__(self, partitions: dict[str, int] | None = None) -> None:
        self.url = "memory://"
        self._cond = threading.Condition()
        self._topics: dict[str, list[_Partition]] = {}
        self._committed: dict[tuple[str, str, int], int] = {}
        self._round_robin = count()
        self.ensure_topics(partitions)

    # ------------------------------------------------------------------ topics
    def ensure_topics(self, partitions: dict[str, int] | None = None) -> None:
        with self._cond:
            for name, n in (partitions or TOPIC_PARTITIONS).items():
                if name not in self._topics:
                    self._topics[name] = [_Partition() for _ in range(max(1, n))]

    def _parts(self, topic: str) -> list[_Partition]:
        if topic not in self._topics:
            self.ensure_topics({topic: 1})
        return self._topics[topic]

    def append(
        self,
        topic: str,
        value: bytes,
        key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Message:
        with self._cond:
            parts = self._parts(topic)
            if key is None:
                index = next(self._round_robin) % len(parts)
            else:
                index = zlib.crc32(key.encode()) % len(parts)
            part = parts[index]
            message = Message(
                topic=topic,
                value=value,
                key=key,
                timestamp_ms=int(time.time() * 1000),
                partition=index,
                offset=part.end,
                headers=dict(headers or {}),
            )
            part.messages.append(message)
            self._cond.notify_all()
            return message

    def end_offsets(self, topic: str) -> list[int]:
        with self._cond:
            return [p.end for p in self._parts(topic)]

    def size(self, topic: str) -> int:
        return sum(self.end_offsets(topic))

    def messages(self, topic: str) -> list[Message]:
        """All retained messages of a topic (partition by partition), for inspection."""
        with self._cond:
            return [m for p in self._parts(topic) for m in p.messages]

    # ------------------------------------------------------------------ clients
    def producer(self) -> InMemoryProducer:
        return InMemoryProducer(self)

    def consumer(
        self, group: str, topic_names: list[str], from_beginning: bool = True
    ) -> InMemoryConsumer:
        return InMemoryConsumer(self, group, topic_names, from_beginning)

    def committed(self, group: str, topic: str, partition: int) -> int | None:
        return self._committed.get((group, topic, partition))

    def lag(self, group: str, topic_names: list[str]) -> dict[str, int]:
        with self._cond:
            out = {}
            for topic in topic_names:
                total = 0
                for i, part in enumerate(self._parts(topic)):
                    done = self._committed.get((group, topic, i), part.base)
                    total += part.end - max(done, part.base)
                out[topic] = total
            return out

    def trim(self) -> int:
        """Drop messages every known consumer group has committed (bounded memory)."""
        dropped = 0
        with self._cond:
            groups = {g for g, _, _ in self._committed}
            for topic, parts in self._topics.items():
                for i, part in enumerate(parts):
                    offsets = [self._committed.get((g, topic, i)) for g in groups]
                    if not offsets or any(o is None for o in offsets):
                        continue
                    upto = min(offsets) - part.base  # type: ignore[type-var,operator]
                    if upto > 0:
                        del part.messages[:upto]
                        part.base += upto
                        dropped += upto
        return dropped

    def close(self) -> None:
        with self._cond:
            self._cond.notify_all()


class InMemoryProducer:
    def __init__(self, broker: InMemoryBroker) -> None:
        self.broker = broker

    def send(
        self,
        topic: str,
        value: bytes,
        key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.broker.append(topic, value, key, headers)

    def flush(self, timeout: float = 10.0) -> None:
        return None

    def close(self) -> None:
        return None


class InMemoryConsumer:
    def __init__(
        self, broker: InMemoryBroker, group: str, topic_names: list[str], from_beginning: bool
    ) -> None:
        self.broker = broker
        self.group = group
        self.topics = list(topic_names)
        self.positions: dict[tuple[str, int], int] = {}
        with broker._cond:
            for topic in self.topics:
                for i, part in enumerate(broker._parts(topic)):
                    committed = broker._committed.get((group, topic, i))
                    if committed is not None:
                        start = committed
                    else:
                        start = part.base if from_beginning else part.end
                    self.positions[(topic, i)] = max(start, part.base)
        self._closed = False

    def _collect(self, max_messages: int) -> list[Message]:
        out: list[Message] = []
        broker = self.broker
        progressed = True
        while len(out) < max_messages and progressed:
            progressed = False
            for (topic, i), pos in self.positions.items():
                part = broker._topics[topic][i]
                pos = max(pos, part.base)
                if pos < part.end:
                    take = min(max_messages - len(out), 256, part.end - pos)
                    start = pos - part.base
                    out.extend(part.messages[start : start + take])
                    self.positions[(topic, i)] = pos + take
                    progressed = True
                    if len(out) >= max_messages:
                        break
        return out

    def poll(self, max_messages: int = 500, timeout: float = 0.1) -> list[Message]:
        deadline = time.monotonic() + max(0.0, timeout)
        with self.broker._cond:
            while True:
                out = self._collect(max_messages)
                remaining = deadline - time.monotonic()
                if out or remaining <= 0 or self._closed:
                    return out
                self.broker._cond.wait(remaining)

    def commit(self) -> None:
        with self.broker._cond:
            for (topic, i), pos in self.positions.items():
                self.broker._committed[(self.group, topic, i)] = pos

    def close(self) -> None:
        self._closed = True
