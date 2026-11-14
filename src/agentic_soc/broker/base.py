"""Broker abstraction shared by the in-memory and the Kafka-compatible (Redpanda) backends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from agentic_soc import topics

# Partitions per topic: streams are keyed by entity, so per-entity order is preserved.
TOPIC_PARTITIONS: dict[str, int] = {
    topics.SIGNIN: 3,
    topics.FLOW: 6,
    topics.PROCESS: 6,
    topics.DEAD_LETTER: 1,
    topics.ACTIONS: 1,
}


@dataclass(slots=True)
class Message:
    topic: str
    value: bytes
    key: str | None = None
    timestamp_ms: int = 0
    partition: int = 0
    offset: int = -1
    headers: dict[str, str] = field(default_factory=dict)


class Producer(Protocol):
    def send(
        self,
        topic: str,
        value: bytes,
        key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None: ...

    def flush(self, timeout: float = 10.0) -> None: ...

    def close(self) -> None: ...


class Consumer(Protocol):
    def poll(self, max_messages: int = 500, timeout: float = 0.1) -> list[Message]: ...

    def commit(self) -> None: ...

    def close(self) -> None: ...


class Broker(Protocol):
    url: str

    def ensure_topics(self, partitions: dict[str, int] | None = None) -> None: ...

    def producer(self) -> Producer: ...

    def consumer(
        self, group: str, topic_names: list[str], from_beginning: bool = True
    ) -> Consumer: ...

    def lag(self, group: str, topic_names: list[str]) -> dict[str, int]: ...

    def close(self) -> None: ...
