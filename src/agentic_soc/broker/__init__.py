"""Event broker: Kafka-compatible (Redpanda) or in-memory, selected by URL."""

from __future__ import annotations

import os

from agentic_soc.broker.base import TOPIC_PARTITIONS, Broker, Consumer, Message, Producer
from agentic_soc.broker.memory import InMemoryBroker

DEFAULT_URL = "memory://"


def connect(url: str | None = None) -> Broker:
    """``memory://`` (default) or ``kafka://host:port[,host:port]``; ``SOC_BROKER`` overrides."""
    url = url or os.environ.get("SOC_BROKER", DEFAULT_URL)
    if url.startswith("memory://"):
        return InMemoryBroker()
    if url.startswith("kafka://"):
        from agentic_soc.broker.kafka import KafkaBroker

        broker = KafkaBroker(url.removeprefix("kafka://"))
        broker.ensure_topics()
        return broker
    raise ValueError(f"unsupported broker URL {url!r} (use memory:// or kafka://host:port)")


__all__ = [
    "TOPIC_PARTITIONS",
    "Broker",
    "Consumer",
    "InMemoryBroker",
    "Message",
    "Producer",
    "connect",
]
