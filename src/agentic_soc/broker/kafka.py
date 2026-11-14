"""Kafka-protocol backend (Redpanda) on top of confluent-kafka / librdkafka."""

from __future__ import annotations

import logging

from confluent_kafka import Consumer as _KConsumer
from confluent_kafka import KafkaError, KafkaException, TopicPartition
from confluent_kafka import Producer as _KProducer
from confluent_kafka.admin import AdminClient, NewTopic

from agentic_soc.broker.base import TOPIC_PARTITIONS, Message

log = logging.getLogger(__name__)


class KafkaBroker:
    def __init__(self, bootstrap: str, client_id: str = "agentic-soc") -> None:
        self.bootstrap = bootstrap
        self.url = f"kafka://{bootstrap}"
        self.client_id = client_id
        self._admin = AdminClient({"bootstrap.servers": bootstrap, "client.id": client_id})

    def ensure_topics(
        self, partitions: dict[str, int] | None = None, timeout: float = 15.0
    ) -> None:
        wanted = partitions or TOPIC_PARTITIONS
        existing = set(self._admin.list_topics(timeout=timeout).topics)
        new = [
            NewTopic(name, num_partitions=n, replication_factor=1, config={"retention.ms": "-1"})
            for name, n in wanted.items()
            if name not in existing
        ]
        if not new:
            return
        for name, future in self._admin.create_topics(new, request_timeout=timeout).items():
            try:
                future.result()
            except KafkaException as exc:
                if exc.args[0].code() != KafkaError.TOPIC_ALREADY_EXISTS:
                    raise
                log.debug("topic %s already exists", name)

    def producer(self) -> KafkaProducer:
        return KafkaProducer(self.bootstrap, self.client_id)

    def consumer(
        self, group: str, topic_names: list[str], from_beginning: bool = True
    ) -> KafkaConsumer:
        return KafkaConsumer(self.bootstrap, group, topic_names, from_beginning)

    def lag(self, group: str, topic_names: list[str]) -> dict[str, int]:
        probe = _KConsumer(
            {"bootstrap.servers": self.bootstrap, "group.id": group, "enable.auto.commit": False}
        )
        try:
            metadata = probe.list_topics(timeout=10)
            out: dict[str, int] = {}
            for topic in topic_names:
                info = metadata.topics.get(topic)
                if info is None:
                    out[topic] = 0
                    continue
                parts = [TopicPartition(topic, p) for p in info.partitions]
                committed = probe.committed(parts, timeout=10)
                total = 0
                for tp in committed:
                    low, high = probe.get_watermark_offsets(tp, timeout=10, cached=False)
                    done = tp.offset if tp.offset >= 0 else low
                    total += max(0, high - done)
                out[topic] = total
            return out
        finally:
            probe.close()

    def close(self) -> None:
        return None


class KafkaProducer:
    def __init__(self, bootstrap: str, client_id: str) -> None:
        self._p = _KProducer(
            {
                "bootstrap.servers": bootstrap,
                "client.id": client_id,
                "linger.ms": 10,
                "compression.type": "zstd",
                "enable.idempotence": True,
                "queue.buffering.max.messages": 500_000,
            }
        )

    def send(
        self,
        topic: str,
        value: bytes,
        key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        kwargs = {"value": value, "key": key.encode() if key is not None else None}
        if headers:
            kwargs["headers"] = list(headers.items())
        while True:
            try:
                self._p.produce(topic, **kwargs)
                break
            except BufferError:
                self._p.poll(0.2)
        self._p.poll(0)

    def flush(self, timeout: float = 10.0) -> None:
        self._p.flush(timeout)

    def close(self) -> None:
        self._p.flush(10)


class KafkaConsumer:
    def __init__(
        self, bootstrap: str, group: str, topic_names: list[str], from_beginning: bool
    ) -> None:
        self._c = _KConsumer(
            {
                "bootstrap.servers": bootstrap,
                "group.id": group,
                "auto.offset.reset": "earliest" if from_beginning else "latest",
                "enable.auto.commit": False,
                "enable.partition.eof": False,
            }
        )
        self._c.subscribe(list(topic_names))

    def poll(self, max_messages: int = 500, timeout: float = 0.1) -> list[Message]:
        out: list[Message] = []
        for raw in self._c.consume(num_messages=max_messages, timeout=timeout):
            error = raw.error()
            if error is not None:
                if error.code() != KafkaError._PARTITION_EOF:
                    log.warning("consumer error: %s", error)
                continue
            key = raw.key()
            headers = {
                k: v.decode() if isinstance(v, bytes) else str(v) for k, v in (raw.headers() or [])
            }
            out.append(
                Message(
                    topic=raw.topic(),
                    value=raw.value() or b"",
                    key=key.decode() if key is not None else None,
                    timestamp_ms=raw.timestamp()[1],
                    partition=raw.partition(),
                    offset=raw.offset(),
                    headers=headers,
                )
            )
        return out

    def commit(self) -> None:
        try:
            self._c.commit(asynchronous=False)
        except KafkaException as exc:
            if exc.args[0].code() != KafkaError._NO_OFFSET:
                raise

    def close(self) -> None:
        self._c.close()
