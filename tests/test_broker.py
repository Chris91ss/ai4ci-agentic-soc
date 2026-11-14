from __future__ import annotations

import os
import threading
import uuid

import orjson
import pytest

from agentic_soc.broker import InMemoryBroker, connect
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.simulator.live import LiveSimulator


def test_keyed_messages_keep_per_key_order() -> None:
    broker = InMemoryBroker({"t": 4})
    producer = broker.producer()
    for i in range(200):
        producer.send("t", str(i).encode(), key=f"k{i % 7}")
    consumer = broker.consumer("g", ["t"])
    got = consumer.poll(max_messages=1000)
    assert len(got) == 200
    by_key: dict[str, list[int]] = {}
    for m in got:
        by_key.setdefault(m.key, []).append(int(m.value))
    assert all(v == sorted(v) for v in by_key.values())
    assert len({m.partition for m in got}) > 1


def test_groups_commit_and_redelivery() -> None:
    broker = InMemoryBroker({"t": 2})
    producer = broker.producer()
    for i in range(10):
        producer.send("t", b"x%d" % i, key=str(i))
    first = broker.consumer("g1", ["t"])
    assert len(first.poll(max_messages=4)) == 4
    first.commit()
    assert broker.lag("g1", ["t"]) == {"t": 6}
    assert len(first.poll(max_messages=100)) == 6  # read but not committed (crash)
    again = broker.consumer("g1", ["t"])  # restart: at-least-once redelivery
    assert len(again.poll(max_messages=100)) == 6
    again.commit()
    assert broker.lag("g1", ["t"]) == {"t": 0}
    assert len(broker.consumer("g2", ["t"]).poll(max_messages=100)) == 10
    assert broker.consumer("g3", ["t"], from_beginning=False).poll(timeout=0) == []


def test_trim_drops_only_committed_messages() -> None:
    broker = InMemoryBroker({"t": 1})
    producer = broker.producer()
    for i in range(10):
        producer.send("t", b"%d" % i)
    a, b = broker.consumer("a", ["t"]), broker.consumer("b", ["t"])
    a.poll(max_messages=8)
    a.commit()
    b.poll(max_messages=3)
    b.commit()
    assert broker.trim() == 3
    assert [int(m.value) for m in b.poll(max_messages=100)] == list(range(3, 10))
    assert broker.lag("a", ["t"]) == {"t": 2}


def test_blocking_poll_wakes_up_on_new_messages() -> None:
    broker = InMemoryBroker({"t": 1})
    consumer = broker.consumer("g", ["t"])
    timer = threading.Timer(0.05, lambda: broker.producer().send("t", b"late"))
    timer.start()
    got = consumer.poll(timeout=2.0)
    timer.join()
    assert [m.value for m in got] == [b"late"]


def test_connect_urls() -> None:
    assert isinstance(connect("memory://"), InMemoryBroker)
    with pytest.raises(ValueError):
        connect("amqp://x")


def test_live_simulator_publishes_and_applies_actions() -> None:
    cfg = load_config(
        overrides={"org": {"users": 40}, "duration_h": 0.5, "campaign": {"enabled": False}}
    )
    sim = Simulator(cfg)
    broker = InMemoryBroker()
    live = LiveSimulator(sim, broker, speed=0)
    live.run(max_ticks=5)
    published = sum(broker.size(t) for t in ("signin", "flow", "process"))
    assert published == live.published > 0
    message = broker.messages("flow")[0]
    assert message.headers["sim_ts"].startswith("2026-03-02T")
    host = sim.ent.hosts[0].host_id
    action = {"action_id": "A-1", "type": "isolate_host", "target": host, "status": "approved"}
    broker.producer().send("actions", orjson.dumps(action))
    broker.producer().send(
        "actions", orjson.dumps(action | {"action_id": "A-2", "status": "proposed"})
    )
    broker.producer().send("actions", b"{not json")
    live.run()
    assert live.applied == 1 and sim.ctx.control.is_isolated(host, sim.clock)
    assert sim.finished and live.published == sim.delivery.stats.delivered


KAFKA_URL = os.environ.get("SOC_KAFKA_URL")


@pytest.mark.integration
@pytest.mark.skipif(not KAFKA_URL, reason="set SOC_KAFKA_URL=kafka://localhost:19092 (make up)")
def test_kafka_roundtrip() -> None:
    broker = connect(KAFKA_URL)
    topic = f"it-{uuid.uuid4().hex[:8]}"
    broker.ensure_topics({topic: 3})
    producer = broker.producer()
    for i in range(50):
        producer.send(topic, b"%d" % i, key=f"k{i % 5}", headers={"sim_ts": "x"})
    producer.flush()
    consumer = broker.consumer(f"g-{topic}", [topic])
    got = []
    for _ in range(50):
        got += consumer.poll(max_messages=100, timeout=0.5)
        if len(got) >= 50:
            break
    assert sorted(int(m.value) for m in got) == list(range(50))
    assert got[0].headers == {"sim_ts": "x"}
    consumer.commit()
    assert broker.lag(f"g-{topic}", [topic]) == {topic: 0}
    consumer.close()
