from __future__ import annotations

import itertools
from collections import Counter
from datetime import timedelta

import pytest

from agentic_soc.schemas import NetworkFlowEvent, SchemaError, SignInEvent, parse_event
from agentic_soc.simulator.config import SimulatorConfig, load_config
from agentic_soc.simulator.delivery import DeliveryModel
from agentic_soc.simulator.generators import BenignActivity, build_context


@pytest.fixture(scope="module")
def delivered():
    cfg = load_config(overrides={"seed": 3})
    activity = BenignActivity(build_context(cfg))
    model = DeliveryModel(cfg)
    start = cfg.start + timedelta(hours=5)  # 07:00 local, before the start of the working day
    t = start
    out = []
    while t < start + timedelta(hours=3):
        model.submit(activity.step(t, cfg.tick_s), t)
        t += timedelta(seconds=cfg.tick_s)
        out.extend(model.pop_ready(t))
    out.extend(model.pop_ready(t + timedelta(hours=3)))
    return model, out


def test_every_submitted_event_is_delivered(delivered) -> None:
    model, out = delivered
    assert model.pending() == 0
    assert len(out) == model.stats.submitted + model.stats.duplicates
    assert len({d.event_id for d in out}) == model.stats.submitted


def test_arrivals_are_out_of_order_with_stragglers(delivered) -> None:
    _, out = delivered
    by_topic: dict[str, list] = {}
    for d in out:
        by_topic.setdefault(d.topic, []).append(d)
    for topic, msgs in by_topic.items():
        inversions = sum(1 for a, b in itertools.pairwise(msgs) if b.true_time < a.true_time)
        assert inversions > 0, topic
        delays = [(d.deliver_at - d.true_time).total_seconds() for d in msgs]
        assert max(delays) > 60, topic
    flow_delays = sorted((d.deliver_at - d.true_time).total_seconds() for d in by_topic["flow"])
    assert 8 < flow_delays[len(flow_delays) // 2] < 25


def test_duplicates_share_the_event_id(delivered) -> None:
    _, out = delivered
    dups = [d for d in out if d.duplicate]
    assert dups
    counts = Counter(d.event_id for d in out)
    assert all(counts[d.event_id] == 2 for d in dups)


def test_malformed_payloads_fail_validation_with_codes(delivered) -> None:
    _, out = delivered
    bad = [d for d in out if d.malformed]
    assert bad
    codes = set()
    for d in bad:
        with pytest.raises(SchemaError) as info:
            parse_event(d.topic, d.value)
        codes.add(info.value.code)
    assert codes <= {"invalid_json", "validation_error", "unknown_version"}


def test_legacy_producers_are_upgraded(delivered) -> None:
    model, out = delivered
    assert model.stats.legacy > 0
    legacy = [d for d in out if b'"schema_version":"0.9"' in d.value]
    kinds = {d.topic for d in legacy}
    assert kinds == {"signin", "flow"}
    for d in legacy[:200]:
        event = parse_event(d.topic, d.value)
        assert event.schema_version == "1.0"
        assert isinstance(event, SignInEvent | NetworkFlowEvent)


def test_source_clocks_are_skewed(delivered) -> None:
    _, out = delivered
    offsets = []
    for d in out:
        if d.malformed or d.topic != "process":
            continue
        event = parse_event(d.topic, d.value)
        offsets.append((event.event_time - d.true_time).total_seconds())
    assert any(abs(o) > 0.05 for o in offsets)
    assert max(abs(o) for o in offsets) < 200


def test_config_requires_delivery_for_every_stream() -> None:
    partial = {"median_delay_s": 1, "late_prob": 0, "late_delay_s": [1, 2], "duplicate_prob": 0}
    with pytest.raises(ValueError, match="delivery settings missing"):
        SimulatorConfig.model_validate({"delivery": {"signin": partial}})
