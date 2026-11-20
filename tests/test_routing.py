from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentic_soc.correlation import CorrelationEngine
from agentic_soc.detectors.base import Score
from agentic_soc.features import FEATURES, FeatureRow
from agentic_soc.ingestion import Inventory
from agentic_soc.routing import (
    CircuitBreaker,
    RiskRouter,
    RouterConfig,
    playbook_decision,
    spray_sources,
)
from agentic_soc.simulator import Simulator, load_config

T0 = datetime(2026, 3, 2, 20, tzinfo=UTC)


@pytest.fixture(scope="module")
def inventory() -> Inventory:
    return Inventory.from_enterprise(Simulator(load_config(overrides={"org": {"users": 40}})).ent)


def scored(kind, key, users=(), hosts=(), ips=(), score=0.999, techniques=("T1078",), minute=0):
    start = T0 + timedelta(minutes=minute)
    row = FeatureRow(kind, key, start, start + timedelta(minutes=15), list(users), list(hosts), list(ips), [f"e-{key}"],
                     dict.fromkeys(FEATURES[kind], 0.0))  # fmt: skip
    return row, Score(kind.split("-")[0], kind, score, 0.99, [], list(techniques), f"{key}")


def test_low_risk_is_logged_and_high_risk_queued_by_priority(inventory) -> None:
    engine, router = CorrelationEngine(inventory), RiskRouter(RouterConfig(log_below=0.4))
    low = engine.ingest([scored("M1-user", "user:x", users=["x"], score=0.9905)], T0)[0]
    assert router.route(low, T0).route == "log" and low.incident.status == "logged"
    ws = next(h for h in inventory.hosts.values() if h.kind == "workstation")
    mid = engine.ingest(
        [scored("M1-ip", "ip:45.32.1.1", ips=["45.32.1.1"], techniques=["T1110.003"])], T0
    )[0]
    high = engine.ingest([scored("M2", "c2", users=[ws.owner], hosts=[ws.host_id], ips=["10.10.1.1", "95.216.1.1"],
                                 techniques=["T1071.001"]),
                          scored("M3", f"host:{ws.host_id}", users=[ws.owner], hosts=[ws.host_id], techniques=["T1003.001"])], T0)[0]  # fmt: skip
    assert router.route(mid, T0).route == "agent" and router.route(high, T0).route == "agent"
    assert router.queued() == [high.incident.incident_id, mid.incident.incident_id]
    assert router.next() == high.incident.incident_id and router.queue_length == 1


def test_escalation_retriages_and_saturation_falls_back_to_playbook(inventory) -> None:
    engine, router = (
        CorrelationEngine(inventory),
        RiskRouter(RouterConfig(max_queue=1, log_below=0.4)),
    )
    first = engine.ingest(
        [scored("M1-ip", "ip:45.32.1.1", ips=["45.32.1.1"], techniques=["T1110.003"])], T0
    )[0]
    assert router.route(first, T0).route == "agent"
    other = engine.ingest(
        [scored("M1-ip", "ip:45.32.9.9", ips=["45.32.9.9"], techniques=["T1110.003"])], T0
    )[0]
    decision = router.route(other, T0)
    assert decision.route == "playbook" and "saturated" in decision.reason
    incident_id = router.next()
    state = engine.get(incident_id)
    router.mark_triaged(state)
    state.status = "contained"
    again = engine.ingest(
        [scored("M1-ip", "ip:45.32.1.1", ips=["45.32.1.1"], techniques=["T1110.003"], minute=20)],
        T0,
    )[0]
    assert router.route(again, T0).route == "none"
    escalated = engine.ingest(
        [scored("M2", "exfil", ips=["45.32.1.1", "95.216.1.1"], techniques=["T1041"], minute=30)],
        T0,
    )[0]
    assert router.route(escalated, T0).route == "agent"


def test_circuit_breaker_opens_and_recovers() -> None:
    breaker = CircuitBreaker(failures=2, cooldown_s=600)
    assert breaker.allow(T0)
    breaker.record(False, T0)
    breaker.record(False, T0)
    assert breaker.state == "open" and not breaker.allow(T0 + timedelta(minutes=5))
    assert breaker.allow(T0 + timedelta(minutes=11)) and breaker.state == "half_open"
    breaker.record(False, T0 + timedelta(minutes=11))
    assert breaker.state == "open" and breaker.trips == 2
    assert breaker.allow(T0 + timedelta(minutes=22))
    breaker.record(True, T0 + timedelta(minutes=22))
    assert breaker.state == "closed"


def test_router_uses_playbook_while_breaker_is_open(inventory) -> None:
    engine, router = (
        CorrelationEngine(inventory),
        RiskRouter(RouterConfig(breaker_failures=1, log_below=0.4)),
    )
    router.agent_result(False, T0)
    update = engine.ingest(
        [scored("M1-ip", "ip:45.32.1.1", ips=["45.32.1.1"], techniques=["T1110.003"])], T0
    )[0]
    decision = router.route(update, T0)
    assert decision.route == "playbook" and "breaker" in decision.reason


def test_playbooks_contain_without_touching_infrastructure(inventory) -> None:
    engine = CorrelationEngine(inventory)
    ws = next(h for h in inventory.hosts.values() if h.kind == "workstation")
    dc = next(h for h in inventory.hosts.values() if h.role == "dc")
    admin = next(u for u in inventory.users.values() if u.admin_account).admin_account
    updates = engine.ingest([
        scored("M2", "c2", users=[ws.owner], hosts=[ws.host_id], ips=["10.10.1.1", "95.216.1.1"], techniques=["T1071.001"]),
        scored("M2", "dns", hosts=[dc.host_id], ips=["10.10.1.1", dc.static_ip], techniques=["T1071.001"]),
        scored("M3", f"host:{ws.host_id}", users=[admin], hosts=[ws.host_id], techniques=["T1003.001"]),
        scored("M1-ip", "spray", ips=["45.32.7.7"], techniques=["T1110.003"]),
        scored("M1-user", "sprayed", users=["victim"], ips=["45.32.7.7"], techniques=["T1110"]),
    ], T0)  # fmt: skip
    host_case, spray_case = (u.incident for u in updates)
    decision = playbook_decision(host_case, inventory)
    actions = {(a.type, a.target) for a in decision.all_actions()}
    assert actions == {
        ("isolate_host", ws.host_id),
        ("disable_account", admin),
        ("block_ip", "95.216.1.1"),
    }
    assert (
        decision.action.type == "isolate_host"
        and decision.verdict == "malicious"
        and decision.evidence
    )
    assert playbook_decision(host_case, inventory, done=actions).all_actions() == []
    spray = {(a.type, a.target) for a in playbook_decision(spray_case, inventory).all_actions()}
    assert spray == {
        ("block_ip", "45.32.7.7")
    }  # a failed sprayed sign-in is not an account takeover


def test_spray_sources_count_failed_accounts_on_rented_networks(inventory) -> None:
    engine = CorrelationEngine(inventory)

    def incident(rows):
        return engine.ingest(rows, T0)[-1].incident

    def failed(users, ip, techniques=("T1110",)):
        return [
            scored("M1-user", f"user:{u}", users=[u], ips=[ip], techniques=techniques)
            for u in users
        ]

    def blocked(state):
        return [action.target for action, _ in spray_sources(state, inventory)]

    assert blocked(incident(failed(["ana", "ion", "maria"], "45.32.7.7"))) == ["45.32.7.7"]  # Vultr
    assert (
        blocked(incident(failed(["dan", "eva"], "45.32.8.8"))) == []
    )  # two accounts: maybe a typo
    # An M1-ip alert lists the accounts that signed in, so a busy address is not a spray ...
    busy = scored(
        "M1-ip",
        "ip:193.106.191.5",
        users=["a", "b", "c"],
        ips=["193.106.191.5"],
        techniques=["T1110"],
    )
    assert blocked(incident([busy])) == []
    # ... unless the detector saw three accounts fail from it in one window.
    spray = scored("M1-ip", "ip:51.75.1.1", ips=["51.75.1.1"], techniques=["T1110.003"])
    assert blocked(incident([spray])) == ["51.75.1.1"]
    # Accounts that also signed in, shared ZTNA egress (S1) and home ISPs are left to the agent.
    assert blocked(incident(failed(["f", "g", "h"], "45.32.9.9", ("T1110", "T1078")))) == []
    assert blocked(incident(failed(["i", "j", "k"], "165.225.1.10"))) == []  # Zscaler
    assert blocked(incident(failed(["l", "m", "n"], "73.0.153.70"))) == []  # Comcast
