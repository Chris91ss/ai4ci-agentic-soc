from __future__ import annotations

from datetime import UTC, datetime, timedelta

import orjson
import pytest

from agentic_soc.actions import (
    ActionManager,
    BrokerActionSink,
    CallbackActionSink,
    PolicyConfig,
    PolicyGate,
)
from agentic_soc.broker import InMemoryBroker
from agentic_soc.ingestion import Inventory
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.storage import Store

T0 = datetime(2026, 3, 2, 22, tzinfo=UTC)


@pytest.fixture(scope="module")
def sim() -> Simulator:
    return Simulator(load_config(overrides={"org": {"users": 40}, "duration_h": 1}))


@pytest.fixture()
def inventory(sim) -> Inventory:
    return Inventory.from_enterprise(sim.ent)


def test_policy_gate_targets_and_protected_assets(inventory) -> None:
    gate = PolicyGate(inventory)
    user = next(iter(inventory.users.values()))
    dc = next(h for h in inventory.hosts.values() if h.role == "dc")
    ms_ip = next(ip for ip in ("52.96.1.10", "52.97.3.3") if inventory.geoip(ip))
    cases = {
        ("revoke_sessions", f"CORP\\{user.user_id.upper()}"): "execute",
        ("disable_account", user.upn): "pending_approval",
        ("disable_account", "svc_backup"): "deny",
        ("disable_account", "nobody"): "deny",
        ("isolate_host", user.workstation.lower()): "pending_approval",
        ("isolate_host", dc.host_id): "deny",
        ("block_ip", "95.216.10.10"): "execute",
        ("block_ip", "10.10.1.5"): "deny",
        ("block_ip", next(iter(inventory.office_egress.values()))): "deny",
        ("block_ip", ms_ip): "deny",
        ("block_ip", "not-an-ip"): "deny",
        ("revoke_sessions", f"user:{user.user_id}"): "execute",
        ("block_ip", "ip:95.216.10.11"): "execute",
    }
    for (action, target), expected in cases.items():
        verdict = gate.evaluate(action, target, "agent", T0)
        assert verdict.outcome == expected, (action, target, verdict.reason)
    assert gate.evaluate("isolate_host", dc.host_id, "analyst", T0).outcome == "execute"
    assert gate.evaluate("format_disk", "x", "agent", T0).outcome == "deny"


def test_lifecycle_audit_and_feedback_to_the_simulator(sim, inventory) -> None:
    store = Store.memory()
    applied = []
    manager = ActionManager(
        PolicyGate(inventory), CallbackActionSink(lambda t, x, i: applied.append((t, x))), store
    )
    user = next(iter(inventory.users.values()))
    low = manager.propose("INC-1", "block_ip", "95.216.10.10", "agent", T0, "C2 beacon", ["AL-1"])
    assert (
        low.status == "executed"
        and low.approved_by == "policy:auto"
        and applied == [("block_ip", "95.216.10.10")]
    )
    high = manager.propose(
        "INC-1", "isolate_host", user.workstation, "agent", T0, "credential dumping"
    )
    assert high.status == "pending_approval" and manager.pending() == [high]
    assert (
        manager.propose("INC-1", "isolate_host", user.workstation, "agent", T0).action_id
        == high.action_id
    )
    done = manager.approve(high.action_id, "dana", T0 + timedelta(minutes=3))
    assert done.status == "executed" and done.approved_by == "dana" and len(applied) == 2
    with pytest.raises(ValueError):
        manager.approve(high.action_id, "dana", T0)
    denied = manager.propose("INC-1", "block_ip", "10.10.1.5", "agent", T0)
    assert denied.status == "denied" and "internal" in denied.justification
    other = manager.propose("INC-2", "disable_account", user.user_id, "agent", T0)
    rejected = manager.reject(other.action_id, "dana", T0, "travelling, confirmed by phone")
    assert rejected.status == "rejected"
    with pytest.raises(ValueError, match="allow-list"):
        manager.propose("INC-1", "wipe_host", "WS-0001", "agent", T0)
    stored = {a["action_id"]: a["status"] for a in store.list_actions()}
    assert stored[high.action_id] == "executed" and stored[denied.action_id] == "denied"
    actions_logged = [e["action"] for e in store.audit_entries(high.action_id)]
    assert actions_logged == ["executed", "approve", "hold_for_approval", "propose"]
    assert store.verify_audit_chain() == (True, None)


def test_unattended_runs_auto_approve_and_rate_limit(inventory) -> None:
    manager = ActionManager(
        PolicyGate(
            inventory, PolicyConfig(auto_approve_high_impact=True, max_auto_actions_per_hour=2)
        ),
        None,
    )
    users = list(inventory.users.values())
    statuses = [
        manager.propose(f"INC-{i}", "disable_account", u.user_id, "agent", T0).status
        for i, u in enumerate(users[:3])
    ]
    assert statuses == ["executed", "executed", "pending_approval"]
    assert [a.status for a in manager.approve_all_pending("auto-analyst", T0)] == ["executed"]


def test_broker_sink_feeds_the_live_simulator(sim, inventory) -> None:
    from agentic_soc.simulator.live import LiveSimulator

    broker = InMemoryBroker()
    live = LiveSimulator(sim, broker, speed=0)
    manager = ActionManager(PolicyGate(inventory), BrokerActionSink(broker.producer()))
    action = manager.propose("INC-1", "block_ip", "95.216.10.10", "agent", T0)
    message = orjson.loads(broker.messages("actions")[0].value)
    assert message["status"] == "approved" and message["target"] == "95.216.10.10"
    live.apply_pending_actions()
    assert sim.ctx.control.is_blocked("95.216.10.10", sim.clock) and action.status == "executed"
