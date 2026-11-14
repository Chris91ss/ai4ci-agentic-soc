from __future__ import annotations

from collections import Counter
from datetime import timedelta

import numpy as np
import pytest

from agentic_soc.schemas import parse_event
from agentic_soc.simulator import Simulator
from agentic_soc.simulator.config import load_config
from agentic_soc.simulator.enterprise import is_internal
from agentic_soc.simulator.generators import BenignActivity, build_context
from agentic_soc.simulator.model import SimEvent


def account_of(event: SimEvent) -> str:
    return event.payload["user"].split("@")[0].split("\\")[-1].lower()


@pytest.fixture(scope="module")
def day_run() -> tuple[BenignActivity, list[SimEvent]]:
    cfg = load_config(overrides={"duration_h": 24})
    activity = BenignActivity(build_context(cfg))
    return activity, activity.run(cfg.start, cfg.start + timedelta(hours=24))


def test_volumes_and_schema_validity(day_run) -> None:
    _, events = day_run
    counts = Counter(e.stream for e in events)
    assert 2_000 < counts["signin"] < 20_000
    assert 50_000 < counts["flow"] < 400_000
    assert 20_000 < counts["process"] < 200_000
    for event in events[::25]:
        parse_event(event.stream, event.payload)


def test_events_fall_in_their_tick_and_ids_are_unique(day_run) -> None:
    activity, events = day_run
    ids = [e.event_id for e in events]
    assert len(set(ids)) == len(ids)
    start = activity.ctx.config.start
    assert all(start <= e.time < start + timedelta(hours=24, minutes=2) for e in events)


def test_diurnal_cycle(day_run) -> None:
    activity, events = day_run
    local_hours = Counter((activity.ctx.ent.local(e.time).hour, e.stream) for e in events)
    for stream in ("signin", "flow", "process"):
        assert local_hours[(10, stream)] > 3 * local_hours[(3, stream)]


def test_benign_lookalikes_are_present(day_run) -> None:
    activity, events = day_run
    tags = Counter(e.label.tag for e in events if e.label is not None)
    for tag in ("typo", "admin_rdp", "backup", "offsite_backup", "edr_heartbeat", "edr_cloud_sync"):
        assert tags[tag] > 0, tag
    assert not any(e.label.malicious for e in events if e.label is not None)
    vpn_ip = activity.ctx.ent.servers_by_role["vpn"][0].static_ip
    tunnels = [
        e
        for e in events
        if e.stream == "flow"
        and e.payload["dst_ip"] == vpn_ip
        and e.payload["dst_port"] == 443
        and not is_internal(e.payload["src_ip"])
    ]
    assert tunnels and all(e.label.tag in {"remote_vpn", "travel"} for e in tunnels)


def test_entity_identifiers_differ_per_stream(day_run) -> None:
    _, events = day_run
    by_stream = {s: next(e for e in events if e.stream == s) for s in ("signin", "process")}
    signin_users = {e.payload["user"] for e in events if e.stream == "signin"}
    assert any(u.endswith("@corp.example") for u in signin_users)  # IdP UPN
    assert any(u.endswith("@CORP.EXAMPLE") for u in signin_users)  # Kerberos principal
    assert by_stream["process"].payload["host"].endswith(".corp.example")
    assert any("\\" in e.payload["user"] for e in events if e.stream == "process")


def test_generation_is_deterministic() -> None:
    cfg = load_config(overrides={"seed": 21})
    runs = []
    for _ in range(2):
        activity = BenignActivity(build_context(cfg))
        start = cfg.start + timedelta(hours=9)
        runs.append([e.payload for e in activity.run(start, start + timedelta(minutes=20))])
    assert runs[0] == runs[1]


def test_containment_changes_emitted_telemetry() -> None:
    cfg = load_config(overrides={"seed": 5})
    ctx = build_context(cfg)
    activity = BenignActivity(ctx)
    start = cfg.start + timedelta(hours=8)  # 10:00 local, Monday
    victim = next(
        u
        for u in ctx.ent.users
        if not ctx.planner.plan(u, 0).remote and ctx.planner.plan(u, 0).works
    )
    host = ctx.ent.hosts_by_id[victim.workstation]
    blocked = ctx.ent.services["o365"].ips
    ctx.control.apply("disable_account", victim.user_id, start)
    ctx.control.apply("isolate_host", host.host_id, start)
    for ip in blocked:
        ctx.control.apply("block_ip", ip, start)
    events = activity.run(start, start + timedelta(hours=3))
    victim_signins = [e for e in events if e.stream == "signin" and account_of(e) == victim.user_id]
    assert victim_signins and all(e.payload["outcome"] == "failure" for e in victim_signins)
    assert {e.payload.get("failure_reason") for e in victim_signins} <= {"account_disabled"}
    ws_ip = ctx.ent.dhcp_ip(host.host_id, start)
    edr_ip = ctx.ent.servers_by_role["edr"][0].static_ip
    host_flows = [e for e in events if e.stream == "flow" and e.payload["src_ip"] == ws_ip]
    assert all(e.payload["dst_ip"] == edr_ip for e in host_flows)
    to_blocked = [e for e in events if e.stream == "flow" and e.payload["dst_ip"] in blocked]
    assert to_blocked and all(
        e.payload["fw_action"] == "blocked" and e.payload["bytes_in"] == 0 for e in to_blocked
    )


def test_revoked_sessions_force_reauthentication() -> None:
    cfg = load_config(overrides={"seed": 5})
    ctx = build_context(cfg)
    activity = BenignActivity(ctx)
    start = cfg.start + timedelta(hours=8)
    user = next(u for u in ctx.ent.users if ctx.planner.plan(u, 0).works)
    ctx.control.apply("revoke_sessions", user.user_id, start)
    events = activity.run(start, start + timedelta(hours=4))
    reasons = [
        e.payload.get("failure_reason")
        for e in events
        if e.stream == "signin" and account_of(e) == user.user_id
    ]
    assert reasons.count("session_revoked") == 1


def test_remote_work_shift_moves_egress_and_hours() -> None:
    config = load_config(
        overrides={"org": {"users": 50}, "duration_h": 60, "drift": {"enabled": True, "at_h": 30}}
    )
    sim = Simulator(config)
    planner = sim.ctx.planner
    before = [planner.plan(u, 0) for u in sim.ent.users]
    after = [planner.plan(u, 2) for u in sim.ent.users]
    share = lambda plans: sum(p.remote for p in plans if p.works) / sum(p.works for p in plans)  # noqa: E731
    assert share(after) > share(before) + 0.3
    ztna = [p for p in after if p.remote and p.trip is None]
    assert ztna and all(sim.ent.geo.lookup(p.public_ip).org == "Zscaler" for p in ztna)
    assert (
        np.mean([p.start.hour + p.start.minute / 60 for p in after if p.works])
        > np.mean([p.start.hour + p.start.minute / 60 for p in before if p.works]) + 1.0
    )
