from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

import pytest

from agentic_soc.schemas import parse_event
from agentic_soc.schemas.attack import is_valid_technique
from agentic_soc.simulator.campaign import INJECTION_COMMENT, STAGES, Campaign
from agentic_soc.simulator.config import load_config
from agentic_soc.simulator.generators import BenignActivity, build_context
from agentic_soc.simulator.model import SimEvent

TICK = 60


def make_campaign(seed: int = 7, **campaign: object) -> Campaign:
    overrides: dict[str, object] = {"seed": seed}
    if campaign:
        overrides["campaign"] = campaign
    cfg = load_config(overrides=overrides)
    return Campaign(BenignActivity(build_context(cfg)))


def run(
    campaign: Campaign,
    start: datetime | None = None,
    hours: float = 20,
    until: Callable[[Campaign], bool] | None = None,
) -> tuple[list[SimEvent], datetime]:
    t = start or campaign.start - timedelta(minutes=1)
    end = campaign.start + timedelta(hours=hours)
    events: list[SimEvent] = []
    while t < end:
        events += campaign.step(t, TICK)
        t += timedelta(seconds=TICK)
        if until is not None and until(campaign):
            break
    return events, t


def reached(stage: str) -> Callable[[Campaign], bool]:
    return lambda c: stage in c.stage_times


@pytest.fixture(scope="module")
def undefended() -> tuple[Campaign, list[SimEvent]]:
    campaign = make_campaign()
    events, _ = run(campaign)
    return campaign, events


def test_full_kill_chain_without_defence(undefended) -> None:
    campaign, _ = undefended
    truth = campaign.truth()
    assert truth["status"] == "completed"
    times = [campaign.stage_times[s] for s in STAGES]
    assert times == sorted(times)
    assert truth["exfil_bytes"] >= truth["exfil_target_bytes"] > 1e9
    assert truth["victim"] in truth["compromised_users"]
    assert truth["admin_account"].startswith("adm-")
    ents = truth["entities"]
    assert {truth["workstation"], truth["staging_host"]} <= set(ents["hosts"])
    assert truth["victim"] in ents["users"] and truth["admin_account"] in ents["users"]
    assert set(truth["c2_ips"]) <= set(ents["ips"]) and len(truth["c2_ips"]) == 1
    exfil_h = (campaign.stage_times["exfiltration"] - campaign.start).total_seconds() / 3600
    assert 3 < exfil_h < 14


def test_events_are_labelled_and_schema_valid(undefended) -> None:
    _, events = undefended
    assert {e.stream for e in events} == {"signin", "flow", "process"}
    for event in events:
        assert event.label is not None and event.label.malicious
        assert event.label.stage in STAGES
        assert is_valid_technique(event.label.technique)
        parse_event(event.stream, event.payload)


def test_password_spray_shape(undefended) -> None:
    campaign, events = undefended
    spray = [e for e in events if e.stream == "signin" and e.label.stage == "spray"]
    users = {e.payload["user"] for e in spray}
    ips = {e.payload["src_ip"] for e in spray}
    assert len(users) >= 60 and len(ips) == 2
    outcomes = [e.payload["outcome"] for e in spray]
    assert outcomes.count("success") == len(campaign.compromised) >= 2
    assert {e.payload["source"] for e in spray} == {"vpn-legacy"}
    beacons = [e for e in events if e.stream == "flow" and e.label.stage == "command_and_control"]
    assert len(beacons) > 50


def test_prompt_injection_strings_can_be_toggled(undefended) -> None:
    _, events = undefended
    assert any(INJECTION_COMMENT in e.payload.get("command_line", "") for e in events)
    assert any("SOC assistant" in e.payload.get("user_agent", "") for e in events)
    clean, _ = run(make_campaign(prompt_injection=False), hours=8)
    assert not any("AI ANALYST" in e.payload.get("command_line", "") for e in clean)


def test_campaign_is_deterministic() -> None:
    a, b = make_campaign(seed=9), make_campaign(seed=9)
    ea, _ = run(a, hours=12)
    eb, _ = run(b, hours=12)
    assert [e.payload for e in ea] == [e.payload for e in eb]
    assert a.truth() == b.truth()
    assert make_campaign(seed=10).truth()["start"] != a.truth()["start"]


def test_disabled_campaign_emits_nothing() -> None:
    campaign = make_campaign(enabled=False)
    events, _ = run(campaign)
    assert events == [] and campaign.truth()["status"] == "disabled"


def test_blocking_spray_infrastructure_makes_the_attacker_pivot() -> None:
    campaign = make_campaign()
    _, t = run(campaign, until=reached("spray"))
    for ip in campaign.spray_ips[:2]:
        campaign.control.apply("block_ip", ip, t)
    events, _ = run(campaign, start=t)
    truth = campaign.truth()
    assert [p["kind"] for p in truth["pivots"]][:2] == ["spray", "spray"]
    blocked = [
        e
        for e in events
        if e.stream == "signin" and e.payload.get("failure_reason") == "blocked_ip"
    ]
    assert 1 <= len(blocked) <= 6
    assert len(truth["spray_ips"]) == 4
    assert truth["status"] == "completed"


def test_spray_blocked_without_pivot_stalls() -> None:
    campaign = make_campaign(pivot=False)
    for ip in campaign.spray_ips[:2]:
        campaign.control.apply("block_ip", ip, campaign.start - timedelta(minutes=5))
    run(campaign)
    truth = campaign.truth()
    assert truth["status"] == "stalled"
    assert truth["stall_reason"] == "password spray found no valid account"
    assert truth["exfil_bytes"] == 0 and truth["entities"]["hosts"] == []


def test_isolating_the_foothold_stops_the_campaign() -> None:
    campaign = make_campaign()
    _, t = run(campaign, until=reached("command_and_control"))
    ws = campaign.ws.host_id
    campaign.control.apply("isolate_host", ws, t)
    events, _ = run(campaign, start=t)
    truth = campaign.truth()
    assert truth["status"] == "stalled" and "isolated" in truth["stall_reason"]
    assert truth["exfil_bytes"] == 0
    ws_ip = campaign.ent.dhcp_ip(ws, t)
    assert not [e for e in events if e.stream == "flow" and e.payload["src_ip"] == ws_ip]
    assert ws in truth["entities"]["hosts"]


def test_blocking_c2_rotates_then_stalls() -> None:
    campaign = make_campaign()
    _, t = run(campaign, until=reached("command_and_control"))
    first = campaign.c2_ips[0]
    campaign.control.apply("block_ip", first, t)
    _, t = run(campaign, start=t, until=lambda c: c.c2_index == 1)
    assert campaign.truth()["pivots"][-1] == {
        "time": campaign.pivots[-1]["time"],
        "kind": "c2",
        "to": campaign.c2_ips[1],
    }
    for ip in campaign.c2_ips[1:]:
        campaign.control.apply("block_ip", ip, t)
    events, _ = run(campaign, start=t)
    truth = campaign.truth()
    assert truth["status"] == "stalled" and "C2" in truth["stall_reason"]
    assert truth["exfil_bytes"] == 0
    blocked = [e for e in events if e.stream == "flow" and e.payload["fw_action"] == "blocked"]
    assert blocked and len(truth["c2_ips"]) == 3


def test_disabling_the_harvested_admin_stops_lateral_movement() -> None:
    campaign = make_campaign()
    _, t = run(campaign, until=reached("credential_access"))
    campaign.control.apply("disable_account", campaign.admin, t)
    events, _ = run(campaign, start=t)
    truth = campaign.truth()
    assert truth["status"] == "stalled"
    assert truth["stall_reason"] == "privileged account disabled before lateral movement"
    assert "lateral_movement" not in truth["stage_times"]
    failures = [
        e
        for e in events
        if e.stream == "signin" and e.payload.get("failure_reason") == "account_disabled"
    ]
    assert failures and failures[0].payload["user"].startswith("adm-")
    assert campaign.implants  # the workstation implant keeps beaconing until it is isolated


def test_revoked_session_burns_the_account_and_the_attacker_switches() -> None:
    campaign = make_campaign()
    assert len(campaign.weak_guess) >= 2
    _, t = run(campaign, until=reached("initial_access"))
    first = campaign.victim.user_id
    campaign.control.apply("revoke_sessions", first, t)
    events, _ = run(campaign, start=t)
    truth = campaign.truth()
    denied = [
        e
        for e in events
        if e.stream == "signin" and e.payload.get("failure_reason") == "mfa_denied"
    ]
    assert denied and first in denied[0].payload["user"]
    assert truth["victim"] != first and first in campaign.burned
    assert truth["status"] == "completed"
