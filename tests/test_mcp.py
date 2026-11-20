from __future__ import annotations

import asyncio
import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from mcp import Client

from agentic_soc.agent.react import compact_json
from agentic_soc.mcp_server import (
    SocContext,
    SocTools,
    build_server,
    contains_injection,
    looks_like_injection,
    quote,
)
from agentic_soc.mcp_server.tools import representative
from agentic_soc.simulator.campaign import INJECTION_COMMENT

EXPECTED_TOOLS = {"get_incident", "get_entity_timeline", "get_asset_context", "score_signins", "score_flows",
                  "score_processes", "propose_action"}  # fmt: skip


@pytest.fixture(scope="module")
def soc(mini_soc):
    ctx = SocContext(store=mini_soc.store, inventory=mini_soc.inventory, profiles=mini_soc.profiles,
                     detectors=mini_soc.client(), actions=mini_soc.actions, clock=lambda: mini_soc.clock,
                     correlation=mini_soc.correlation, resolver=mini_soc.pipeline.resolver)  # fmt: skip
    return mini_soc, ctx, build_server(SocTools(ctx))


def call(server, name: str, args: dict[str, Any]) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with Client(server) as client:
            result = await client.call_tool(name, args)
            assert not result.is_error, result.content
            return result.structured_content

    return asyncio.run(run())


def test_tools_are_listed_with_schemas(soc) -> None:
    _, _, server = soc

    async def run():
        async with Client(server) as client:
            return (await client.list_tools()).tools, client.instructions

    tools, instructions = asyncio.run(run())
    assert {t.name for t in tools} == EXPECTED_TOOLS
    propose = next(t for t in tools if t.name == "propose_action")
    assert set(propose.input_schema["required"]) == {
        "incident_id",
        "action_type",
        "target",
        "justification",
    }
    assert "$untrusted" in (instructions or "")


def test_get_incident_and_timeline(soc) -> None:
    mini, _, server = soc
    incident = mini.top_incident()
    view = call(server, "get_incident", {"incident_id": incident.incident_id})
    assert view["risk"] > 0.5 and view["alerts"] and view["entities"]["users"]
    assert all("$untrusted" in a["summary"] for a in view["alerts"] if a["summary"])
    assert any(t.get("tactic") for t in view["techniques"])
    victim = mini.sim.campaign.victim.user_id
    timeline = call(server, "get_entity_timeline", {"entity": f"user:{victim}",
                                                    "start": (mini.sim.campaign.start - timedelta(hours=1)).isoformat(),
                                                    "end": mini.clock.isoformat(), "limit": 200})  # fmt: skip
    assert timeline["returned"] > 0 and "signin" in timeline["counts"]
    agents = [e["user_agent"] for e in timeline["events"] if "user_agent" in e]
    assert agents and all("$untrusted" in ua for ua in agents)
    ws = mini.sim.campaign.ws.host_id
    host = call(server, "get_entity_timeline", {"entity": f"host:{ws}", "streams": ["process"], "limit": 200,
                                                "start": mini.sim.campaign.start.isoformat(), "end": mini.clock.isoformat()})  # fmt: skip
    assert contains_injection(host["events"]), "the campaign's prompt injection must be flagged"


def test_asset_context(soc) -> None:
    mini, _, server = soc
    victim = mini.sim.campaign.victim.user_id
    user = call(server, "get_asset_context", {"entity": f"user:{victim}"})
    assert user["account_kind"] == "user" and user["baseline"]["successful_signins"] > 0
    dc = next(h for h in mini.inventory.hosts.values() if h.role == "dc")
    assert (
        call(server, "get_asset_context", {"entity": f"host:{dc.host_id}"})[
            "protected_infrastructure"
        ]
        is True
    )
    c2 = mini.sim.campaign.c2_ips[0]
    ip = call(server, "get_asset_context", {"entity": f"ip:{c2}"})
    assert (
        ip["zone"] == "external"
        and ip["geo"]["category"] == "hosting"
        and ip["contacts_last_24h"]["flows"] > 10
    )


def test_scoring_tools_call_the_detectors(soc) -> None:
    mini, _, server = soc
    campaign = mini.sim.campaign
    window = {
        "start": campaign.start.isoformat(),
        "end": (campaign.start + timedelta(hours=6)).isoformat(),
    }
    spray = call(server, "score_signins", {"entity": f"ip:{campaign.spray_ips[0]}"} | window)
    assert spray["detector"] == "M1" and spray["windows_scored"] > 0 and spray["max_score"] > 0.9
    flows = call(server, "score_flows", {"entity": f"ip:{campaign.c2_ips[0]}"} | window)
    assert flows["detector"] == "M2" and flows["alerting_windows"] > 0
    procs = call(server, "score_processes", {"entity": f"host:{campaign.ws.host_id}"} | window)
    assert procs["detector"] == "M3" and procs["windows_scored"] > 0


def test_scoring_tools_score_without_holding_the_pipeline_lock(mini_soc) -> None:
    # In live mode the pipeline keeps ingesting while the agent investigates. Scoring rebuilds
    # features from thousands of events, so the lock must only be held while the tool reads.
    lock = threading.RLock()
    lock_free: list[bool] = []

    def free_in_another_thread() -> bool:
        result: list[bool] = []

        def attempt() -> None:
            acquired = lock.acquire(timeout=1)
            if acquired:
                lock.release()
            result.append(acquired)

        thread = threading.Thread(target=attempt)
        thread.start()
        thread.join()
        return result[0]

    class Probe:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def score(self, name: str, rows: list[Any]) -> list[Any]:
            lock_free.append(free_in_another_thread())
            return self.inner.score(name, rows)

        def versions(self) -> dict[str, str]:
            return self.inner.versions()

    ctx = SocContext(store=mini_soc.store, inventory=mini_soc.inventory, profiles=mini_soc.profiles,
                     detectors=Probe(mini_soc.client()), actions=mini_soc.actions, clock=lambda: mini_soc.clock,
                     correlation=mini_soc.correlation, resolver=mini_soc.pipeline.resolver, lock=lock)  # fmt: skip
    server = build_server(SocTools(ctx))
    campaign = mini_soc.sim.campaign
    window = {
        "start": campaign.start.isoformat(),
        "end": (campaign.start + timedelta(hours=6)).isoformat(),
    }
    call(server, "score_signins", {"entity": f"ip:{campaign.spray_ips[0]}"} | window)
    call(server, "score_flows", {"entity": f"ip:{campaign.c2_ips[0]}"} | window)
    call(server, "score_processes", {"entity": f"host:{campaign.ws.host_id}"} | window)
    assert lock_free == [True, True, True]


def test_propose_action_goes_through_the_policy_gate(soc) -> None:
    mini, ctx, server = soc
    incident = mini.top_incident().incident_id
    c2 = mini.sim.campaign.c2_ips[0]
    dc = next(h for h in mini.inventory.hosts.values() if h.role == "dc")
    block = call(server, "propose_action", {"incident_id": incident, "action_type": "block_ip", "target": c2,
                                            "justification": "C2 beacon every minute (AL-x)"})  # fmt: skip
    assert block["status"] == "executed"
    isolate_dc = call(server, "propose_action", {"incident_id": incident, "action_type": "isolate_host",
                                                 "target": dc.host_id, "justification": "attacker touched it"})  # fmt: skip
    assert isolate_dc["status"] == "denied" and "protected" in isolate_dc["reason"]
    disable = call(server, "propose_action", {"incident_id": incident, "action_type": "disable_account",
                                              "target": mini.sim.campaign.victim.user_id,
                                              "justification": "sign-in from a hosting provider at night"})  # fmt: skip
    assert disable["status"] == "pending_approval"
    bad = call(server, "propose_action", {"incident_id": incident, "action_type": "wipe", "target": "x",
                                          "justification": "testing the allow-list"})  # fmt: skip
    assert "allow-list" in bad["error"]
    assert call(server, "get_asset_context", {"entity": "bogus"})["error"].startswith(
        "entity must look like"
    )
    assert any(c["tool"] == "propose_action" and c["ok"] for c in ctx.tool_calls)


def test_quoting_flags_injection() -> None:
    assert looks_like_injection(INJECTION_COMMENT)
    wrapped = quote("powershell.exe -enc AAA" + INJECTION_COMMENT)
    assert wrapped["injection_suspected"] is True and wrapped["$untrusted"].startswith("powershell")
    assert quote("chrome.exe --type=renderer") == {"$untrusted": "chrome.exe --type=renderer"}
    assert quote("x" * 1000)["$untrusted"].endswith("[truncated]")
    assert "$untrusted" not in quote('{"$untrusted": "nested"}')["$untrusted"]


def _alert(i: int, kind: str, techniques: list[str], score: float = 1.0) -> dict:
    return {
        "alert_id": f"AL-{i:03d}", "detector": kind.split("-")[0], "model_version": kind, "score": score,
        "window_end": datetime(2026, 3, 16, 10, i % 60, tzinfo=UTC), "techniques": techniques,
        "summary": "x" * 300, "entities": {"users": [f"user{i}"], "ips": ["203.0.113.9"]},
    }  # fmt: skip


def test_incident_view_keeps_every_kind_of_alert() -> None:
    spray = [_alert(i, "M1-user", ["T1110", "T1133"]) for i in range(40)]
    source = _alert(50, "M1-ip", ["T1110.003"])
    victim = _alert(60, "M1-user", ["T1078"], score=0.97)
    chosen = representative([*spray, source, victim], 15)
    assert len(chosen) == 15
    # The strongest alert of each signature comes first.
    assert [a["alert_id"] for a in chosen[:3]] == ["AL-000", "AL-050", "AL-060"]
    # An agent that shortens long lists from the end still sees all three signatures.
    view = json.loads(compact_json({"alerts": chosen}, 2500))
    assert view["_truncated"]
    assert {a["alert_id"] for a in view["alerts"]} >= {"AL-000", "AL-050", "AL-060"}
