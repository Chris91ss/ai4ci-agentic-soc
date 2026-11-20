from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

import pytest

from agentic_soc.agent import (
    LLMError,
    LLMResponse,
    OllamaLLM,
    ScriptedLLM,
    ToolCall,
    TriageAgent,
    dismissal_guardrail,
)
from agentic_soc.mcp_server import SocContext, SocTools, build_server


@pytest.fixture(scope="module")
def setup(mini_soc):
    ctx = SocContext(store=mini_soc.store, inventory=mini_soc.inventory, profiles=mini_soc.profiles,
                     detectors=mini_soc.client(), actions=mini_soc.actions, clock=lambda: mini_soc.clock,
                     correlation=mini_soc.correlation, resolver=mini_soc.pipeline.resolver)  # fmt: skip
    return mini_soc, build_server(SocTools(ctx))


def triage(agent: TriageAgent, mini, incident) -> Any:
    return asyncio.run(agent.triage(incident.incident_id, incident.risk.risk, 1, mini.clock))


def campaign_entities(mini) -> set[str]:
    return set().union(*mini.sim.truth()["campaign"]["entities"].values())


def test_scripted_analyst_contains_the_campaign(setup) -> None:
    mini, server = setup
    incident = mini.top_incident()
    result = triage(TriageAgent(ScriptedLLM(), server), mini, incident)
    assert result.ok, result.error
    decision = result.decision
    assert decision.verdict == "malicious" and decision.confidence >= 0.8
    targets = {a.target for a in decision.all_actions()}
    assert targets and targets <= campaign_entities(mini)
    assert result.tool_calls >= 5 and result.invalid_tool_calls == 0 and result.repairs == 0
    assert {s.tool for s in result.steps if s.kind == "tool"} >= {
        "get_incident",
        "get_asset_context",
    }
    assert all(
        e.id in json.dumps([s.result for s in result.steps], default=str) for e in decision.evidence
    )


def test_scripted_analyst_does_not_contain_benign_incidents(setup) -> None:
    mini, server = setup
    agent = TriageAgent(ScriptedLLM(), server)
    attack = campaign_entities(mini)
    benign = [s for s in mini.correlation.incidents.values()
              if not set().union(*(set(v) for v in s.entities().model_dump().values())) & attack]  # fmt: skip
    assert benign
    for incident in benign[:4]:
        result = triage(agent, mini, incident)
        assert result.ok and result.decision.verdict in {"benign", "suspicious"}
        assert result.decision.all_actions() == []


class FaultyLLM:
    """Calls a non-existent tool, then cites hallucinated evidence, then recovers."""

    name = "faulty"

    def __init__(self, incident_id: str) -> None:
        self.incident_id = incident_id
        self.turn = 0

    def chat(self, messages, tools=None, response_format=None) -> LLMResponse:
        self.turn += 1
        if self.turn == 1:
            return LLMResponse("", [ToolCall("delete_everything", {})])
        if self.turn == 2:
            return LLMResponse("", [ToolCall("get_incident", {"incident_id": self.incident_id})])
        alert = json.loads(
            next(m for m in reversed(messages) if m["role"] == "tool" and "alerts" in m["content"])[
                "content"
            ]
        )["alerts"][0]
        cited = "AL-made-up" if self.turn == 3 else alert["alert_id"]
        decision = {"incident_id": self.incident_id, "verdict": "suspicious", "evidence": [{"id": cited, "kind": "alert"}],
                    "action": {"type": "none"}, "confidence": 0.4}  # fmt: skip
        return LLMResponse("```json\n" + json.dumps(decision) + "\n```")


def test_guardrails_count_invalid_calls_and_repair_hallucinations(setup) -> None:
    mini, server = setup
    incident = mini.top_incident()
    result = triage(TriageAgent(FaultyLLM(incident.incident_id), server), mini, incident)
    assert result.ok and result.invalid_tool_calls == 1 and result.repairs == 1
    assert "not seen in any tool result" in next(
        s.error for s in result.steps if s.kind == "decision"
    )


class BrokenLLM:
    name = "broken"

    def chat(self, messages, tools=None, response_format=None) -> LLMResponse:
        return LLMResponse("I think it is probably fine?")


def test_agent_failure_is_reported(setup) -> None:
    mini, server = setup
    result = triage(TriageAgent(BrokenLLM(), server, max_repairs=2), mini, mini.top_incident())
    assert not result.ok and result.repairs == 2 and "no valid decision" in result.error


class DownLLM:
    name = "down"

    def chat(self, messages, tools=None, response_format=None) -> LLMResponse:
        raise LLMError("Ollama request failed: 500")


def test_llm_outage_is_caught_not_raised(setup) -> None:
    mini, server = setup
    result = triage(TriageAgent(DownLLM(), server), mini, mini.top_incident())
    assert not result.ok and "500" in result.error and result.steps[-1].kind == "error"


def test_extra_actions_without_a_primary_action_are_promoted() -> None:
    reply = {"verdict": "malicious", "evidence": [{"id": "AL-1", "kind": "alert"}], "action": {"type": "none"},
             "extra_actions": [{"type": "block_ip", "target": "45.32.7.7"}], "confidence": 0.9}  # fmt: skip
    decision, error = TriageAgent(DownLLM(), None)._validate(
        json.dumps(reply), "INC-1", "AL-1 45.32.7.7"
    )
    assert error is None and decision is not None
    assert decision.action.target == "45.32.7.7" and decision.extra_actions == []


def test_dismissal_guardrail_escalates_high_risk() -> None:
    from agentic_soc.schemas import Decision

    benign = Decision(incident_id="I", verdict="benign", evidence=[{"id": "AL-1", "kind": "alert"}],
                      action={"type": "none"}, confidence=0.8)  # fmt: skip
    escalated, note = dismissal_guardrail(benign, 0.91, ["M1", "M2"], {"command-and-control"})
    assert escalated.verdict == "suspicious" and note and "escalated" in escalated.rationale
    kept, note = dismissal_guardrail(benign, 0.55, ["M1"], {"initial-access"})
    assert kept.verdict == "benign" and note is None


@pytest.mark.llm
@pytest.mark.skipif(
    not os.environ.get("SOC_TEST_LLM"), reason="set SOC_TEST_LLM=1 with Ollama serving gpt-oss:20b"
)
def test_local_llm_triage(setup) -> None:
    mini, server = setup
    llm = OllamaLLM()
    if not llm.available():
        pytest.skip("model not available")
    result = triage(TriageAgent(llm, server, max_steps=8), mini, mini.top_incident())
    assert result.llm_calls >= 2 and result.tool_calls >= 1
    assert result.ok, result.error


def test_scripted_llm_delay() -> None:
    llm = ScriptedLLM(delay_s=0.05)
    messages = [{"role": "user", "content": "Triage incident INC-00001 (risk 0.9)."}]
    started = time.perf_counter()
    response = llm.chat(messages, tools=[{"type": "function"}])
    assert time.perf_counter() - started >= 0.05
    assert response.tool_calls[0].name == "get_incident"


def _flow_incident(destination: str) -> dict[str, Any]:
    """An odd flow labelled as C2 next to rare admin processes on another server."""
    flow = {
        "alert_id": "AL-1",
        "detector": "M2",
        "kind": "M2",
        "score": 0.82,
        "techniques": ["T1071.001"],
        "entities": {"users": [], "hosts": ["SRV-APP-08"], "ips": ["10.20.4.18", destination]},
    }
    rare = {
        "alert_id": "AL-2",
        "detector": "M3",
        "kind": "M3",
        "score": 0.99,
        "techniques": ["T1059.001"],
        "entities": {"users": ["adm-david.bernard"], "hosts": ["SRV-FILE-04"], "ips": []},
    }
    return {"incident_id": "INC-00038", "risk": 0.78, "detectors": ["M2", "M3"], "alerts": [flow, rare],
            "techniques": [{"id": "T1071.001"}, {"id": "T1059.001"}]}  # fmt: skip


def test_c2_needs_an_external_destination() -> None:
    llm = ScriptedLLM()
    internal = llm.decide("INC-00038", _flow_incident("10.20.3.13"), [])
    assert internal["verdict"] == "suspicious" and internal["action"]["type"] == "none"
    external = llm.decide("INC-00038", _flow_incident("193.106.191.70"), [])
    assert external["verdict"] == "malicious" and "C2" in external["rationale"]
    assert {"type": "block_ip", "target": "193.106.191.70"} in [
        external["action"],
        *external["extra_actions"],
    ]


def _signin_incident() -> dict[str, Any]:
    """A spray from an anonymiser that got into one account, next to two staff signing in through
    the company's ZTNA egress (a cloud address), one of them after a typo."""
    spray = {
        "alert_id": "AL-1",
        "detector": "M1",
        "kind": "M1-ip",
        "score": 1.0,
        "techniques": ["T1110.003"],
        "entities": {
            "users": ["anna.novak", "lukas.dumitru"],
            "hosts": [],
            "ips": ["185.220.102.90"],
        },
    }
    egress = {
        "alert_id": "AL-2",
        "detector": "M1",
        "kind": "M1-ip",
        "score": 0.99,
        "techniques": ["T1110", "T1078"],
        "entities": {"users": ["florin.tudor", "anna.novak"], "hosts": [], "ips": ["165.225.67.6"]},
    }
    victim = {
        "alert_id": "AL-3",
        "detector": "M1",
        "kind": "M1-user",
        "score": 1.0,
        "techniques": ["T1078", "T1133"],
        "entities": {"users": ["lukas.dumitru"], "hosts": [], "ips": ["185.220.102.90"]},
    }
    return {"incident_id": "INC-00058", "risk": 0.87, "detectors": ["M1"], "alerts": [spray, egress, victim],
            "techniques": [{"id": t} for t in ("T1078", "T1110", "T1110.003", "T1133")],
            "first_seen": "2026-03-11T08:15:00Z", "last_seen": "2026-03-11T08:45:00Z", "now": "2026-03-11T08:47:00Z"}  # fmt: skip


def test_valid_account_use_needs_an_attacker_like_source() -> None:
    llm = ScriptedLLM()
    incident = _signin_incident()
    looked_up = {args["entity"] for name, args in llm.plan(incident) if name == "get_asset_context"}
    assert {"ip:185.220.102.90", "ip:165.225.67.6"} <= looked_up
    history = [
        ("get_asset_context", {"entity": "ip:185.220.102.90"}, {"geo": {"category": "anonymizer"}}),
        (
            "get_asset_context",
            {"entity": "ip:165.225.67.6"},
            {"geo": {"category": "cloud", "org": "Zscaler"}},
        ),
    ]
    decision = llm.decide("INC-00058", incident, history)
    actions = [decision["action"], *decision["extra_actions"]]
    assert decision["verdict"] == "malicious"
    assert {"type": "block_ip", "target": "185.220.102.90"} in actions
    assert {"type": "revoke_sessions", "target": "lukas.dumitru"} in actions
    assert not any(a["target"] in {"florin.tudor", "anna.novak"} for a in actions)
