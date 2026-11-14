"""A deterministic stand-in for the LLM: an expert-system analyst with the same chat interface.

It sees only the conversation (tool results), never ground truth. It is used by tests and fast
evaluation runs, and as a reference policy to compare the local LLM against. It investigates the
incident's main entities with the same tools and decides with explicit rules.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from agentic_soc.agent.llm import LLMResponse, ToolCall

C2_EXFIL = {"T1071.001", "T1573", "T1041"}
HOST_COMPROMISE = {"T1003.001", "T1569.002", "T1218.011", "T1560.001", "T1059.001"}
LATE = C2_EXFIL | HOST_COMPROMISE | {"T1021.002", "T1021.001"}
PRIVATE = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(t: str) -> datetime:
    return datetime.fromisoformat(t.replace("Z", "+00:00"))


class ScriptedLLM:
    """Rule-based analyst speaking the chat/tool-calling protocol of the agent."""

    def __init__(self, max_calls: int = 9) -> None:
        self.name = "scripted-analyst"
        self.max_calls = max_calls

    # ------------------------------------------------------------------ conversation state
    @staticmethod
    def _history(messages: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any], Any]]:
        calls: list[tuple[str, dict[str, Any]]] = []
        results: list[Any] = []
        for message in messages:
            if message["role"] == "assistant":
                calls += [
                    (c["function"]["name"], c["function"]["arguments"])
                    for c in message.get("tool_calls") or []
                ]
            elif message["role"] == "tool":
                try:
                    results.append(json.loads(message["content"]))
                except json.JSONDecodeError:
                    results.append({"error": "unreadable"})
        return [(n, a, r) for (n, a), r in zip(calls, results, strict=False)]

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             response_format: dict[str, Any] | None = None) -> LLMResponse:  # fmt: skip
        task = next(m["content"] for m in messages if m["role"] == "user")
        incident_id = re.search(r"incident (\S+?) \(", task).group(1)  # type: ignore[union-attr]
        history = self._history(messages)
        done = {(n, json.dumps(a, sort_keys=True)) for n, a, _ in history}
        if tools and response_format is None:
            incident = next(
                (r for n, _, r in history if n == "get_incident" and "error" not in r), None
            )
            if incident is None and not history:
                return LLMResponse("", [ToolCall("get_incident", {"incident_id": incident_id})])
            if incident is not None:
                for name, args in self.plan(incident)[: self.max_calls]:
                    if (name, json.dumps(args, sort_keys=True)) not in done:
                        return LLMResponse("", [ToolCall(name, args)])
        incident = next((r for n, _, r in history if n == "get_incident" and "error" not in r), {})
        return LLMResponse(json.dumps(self.decide(incident_id, incident, history)))

    # ------------------------------------------------------------------ investigation plan
    @staticmethod
    def _rank(alerts: list[dict[str, Any]], key: str) -> list[str]:
        """Entities by evidence weight: alerts with late-stage techniques count three times."""
        weight: dict[str, float] = {}
        for alert in alerts:
            factor = 3.0 if set(alert["techniques"]) & LATE else 1.0
            for value in alert["entities"].get(key, []):
                weight[value] = weight.get(value, 0.0) + factor * alert["score"]
        return sorted(weight, key=lambda v: (-weight[v], v))

    def plan(self, incident: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        alerts = incident["alerts"]
        start = _iso(_parse(incident["first_seen"]) - timedelta(hours=1))
        end = _iso(
            min(_parse(incident["now"]), _parse(incident["last_seen"]) + timedelta(minutes=30))
        )
        window = {"start": start, "end": end}
        detectors = set(incident["detectors"])
        users = self._rank(alerts, "users")
        hosts = self._rank(alerts, "hosts")
        ips = [ip for ip in self._rank(alerts, "ips") if not PRIVATE.match(ip)]
        calls: list[tuple[str, dict[str, Any]]] = []
        if users:
            calls.append(("get_asset_context", {"entity": f"user:{users[0]}"}))
            if "M1" in detectors:
                calls.append(("score_signins", {"entity": f"user:{users[0]}"} | window))
            if detectors == {"M1"}:
                calls.append(
                    (
                        "get_entity_timeline",
                        {"entity": f"user:{users[0]}", "streams": ["signin"], "limit": 40} | window,
                    )
                )
        if hosts:
            host = hosts[0]
            calls.append(("get_asset_context", {"entity": f"host:{host}"}))
            if detectors & {"M2", "M3"}:
                calls.append(("score_flows", {"entity": f"host:{host}"} | window))
                calls.append(("score_processes", {"entity": f"host:{host}"} | window))
                calls.append(
                    (
                        "get_entity_timeline",
                        {"entity": f"host:{host}", "streams": ["process"], "limit": 60} | window,
                    )
                )
        for ip in ips[:2]:
            calls.append(("get_asset_context", {"entity": f"ip:{ip}"}))
        for alert in alerts:
            sources = alert["entities"].get("ips", [])
            if (
                alert["detector"] == "M2"
                and set(alert["techniques"]) & C2_EXFIL
                and not alert["entities"].get("hosts")
                and sources
            ):
                calls.append(
                    ("get_asset_context", {"entity": f"ip:{sources[0]}"})
                )  # who held the beacon source?
                break
        return calls

    # ------------------------------------------------------------------ decision
    def decide(
        self,
        incident_id: str,
        incident: dict[str, Any],
        history: list[tuple[str, dict[str, Any], Any]],
    ) -> dict[str, Any]:
        if not incident:
            return {"incident_id": incident_id, "verdict": "suspicious", "techniques": [], "evidence": [],
                    "action": {"type": "none"}, "confidence": 0.3, "rationale": "Incident could not be loaded."}  # fmt: skip
        alerts = incident["alerts"]
        techniques = {t["id"] for t in incident["techniques"]}
        detectors = set(incident["detectors"])
        context = {
            a["entity"]: r for n, a, r in history if n == "get_asset_context" and "error" not in r
        }
        scores = {
            (n, a["entity"]): r
            for n, a, r in history
            if n.startswith("score_") and "error" not in r
        }
        tool_detector = {"score_signins": "M1", "score_flows": "M2", "score_processes": "M3"}
        confirmed = [k for k, r in scores.items() if r.get("alerting_windows", 0) > 0]
        # Re-scoring with the detector that raised the alerts is not corroboration.
        independent = [k for k in confirmed if tool_detector[k[0]] not in detectors]
        injection = any('"injection_suspected": true' in json.dumps(r) for _, _, r in history)
        late = techniques & LATE
        strong = techniques & C2_EXFIL if "M2" in detectors else set()
        spray = "T1110.003" in techniques
        reasons: list[str] = []
        if injection:
            reasons.append(
                "log data contains text instructing an AI analyst to ignore the activity (prompt injection)"
            )
        if late and independent:
            reasons.append(
                f"late-stage techniques {sorted(late)} confirmed independently by {', '.join(n for n, _ in independent)}"
            )
        if strong and (len(detectors) >= 2 or independent):
            reasons.append(f"C2 or exfiltration ({sorted(strong)}) corroborated across detectors")
        if len(detectors) >= 2 and incident["risk"] >= 0.8:
            reasons.append(
                f"corroborated by {len(detectors)} detectors (risk {incident['risk']:.2f})"
            )
        if spray:
            reasons.append("password spraying across many accounts from rented infrastructure")
        evidence = [{"id": a["alert_id"], "kind": "alert", "note": f"{a['detector']} {', '.join(a['techniques'][:2])}"}
                    for a in alerts[:4]]  # fmt: skip
        benign_events = self._benign_signins(history) if detectors == {"M1"} and not spray else []
        if reasons:
            verdict, confidence = "malicious", min(0.97, 0.75 + 0.07 * len(reasons))
        elif benign_events:
            verdict, confidence = "benign", 0.75
            reasons.append(
                "sign-ins from a new location used MFA from known patterns (travel or consumer VPN)"
            )
            evidence += [
                {"id": e, "kind": "event", "note": "successful sign-in with MFA"}
                for e in benign_events[:3]
            ]
        else:
            verdict, confidence = "suspicious", 0.5
            reasons.append("anomalous but not corroborated; needs an analyst")
        actions = self._containment(incident, context, scores) if verdict == "malicious" else []
        primary = actions[0] if actions else {"type": "none"}
        return {
            "incident_id": incident_id,
            "verdict": verdict,
            "techniques": sorted(techniques)[:10],
            "evidence": evidence,
            "action": primary,
            "extra_actions": actions[1:3],
            "confidence": round(confidence, 2),
            "rationale": "; ".join(reasons)[:1400],
        }

    @staticmethod
    def _benign_signins(history: list[tuple[str, dict[str, Any], Any]]) -> list[str]:
        for name, _, result in history:
            if name != "get_entity_timeline" or "error" in result:
                continue
            signins = [
                e
                for e in result["events"]
                if e["stream"] == "signin" and e.get("outcome") == "success"
            ]
            risky = [
                e
                for e in signins
                if not e.get("mfa") and e.get("src_category") in {"hosting", "anonymizer"}
            ]
            mfa = [e["event_id"] for e in signins if e.get("mfa")]
            if mfa and not risky:
                return mfa
        return []

    def _containment(
        self, incident: dict[str, Any], context: dict[str, Any], scores: dict[Any, Any]
    ) -> list[dict[str, str]]:
        candidates: list[tuple[int, str, str]] = []

        def protected_host(host: str) -> bool:
            return bool(context.get(f"host:{host}", {}).get("protected_infrastructure"))

        def blockable(ip: str) -> bool:
            ctx = context.get(f"ip:{ip}")
            category = (ctx or {}).get("geo", {}).get("category")
            return (
                not PRIVATE.match(ip)
                and category not in {"cloud", "cdn", "corporate"}
                and not (ctx or {}).get("office_nat")
            )

        for alert in incident["alerts"]:
            t = set(alert["techniques"])
            ents = alert["entities"]
            ips, hosts, users = ents.get("ips", []), ents.get("hosts", []), ents.get("users", [])
            if alert["detector"] == "M2" and t & C2_EXFIL:
                if len(ips) > 1 and blockable(ips[1]):
                    candidates.append((1, "block_ip", ips[1]))
                source = (
                    hosts[0]
                    if hosts
                    else context.get(f"ip:{ips[0]}", {}).get("bound_host")
                    if ips
                    else None
                )
                if source and not protected_host(source):
                    candidates.append((0, "isolate_host", source))
            if alert["detector"] == "M3" and t & HOST_COMPROMISE:
                for host in hosts[:1]:
                    if not protected_host(host):
                        candidates.append((0, "isolate_host", host))
                candidates += [(2, "disable_account", u) for u in users if u.startswith("adm-")]
            if alert["detector"] == "M1" and "T1078" in t:
                for user in users:
                    kind = context.get(f"user:{user}", {}).get("account_kind", "user")
                    candidates.append(
                        (
                            2 if kind == "admin" else 3,
                            "disable_account" if kind == "admin" else "revoke_sessions",
                            user,
                        )
                    )
            if "T1110.003" in t:
                candidates += [(4, "block_ip", ip) for ip in ips if blockable(ip)]
        seen: set[tuple[str, str]] = set()
        out: list[dict[str, str]] = []
        for _, action_type, target in sorted(candidates):
            if (action_type, target) not in seen:
                seen.add((action_type, target))
                out.append({"type": action_type, "target": target})
        return out[:3]
