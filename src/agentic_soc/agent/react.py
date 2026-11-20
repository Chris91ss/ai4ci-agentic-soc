"""The triage agent: a ReAct loop (reason, call a tool, observe) over the MCP tools, ending in a
JSON-schema-validated decision.

Guardrails: unknown tools and rejected arguments count as invalid tool calls; the decision must
validate against the schema (dismissals cite evidence, actions have targets); every cited
evidence ID and every action target must have appeared in a tool result of this conversation
(no hallucinated evidence); invalid decisions get a bounded number of repair attempts with
schema-constrained output.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mcp import Client
from pydantic import ValidationError

from agentic_soc.agent.llm import LLM, LLMError, LLMResponse, tool_schemas
from agentic_soc.agent.prompts import (
    FINAL_PROMPT,
    REPAIR_PROMPT,
    SYSTEM_PROMPT,
    TASK_PROMPT,
    decision_schema,
)
from agentic_soc.schemas import Decision


@dataclass
class Step:
    index: int
    kind: str  # tool, invalid_tool, decision, repair, error
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    result: Any = None
    ok: bool = True
    error: str | None = None
    latency_ms: float = 0.0
    thinking: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            k: getattr(self, k)
            for k in (
                "index",
                "kind",
                "tool",
                "arguments",
                "result",
                "ok",
                "error",
                "latency_ms",
                "thinking",
            )
        }


@dataclass
class TriageResult:
    incident_id: str
    model: str
    decision: Decision | None = None
    steps: list[Step] = field(default_factory=list)
    llm_calls: int = 0
    tool_calls: int = 0
    invalid_tool_calls: int = 0
    repairs: int = 0
    prompt_tokens: int = 0
    output_tokens: int = 0
    llm_latency_s: float = 0.0
    latency_s: float = 0.0
    injection_seen: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.decision is not None


def _leaves(error: BaseException) -> list[BaseException]:
    """Leaf exceptions of (nested) exception groups raised through anyio task groups."""
    if isinstance(error, BaseExceptionGroup):
        return [leaf for inner in error.exceptions for leaf in _leaves(inner)]
    return [error]


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def compact_json(payload: Any, limit: int) -> str:
    """Serialise ``payload`` within ``limit`` characters while keeping it valid JSON: the
    longest lists are shortened from the end and the result is marked ``_truncated``."""
    text = _dumps(payload)
    if len(text) <= limit:
        return text
    if not isinstance(payload, dict):
        return text[:limit]
    data = json.loads(text)
    data["_truncated"] = True

    def longest(node: Any) -> list[Any] | None:
        best: list[Any] | None = None
        best_size = 0
        stack = [node]
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                size = len(_dumps(item))
                if len(item) > 1 and size > best_size:
                    best, best_size = item, size
                stack.extend(v for v in item if isinstance(v, dict | list))
            elif isinstance(item, dict):
                stack.extend(v for v in item.values() if isinstance(v, dict | list))
        return best

    text = _dumps(data)
    while len(text) > limit:
        target = longest(data)
        if target is None:
            return text[:limit]
        del target[max(1, len(target) * 3 // 4) :]
        text = _dumps(data)
    return text


def extract_json(text: str) -> dict[str, Any]:
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in the reply")
    return json.loads(cleaned[start : end + 1])


class TriageAgent:
    def __init__(
        self,
        llm: LLM,
        server: Any,
        max_steps: int = 12,
        max_repairs: int = 2,
        result_chars: int = 7000,
    ) -> None:
        self.llm = llm
        self.server = server  # an MCPServer instance (in-process) or the URL of one
        self.max_steps = max_steps
        self.max_repairs = max_repairs
        self.result_chars = result_chars

    # ------------------------------------------------------------------ helpers
    def _chat(
        self, result: TriageResult, messages: list[dict[str, Any]], **kwargs: Any
    ) -> LLMResponse:
        try:
            response = self.llm.chat(messages, **kwargs)
        except LLMError:
            result.llm_calls += 1
            reseed = getattr(self.llm, "reseed", None)
            if reseed is not None:
                reseed()  # sampling the same way again would repeat a malformed reply
            response = self.llm.chat(messages, **kwargs)  # one retry; a second failure propagates
        result.llm_calls += 1
        result.prompt_tokens += response.prompt_tokens
        result.output_tokens += response.output_tokens
        result.llm_latency_s += response.latency_s
        return response

    def _validate(
        self, text: str, incident_id: str, observed: str
    ) -> tuple[Decision | None, str | None]:
        try:
            data = extract_json(text)
        except (ValueError, json.JSONDecodeError) as exc:
            return None, f"not valid JSON ({exc})"
        if isinstance(data, dict):
            data["incident_id"] = incident_id
            action, extra = data.get("action"), data.get("extra_actions")
            no_primary = not isinstance(action, dict) or action.get("type") in {None, "none"}
            if no_primary and isinstance(extra, list) and extra:
                data["action"], data["extra_actions"] = extra[0], extra[1:]
        try:
            decision = Decision.model_validate(data)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:4]
            )
            return None, f"schema violation ({problems})"
        missing = [e.id for e in decision.evidence if e.id not in observed]
        if missing:
            return None, f"evidence IDs not seen in any tool result: {missing[:5]}"
        unknown = [
            a.target for a in decision.all_actions() if a.target and a.target not in observed
        ]
        if unknown:
            return None, f"action targets not seen in any tool result: {unknown}"
        return decision, None

    # ------------------------------------------------------------------ the loop
    async def triage(
        self, incident_id: str, risk: float, priority: int, now: datetime
    ) -> TriageResult:
        started = time.perf_counter()
        result = TriageResult(incident_id=incident_id, model=self.llm.name)
        try:
            async with Client(self.server) as client:
                await self._loop(client, result, incident_id, risk, priority, now)
        except* LLMError as group:
            message = "; ".join(str(e) for e in _leaves(group))
            result.error = message
            result.steps.append(Step(len(result.steps), "error", ok=False, error=message))
        result.latency_s = time.perf_counter() - started
        return result

    async def _loop(
        self,
        client: Client,
        result: TriageResult,
        incident_id: str,
        risk: float,
        priority: int,
        now: datetime,
    ) -> None:
        tools = (await client.list_tools()).tools
        names = {t.name for t in tools}
        schemas = tool_schemas(tools)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": TASK_PROMPT.format(incident_id=incident_id, risk=risk, priority=priority,
                                                           now=now.strftime("%Y-%m-%dT%H:%M:%SZ"))},
        ]  # fmt: skip
        observed: list[str] = []
        response: LLMResponse | None = None
        for _ in range(self.max_steps):
            response = self._chat(result, messages, tools=schemas)
            if not response.tool_calls:
                break
            messages.append({
                "role": "assistant", "content": response.content,
                "tool_calls": [{"function": {"name": c.name, "arguments": c.arguments}} for c in response.tool_calls],
            })  # fmt: skip
            for call in response.tool_calls:
                t0 = time.perf_counter()
                step = Step(
                    len(result.steps),
                    "tool",
                    call.name,
                    call.arguments,
                    thinking=response.thinking[:2000],
                )
                if call.name not in names:
                    payload: Any = {
                        "error": f"unknown tool {call.name!r}; available tools: {sorted(names)}"
                    }
                    step.kind, step.ok, step.error = "invalid_tool", False, payload["error"]
                    result.invalid_tool_calls += 1
                else:
                    reply = await client.call_tool(call.name, call.arguments)
                    if reply.is_error:
                        text = " ".join(getattr(c, "text", "") for c in reply.content)[:500]
                        payload = {"error": text}
                        step.kind, step.ok, step.error = "invalid_tool", False, text
                        result.invalid_tool_calls += 1
                    else:
                        payload = reply.structured_content
                        result.tool_calls += 1
                        if isinstance(payload, dict) and "error" in payload:
                            # The tool rejected the arguments (e.g. a malformed entity).
                            step.kind, step.ok, step.error = (
                                "invalid_tool",
                                False,
                                str(payload["error"]),
                            )
                            result.invalid_tool_calls += 1
                text = _dumps(payload)
                if '"injection_suspected":true' in text:
                    result.injection_seen = True
                shown = compact_json(payload, self.result_chars)
                observed.append(shown)
                step.result = payload
                step.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
                result.steps.append(step)
                messages.append({"role": "tool", "tool_name": call.name, "content": shown})
        else:
            messages.append({"role": "user", "content": FINAL_PROMPT})
            response = self._chat(result, messages, response_format=decision_schema())
        assert response is not None
        seen = "\n".join(observed)
        decision, error = self._validate(response.content, incident_id, seen)
        result.steps.append(Step(len(result.steps), "decision", ok=decision is not None, error=error,
                                 result=response.content[:3000], thinking=response.thinking[:2000]))  # fmt: skip
        attempts = 0
        while decision is None and attempts < self.max_repairs:
            attempts += 1
            result.repairs += 1
            messages += [{"role": "assistant", "content": response.content},
                         {"role": "user", "content": REPAIR_PROMPT.format(error=error)}]  # fmt: skip
            response = self._chat(result, messages, response_format=decision_schema())
            decision, error = self._validate(response.content, incident_id, seen)
            result.steps.append(Step(len(result.steps), "repair", ok=decision is not None, error=error,
                                     result=response.content[:3000]))  # fmt: skip
        result.decision = decision
        if decision is None:
            result.error = f"no valid decision: {error}"


HIGH_RISK = 0.8
LATE_TACTICS = {
    "credential-access",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
}


def dismissal_guardrail(
    decision: Decision, risk: float, detectors: list[str], tactics: set[str]
) -> tuple[Decision, str | None]:
    """The agent may not dismiss a high-risk incident: such a dismissal is escalated to an
    analyst as suspicious (the original decision is kept for evaluation)."""
    if decision.verdict != "benign":
        return decision, None
    if risk >= HIGH_RISK or (len(set(detectors)) >= 2 and tactics & LATE_TACTICS):
        note = (f"agent dismissal escalated: risk {risk:.2f}, detectors {sorted(set(detectors))}, "
                f"tactics {sorted(tactics & LATE_TACTICS)}")  # fmt: skip
        escalated = decision.model_copy(
            update={"verdict": "suspicious", "rationale": f"[{note}] {decision.rationale}"[:1500]}
        )
        return escalated, note
    return decision, None
