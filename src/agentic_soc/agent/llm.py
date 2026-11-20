"""LLM clients for the triage agent: a local open-weight model served by Ollama.

Messages follow the Ollama chat format; tool schemas are OpenAI-style function definitions
built from the MCP server's tool list.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

DEFAULT_MODEL = os.environ.get("SOC_LLM_MODEL", "gpt-oss:20b")
DEFAULT_HOST = os.environ.get("SOC_OLLAMA", "http://127.0.0.1:11434")


@dataclass(slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    id: str | None = None


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    thinking: str = ""
    prompt_tokens: int = 0
    output_tokens: int = 0
    latency_s: float = 0.0


class LLM(Protocol):
    name: str

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> LLMResponse: ...


class LLMError(RuntimeError):
    pass


class OllamaLLM:
    """Chat with a local model through Ollama's /api/chat (tool calling, JSON-schema output)."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        host: str = DEFAULT_HOST,
        temperature: float = 0.1,
        num_ctx: int = 16384,
        think: str | bool | None = "low",
        timeout_s: float = 300.0,
        seed: int | None = 7,
    ) -> None:
        self.model = model
        self.name = f"ollama:{model}"
        self.host = host.rstrip("/")
        self.options: dict[str, Any] = {"temperature": temperature, "num_ctx": num_ctx}
        if seed is not None:
            self.options["seed"] = seed
        self.think = think
        self.http = httpx.Client(timeout=timeout_s)

    def available(self) -> bool:
        try:
            tags = self.http.get(f"{self.host}/api/tags", timeout=5).json()
        except (httpx.HTTPError, ValueError):
            return False
        return any(m.get("name", "").startswith(self.model) for m in tags.get("models", []))

    def reseed(self) -> None:
        """Sample with another seed from now on: with a fixed seed, a retry repeats the reply that
        failed (for example a tool call Ollama could not parse)."""
        if "seed" in self.options:
            self.options["seed"] += 1

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": self.options,
        }
        if tools:
            payload["tools"] = tools
        if response_format is not None:
            payload["format"] = response_format
        if self.think is not None:
            payload["think"] = self.think
        started = time.perf_counter()
        try:
            response = self.http.post(f"{self.host}/api/chat", json=payload)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:300].strip()
            raise LLMError(f"Ollama request failed: {exc.response.status_code} {detail}") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc
        data = response.json()
        message = data.get("message", {})
        calls = [
            ToolCall(c["function"]["name"], c["function"].get("arguments") or {}, c.get("id"))
            for c in message.get("tool_calls") or []
        ]
        return LLMResponse(
            content=message.get("content") or "",
            tool_calls=calls,
            thinking=message.get("thinking") or "",
            prompt_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
            latency_s=time.perf_counter() - started,
        )


def tool_schemas(mcp_tools: list[Any]) -> list[dict[str, Any]]:
    """OpenAI-style function schemas from MCP tool definitions."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema,
            },
        }
        for t in mcp_tools
    ]
