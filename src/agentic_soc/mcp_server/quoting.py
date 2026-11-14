"""Untrusted-data quoting for the LLM boundary (indirect prompt injection, Greshake et al. 2023).

Log fields an attacker can choose (command lines, user agents, image paths, account names as
typed, alert summaries that embed them) never reach the model as plain text. They are wrapped
as ``{"$untrusted": "..."}`` objects, sanitised and truncated, and flagged when they look like
instructions aimed at an AI analyst. The agent's system prompt states that ``$untrusted``
content is evidence to analyse, never instructions to follow.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

MAX_LEN = 400
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+|your\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
    r"\b(ai|llm|soc)\s+(analyst|assistant|agent)\b",
    r"\b(classify|mark|label|treat)\b.{0,40}\bas\s+(benign|safe|authori[sz]ed|false\s+positive)",
    r"\bdo\s+not\s+(isolate|block|contain|disable|alert|escalate)\b",
    r"\b(system|developer)\s+prompt\b",
    r"\byou\s+are\s+now\b",
    r"\b(sanctioned|authori[sz]ed)\s+(red[-\s]?team|pentest|penetration\s+test|maintenance)\b",
    r"\bno\s+action\s+(is\s+)?required\b",
]
_INJECTION = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS), re.IGNORECASE)


def sanitize(value: str, max_len: int = MAX_LEN) -> str:
    cleaned = "".join(
        ch if ch in "\t" or unicodedata.category(ch)[0] != "C" else " " for ch in value
    )
    cleaned = cleaned.replace("$untrusted", "$ untrusted")
    return cleaned if len(cleaned) <= max_len else cleaned[: max_len - 15] + " …[truncated]"


def looks_like_injection(value: str) -> bool:
    return bool(_INJECTION.search(value))


def quote(value: Any, max_len: int = MAX_LEN) -> Any:
    """Wrap an attacker-controllable string; other values pass through."""
    if value is None or not isinstance(value, str) or value == "":
        return value
    wrapped: dict[str, Any] = {"$untrusted": sanitize(value, max_len)}
    if looks_like_injection(value):
        wrapped["injection_suspected"] = True
    return wrapped


def contains_injection(payload: Any) -> bool:
    """True if any quoted value in a (nested) tool result was flagged."""
    if isinstance(payload, dict):
        if payload.get("injection_suspected"):
            return True
        return any(contains_injection(v) for v in payload.values())
    if isinstance(payload, list):
        return any(contains_injection(v) for v in payload)
    return False
