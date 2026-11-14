"""Schema registry: decode, validate and upgrade raw telemetry payloads by stream and version."""

from __future__ import annotations

from typing import Any

import pydantic_core
from pydantic import BaseModel, ValidationError

from agentic_soc.schemas.events import (
    LegacyFlowEventV09,
    LegacySignInEventV09,
    NetworkFlowEvent,
    ProcessEvent,
    SignInEvent,
    TelemetryEvent,
)

CURRENT_VERSION = "1.0"

REGISTRY: dict[tuple[str, str], type[BaseModel]] = {
    ("signin", "1.0"): SignInEvent,
    ("flow", "1.0"): NetworkFlowEvent,
    ("process", "1.0"): ProcessEvent,
    ("signin", "0.9"): LegacySignInEventV09,
    ("flow", "0.9"): LegacyFlowEventV09,
}


class SchemaError(ValueError):
    """Raised when a payload cannot be turned into a valid current-version event."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def supported_versions(stream: str) -> list[str]:
    return sorted(version for (s, version) in REGISTRY if s == stream)


def parse_event(stream: str, payload: bytes | str | dict[str, Any]) -> TelemetryEvent:
    """Validate ``payload`` for ``stream`` and return it as a current-version event.

    Raises :class:`SchemaError` with a machine-readable code (``invalid_json``,
    ``not_an_object``, ``unknown_version``, ``validation_error``) so that ingestion can route
    the payload to the dead-letter topic.
    """
    return parse_event_versioned(stream, payload)[0]


def parse_event_versioned(
    stream: str, payload: bytes | str | dict[str, Any]
) -> tuple[TelemetryEvent, str]:
    """Like :func:`parse_event`, also returning the schema version the producer used."""
    if isinstance(payload, dict):
        data = payload
    else:
        try:
            data = pydantic_core.from_json(payload)
        except ValueError as exc:
            raise SchemaError("invalid_json", str(exc)[:200]) from None
    if not isinstance(data, dict):
        raise SchemaError("not_an_object", f"expected a JSON object, got {type(data).__name__}")
    version = data.get("schema_version", CURRENT_VERSION)
    model = REGISTRY.get((stream, str(version)))
    if model is None:
        raise SchemaError("unknown_version", f"no schema for stream={stream!r} version={version!r}")
    try:
        event = model.model_validate(data)
    except ValidationError as exc:
        errors = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()[:5]
        )
        raise SchemaError("validation_error", errors) from None
    if isinstance(event, LegacySignInEventV09 | LegacyFlowEventV09):
        return event.upgrade(), str(version)
    return event, str(version)  # type: ignore[return-value]


def json_schemas() -> dict[str, dict[str, Any]]:
    """JSON Schemas of every registered event version, keyed ``<stream>-<version>``."""
    return {
        f"{stream}-{version}": model.model_json_schema()
        for (stream, version), model in sorted(REGISTRY.items())
    }
