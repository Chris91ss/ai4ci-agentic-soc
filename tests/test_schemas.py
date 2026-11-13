from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentic_soc.schemas import (
    Action,
    Decision,
    EvidenceRef,
    NetworkFlowEvent,
    ProposedAction,
    SchemaError,
    SignInEvent,
    json_schemas,
    parse_event,
)
from agentic_soc.schemas.attack import is_valid_technique, tactic_of

T0 = datetime(2026, 3, 2, 9, 30, tzinfo=UTC)


def signin_payload(**overrides: object) -> dict:
    payload = {
        "event_id": "evt-0000001",
        "schema_version": "1.0",
        "event_time": T0.isoformat(),
        "source": "idp",
        "user": "jdoe@corp.example",
        "src_ip": "10.10.1.25",
        "app": "o365",
        "logon_type": "sso",
        "auth_protocol": "saml",
        "outcome": "success",
        "mfa": True,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "country": "RO",
    }
    payload.update(overrides)
    return payload


def test_parse_current_signin_from_bytes() -> None:
    event = parse_event("signin", json.dumps(signin_payload()).encode())
    assert isinstance(event, SignInEvent)
    assert event.event_time == T0
    assert event.class_uid == 3002


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"{not json", "invalid_json"),
        (b"[1, 2]", "not_an_object"),
        (json.dumps(signin_payload(schema_version="7.0")).encode(), "unknown_version"),
        (json.dumps(signin_payload(src_ip="999.1.1.1")).encode(), "validation_error"),
        (json.dumps(signin_payload(unexpected="x")).encode(), "validation_error"),
        (json.dumps(signin_payload(event_time="2026-03-02T09:30:00")).encode(), "validation_error"),
    ],
)
def test_invalid_payloads_raise_coded_errors(payload: bytes, code: str) -> None:
    with pytest.raises(SchemaError) as info:
        parse_event("signin", payload)
    assert info.value.code == code


def test_ip_addresses_are_canonicalised() -> None:
    event = parse_event("signin", signin_payload(src_ip="2001:DB8:0:0::1"))
    assert event.src_ip == "2001:db8::1"


def test_legacy_signin_is_upgraded() -> None:
    legacy = {
        "schema_version": "0.9",
        "event_id": "legacy-000001",
        "ts": int(T0.timestamp() * 1000),
        "username": "jdoe@corp.example",
        "ip": "86.120.4.4",
        "result": "fail",
        "reason": "bad_password",
        "vpn_ip": None,
    }
    event = parse_event("signin", legacy)
    assert isinstance(event, SignInEvent)
    assert event.schema_version == "1.0"
    assert event.outcome == "failure"
    assert event.failure_reason == "bad_password"
    assert event.logon_type == "vpn"
    assert event.event_time == T0


def test_legacy_flow_is_upgraded() -> None:
    start = T0.timestamp()
    legacy = {
        "schema_version": "0.9",
        "event_id": "legacy-flow-01",
        "start": start,
        "end": start + 1.5,
        "src": "10.10.1.25",
        "sport": 51234,
        "dst": "52.10.0.4",
        "dport": 443,
        "proto": 6,
        "bytes_fwd": 1200,
        "bytes_rev": 54000,
        "sensor": "netflow-v5",
    }
    event = parse_event("flow", legacy)
    assert isinstance(event, NetworkFlowEvent)
    assert event.protocol == "tcp"
    assert event.duration_ms == 1500
    assert (event.bytes_out, event.bytes_in) == (1200, 54000)


def test_every_registered_schema_exports_json_schema() -> None:
    schemas = json_schemas()
    assert {"signin-1.0", "flow-1.0", "process-1.0", "signin-0.9", "flow-0.9"} <= set(schemas)
    assert "command_line" in schemas["process-1.0"]["properties"]


def test_decision_guardrails() -> None:
    malicious = Decision(
        incident_id="INC-1",
        verdict="malicious",
        techniques=["T1110.003"],
        evidence=[EvidenceRef(id="alert-1", kind="alert", note="spray from one IP")],
        action=ProposedAction(type="block_ip", target="45.10.2.3"),
        confidence=0.9,
    )
    assert malicious.action.type == "block_ip"
    with pytest.raises(ValidationError, match="must cite"):
        Decision(
            incident_id="INC-1",
            verdict="benign",
            action=ProposedAction(type="none"),
            confidence=0.8,
        )
    with pytest.raises(ValidationError, match="cannot carry"):
        Decision(
            incident_id="INC-1",
            verdict="benign",
            evidence=[EvidenceRef(id="evt-1", kind="event")],
            action=ProposedAction(type="isolate_host", target="WS-0001"),
            confidence=0.8,
        )
    with pytest.raises(ValidationError, match="needs a target"):
        Decision(
            incident_id="INC-1",
            verdict="malicious",
            action=ProposedAction(type="disable_account"),
            confidence=0.8,
        )
    with pytest.raises(ValidationError):
        Decision(
            incident_id="INC-1",
            verdict="malicious",
            techniques=["lateral movement"],
            action=ProposedAction(type="none"),
            confidence=0.5,
        )


def test_action_impact_must_follow_allow_list() -> None:
    Action(
        action_id="A-1",
        type="isolate_host",
        target="WS-0001",
        impact="high",
        requested_by="agent",
        created_at=T0,
    )
    with pytest.raises(ValidationError, match="impact"):
        Action(
            action_id="A-2",
            type="isolate_host",
            target="WS-0001",
            impact="low",
            requested_by="agent",
            created_at=T0,
        )


def test_attack_catalog_helpers() -> None:
    assert is_valid_technique("T1003.001")
    assert not is_valid_technique("T13")
    assert tactic_of("T1003.001") == "credential-access"
    assert tactic_of("T1021.002") == "lateral-movement"
    assert tactic_of("T9999") is None
