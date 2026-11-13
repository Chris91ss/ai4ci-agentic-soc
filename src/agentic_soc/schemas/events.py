"""Versioned telemetry event schemas (OCSF-inspired).

Each stream has a current schema (``1.0``). Two legacy producers still emit ``0.9`` payloads
(an old VPN appliance for sign-ins and a NetFlow v5 collector for flows); the registry in
:mod:`agentic_soc.schemas.registry` upgrades them to the current version during ingestion.

Fields that an attacker can control (user agents, command lines) are plain strings: they are
data, never instructions, and are quoted as such before reaching the triage agent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated, ClassVar, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field


def _canonical_ip(value: str) -> str:
    return str(ip_address(value))


IPStr = Annotated[str, AfterValidator(_canonical_ip)]
Port = Annotated[int, Field(ge=0, le=65535)]
NonNegInt = Annotated[int, Field(ge=0)]

STREAMS: tuple[str, ...] = ("signin", "flow", "process")

LogonType = Literal["interactive", "remote_interactive", "network", "vpn", "sso", "service"]
AuthProtocol = Literal["kerberos", "ntlm", "saml", "oauth", "password"]
FailureReason = Literal[
    "bad_password",
    "unknown_user",
    "account_disabled",
    "mfa_denied",
    "mfa_timeout",
    "password_expired",
    "blocked_ip",
    "session_revoked",
]


class RawEvent(BaseModel):
    """Fields shared by every telemetry event (OCSF base event, simplified)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stream: ClassVar[str] = ""
    class_uid: ClassVar[int] = 0

    event_id: str = Field(min_length=8, max_length=64)
    schema_version: Literal["1.0"] = "1.0"
    event_time: AwareDatetime = Field(
        description="Time recorded by the source clock (may be skewed)."
    )
    source: str = Field(min_length=1, max_length=64, description="Producing system or sensor.")


class SignInEvent(RawEvent):
    """Authentication event from the identity provider, VPN or a domain controller (OCSF 3002)."""

    stream: ClassVar[str] = "signin"
    class_uid: ClassVar[int] = 3002

    user: str = Field(min_length=1, max_length=128, description="Account as presented (UPN).")
    src_ip: IPStr
    app: str = Field(min_length=1, max_length=64)
    dst_host: str | None = Field(default=None, max_length=128)
    logon_type: LogonType
    auth_protocol: AuthProtocol
    outcome: Literal["success", "failure"]
    failure_reason: FailureReason | None = None
    mfa: bool = False
    user_agent: str = Field(default="", max_length=512)
    device_id: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    city: str | None = Field(default=None, max_length=64)
    assigned_ip: IPStr | None = Field(default=None, description="Address leased by the VPN.")


class NetworkFlowEvent(RawEvent):
    """Bidirectional flow record from a network sensor or the perimeter firewall (OCSF 4001)."""

    stream: ClassVar[str] = "flow"
    class_uid: ClassVar[int] = 4001

    src_ip: IPStr
    src_port: Port
    dst_ip: IPStr
    dst_port: Port
    protocol: Literal["tcp", "udp", "icmp"]
    duration_ms: NonNegInt
    bytes_out: NonNegInt = Field(description="Bytes sent from source to destination.")
    bytes_in: NonNegInt = Field(description="Bytes sent from destination to source.")
    packets_out: NonNegInt = 0
    packets_in: NonNegInt = 0
    fw_action: Literal["allowed", "blocked"] = "allowed"


class ProcessEvent(RawEvent):
    """Process launch reported by the endpoint agent (OCSF 1007)."""

    stream: ClassVar[str] = "process"
    class_uid: ClassVar[int] = 1007

    host: str = Field(min_length=1, max_length=128, description="Host FQDN as reported by the EDR.")
    user: str = Field(min_length=1, max_length=128, description="DOMAIN\\account of the process.")
    pid: Annotated[int, Field(ge=0)]
    ppid: Annotated[int, Field(ge=0)]
    process_name: str = Field(min_length=1, max_length=128)
    parent_name: str = Field(min_length=1, max_length=128)
    command_line: str = Field(default="", max_length=2048)
    image_path: str = Field(default="", max_length=512)
    integrity: Literal["low", "medium", "high", "system"] = "medium"


# --------------------------------------------------------------------------- legacy (0.9)


class LegacySignInEventV09(BaseModel):
    """Sign-in record from the legacy VPN appliance (schema 0.9)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stream: ClassVar[str] = "signin"

    schema_version: Literal["0.9"]
    event_id: str = Field(min_length=8, max_length=64)
    ts: int = Field(ge=0, description="Epoch milliseconds.")
    username: str = Field(min_length=1, max_length=128)
    ip: IPStr
    result: Literal["ok", "fail"]
    reason: FailureReason | None = None
    ua: str = Field(default="", max_length=512)
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    vpn_ip: IPStr | None = None

    def upgrade(self) -> SignInEvent:
        return SignInEvent(
            event_id=self.event_id,
            event_time=datetime.fromtimestamp(self.ts / 1000, tz=UTC),
            source="vpn-legacy",
            user=self.username,
            src_ip=self.ip,
            app="vpn",
            logon_type="vpn",
            auth_protocol="password",
            outcome="success" if self.result == "ok" else "failure",
            failure_reason=self.reason if self.result == "fail" else None,
            mfa=False,
            user_agent=self.ua,
            country=self.country,
            assigned_ip=self.vpn_ip,
        )


_PROTO_NUMBERS: dict[int, Literal["tcp", "udp", "icmp"]] = {6: "tcp", 17: "udp", 1: "icmp"}


class LegacyFlowEventV09(BaseModel):
    """Flow record from the NetFlow v5 collector (schema 0.9)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stream: ClassVar[str] = "flow"

    schema_version: Literal["0.9"]
    event_id: str = Field(min_length=8, max_length=64)
    start: float = Field(ge=0, description="Epoch seconds.")
    end: float = Field(ge=0)
    src: IPStr
    sport: Port
    dst: IPStr
    dport: Port
    proto: Literal[1, 6, 17]
    bytes_fwd: NonNegInt
    bytes_rev: NonNegInt
    pkts_fwd: NonNegInt = 0
    pkts_rev: NonNegInt = 0
    sensor: str = Field(min_length=1, max_length=64)

    def upgrade(self) -> NetworkFlowEvent:
        return NetworkFlowEvent(
            event_id=self.event_id,
            event_time=datetime.fromtimestamp(self.start, tz=UTC),
            source=self.sensor,
            src_ip=self.src,
            src_port=self.sport,
            dst_ip=self.dst,
            dst_port=self.dport,
            protocol=_PROTO_NUMBERS[self.proto],
            duration_ms=max(0, round((self.end - self.start) * 1000)),
            bytes_out=self.bytes_fwd,
            bytes_in=self.bytes_rev,
            packets_out=self.pkts_fwd,
            packets_in=self.pkts_rev,
        )


TelemetryEvent = SignInEvent | NetworkFlowEvent | ProcessEvent
