"""Normalised, enriched events as stored in the hot/cold stores and fed to online inference."""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
from typing import Any, ClassVar


@dataclass(slots=True)
class NormEvent:
    stream: ClassVar[str] = ""

    event_id: str
    event_time: datetime  # as reported by the source clock
    ingest_time: datetime  # arrival at the broker, simulation clock
    source: str
    schema_version: str  # version used by the producer (0.9 = legacy, upgraded)

    def row(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass(slots=True)
class NormSignin(NormEvent):
    stream: ClassVar[str] = "signin"

    user_raw: str
    user_id: str
    user_kind: str  # user, admin, service, system, unknown
    person: str | None  # employee behind the account
    src_ip: str
    src_zone: str
    src_country: str | None
    src_city: str | None
    src_asn: int | None
    src_org: str | None
    src_category: str | None  # isp, mobile, cloud, cdn, hosting, anonymizer, corporate
    src_host: str | None  # static (server) source address
    app: str
    dst_host: str | None
    logon_type: str
    auth_protocol: str
    outcome: str
    failure_reason: str | None
    mfa: bool
    user_agent: str
    device_id: str | None
    assigned_ip: str | None


@dataclass(slots=True)
class NormFlow(NormEvent):
    stream: ClassVar[str] = "flow"

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration_ms: int
    bytes_out: int
    bytes_in: int
    packets_out: int
    packets_in: int
    fw_action: str
    src_zone: str
    dst_zone: str
    direction: str  # outbound, inbound, internal, transit
    src_host: str | None  # static addresses only; DHCP/VPN bindings are resolved online
    dst_host: str | None
    service: str
    dst_country: str | None
    dst_asn: int | None
    dst_org: str | None
    dst_category: str | None


@dataclass(slots=True)
class NormProcess(NormEvent):
    stream: ClassVar[str] = "process"

    host_raw: str
    host_id: str | None
    host_role: str | None
    host_kind: str | None
    host_criticality: int | None
    user_raw: str
    user_id: str
    user_kind: str
    person: str | None
    pid: int
    ppid: int
    process_name: str  # lower case
    parent_name: str  # lower case
    command_line: str
    image_path: str
    integrity: str


NormEventT = NormSignin | NormFlow | NormProcess


EVENT_TYPES: dict[str, type[NormEvent]] = {
    "signin": NormSignin,
    "flow": NormFlow,
    "process": NormProcess,
}


def from_row(row: dict[str, Any]) -> NormEventT:
    """Rebuild a normalised event from a stored row (with its ``stream`` column)."""
    cls = EVENT_TYPES[row["stream"]]
    return cls(**{f.name: row[f.name] for f in fields(cls)})  # type: ignore[return-value]
