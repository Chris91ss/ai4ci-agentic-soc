"""Normalisation and enrichment of validated events (identities, assets, zones, GeoIP)."""

from __future__ import annotations

from datetime import datetime

from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.ingestion.models import NormEventT, NormFlow, NormProcess, NormSignin
from agentic_soc.schemas import NetworkFlowEvent, ProcessEvent, SignInEvent, TelemetryEvent

SERVICES = {
    22: "ssh",
    53: "dns",
    80: "http",
    88: "kerberos",
    135: "rpc",
    389: "ldap",
    443: "https",
    445: "smb",
    1433: "mssql",
    3200: "sap",
    3389: "rdp",
    5985: "winrm",
    8080: "http-alt",
    8443: "edr",
    8801: "zoom",
    9100: "metrics",
}


def _direction(src_zone: str, dst_zone: str) -> str:
    src_ext, dst_ext = src_zone == "external", dst_zone == "external"
    if src_ext and dst_ext:
        return "transit"
    if dst_ext:
        return "outbound"
    if src_ext:
        return "inbound"
    return "internal"


def normalize_signin(
    ev: SignInEvent, inv: Inventory, ingest_time: datetime, version: str
) -> NormSignin:
    user_id, kind = inv.resolve_account(ev.user)
    geo = inv.geoip(ev.src_ip)
    return NormSignin(
        event_id=ev.event_id,
        event_time=ev.event_time,
        ingest_time=ingest_time,
        source=ev.source,
        schema_version=version,
        user_raw=ev.user,
        user_id=user_id,
        user_kind=kind,
        person=inv.person_of(user_id),
        src_ip=ev.src_ip,
        src_zone=inv.zone(ev.src_ip),
        src_country=geo.country if geo else ev.country,
        src_city=geo.city if geo else ev.city,
        src_asn=geo.asn if geo else None,
        src_org=geo.org if geo else None,
        src_category=geo.category if geo else None,
        src_host=inv.static_host(ev.src_ip),
        app=ev.app,
        dst_host=inv.resolve_host(ev.dst_host) or ev.dst_host,
        logon_type=ev.logon_type,
        auth_protocol=ev.auth_protocol,
        outcome=ev.outcome,
        failure_reason=ev.failure_reason,
        mfa=ev.mfa,
        user_agent=ev.user_agent,
        device_id=ev.device_id,
        assigned_ip=ev.assigned_ip,
    )


def normalize_flow(
    ev: NetworkFlowEvent, inv: Inventory, ingest_time: datetime, version: str
) -> NormFlow:
    src_zone, dst_zone = inv.zone(ev.src_ip), inv.zone(ev.dst_ip)
    geo = inv.geoip(ev.dst_ip) if dst_zone == "external" else None
    return NormFlow(
        event_id=ev.event_id,
        event_time=ev.event_time,
        ingest_time=ingest_time,
        source=ev.source,
        schema_version=version,
        src_ip=ev.src_ip,
        src_port=ev.src_port,
        dst_ip=ev.dst_ip,
        dst_port=ev.dst_port,
        protocol=ev.protocol,
        duration_ms=ev.duration_ms,
        bytes_out=ev.bytes_out,
        bytes_in=ev.bytes_in,
        packets_out=ev.packets_out,
        packets_in=ev.packets_in,
        fw_action=ev.fw_action,
        src_zone=src_zone,
        dst_zone=dst_zone,
        direction=_direction(src_zone, dst_zone),
        src_host=inv.static_host(ev.src_ip),
        dst_host=inv.static_host(ev.dst_ip),
        service=SERVICES.get(ev.dst_port, f"{ev.protocol}/{ev.dst_port}"),
        dst_country=geo.country if geo else None,
        dst_asn=geo.asn if geo else None,
        dst_org=geo.org if geo else None,
        dst_category=geo.category if geo else None,
    )


def normalize_process(
    ev: ProcessEvent, inv: Inventory, ingest_time: datetime, version: str
) -> NormProcess:
    host_id = inv.resolve_host(ev.host)
    host = inv.hosts.get(host_id) if host_id else None
    user_id, kind = inv.resolve_account(ev.user)
    return NormProcess(
        event_id=ev.event_id,
        event_time=ev.event_time,
        ingest_time=ingest_time,
        source=ev.source,
        schema_version=version,
        host_raw=ev.host,
        host_id=host_id,
        host_role=host.role if host else None,
        host_kind=host.kind if host else None,
        host_criticality=host.criticality if host else None,
        user_raw=ev.user,
        user_id=user_id,
        user_kind=kind,
        person=inv.person_of(user_id),
        pid=ev.pid,
        ppid=ev.ppid,
        process_name=ev.process_name.lower(),
        parent_name=ev.parent_name.lower(),
        command_line=ev.command_line,
        image_path=ev.image_path,
        integrity=ev.integrity,
    )


def normalize(
    ev: TelemetryEvent, inv: Inventory, ingest_time: datetime, version: str
) -> NormEventT:
    if isinstance(ev, SignInEvent):
        return normalize_signin(ev, inv, ingest_time, version)
    if isinstance(ev, NetworkFlowEvent):
        return normalize_flow(ev, inv, ingest_time, version)
    return normalize_process(ev, inv, ingest_time, version)
