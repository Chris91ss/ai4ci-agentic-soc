"""Deterministic playbooks (SOAR-style): the fallback decision maker when the agent is slow,
down or saturated, and the decision maker of the baselines without an agent.

Each playbook maps evidence patterns of an incident to containment, using the entities its
alerts point at: beacons and uploads to external addresses -> block the address and isolate
the source host; password spraying -> block the spraying addresses; account takeover signs ->
revoke the account's sessions; credential dumping or PsExec by a privileged account ->
disable that account and isolate the host. Playbooks never dismiss an incident.
"""

from __future__ import annotations

from collections.abc import Iterable

from agentic_soc.correlation.engine import IncidentState
from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.schemas import Alert, Decision, EvidenceRef, ProposedAction

C2_EXFIL = {"T1071.001", "T1573", "T1041"}
SPRAY = {"T1110.003", "T1110"}
TAKEOVER = {"T1078", "T1133"}
HOST_COMPROMISE = {"T1003.001", "T1569.002", "T1218.011", "T1059.001", "T1560.001"}
IMPACT_ORDER = {"isolate_host": 0, "disable_account": 1, "block_ip": 2, "revoke_sessions": 3}
LATE = {"credential-access", "lateral-movement", "command-and-control", "exfiltration"}


INFRASTRUCTURE_ROLES = {"dc", "edr", "monitoring", "vpn", "proxy", "wsus", "mail"}


def _external(inv: Inventory, ip: str) -> bool:
    return inv.zone(ip) == "external" and ip not in inv.office_egress.values()


def _isolatable(inv: Inventory, host: str) -> bool:
    """Playbooks never isolate shared infrastructure; that takes an analyst."""
    info = inv.hosts.get(host)
    return info is not None and not (info.kind == "server" and info.role in INFRASTRUCTURE_ROLES)


def _source_host(inv: Inventory, alert: Alert) -> str | None:
    """Host that originated a flow alert (entities.ips is [source, destination])."""
    if not alert.entities.ips:
        return None
    src_ip = alert.entities.ips[0]
    for host in alert.entities.hosts:
        info = inv.hosts.get(host)
        if info is not None and (
            info.static_ip == src_ip or (info.kind == "workstation" and not info.static_ip)
        ):
            return host
    return None


def playbook_actions(incident: IncidentState, inv: Inventory) -> list[tuple[ProposedAction, Alert]]:
    """Candidate containment actions with the alert that justifies each."""
    candidates: list[tuple[ProposedAction, Alert]] = []
    for alert in sorted(incident.alerts.values(), key=lambda a: -a.score):
        techniques = set(alert.techniques)
        users, hosts, ips = alert.entities.users, alert.entities.hosts, alert.entities.ips
        if alert.stream == "flow" and techniques & C2_EXFIL:
            for ip in ips[1:2]:  # destination of the conversation
                if _external(inv, ip):
                    candidates.append((ProposedAction(type="block_ip", target=ip), alert))
            source = _source_host(inv, alert)
            if source is not None and _isolatable(inv, source):
                candidates.append((ProposedAction(type="isolate_host", target=source), alert))
        if techniques & SPRAY:
            for ip in ips:
                if _external(inv, ip):
                    candidates.append((ProposedAction(type="block_ip", target=ip), alert))
        if alert.stream == "signin" and techniques & TAKEOVER and not techniques & SPRAY:
            for user in users:
                if inv.account_kind(user) in {"user", "admin"}:
                    candidates.append((ProposedAction(type="revoke_sessions", target=user), alert))
        if alert.stream == "process" and techniques & HOST_COMPROMISE:
            for host in hosts[:1]:
                if _isolatable(inv, host):
                    candidates.append((ProposedAction(type="isolate_host", target=host), alert))
            for user in users:
                if inv.account_kind(user) == "admin":
                    candidates.append((ProposedAction(type="disable_account", target=user), alert))
    return candidates


def playbook_decision(
    incident: IncidentState,
    inv: Inventory,
    done: Iterable[tuple[str, str]] = (),
) -> Decision:
    """A decision for ``incident`` skipping actions already taken (``done``: (type, target))."""
    risk = incident.risk.risk if incident.risk else 0.0
    taken = set(done)
    seen: set[tuple[str, str]] = set()
    chosen: list[tuple[ProposedAction, Alert]] = []
    for action, alert in playbook_actions(incident, inv):
        key = (action.type, action.target or "")
        if key in taken or key in seen:
            continue
        seen.add(key)
        chosen.append((action, alert))
    chosen.sort(key=lambda pair: IMPACT_ORDER[pair[0].type])
    chosen = chosen[:3]
    verdict = "malicious" if risk >= 0.85 or incident.tactics() & LATE else "suspicious"
    top_alerts = sorted(incident.alerts.values(), key=lambda a: -a.score)[:5]
    evidence = [EvidenceRef(id=a.alert_id, kind="alert", note=a.summary[:290]) for a in top_alerts]
    actions = [a for a, _ in chosen]
    primary = actions[0] if actions else ProposedAction(type="none")
    reasons = "; ".join(
        f"{a.type} {a.target} ({alert.detector} {', '.join(alert.techniques[:2])})"
        for a, alert in chosen
    )
    return Decision(
        incident_id=incident.incident_id,
        verdict=verdict,
        techniques=incident.techniques[:10],
        evidence=evidence,
        action=primary,
        extra_actions=actions[1:],
        confidence=round(min(0.95, max(0.3, risk)), 3),
        rationale=(
            f"Playbook: {reasons}"
            if reasons
            else "Playbook: no containment rule matched; left for an analyst"
        )[:1500],
    )
