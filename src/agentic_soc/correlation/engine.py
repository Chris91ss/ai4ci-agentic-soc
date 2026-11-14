"""Correlation engine: detector alerts -> incidents.

Alerts that share a user, host or IP within a time horizon belong to the same incident; an
alert linking two incidents merges them. Shared infrastructure (domain controllers, the EDR and
monitoring servers, the VPN gateway, proxies, office NAT addresses) is recorded on incidents but
never used for linking, otherwise every alert touching DNS or the VPN would collapse into one
incident. Alert IDs are deterministic per detector, key and window, so a late re-fired window
updates its alert instead of creating a new one.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from agentic_soc.correlation.risk import RiskBreakdown, incident_risk, priority_of
from agentic_soc.detectors.base import Score
from agentic_soc.features import FeatureRow
from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.schemas import Alert, EntityRefs, FeatureContribution

STREAM_OF = {"M1-user": "signin", "M1-ip": "signin", "M2": "flow", "M3": "process"}
INFRASTRUCTURE_ROLES = {"dc", "edr", "monitoring", "vpn", "proxy", "wsus", "mail", "print"}
OPEN_STATUSES = {"open", "logged", "queued", "triaging", "awaiting_approval"}


def alert_id(row: FeatureRow) -> str:
    digest = hashlib.blake2b(
        f"{row.detector}|{row.key}|{row.window_start.isoformat()}".encode(), digest_size=6
    )
    return f"AL-{digest.hexdigest()}"


def make_alert(row: FeatureRow, score: Score) -> Alert:
    detector = "M1" if row.detector.startswith("M1") else row.detector
    return Alert(
        alert_id=alert_id(row),
        detector=detector,
        model_version=row.detector,
        stream=STREAM_OF[row.detector],
        window_start=row.window_start,
        window_end=row.window_end,
        score=min(1.0, max(0.0, score.score)),
        threshold=min(1.0, max(0.0, score.threshold)),
        severity=score.severity,  # type: ignore[arg-type]
        entities=EntityRefs(users=list(row.users), hosts=list(row.hosts), ips=list(row.ips)),
        event_ids=list(row.event_ids)[:500],
        top_features=[
            FeatureContribution(
                name=str(f["name"]),
                value=f.get("value", 0.0),
                contribution=float(f.get("contribution", 0.0)),
            )
            for f in score.top_features
        ],
        techniques=list(score.techniques),
        summary=score.summary,
    )


@dataclass
class IncidentState:
    incident_id: str
    created_at: datetime
    alerts: dict[str, Alert] = field(default_factory=dict)
    kinds: dict[str, str] = field(default_factory=dict)  # alert_id -> feature kind (M1-user, ...)
    status: str = "open"
    route: str | None = None
    verdict: str | None = None
    decided_by: str | None = None
    confidence: float | None = None
    updated_at: datetime | None = None
    risk: RiskBreakdown | None = None
    triaged_risk: float = 0.0  # risk when last routed/triaged (re-triage on escalation)
    triaged_tactics: frozenset[str] = frozenset()

    @property
    def first_seen(self) -> datetime:
        return min(a.window_start for a in self.alerts.values())

    @property
    def last_seen(self) -> datetime:
        return max(a.window_end for a in self.alerts.values())

    def entities(self) -> EntityRefs:
        users, hosts, ips = {}, {}, {}
        for a in sorted(self.alerts.values(), key=lambda x: -x.score):
            users.update(dict.fromkeys(a.entities.users))
            hosts.update(dict.fromkeys(a.entities.hosts))
            ips.update(dict.fromkeys(a.entities.ips))
        return EntityRefs(users=list(users), hosts=list(hosts), ips=list(ips))

    @property
    def detectors(self) -> list[str]:
        return sorted({a.detector for a in self.alerts.values()})

    @property
    def streams(self) -> list[str]:
        return sorted({a.stream for a in self.alerts.values()})

    @property
    def techniques(self) -> list[str]:
        return sorted({t for a in self.alerts.values() for t in a.techniques})

    def margins(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for aid, alert in self.alerts.items():
            kind = self.kinds.get(aid, alert.detector)
            margin = (alert.score - alert.threshold) / max(1e-9, 1.0 - alert.threshold)
            out[kind] = max(out.get(kind, 0.0), min(1.0, max(0.0, margin)))
        return out

    def summary(self) -> str:
        top = sorted(self.alerts.values(), key=lambda a: (-a.score, a.window_end))
        seen: set[str] = set()
        parts = []
        for alert in top:
            key = f"{alert.detector}:{alert.techniques[:1]}"
            if key in seen or not alert.summary:
                continue
            seen.add(key)
            parts.append(alert.summary)
            if len(parts) == 3:
                break
        return " | ".join(parts)

    def tactics(self) -> frozenset[str]:
        from agentic_soc.schemas.attack import tactic_of

        return frozenset(t for t in (tactic_of(x) for x in self.techniques) if t)

    def to_record(self) -> dict[str, Any]:
        risk = self.risk.risk if self.risk else 0.0
        entities = self.entities()
        return {
            "incident_id": self.incident_id,
            "status": self.status,
            "risk": round(risk, 4),
            "priority": priority_of(risk),
            "created_at": self.created_at,
            "updated_at": self.updated_at or self.created_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "entity_keys": " " + " ".join(sorted(entities.keys())) + " ",
            "entities": entities.model_dump(),
            "alert_ids": sorted(self.alerts),
            "detectors": self.detectors,
            "streams": self.streams,
            "techniques": self.techniques,
            "route": self.route,
            "summary": self.summary(),
            "verdict": self.verdict,
            "decided_by": self.decided_by,
            "confidence": self.confidence,
        }


@dataclass
class IncidentUpdate:
    incident: IncidentState
    new_alerts: list[Alert]
    created: bool
    merged: list[str]


class CorrelationEngine:
    def __init__(self, inventory: Inventory, horizon_h: float = 6.0, prefix: str = "INC") -> None:
        self.inv = inventory
        self.horizon = timedelta(hours=horizon_h)
        self.prefix = prefix
        self.incidents: dict[str, IncidentState] = {}
        self.alert_incident: dict[str, str] = {}
        self.index: dict[str, set[str]] = defaultdict(set)
        self._seq = 0
        self.stop = self._stop_list()
        self.alerts_seen = 0

    def _stop_list(self) -> set[str]:
        stop = {f"ip:{ip}" for ip in self.inv.office_egress.values()}
        for host in self.inv.hosts.values():
            if host.kind == "server" and host.role in INFRASTRUCTURE_ROLES:
                stop.add(f"host:{host.host_id}")
                if host.static_ip:
                    stop.add(f"ip:{host.static_ip}")
        return stop

    def link_keys(self, alert: Alert) -> set[str]:
        return alert.entities.keys() - self.stop

    def _new_id(self) -> str:
        self._seq += 1
        return f"{self.prefix}-{self._seq:05d}"

    def _criticality(self, state: IncidentState) -> tuple[int, bool]:
        entities = state.entities()
        crit = max(
            (self.inv.hosts[h].criticality for h in entities.hosts if h in self.inv.hosts),
            default=2,
        )
        admin = any(self.inv.account_kind(u) == "admin" for u in entities.users)
        return crit, admin

    def _rescore(self, state: IncidentState, now: datetime) -> None:
        crit, admin = self._criticality(state)
        state.risk = incident_risk(state.margins(), set(state.techniques), crit, admin)
        state.updated_at = now

    def ingest(self, scored: list[tuple[FeatureRow, Score]], now: datetime) -> list[IncidentUpdate]:
        """Turn alerting scores into alerts and fold them into incidents."""
        touched: dict[str, IncidentUpdate] = {}
        for row, score in scored:
            if not score.alert:
                continue
            alert = make_alert(row, score)
            self.alerts_seen += 1
            existing = self.alert_incident.get(alert.alert_id)
            if existing is not None and existing in self.incidents:
                state = self.incidents[existing]
                previous = state.alerts[alert.alert_id]
                if alert.score >= previous.score or len(alert.event_ids) > len(previous.event_ids):
                    state.alerts[alert.alert_id] = alert
                touched.setdefault(existing, IncidentUpdate(state, [], False, []))
                self._index(alert, existing)
                continue
            keys = self.link_keys(alert)
            candidates = {
                iid
                for key in keys
                for iid in self.index.get(key, ())
                if iid in self.incidents and self._overlaps(self.incidents[iid], alert)
            }
            if candidates:
                target_id = min(candidates, key=lambda i: (self.incidents[i].created_at, i))
                state = self.incidents[target_id]
                merged = []
                for other in sorted(candidates - {target_id}):
                    self._merge(state, self.incidents.pop(other))
                    merged.append(other)
                    touched.pop(other, None)
                update = touched.setdefault(target_id, IncidentUpdate(state, [], False, []))
                update.merged += merged
            else:
                target_id = self._new_id()
                state = IncidentState(target_id, created_at=now)
                self.incidents[target_id] = state
                update = touched.setdefault(target_id, IncidentUpdate(state, [], True, []))
            state.alerts[alert.alert_id] = alert
            state.kinds[alert.alert_id] = row.detector
            self.alert_incident[alert.alert_id] = target_id
            self._index(alert, target_id)
            update.new_alerts.append(alert)
        for update in touched.values():
            self._rescore(update.incident, now)
        return list(touched.values())

    def _overlaps(self, state: IncidentState, alert: Alert) -> bool:
        if state.status not in OPEN_STATUSES and state.status != "contained":
            return False
        return (
            alert.window_start <= state.last_seen + self.horizon
            and alert.window_end >= state.first_seen - self.horizon
        )

    def _index(self, alert: Alert, incident_id: str) -> None:
        for key in self.link_keys(alert):
            self.index[key].add(incident_id)

    def _merge(self, into: IncidentState, other: IncidentState) -> None:
        into.alerts.update(other.alerts)
        into.kinds.update(other.kinds)
        into.created_at = min(into.created_at, other.created_at)
        for aid, alert in other.alerts.items():
            self.alert_incident[aid] = into.incident_id
            self._index(alert, into.incident_id)
        if other.status not in OPEN_STATUSES and into.status in OPEN_STATUSES:
            into.status = other.status

    def get(self, incident_id: str) -> IncidentState | None:
        return self.incidents.get(incident_id)

    def stats(self) -> dict[str, Any]:
        return {
            "alerts": len(self.alert_incident),
            "incidents": len(self.incidents),
            "alert_to_incident_ratio": round(
                len(self.alert_incident) / max(1, len(self.incidents)), 2
            ),
        }
