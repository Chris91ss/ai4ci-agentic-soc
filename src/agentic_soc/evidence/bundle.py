"""Evidence bundles: every verdict stored with the data behind it (RFC, evidence and verification).

A bundle holds the incident's alerts (detector scores with top contributing features), the
events that triggered them, the baselines of the entities involved (usual sign-in countries
and hours of an account, the traffic volume of a host, GeoIP and contacts of an address) and,
for agent decisions, every tool call. Items the decision cites by ID are flagged, and cited IDs
missing from the bundle are reported, so a verdict can be verified rather than trusted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from agentic_soc.correlation import IncidentState
from agentic_soc.features import EntityResolver, Profiles
from agentic_soc.ingestion import Inventory
from agentic_soc.schemas import Alert, Decision
from agentic_soc.storage import Store

EVENT_ENTITY = {"signin": "user_id", "flow": "src_ip", "process": "host_id"}
ENTITY_PREFIX = {"signin": "user", "flow": "ip", "process": "host"}
NOT_EVENTS = ("AL-", "ACT-", "INC-", "user:", "host:", "ip:")
TOOL_CALL_REF = re.compile(r"^D(\d+|None):\d+$")


@dataclass
class EvidenceBundle:
    incident_id: str
    decision_id: int | None
    items: list[dict[str, Any]] = field(default_factory=list)
    cited: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # cited but absent from the bundle

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in self.items:
            out[item["kind"]] = out.get(item["kind"], 0) + 1
        return out


def _primary_entity(alert: Alert) -> str | None:
    refs = alert.entities
    if alert.stream == "process" and refs.hosts:
        return f"host:{refs.hosts[0]}"
    if alert.stream == "flow" and refs.ips:
        return f"ip:{refs.ips[0]}"
    for prefix, values in (("user", refs.users), ("host", refs.hosts), ("ip", refs.ips)):
        if values:
            return f"{prefix}:{values[0]}"
    return None


def _clip(value: Any, limit: int = 3000) -> Any:
    text = json.dumps(value, default=str)
    return value if len(text) <= limit else {"_clipped": text[:limit]}


def _item(kind: str, ref: str, stream: str | None, entity: str | None, detector: str | None,
          time: datetime | None, cited: bool, data: dict[str, Any]) -> dict[str, Any]:  # fmt: skip
    return {"kind": kind, "ref_id": ref, "stream": stream, "entity": entity,
            "detector": detector, "time": time, "cited": cited, "data": data}  # fmt: skip


class EvidenceBuilder:
    def __init__(
        self,
        store: Store,
        inventory: Inventory,
        profiles: Profiles,
        resolver: EntityResolver | None = None,
        max_events: int = 150,
        max_entities: int = 8,
        baseline_h: float = 24.0,
    ) -> None:
        self.store = store
        self.inv = inventory
        self.profiles = profiles
        self.resolver = resolver
        self.max_events = max_events
        self.max_entities = max_entities
        self.baseline = timedelta(hours=baseline_h)

    # ------------------------------------------------------------------ pieces
    def _alerts(self, state: IncidentState, cited: set[str]) -> list[dict[str, Any]]:
        out = []
        for alert in sorted(state.alerts.values(), key=lambda a: (-a.score, a.window_end)):
            data = {
                "kind": state.kinds.get(alert.alert_id, alert.model_version),
                "score": alert.score,
                "threshold": alert.threshold,
                "severity": alert.severity,
                "techniques": alert.techniques,
                "summary": alert.summary,
                "top_features": [f.model_dump() for f in alert.top_features],
                "window": [alert.window_start, alert.window_end],
                "entities": alert.entities.model_dump(),
                "events": len(alert.event_ids),
            }
            out.append(_item("alert", alert.alert_id, alert.stream, _primary_entity(alert),
                             alert.detector, alert.window_end, alert.alert_id in cited, data))  # fmt: skip
        return out

    def _events(self, state: IncidentState, cited: set[str]) -> list[dict[str, Any]]:
        detector_of: dict[str, str] = {}
        wanted = [
            c for c in sorted(cited) if not c.startswith(NOT_EVENTS) and not TOOL_CALL_REF.match(c)
        ]
        for alert in sorted(state.alerts.values(), key=lambda a: -a.score):
            for event_id in alert.event_ids:
                detector_of.setdefault(event_id, alert.detector)
            wanted += alert.event_ids[:20]
        out = []
        for row in self.store.events_by_ids(list(dict.fromkeys(wanted))[: self.max_events]):
            stream = row["stream"]
            value = row.get(EVENT_ENTITY[stream])
            entity = f"{ENTITY_PREFIX[stream]}:{value}" if value else None
            data = {k: v for k, v in row.items() if v is not None and v != ""}
            out.append(_item("event", row["event_id"], stream, entity, detector_of.get(row["event_id"]),
                             row["event_time"], row["event_id"] in cited, data))  # fmt: skip
        return out

    def _user_baseline(self, user: str) -> dict[str, Any]:
        data: dict[str, Any] = {"account_kind": self.inv.account_kind(user)}
        profile = self.profiles.accounts.get(user)
        if profile is None:
            return data | {"note": "no sign-in baseline for this account"}
        return data | {
            "successful_signins": profile.n,
            "failed_signins": profile.fails,
            "usual_countries": dict(profile.countries.most_common(5)),
            "usual_networks": len(profile.asns),
            "known_devices": len(profile.devices),
            "local_hours": list(profile.hours),
            "logon_types": sorted(profile.logon_types),
            "apps": sorted(profile.apps),
            "hosts_logged_on": sorted(profile.dst_hosts)[:12],
        }

    def _host_baseline(
        self, host: str, before: tuple[datetime, datetime], during: tuple[datetime, datetime]
    ) -> dict[str, Any] | None:
        info = self.inv.hosts.get(host)
        if info is None:
            return None
        ips = [info.static_ip] if info.static_ip else []
        if not ips and self.resolver is not None:
            ips = self.resolver.ips_for_host(host, before[0], during[1])
        hours_during = round((during[1] - during[0]).total_seconds() / 3600, 2)
        return {
            "kind": info.kind,
            "role": info.role,
            "zone": info.zone,
            "criticality": info.criticality,
            "owner": info.owner,
            "addresses": ips,
            "traffic_before": self.store.flow_volume(ips, *before)
            | {"hours": self.baseline.total_seconds() / 3600},
            "traffic_during": self.store.flow_volume(ips, *during) | {"hours": hours_during},
        }

    def _ip_baseline(self, ip: str, during: tuple[datetime, datetime]) -> dict[str, Any]:
        geo = self.inv.geoip(ip)
        return {
            "office_nat": ip in self.inv.office_egress.values(),
            "seen_in_baseline_signins": ip in self.profiles.known_ips,
            "geo": None
            if geo is None
            else {
                "country": geo.country,
                "city": geo.city,
                "asn": geo.asn,
                "org": geo.org,
                "category": geo.category,
            },
            "contacts_during": self.store.ip_contacts(ip, *during),
        }

    def _baselines(self, state: IncidentState, cited: set[str]) -> list[dict[str, Any]]:
        entities = state.entities()
        first = state.first_seen
        before = (first - self.baseline, first)
        during = (first, max(state.last_seen, first + timedelta(minutes=1)))
        out = []
        for user in entities.users[: self.max_entities]:
            ref = f"user:{user}"
            out.append(_item("baseline", ref, "signin", ref, None, first, ref in cited,
                             self._user_baseline(user)))  # fmt: skip
        for host in entities.hosts[: self.max_entities]:
            data = self._host_baseline(host, before, during)
            if data is not None:
                ref = f"host:{host}"
                out.append(_item("baseline", ref, "flow", ref, None, first, ref in cited, data))
        for ip in entities.ips[: self.max_entities]:
            if self.inv.zone(ip) == "external":
                ref = f"ip:{ip}"
                out.append(_item("baseline", ref, "flow", ref, None, first, ref in cited,
                                 self._ip_baseline(ip, during)))  # fmt: skip
        return out

    def _tool_calls(
        self, steps: list[Any], decision_id: int | None, started: datetime, cited: set[str]
    ) -> list[dict[str, Any]]:
        out = []
        for step in steps:
            if step.kind not in {"tool", "invalid_tool"}:
                continue
            text = json.dumps(step.result, default=str)
            entity = (step.arguments or {}).get("entity")
            data = {
                "tool": step.tool,
                "arguments": step.arguments,
                "ok": step.ok,
                "error": step.error,
                "latency_ms": step.latency_ms,
                "result": _clip(step.result),
            }
            out.append(_item("tool_call", f"D{decision_id}:{step.index}", None,
                             entity if isinstance(entity, str) else None, None, started,
                             any(c in text for c in cited), data))  # fmt: skip
        return out

    # ------------------------------------------------------------------ bundle
    def build(
        self,
        state: IncidentState,
        decision: Decision,
        decision_id: int | None = None,
        steps: list[Any] | None = None,
        started: datetime | None = None,
    ) -> EvidenceBundle:
        cited = {ref.id for ref in decision.evidence}
        items = self._alerts(state, cited) + self._events(state, cited)
        items += self._baselines(state, cited)
        if steps:
            items += self._tool_calls(steps, decision_id, started or state.first_seen, cited)
        for item in items:
            item["incident_id"] = state.incident_id
        present = {item["ref_id"] for item in items}
        missing = sorted(c for c in cited if c not in present)
        return EvidenceBundle(state.incident_id, decision_id, items, sorted(cited), missing)
