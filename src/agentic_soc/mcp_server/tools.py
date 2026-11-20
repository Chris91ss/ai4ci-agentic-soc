"""The SOC capabilities exposed to the triage agent (implemented once, served over MCP).

Every tool returns JSON-serialisable data. Attacker-controllable strings are quoted
(:mod:`agentic_soc.mcp_server.quoting`); containment goes through the policy gate.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from agentic_soc.actions import ActionManager
from agentic_soc.correlation import CorrelationEngine
from agentic_soc.detectors.service import DetectorClient
from agentic_soc.features import FeaturePipeline, Profiles
from agentic_soc.features.resolver import EntityResolver
from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.ingestion.models import from_row
from agentic_soc.mcp_server.quoting import quote
from agentic_soc.schemas.attack import TECHNIQUES
from agentic_soc.storage.hot import Store

UNTRUSTED_FIELDS = {"user_agent", "user_raw", "command_line", "image_path", "host_raw", "summary"}
EVENT_FIELDS = {
    "signin": ["user_id", "user_raw", "src_ip", "src_country", "src_org", "src_category", "app", "dst_host",
               "logon_type", "auth_protocol", "outcome", "failure_reason", "mfa", "user_agent", "assigned_ip"],
    "flow": ["src_ip", "dst_ip", "dst_port", "service", "direction", "bytes_out", "bytes_in", "duration_ms",
             "fw_action", "src_host", "dst_host", "dst_org", "dst_category"],
    "process": ["host_id", "user_id", "parent_name", "process_name", "command_line", "image_path", "integrity"],
}  # fmt: skip


class ToolError(ValueError):
    """An expected error reported back to the agent (bad arguments, unknown entity)."""


def parse_time(value: str | datetime | None, default: datetime) -> datetime:
    if value is None or value == "":
        return default
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ToolError(
            f"invalid time {value!r}; use ISO 8601 such as 2026-03-02T21:30:00Z"
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def iso(t: datetime | None) -> str | None:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def representative(alerts: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """The strongest alert of every detector and technique signature first, then the others by
    score. Dozens of near-identical alerts (a spray hits many accounts) must not push the one
    alert that names the spraying address out of the view, nor out of an agent's context when
    it shortens long lists from the end."""
    ranked = sorted(alerts, key=lambda a: (-a["score"], a["window_end"]))
    lead: dict[tuple[Any, ...], int] = {}
    for i, alert in enumerate(ranked):
        kind = alert.get("model_version") or alert["detector"]
        lead.setdefault((kind, tuple(sorted(alert["techniques"]))), i)
    first = set(lead.values())
    order = sorted(first) + [i for i in range(len(ranked)) if i not in first]
    return [ranked[i] for i in order[:limit]]


def parse_entity(entity: str) -> tuple[str, str]:
    kind, _, value = entity.partition(":")
    if kind not in {"user", "host", "ip"} or not value:
        raise ToolError(
            f"entity must look like user:<account>, host:<host id> or ip:<address>, got {entity!r}"
        )
    return kind, value.strip()


@dataclass
class SocContext:
    store: Store
    inventory: Inventory
    profiles: Profiles
    detectors: DetectorClient
    actions: ActionManager
    clock: Callable[[], datetime]
    correlation: CorrelationEngine | None = None
    resolver: EntityResolver | None = None
    feature_config: Any = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    lock: Any = None  # live pipeline: tool calls wait while the pipeline updates its state


class SocTools:
    def __init__(self, ctx: SocContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------ helpers
    def _entity(self, entity: str) -> tuple[str, str]:
        """``user:``, ``host:`` or ``ip:`` and an identifier. Models often drop the prefix, so a bare
        address, host id or account is accepted too when the inventory knows it."""
        value = entity.strip()
        kind, _, rest = value.partition(":")
        if kind in {"user", "host", "ip"} and rest:
            return kind, rest.strip()
        inv = self.ctx.inventory
        try:
            return "ip", str(ipaddress.ip_address(value))
        except ValueError:
            pass
        if value.upper() in inv.hosts:
            return "host", value.upper()
        if inv.account_kind(value) != "unknown":
            return "user", value
        return parse_entity(entity)  # raises with the expected format

    @staticmethod
    def _streams(names: list[str] | None) -> list[str] | None:
        """The stream filter, in the usual spellings (sign-in, flows, processes). An unknown name is
        an error rather than a filter that silently matches nothing."""
        if not names:
            return None
        out = []
        for name in names:
            key = re.sub(r"[^a-z]", "", str(name).lower())
            stream = next((s for s in ("signin", "flow", "process") if key.startswith(s)), None)
            if stream is None and key.startswith(("login", "logon")):
                stream = "signin"
            if stream is None:
                raise ToolError(f"unknown stream {name!r}; use signin, flow or process")
            out.append(stream)
        return out

    @staticmethod
    def _time(value: str | None, default: datetime, name: str, notes: list[str]) -> datetime:
        """An optional time bound; one that cannot be read falls back to the default, with a note
        in the result instead of failing the whole call."""
        try:
            return parse_time(value, default)
        except ToolError:
            notes.append(f"could not read {name} {value!r}; used {iso(default)}")
            return default

    def _alert_view(self, alert: dict[str, Any]) -> dict[str, Any]:
        return {
            "alert_id": alert["alert_id"],
            "detector": alert["detector"],
            "kind": alert.get("model_version"),
            "window": [iso(alert["window_start"]), iso(alert["window_end"])],
            "score": round(alert["score"], 4),
            "threshold": round(alert["threshold"], 4),
            "severity": alert["severity"],
            "techniques": alert["techniques"],
            "entities": alert["entities"],
            "top_features": alert["top_features"][:4],
            "summary": quote(alert.get("summary") or ""),
        }

    def _event_view(self, row: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {
            "event_id": row["event_id"],
            "stream": row["stream"],
            "time": iso(row["event_time"]),
        }
        for name in EVENT_FIELDS[row["stream"]]:
            value = row.get(name)
            if value is None or value == "":
                continue
            out[name] = quote(value) if name in UNTRUSTED_FIELDS else value
        return out

    def _incident_record(
        self, incident_id: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any] | None]:
        state = self.ctx.correlation.get(incident_id) if self.ctx.correlation else None
        if state is not None:
            record = state.to_record()
            alerts = [
                a.model_dump() | {"model_version": state.kinds.get(a.alert_id)}
                for a in state.alerts.values()
            ]
            breakdown = state.risk.as_dict() if state.risk else None
            return record, alerts, breakdown
        record = self.ctx.store.get_incident(incident_id)
        if record is None:
            raise ToolError(f"unknown incident {incident_id!r}")
        return record, self.ctx.store.list_alerts(incident_id=incident_id, limit=200), None

    def _ips_for(self, kind: str, value: str, start: datetime, end: datetime) -> list[str]:
        if self.ctx.resolver is None:
            info = self.ctx.inventory.hosts.get(value) if kind == "host" else None
            return [info.static_ip] if info and info.static_ip else []
        if kind == "host":
            return self.ctx.resolver.ips_for_host(value, start, end)
        if kind == "user":
            return self.ctx.resolver.ips_for_user(value, start, end)
        return []

    # ------------------------------------------------------------------ tools
    def get_incident(self, incident_id: str, max_alerts: int = 15) -> dict[str, Any]:
        record, alerts, breakdown = self._incident_record(incident_id)
        alerts = sorted(alerts, key=lambda a: (-a["score"], a["window_end"]))
        per_detector: dict[str, int] = {}
        for alert in alerts:
            per_detector[alert["detector"]] = per_detector.get(alert["detector"], 0) + 1
        actions = [
            {
                "action_id": a.action_id,
                "type": a.type,
                "target": a.target,
                "status": a.status,
                "requested_by": a.requested_by,
            }
            for a in self.ctx.actions.for_incident(incident_id)
        ]
        return {
            "incident_id": incident_id,
            "status": record["status"],
            "risk": record["risk"],
            "risk_breakdown": breakdown,
            "priority": record["priority"],
            "first_seen": iso(record["first_seen"]),
            "last_seen": iso(record["last_seen"]),
            "now": iso(self.ctx.clock()),
            "detectors": record["detectors"],
            "alert_counts": per_detector,
            "techniques": [
                {"id": t, "name": TECHNIQUES[t].name, "tactic": TECHNIQUES[t].tactic}
                if t in TECHNIQUES
                else {"id": t}
                for t in record["techniques"]
            ],
            "entities": record["entities"],
            "alerts": [self._alert_view(a) for a in representative(alerts, max_alerts)],
            "alerts_omitted": max(0, len(alerts) - max_alerts),
            "actions_taken": actions,
        }

    def get_entity_timeline(
        self,
        entity: str,
        start: str | None = None,
        end: str | None = None,
        streams: list[str] | None = None,
        limit: int = 40,
    ) -> dict[str, Any]:
        kind, value = self._entity(entity)
        streams = self._streams(streams)
        now = self.ctx.clock()
        notes: list[str] = []
        t_end = self._time(end, now, "end", notes)
        t_start = self._time(start, t_end - timedelta(hours=6), "start", notes)
        if t_start >= t_end:
            raise ToolError("start must be before end")
        limit = max(1, min(int(limit), 200))
        ips = self._ips_for(kind, value, t_start, t_end)
        rows = self.ctx.store.timeline(
            kind, value, t_start, t_end, streams=streams, ips=ips, limit=limit
        )
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["stream"]] = counts.get(row["stream"], 0) + 1
        out = {
            "entity": f"{kind}:{value}",
            "window": [iso(t_start), iso(t_end)],
            "addresses_used": ips,
            "returned": len(rows),
            "counts": counts,
            "truncated": len(rows) >= limit,
            "events": [self._event_view(r) for r in rows],
        }
        return out | ({"notes": notes} if notes else {})

    def get_asset_context(self, entity: str) -> dict[str, Any]:
        kind, value = self._entity(entity)
        inv, now = self.ctx.inventory, self.ctx.clock()
        out: dict[str, Any] = {"entity": f"{kind}:{value}"}
        if kind == "user":
            account_kind = inv.account_kind(value)
            out["account_kind"] = account_kind
            person = inv.person_of(value)
            info = inv.users.get(person or "")
            if info is not None:
                out |= {"display_name": info.display_name, "role": info.role, "department": info.department,
                        "office": info.office, "workstation": info.workstation, "admin_account": info.admin_account}  # fmt: skip
            if account_kind == "admin":
                out["owner"] = person
            profile = self.ctx.profiles.accounts.get(value)
            if profile is not None:
                top_hours = sorted(range(24), key=lambda h: -profile.hours[h])[:4]
                out["baseline"] = {
                    "successful_signins": profile.n,
                    "failed_signins": profile.fails,
                    "usual_countries": dict(profile.countries.most_common(4)),
                    "usual_networks": len(profile.asns),
                    "usual_local_hours": sorted(top_hours),
                    "known_devices": len(profile.devices),
                    "apps": sorted(profile.apps),
                    "logon_types": sorted(profile.logon_types),
                    "hosts_logged_on": sorted(profile.dst_hosts)[:10],
                }
            else:
                out["baseline"] = None
            out["addresses_last_24h"] = self._ips_for("user", value, now - timedelta(hours=24), now)
        elif kind == "host":
            host = inv.hosts.get(value)
            if host is None:
                raise ToolError(f"unknown host {value!r}")
            out |= {"kind": host.kind, "role": host.role, "zone": host.zone, "os": host.os,
                    "criticality": host.criticality, "office": host.office, "owner": host.owner,
                    "static_ip": host.static_ip}  # fmt: skip
            out["protected_infrastructure"] = (
                host.kind == "server" and host.role in self.ctx.actions.gate.cfg.protected_roles
            )
            out["addresses_last_24h"] = self._ips_for("host", value, now - timedelta(hours=24), now)
        else:
            zone = inv.zone(value)
            out["zone"] = zone
            out["office_nat"] = value in inv.office_egress.values()
            host = inv.static_host(value)
            if host:
                out["static_host"] = host
            geo = inv.geoip(value)
            if geo is not None:
                out["geo"] = {
                    "country": geo.country,
                    "city": geo.city,
                    "asn": geo.asn,
                    "org": geo.org,
                    "category": geo.category,
                }
            out["seen_in_baseline_signins"] = value in self.ctx.profiles.known_ips
            if zone == "external":
                contacts = self.ctx.store.ip_contacts(value, now - timedelta(hours=24), now)
                out["contacts_last_24h"] = contacts | {
                    "first_seen": iso(contacts["first_seen"]),
                    "last_seen": iso(contacts["last_seen"]),
                }
            elif self.ctx.resolver is not None:
                out["bound_host"] = self.ctx.resolver.host_for_ip(value, now)
                out["bound_user"] = self.ctx.resolver.user_for_ip(value, now)
        out["actions_on_entity"] = [
            {
                "action_id": a.action_id,
                "type": a.type,
                "status": a.status,
                "incident_id": a.incident_id,
            }
            for a in self.ctx.actions.actions.values()
            if a.target == value
        ]
        return out

    # ------------------------------------------------------------------ scoring tools (M1-M3)
    def _locked(self) -> Any:
        """The live pipeline's lock, held while a tool reads state the pipeline updates."""
        return self.ctx.lock if self.ctx.lock is not None else nullcontext()

    def _score(self, name: str, detectors: set[str], rows: list[dict[str, Any]], keep: Callable[[Any], bool],
               start: datetime, end: datetime, profiles: Profiles) -> dict[str, Any]:  # fmt: skip
        # Runs without the pipeline's lock: rebuilding features from thousands of events takes
        # seconds, and holding the lock for that long stops ingestion in live mode.
        pipeline = FeaturePipeline(
            self.ctx.inventory, profiles, self.ctx.feature_config, detectors=detectors
        )
        events = sorted((from_row(r) for r in rows), key=lambda e: (e.ingest_time, e.event_id))
        pipeline.add(events)
        feature_rows = [
            r
            for r in pipeline.flush().rows()
            if keep(r) and r.window_end > start and r.window_start < end
        ]
        scores = self.ctx.detectors.score(name, feature_rows)
        ranked = sorted(zip(feature_rows, scores, strict=True), key=lambda pair: -pair[1].score)
        return {
            "detector": name,
            "model_version": self.ctx.detectors.versions().get(name),
            "window": [iso(start), iso(end)],
            "windows_scored": len(ranked),
            "alerting_windows": sum(1 for _, s in ranked if s.alert),
            "max_score": round(ranked[0][1].score, 4) if ranked else None,
            "windows": [
                {
                    "kind": row.detector,
                    "key": row.key,
                    "window": [iso(row.window_start), iso(row.window_end)],
                    "score": round(score.score, 4),
                    "threshold": round(score.threshold, 4),
                    "alert": score.alert,
                    "severity": score.severity,
                    "techniques": score.techniques,
                    "top_features": score.top_features[:4],
                    "summary": quote(score.summary),
                    "events": len(row.event_ids),
                }
                for row, score in ranked[:10]
            ],
        }

    def _range(
        self, start: str | None, end: str | None, notes: list[str]
    ) -> tuple[datetime, datetime]:
        now = self.ctx.clock()
        t_end = self._time(end, now, "end", notes)
        t_start = self._time(start, t_end - timedelta(hours=2), "start", notes)
        if t_start >= t_end or t_end - t_start > timedelta(days=2):
            raise ToolError("use a time range of at most 48 hours with start before end")
        return t_start, t_end

    def score_signins(
        self, entity: str, start: str | None = None, end: str | None = None
    ) -> dict[str, Any]:
        kind, value = self._entity(entity)
        if kind == "host":
            raise ToolError("score_signins takes a user:<account> or ip:<address>")
        notes: list[str] = []
        with self._locked():
            t_start, t_end = self._range(start, end, notes)
            rows = self.ctx.store.timeline(
                kind, value, t_start - timedelta(minutes=15), t_end, streams=["signin"], limit=5000
            )
            profiles = self.ctx.profiles
        key = f"user:{value}" if kind == "user" else f"ip:{value}"
        result = self._score("M1", {"M1-user", "M1-ip"}, rows, lambda r: r.key == key, t_start, t_end,
                             profiles)  # fmt: skip
        return result | ({"notes": notes} if notes else {})

    def score_flows(
        self, entity: str, start: str | None = None, end: str | None = None
    ) -> dict[str, Any]:
        kind, value = self._entity(entity)
        notes: list[str] = []
        with self._locked():
            t_start, t_end = self._range(start, end, notes)
            ips = [value] if kind == "ip" else self._ips_for(kind, value, t_start, t_end)
            if not ips:
                raise ToolError(f"no addresses known for {entity} in that window")
            rows: list[dict[str, Any]] = []
            history = t_start - timedelta(hours=1)
            for ip in ips[:5]:
                rows += [r for r in self.ctx.store.timeline("ip", ip, history, t_end, streams=["flow"], limit=20000)
                         if r["src_ip"] == ip or kind == "ip"]  # fmt: skip
            profiles = self.ctx.profiles
        sources = set(ips)
        result = self._score(
            "M2",
            {"M2"},
            rows,
            lambda r: r.key.split("|")[0] in sources or kind == "ip",
            t_start,
            t_end,
            profiles,
        )
        return result | ({"notes": notes} if notes else {})

    def score_processes(
        self, entity: str, start: str | None = None, end: str | None = None
    ) -> dict[str, Any]:
        kind, value = self._entity(entity)
        if kind != "host":
            raise ToolError("score_processes takes a host:<host id>")
        notes: list[str] = []
        with self._locked():
            t_start, t_end = self._range(start, end, notes)
            rows = self.ctx.store.timeline(
                "host", value, t_start, t_end, streams=["process"], limit=20000
            )
            profiles = self.ctx.profiles
        result = self._score("M3", {"M3"}, rows, lambda r: r.key == f"host:{value}", t_start, t_end,
                             profiles)  # fmt: skip
        return result | ({"notes": notes} if notes else {})

    # ------------------------------------------------------------------ containment
    def propose_action(
        self,
        incident_id: str,
        action_type: str,
        target: str,
        justification: str,
        evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        if not justification or len(justification.strip()) < 10:
            raise ToolError("a justification citing the evidence is required")
        try:
            action = self.ctx.actions.propose(
                incident_id,
                action_type,
                target,
                "agent",
                self.ctx.clock(),
                justification,
                evidence_ids or [],
            )
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        result = {"action_id": action.action_id, "type": action.type, "target": action.target,
                  "impact": action.impact, "status": action.status}  # fmt: skip
        if action.status == "denied":
            result["reason"] = action.justification.rsplit("[denied: ", 1)[-1].rstrip("]")
        elif action.status == "pending_approval":
            result["note"] = "high-impact action held for analyst approval"
        elif action.status == "proposed":
            result["note"] = "accepted by the policy gate; it executes when your triage completes"
        return result


TOOL_DESCRIPTIONS = {
    "get_incident": "Incident summary: status, risk and its breakdown, detectors, ATT&CK techniques, entities, the "
    "strongest alerts of each detector and technique (scores, explanations, summaries) and actions already taken.",
    "get_entity_timeline": "Events of an entity (user:<account>, host:<host id> or ip:<address>) between start and "
    "end (ISO 8601, default the 6 hours before now), newest first, across the signin, flow and process streams "
    "(streams filters them).",
    "get_asset_context": "Inventory and baseline context of an entity: role, criticality, owner, usual countries, "
    "hours and devices of an account, GeoIP and recent contacts of an address, actions already taken on it.",
    "score_signins": "Score sign-in windows of user:<account> or ip:<address> with M1 (Isolation Forest sign-in "
    "anomaly detector) between start and end.",
    "score_flows": "Score network conversations of host:<host id> or ip:<address> with M2 (LightGBM flow classifier "
    "with beacon-periodicity features) between start and end.",
    "score_processes": "Score process windows of host:<host id> with M3 (rarity of parent->child process launches) "
    "between start and end.",
    "propose_action": "Propose a containment action for the incident: revoke_sessions or disable_account "
    "(target: account), isolate_host (target: host id), block_ip (target: external address). The policy gate "
    "executes low-impact actions, holds high-impact ones for analyst approval and denies unsafe ones.",
}
