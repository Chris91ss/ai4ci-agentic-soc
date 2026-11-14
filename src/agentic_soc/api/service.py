"""Data behind the SOC console: one service for the REST API, server-sent events and the
static export of a recorded run.

It reads everything from the SOC store, so it serves a live pipeline and a finished run alike.
Attached to a live pipeline it also approves and rejects held actions and streams the
pipeline's events as they happen.
"""

from __future__ import annotations

import statistics
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from agentic_soc.evidence import FeedbackService
from agentic_soc.features import Profiles
from agentic_soc.ingestion import Inventory
from agentic_soc.mcp_server.tools import parse_entity
from agentic_soc.storage import Store
from agentic_soc.storage import schema as s

if TYPE_CHECKING:
    from agentic_soc.broker import Broker
    from agentic_soc.pipeline import SocPipeline

ACTIVE = ("open", "queued", "triaging", "awaiting_approval")


class ReadOnlyError(RuntimeError):
    """The console is showing a recorded run: there is no pipeline to act on."""


def jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [jsonable(v) for v in value]
    if isinstance(value, float) and value != value:  # NaN
        return None
    return value


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return round(ordered[index], 2)


class ConsoleService:
    def __init__(
        self,
        store: Store,
        inventory: Inventory | None = None,
        profiles: Profiles | None = None,
        pipeline: SocPipeline | None = None,
        broker: Broker | None = None,
        run: dict[str, Any] | None = None,
    ) -> None:
        self.store = store
        self.pipeline = pipeline
        self.inventory = inventory or (pipeline.inv if pipeline else None)
        self.profiles = profiles or (pipeline.features.profiles if pipeline else None)
        self.broker = broker
        self.run = run or {}
        self.feedback_service = FeedbackService(store)

    @property
    def live(self) -> bool:
        return self.pipeline is not None

    # ------------------------------------------------------------------ time
    def now(self) -> datetime:
        if self.pipeline is not None and self.pipeline.clock is not None:
            return self.pipeline.now()
        latest = []
        with self.store.engine.connect() as conn:
            for table in s.EVENT_TABLES.values():
                value = conn.execute(select(func.max(table.c.event_time))).scalar()
                if value is not None:
                    if isinstance(value, str):
                        value = datetime.fromisoformat(value)
                    latest.append(value if value.tzinfo else value.replace(tzinfo=UTC))
        return max(latest) if latest else datetime.now(UTC)

    # ------------------------------------------------------------------ overview
    def health(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "status": "ok",
            "live": self.live,
            "now": self.now(),
            "store": self.store.dialect,
            "run": self.run,
        }
        if self.pipeline is not None:
            cfg = self.pipeline.cfg
            out |= {
                "mode": cfg.mode,
                "llm": cfg.llm if cfg.mode == "agent" else None,
                "models": self.pipeline.detectors.versions(),
                "breaker": self.pipeline.router.breaker.state,
                "queue": self.pipeline.router.queued(),
                "agent_busy": bool(self.pipeline.worker and self.pipeline.worker.busy),
            }
        return jsonable(out)

    def stream_health(self, hours: float = 6.0, bucket_s: int = 300) -> dict[str, Any]:
        now = self.now()
        start = now - timedelta(hours=hours)
        out: dict[str, Any] = {
            "now": now,
            "window": [start, now],
            "bucket_s": bucket_s,
            "counts": self.store.stream_counts(start, now, bucket_s),
            "totals": {stream: self.store.count_events(stream) for stream in s.EVENT_TABLES},
            "dead_letters": self.store.dead_letter_summary(),
            "recent_dead_letters": [
                {k: v for k, v in row.items() if k != "raw"}
                | {"raw": str(row.get("raw", ""))[:300]}
                for row in self.store.recent_dead_letters(20)
            ],
        }
        if self.pipeline is not None:
            out["ingestion"] = self.pipeline.ingestion.stage.summary()
            out["windows"] = self.pipeline.features.stats()
        if self.broker is not None:
            from agentic_soc import topics

            lag = getattr(self.broker, "lag", None)
            if lag is not None:
                out["consumer_lag"] = lag("ingestion", list(topics.STREAM_TOPICS.values()))
        return jsonable(out)

    # ------------------------------------------------------------------ incidents
    def incidents(
        self,
        status: list[str] | None = None,
        min_risk: float = 0.0,
        entity: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        rows = self.store.list_incidents(
            status=status, min_risk=min_risk, entity=entity, limit=limit
        )
        actions = Counter(a["incident_id"] for a in self.store.list_actions(limit=100_000))
        out = []
        for row in rows:
            out.append({
                "incident_id": row["incident_id"], "status": row["status"], "risk": row["risk"],
                "priority": row["priority"], "created_at": row["created_at"], "updated_at": row["updated_at"],
                "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                "entities": row["entities"], "detectors": row["detectors"], "techniques": row["techniques"],
                "alerts": len(row["alert_ids"]), "route": row["route"], "verdict": row["verdict"],
                "decided_by": row["decided_by"], "confidence": row["confidence"], "summary": row["summary"],
                "actions": actions.get(row["incident_id"], 0),
            })  # fmt: skip
        return jsonable(out)

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        record = self.store.get_incident(incident_id)
        if record is None:
            return None
        alerts = self.store.list_alerts(incident_id=incident_id, limit=1000)
        alerts.sort(key=lambda a: (-a["score"], a["window_end"]))
        evidence = self.store.list_evidence(incident_id, limit=100_000)
        return jsonable({
            "incident": record,
            "alerts": alerts,
            "decisions": self.store.decisions_for(incident_id),
            "actions": self.store.list_actions(incident_id=incident_id),
            "feedback": self.store.list_feedback(incident_id=incident_id),
            "evidence_counts": dict(Counter(e["kind"] for e in evidence)),
            "cited": sorted({e["ref_id"] for e in evidence if e["cited"]}),
        })  # fmt: skip

    def evidence(self, incident_id: str, **filters: Any) -> list[dict[str, Any]]:
        return jsonable(self.store.list_evidence(incident_id, **filters))

    def trace(self, incident_id: str) -> dict[str, Any]:
        return jsonable({
            "decisions": self.store.decisions_for(incident_id),
            "tool_calls": self.store.tool_calls_for(incident_id),
        })  # fmt: skip

    # ------------------------------------------------------------------ entities
    def timeline(
        self,
        entity: str,
        start: datetime | None = None,
        end: datetime | None = None,
        streams: list[str] | None = None,
        limit: int = 300,
    ) -> dict[str, Any]:
        kind, value = parse_entity(entity)
        end = end or self.now()
        start = start or end - timedelta(hours=24)
        ips: list[str] = []
        resolver = self.pipeline.features.resolver if self.pipeline else None
        if resolver is not None and kind == "host":
            ips = resolver.ips_for_host(value, start, end)
        elif resolver is not None and kind == "user":
            ips = resolver.ips_for_user(value, start, end)
        elif kind == "host" and self.inventory is not None:
            info = self.inventory.hosts.get(value)
            ips = [info.static_ip] if info and info.static_ip else []
        if not ips and kind in {"host", "user"}:
            ips = self.store.addresses_of(kind, value, start - timedelta(hours=24), end)
        events = self.store.timeline(kind, value, start, end, streams, ips, limit)
        alerts = self.store.list_alerts(entity=entity, start=start, end=end, limit=500)
        return jsonable({"entity": entity, "window": [start, end], "addresses": ips,
                         "events": events, "alerts": alerts})  # fmt: skip

    def entity(self, entity: str) -> dict[str, Any]:
        kind, value = parse_entity(entity)
        out: dict[str, Any] = {"entity": entity, "kind": kind}
        inv = self.inventory
        if inv is not None:
            if kind == "user":
                person = inv.person_of(value)
                info = inv.users.get(person or "")
                out["account_kind"] = inv.account_kind(value)
                if info is not None:
                    out["user"] = {"display_name": info.display_name, "role": info.role,
                                   "department": info.department, "office": info.office,
                                   "workstation": info.workstation, "admin_account": info.admin_account}  # fmt: skip
            elif kind == "host" and value in inv.hosts:
                h = inv.hosts[value]
                out["host"] = {"kind": h.kind, "role": h.role, "zone": h.zone, "os": h.os,
                               "criticality": h.criticality, "office": h.office, "owner": h.owner,
                               "static_ip": h.static_ip}  # fmt: skip
            elif kind == "ip":
                out["zone"] = inv.zone(value)
                geo = inv.geoip(value)
                if geo is not None:
                    out["geo"] = {"country": geo.country, "city": geo.city, "asn": geo.asn,
                                  "org": geo.org, "category": geo.category}  # fmt: skip
        if self.profiles is not None and kind == "user":
            profile = self.profiles.accounts.get(value)
            if profile is not None:
                out["baseline"] = {
                    "successful_signins": profile.n, "failed_signins": profile.fails,
                    "usual_countries": dict(profile.countries.most_common(5)),
                    "local_hours": list(profile.hours), "devices": len(profile.devices),
                    "logon_types": sorted(profile.logon_types), "apps": sorted(profile.apps),
                }  # fmt: skip
        out["incidents"] = self.incidents(entity=entity, limit=50)
        out["actions"] = [a for a in self.store.list_actions(limit=100_000) if a["target"] == value]
        return jsonable(out)

    # ------------------------------------------------------------------ actions and feedback
    def actions(self, status: list[str] | None = None, limit: int = 500) -> list[dict[str, Any]]:
        return jsonable(self.store.list_actions(status=status, limit=limit))

    def _require_live(self) -> SocPipeline:
        if self.pipeline is None:
            raise ReadOnlyError("this console shows a recorded run; actions cannot change")
        return self.pipeline

    def approve(self, action_id: str, analyst: str) -> dict[str, Any]:
        pipeline = self._require_live()
        with pipeline.lock:
            action = pipeline.actions.approve(action_id, analyst, pipeline.now())
        return jsonable(action.model_dump())

    def reject(self, action_id: str, analyst: str, reason: str = "") -> dict[str, Any]:
        pipeline = self._require_live()
        with pipeline.lock:
            action = pipeline.actions.reject(action_id, analyst, pipeline.now(), reason)
        return jsonable(action.model_dump())

    def feedback(
        self,
        incident_id: str,
        verdict: str,
        analyst: str,
        comment: str = "",
        alert_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        if self.store.get_incident(incident_id) is None:
            raise KeyError(incident_id)
        n = self.feedback_service.record(
            incident_id, verdict, analyst, self.now(), comment, alert_ids
        )
        return {"incident_id": incident_id, "verdict": verdict, "alerts": n}

    # ------------------------------------------------------------------ metrics and audit
    def metrics(self) -> dict[str, Any]:
        incidents = self.store.list_incidents(limit=100_000)
        decisions = self.store.recent_decisions(limit=100_000)
        actions = self.store.list_actions(limit=100_000)
        alerts = sum(int(r["alerts"]) for r in self.store.alert_counts())
        agent = [d for d in decisions if d["decided_by"] == "agent"]
        latencies = [float(d["latency_s"]) for d in agent]
        with self.store.engine.connect() as conn:
            t = s.tool_calls.c
            calls = conn.execute(
                select(t.ok, func.count())
                .where(t.tool.notin_(["decision", "repair", "error"]))
                .group_by(t.ok)
            ).all()
        tool_ok = {bool(ok): int(n) for ok, n in calls}
        total_calls = sum(tool_ok.values())
        out = {
            "now": self.now(),
            "events": {stream: self.store.count_events(stream) for stream in s.EVENT_TABLES},
            "alerts": alerts,
            "alerts_by_detector": self.store.alert_counts(),
            "incidents": len(incidents),
            "incidents_by_status": dict(Counter(i["status"] for i in incidents)),
            "incidents_by_priority": dict(Counter(str(i["priority"]) for i in incidents)),
            "active_incidents": sum(1 for i in incidents if i["status"] in ACTIVE),
            "alert_to_incident_ratio": round(alerts / len(incidents), 2) if incidents else None,
            "decisions_by": dict(Counter(d["decided_by"] for d in decisions)),
            "verdicts": dict(Counter(d["verdict"] for d in decisions)),
            "actions_by_status": dict(Counter(a["status"] for a in actions)),
            "actions_by_type": dict(Counter(a["type"] for a in actions if a["status"] == "executed")),
            "pending_approvals": sum(1 for a in actions if a["status"] == "pending_approval"),
            "agent": {
                "decisions": len(agent),
                "latency_mean_s": round(statistics.fmean(latencies), 1) if latencies else None,
                "latency_p95_s": _percentile(latencies, 0.95),
                "tool_calls": total_calls,
                "invalid_tool_call_rate": round(tool_ok.get(False, 0) / total_calls, 4) if total_calls else None,
                "escalated_dismissals": sum(1 for d in agent if d["decision"].get("note")),
                "injection_seen": sum(1 for d in agent if d["decision"].get("injection_seen")),
            },
            "detector_feedback": self.feedback_service.detector_stats(),
        }  # fmt: skip
        if self.pipeline is not None:
            out["pipeline"] = {
                "breaker": self.pipeline.router.breaker.state,
                "breaker_trips": self.pipeline.router.breaker.trips,
                "queue": self.pipeline.router.queue_length,
                "routes": dict(self.pipeline.router.stats),
            }
        return jsonable(out)

    def audit(self, object_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        return jsonable(self.store.audit_entries(object_id=object_id, limit=limit))

    def verify_audit(self) -> dict[str, Any]:
        ok, broken = self.store.verify_audit_chain()
        return {"ok": ok, "first_broken": broken}

    # ------------------------------------------------------------------ live events
    def log_since(self, cursor: int) -> tuple[list[dict[str, Any]], int]:
        """Pipeline events after ``cursor`` (an index into the pipeline log)."""
        if self.pipeline is None:
            return [], cursor
        log = self.pipeline.log
        end = len(log)
        return jsonable(log[cursor:end]), end
