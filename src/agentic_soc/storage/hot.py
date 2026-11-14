"""Hot store: recent events for timelines plus every security object, on SQLAlchemy Core.

``postgresql+psycopg://`` URLs target TimescaleDB (event tables become hypertables and bulk
loads use COPY); ``sqlite://`` URLs give a dependency-free store for local runs and tests.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, and_, case, create_engine, func, insert, or_, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.pool import StaticPool

from agentic_soc.ingestion.models import NormEventT
from agentic_soc.schemas import DeadLetter
from agentic_soc.storage import schema as s

log = logging.getLogger(__name__)
DEFAULT_URL = "sqlite:///data/soc.sqlite"
GENESIS = "0" * 64


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_jsonable(v) for v in value]
    return value


class SecurityObjects:
    """CRUD for alerts and incidents (mixed into :class:`Store`)."""

    engine: Engine
    dialect: str

    def _upsert(self, table: Any, key: str, row: dict[str, Any]) -> None:
        with self.engine.begin() as conn:
            exists = conn.execute(select(table.c[key]).where(table.c[key] == row[key])).first()
            if exists:
                conn.execute(table.update().where(table.c[key] == row[key]).values(**row))
            else:
                conn.execute(insert(table), [row])

    def upsert_alert(self, alert: dict[str, Any]) -> None:
        self._upsert(s.alerts, "alert_id", alert)

    def upsert_incident(self, incident: dict[str, Any]) -> None:
        self._upsert(s.incidents, "incident_id", incident)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = (
                conn.execute(select(s.incidents).where(s.incidents.c.incident_id == incident_id))
                .mappings()
                .first()
            )
            return dict(row) if row else None

    def list_incidents(
        self,
        status: Iterable[str] | None = None,
        min_risk: float = 0.0,
        entity: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        t = s.incidents.c
        query = select(s.incidents).where(t.risk >= min_risk)
        if status:
            query = query.where(t.status.in_(list(status)))
        if entity:
            query = query.where(t.entity_keys.like(f"% {entity} %"))
        query = query.order_by(t.priority, t.risk.desc(), t.updated_at.desc()).limit(limit)
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = (
                conn.execute(select(s.alerts).where(s.alerts.c.alert_id == alert_id))
                .mappings()
                .first()
            )
            return dict(row) if row else None

    def list_alerts(
        self,
        incident_id: str | None = None,
        detector: str | None = None,
        entity: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        t = s.alerts.c
        query = select(s.alerts)
        if incident_id:
            query = query.where(t.incident_id == incident_id)
        if detector:
            query = query.where(t.detector == detector)
        if entity:
            query = query.where(t.entity_keys.like(f"% {entity} %"))
        if start:
            query = query.where(t.window_end >= start)
        if end:
            query = query.where(t.window_start < end)
        query = query.order_by(t.window_end.desc()).limit(limit)
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    def reassign_alerts(self, from_incident: str, to_incident: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                s.alerts.update()
                .where(s.alerts.c.incident_id == from_incident)
                .values(incident_id=to_incident)
            )

    def add_decision(self, record: dict[str, Any]) -> int:
        with self.engine.begin() as conn:
            result = conn.execute(insert(s.decisions).values(**record))
            return int(result.inserted_primary_key[0])

    def decisions_for(self, incident_id: str) -> list[dict[str, Any]]:
        query = (
            select(s.decisions)
            .where(s.decisions.c.incident_id == incident_id)
            .order_by(s.decisions.c.id)
        )
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    def recent_decisions(self, limit: int = 100) -> list[dict[str, Any]]:
        query = select(s.decisions).order_by(s.decisions.c.id.desc()).limit(limit)
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    def add_tool_calls(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            with self.engine.begin() as conn:
                conn.execute(insert(s.tool_calls), rows)

    def tool_calls_for(self, incident_id: str) -> list[dict[str, Any]]:
        query = (
            select(s.tool_calls)
            .where(s.tool_calls.c.incident_id == incident_id)
            .order_by(s.tool_calls.c.id)
        )
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    # ------------------------------------------------------------------ evidence
    def upsert_evidence(self, rows: list[dict[str, Any]]) -> None:
        """One row per (incident, kind, reference): a later decision refreshes the data and
        keeps earlier citations."""
        ev = s.evidence
        by_incident: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            by_incident.setdefault(row["incident_id"], []).append(row)
        with self.engine.begin() as conn:
            for incident_id, items in by_incident.items():
                existing = {
                    (r.kind, r.ref_id): (r.id, r.cited)
                    for r in conn.execute(
                        select(ev.c.id, ev.c.kind, ev.c.ref_id, ev.c.cited).where(
                            ev.c.incident_id == incident_id
                        )
                    )
                }
                fresh = []
                for item in items:
                    row = item | {"data": _jsonable(item["data"]), "cited": bool(item["cited"])}
                    hit = existing.get((row["kind"], row["ref_id"]))
                    if hit is None:
                        fresh.append(row)
                        existing[(row["kind"], row["ref_id"])] = (-1, row["cited"])
                    else:
                        values = row | {"cited": row["cited"] or bool(hit[1])}
                        conn.execute(ev.update().where(ev.c.id == hit[0]).values(**values))
                if fresh:
                    conn.execute(insert(ev), fresh)

    def list_evidence(
        self,
        incident_id: str,
        kind: str | None = None,
        entity: str | None = None,
        stream: str | None = None,
        detector: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        cited: bool | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Evidence of an incident filtered by entity, stream, detector and time window."""
        t = s.evidence.c
        query = select(s.evidence).where(t.incident_id == incident_id)
        if kind:
            query = query.where(t.kind == kind)
        if entity:
            query = query.where(t.entity == entity)
        if stream:
            query = query.where(t.stream == stream)
        if detector:
            query = query.where(t.detector == detector)
        if start:
            query = query.where(t.time >= start)
        if end:
            query = query.where(t.time < end)
        if cited is not None:
            query = query.where(t.cited == cited)
        query = query.order_by(t.cited.desc(), t.time, t.id).limit(limit)
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    # ------------------------------------------------------------------ analyst feedback
    def add_feedback(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            with self.engine.begin() as conn:
                conn.execute(insert(s.feedback), rows)

    def list_feedback(
        self, incident_id: str | None = None, alert_id: str | None = None, limit: int = 5000
    ) -> list[dict[str, Any]]:
        t = s.feedback.c
        query = select(s.feedback)
        if incident_id:
            query = query.where(t.incident_id == incident_id)
        if alert_id:
            query = query.where(t.alert_id == alert_id)
        query = query.order_by(t.id).limit(limit)
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    def alert_counts(self) -> list[dict[str, Any]]:
        """Alerts per detector and feature kind (kept in ``model_version``)."""
        t = s.alerts.c
        query = select(t.detector, t.model_version, func.count().label("alerts")).group_by(
            t.detector, t.model_version
        )
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    def alerts_by_ids(self, alert_ids: Iterable[str]) -> list[dict[str, Any]]:
        ids = list(dict.fromkeys(alert_ids))
        out: list[dict[str, Any]] = []
        with self.engine.connect() as conn:
            for chunk in range(0, len(ids), 500):
                query = select(s.alerts).where(s.alerts.c.alert_id.in_(ids[chunk : chunk + 500]))
                out += [dict(r) for r in conn.execute(query).mappings()]
        return out

    def upsert_action(self, action: dict[str, Any]) -> None:
        self._upsert(s.actions, "action_id", action)

    def list_actions(
        self, incident_id: str | None = None, status: Iterable[str] | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        t = s.actions.c
        query = select(s.actions)
        if incident_id:
            query = query.where(t.incident_id == incident_id)
        if status:
            query = query.where(t.status.in_(list(status)))
        query = query.order_by(t.created_at.desc()).limit(limit)
        with self.engine.connect() as conn:
            return [dict(r) for r in conn.execute(query).mappings()]

    def count_alerts(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(s.alerts)).scalar_one())


class Store(SecurityObjects):
    def __init__(self, url: str | None = None, engine: Engine | None = None) -> None:
        self.url = url or os.environ.get("SOC_DB", DEFAULT_URL)
        if engine is None:
            if self.url.startswith("sqlite"):
                path = self.url.split("///", 1)[-1]
                if path and path != ":memory:" and "/" in path:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                engine = create_engine(self.url, connect_args={"check_same_thread": False})
            else:
                engine = create_engine(self.url, pool_pre_ping=True, pool_size=10, max_overflow=10)
        self.engine = engine
        self.dialect = engine.dialect.name

    @classmethod
    def memory(cls) -> Store:
        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        store = cls("sqlite://", engine)
        store.init_schema()
        return store

    # ------------------------------------------------------------------ schema
    def init_schema(self) -> None:
        if self.dialect == "postgresql":
            with self.engine.begin() as conn:
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
        s.metadata.create_all(self.engine)
        if self.dialect == "postgresql":
            with self.engine.begin() as conn:
                for table in s.EVENT_TABLES.values():
                    conn.execute(
                        text(
                            "SELECT create_hypertable(:t, by_range('event_time', INTERVAL '1 day'),"
                            " if_not_exists => TRUE, migrate_data => TRUE)"
                        ),
                        {"t": table.name},
                    )
        elif self.dialect == "sqlite":
            with self.engine.begin() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA synchronous=NORMAL"))

    def reset(self) -> None:
        s.metadata.drop_all(self.engine)
        self.init_schema()

    # ------------------------------------------------------------------ events
    def write_events(self, events: Iterable[NormEventT]) -> None:
        rows: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            rows.setdefault(event.stream, []).append(event.row())
        with self.engine.begin() as conn:
            for stream, batch in rows.items():
                self._bulk_insert(conn, s.EVENT_TABLES[stream], batch)

    def _bulk_insert(self, conn: Connection, table: s.Table, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        if self.dialect == "postgresql":
            columns = [c.name for c in table.columns]
            raw = conn.connection.driver_connection
            with raw.cursor() as cur:  # type: ignore[union-attr]
                cur.execute(
                    f"CREATE TEMP TABLE IF NOT EXISTS tmp_{table.name} "
                    f"(LIKE {table.name} INCLUDING DEFAULTS) ON COMMIT DROP"
                )
                with cur.copy(f"COPY tmp_{table.name} ({', '.join(columns)}) FROM STDIN") as copy:
                    for row in rows:
                        copy.write_row([row[c] for c in columns])
                cur.execute(
                    f"INSERT INTO {table.name} SELECT * FROM tmp_{table.name} ON CONFLICT DO NOTHING"
                )
            return
        stmt = insert(table).prefix_with("OR IGNORE") if self.dialect == "sqlite" else insert(table)
        conn.execute(stmt, rows)

    def write_dead_letters(self, letters: Iterable[DeadLetter]) -> None:
        rows = [letter.model_dump() for letter in letters]
        if rows:
            with self.engine.begin() as conn:
                conn.execute(insert(s.dead_letters), rows)

    def count_events(self, stream: str) -> int:
        table = s.EVENT_TABLES[stream]
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(table)).scalar_one())

    def events_by_ids(self, event_ids: Iterable[str]) -> list[dict[str, Any]]:
        ids = list(dict.fromkeys(event_ids))
        out: list[dict[str, Any]] = []
        if not ids:
            return out
        with self.engine.connect() as conn:
            for stream, table in s.EVENT_TABLES.items():
                for chunk in range(0, len(ids), 500):
                    part = ids[chunk : chunk + 500]
                    for row in conn.execute(
                        select(table).where(table.c.event_id.in_(part))
                    ).mappings():
                        out.append({"stream": stream, **row})
        order = {event_id: i for i, event_id in enumerate(ids)}
        out.sort(key=lambda r: order[r["event_id"]])
        return out

    def timeline(
        self,
        kind: str,
        value: str,
        start: datetime,
        end: datetime,
        streams: Iterable[str] | None = None,
        ips: Iterable[str] = (),
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Events of an entity (``user``, ``host`` or ``ip``) between ``start`` and ``end``.

        ``ips`` adds addresses the entity used in the window (DHCP/VPN bindings resolved
        online), so flows of a workstation can be found although flows carry no host name.
        """
        wanted = set(streams or s.EVENT_TABLES)
        extra_ips = list(dict.fromkeys(ips))
        conditions: dict[str, Any] = {}
        si, fl, pr = s.signin_events.c, s.flow_events.c, s.process_events.c
        if kind == "user":
            conditions["signin"] = or_(si.user_id == value, si.person == value)
            conditions["process"] = or_(pr.user_id == value, pr.person == value)
            if extra_ips:
                conditions["flow"] = or_(fl.src_ip.in_(extra_ips), fl.dst_ip.in_(extra_ips))
        elif kind == "host":
            conditions["process"] = pr.host_id == value
            signin = [si.dst_host == value, si.src_host == value]
            flow = [fl.src_host == value, fl.dst_host == value]
            if extra_ips:
                signin.append(si.src_ip.in_(extra_ips))
                flow += [fl.src_ip.in_(extra_ips), fl.dst_ip.in_(extra_ips)]
            conditions["signin"] = or_(*signin)
            conditions["flow"] = or_(*flow)
        elif kind == "ip":
            conditions["signin"] = or_(si.src_ip == value, si.assigned_ip == value)
            conditions["flow"] = or_(fl.src_ip == value, fl.dst_ip == value)
        else:
            raise ValueError(f"unknown entity kind {kind!r}")
        out: list[dict[str, Any]] = []
        with self.engine.connect() as conn:
            for stream, condition in conditions.items():
                if stream not in wanted:
                    continue
                table = s.EVENT_TABLES[stream]
                query = (
                    select(table)
                    .where(and_(condition, table.c.event_time >= start, table.c.event_time < end))
                    .order_by(table.c.event_time.desc())
                    .limit(limit)
                )
                out += [{"stream": stream, **row} for row in conn.execute(query).mappings()]
        out.sort(key=lambda r: r["event_time"], reverse=True)
        return out[:limit]

    def ip_contacts(self, ip: str, start: datetime, end: datetime) -> dict[str, Any]:
        """How an address was used in a window: flows, internal peers, bytes each way."""
        fl = s.flow_events.c
        query = select(
            func.count().label("flows"),
            func.count(func.distinct(fl.src_ip)).label("sources"),
            func.coalesce(func.sum(fl.bytes_out), 0).label("bytes_to_ip"),
            func.coalesce(func.sum(fl.bytes_in), 0).label("bytes_from_ip"),
            func.min(fl.event_time).label("first_seen"),
            func.max(fl.event_time).label("last_seen"),
            func.coalesce(func.sum(case((fl.fw_action == "blocked", 1), else_=0)), 0).label(
                "blocked"
            ),
        ).where(fl.dst_ip == ip, fl.event_time >= start, fl.event_time < end)
        with self.engine.connect() as conn:
            row = dict(conn.execute(query).mappings().one())
        for key in ("first_seen", "last_seen"):
            value = row[key]
            if isinstance(value, str):
                value = datetime.fromisoformat(value)
            if isinstance(value, datetime) and value.tzinfo is None:
                value = value.replace(tzinfo=UTC)
            row[key] = value
        for key in ("flows", "sources", "bytes_to_ip", "bytes_from_ip", "blocked"):
            row[key] = int(row[key] or 0)
        return row

    def addresses_of(self, kind: str, value: str, start: datetime, end: datetime) -> list[str]:
        """Dynamic addresses of a workstation or account recovered from stored sign-ins (what
        the online resolver learns): interactive logons bind a host's address, VPN logons an
        account's lease."""
        si = s.signin_events.c
        ok = and_(si.outcome == "success", si.event_time >= start, si.event_time < end)
        if kind == "host":
            query = select(si.src_ip).where(
                ok,
                si.dst_host == value,
                si.logon_type == "interactive",
                si.src_zone.in_(["corp", "vpn"]),
            )
        elif kind == "user":
            query = select(func.coalesce(si.assigned_ip, si.src_ip)).where(
                ok,
                or_(si.user_id == value, si.person == value),
                or_(
                    si.logon_type == "vpn",
                    and_(si.logon_type == "interactive", si.src_zone.in_(["corp", "vpn"])),
                ),
            )
        else:
            return []
        with self.engine.connect() as conn:
            return list(dict.fromkeys(r[0] for r in conn.execute(query.distinct()) if r[0]))

    def flow_volume(self, src_ips: Iterable[str], start: datetime, end: datetime) -> dict[str, Any]:
        """Traffic sent by a set of addresses in a window (a host's traffic baseline)."""
        ips = list(dict.fromkeys(src_ips))
        out = {
            "flows": 0,
            "bytes_out": 0,
            "bytes_in": 0,
            "destinations": 0,
            "external_destinations": 0,
        }
        if not ips:
            return out
        fl = s.flow_events.c
        query = select(
            func.count().label("flows"),
            func.coalesce(func.sum(fl.bytes_out), 0).label("bytes_out"),
            func.coalesce(func.sum(fl.bytes_in), 0).label("bytes_in"),
            func.count(func.distinct(fl.dst_ip)).label("destinations"),
            func.count(func.distinct(case((fl.dst_zone == "external", fl.dst_ip)))).label(
                "external_destinations"
            ),
        ).where(fl.src_ip.in_(ips), fl.event_time >= start, fl.event_time < end)
        with self.engine.connect() as conn:
            row = conn.execute(query).mappings().one()
        return {key: int(row[key] or 0) for key in out}

    def stream_counts(
        self, start: datetime, end: datetime, bucket_s: int = 300
    ) -> list[dict[str, Any]]:
        """Event counts per stream and time bucket (stream-health charts)."""
        out = []
        with self.engine.connect() as conn:
            for stream, table in s.EVENT_TABLES.items():
                if self.dialect == "postgresql":
                    bucket = func.time_bucket(
                        text(f"INTERVAL '{int(bucket_s)} seconds'"), table.c.event_time
                    )
                else:
                    epoch = func.cast(func.strftime("%s", table.c.event_time), s.BigInteger)
                    bucket = (epoch // bucket_s) * bucket_s
                query = (
                    select(bucket.label("bucket"), func.count().label("n"))
                    .where(table.c.event_time >= start, table.c.event_time < end)
                    .group_by(bucket)
                    .order_by(bucket)
                )
                for row in conn.execute(query):
                    when = row.bucket
                    if not isinstance(when, datetime):
                        when = datetime.fromtimestamp(int(when), tz=UTC)
                    out.append({"stream": stream, "bucket": when, "count": int(row.n)})
        return out

    def dead_letter_summary(self) -> list[dict[str, Any]]:
        t = s.dead_letters.c
        query = select(t.topic, t.error_code, func.count().label("n")).group_by(
            t.topic, t.error_code
        )
        with self.engine.connect() as conn:
            return [dict(row._mapping) for row in conn.execute(query)]

    def recent_dead_letters(self, limit: int = 50) -> list[dict[str, Any]]:
        query = select(s.dead_letters).order_by(s.dead_letters.c.id.desc()).limit(limit)
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(query).mappings()]

    # ------------------------------------------------------------------ audit log
    def audit(
        self,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        details: dict[str, Any] | None = None,
        ts: datetime | None = None,
    ) -> dict[str, Any]:
        """Append a tamper-evident entry: each hash covers the entry and the previous hash."""
        ts = ts or datetime.now(UTC)
        details = _jsonable(details or {})
        with self.engine.begin() as conn:
            last = conn.execute(
                select(s.audit_log.c.hash).order_by(s.audit_log.c.seq.desc()).limit(1)
            ).scalar_one_or_none()
            prev = last or GENESIS
            entry = {
                "ts": ts.astimezone(UTC).isoformat(),
                "actor": actor,
                "action": action,
                "object_type": object_type,
                "object_id": object_id,
                "details": details,
            }
            digest = hashlib.sha256(
                (prev + json.dumps(entry, sort_keys=True, separators=(",", ":"))).encode()
            ).hexdigest()
            conn.execute(
                insert(s.audit_log),
                [{**entry, "ts": ts, "prev_hash": prev, "hash": digest}],
            )
        return {**entry, "prev_hash": prev, "hash": digest}

    def audit_entries(self, object_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        query = select(s.audit_log).order_by(s.audit_log.c.seq.desc()).limit(limit)
        if object_id is not None:
            query = query.where(s.audit_log.c.object_id == object_id)
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(query).mappings()]

    def verify_audit_chain(self) -> tuple[bool, int | None]:
        """Recompute the hash chain; returns (ok, first broken sequence number)."""
        prev = GENESIS
        with self.engine.connect() as conn:
            for row in conn.execute(select(s.audit_log).order_by(s.audit_log.c.seq)).mappings():
                entry = {
                    "ts": row["ts"].astimezone(UTC).isoformat(),
                    "actor": row["actor"],
                    "action": row["action"],
                    "object_type": row["object_type"],
                    "object_id": row["object_id"],
                    "details": row["details"],
                }
                digest = hashlib.sha256(
                    (prev + json.dumps(entry, sort_keys=True, separators=(",", ":"))).encode()
                ).hexdigest()
                if row["prev_hash"] != prev or row["hash"] != digest:
                    return False, int(row["seq"])
                prev = digest
        return True, None
