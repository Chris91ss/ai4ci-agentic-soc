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

from sqlalchemy import Engine, and_, create_engine, func, insert, or_, select, text
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


class Store:
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
