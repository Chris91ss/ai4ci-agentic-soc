"""Relational schema of the hot store (TimescaleDB in deployment, SQLite for local runs).

Event tables mirror the normalised event dataclasses; on PostgreSQL they become TimescaleDB
hypertables partitioned by ``event_time``. Security objects (alerts, incidents, actions,
decisions, agent tool calls, evidence, analyst feedback) and the hash-chained audit log live
next to them.
"""

from __future__ import annotations

import types
import typing
from dataclasses import fields
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    TypeDecorator,
)

from agentic_soc.ingestion.models import NormFlow, NormProcess, NormSignin


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every backend (SQLite has no time zones)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        value = value.astimezone(UTC)
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


metadata = MetaData()


def _column_type(annotation: object):  # type: ignore[no-untyped-def]
    args = typing.get_args(annotation)
    base = annotation
    nullable = False
    if isinstance(annotation, types.UnionType) or typing.get_origin(annotation) is typing.Union:
        non_none = [a for a in args if a is not type(None)]
        nullable = len(non_none) != len(args)
        base = non_none[0]
    mapping = {str: Text, int: BigInteger, bool: Boolean, float: Float, datetime: UTCDateTime}
    return mapping[base], nullable  # type: ignore[index]


def _event_table(name: str, cls: type, indexes: list[tuple[str, ...]]) -> Table:
    hints = typing.get_type_hints(cls)
    columns = []
    for f in fields(cls):
        col_type, nullable = _column_type(hints[f.name])
        primary = f.name in {"event_id", "event_time"}
        columns.append(Column(f.name, col_type(), primary_key=primary, nullable=nullable or False))
    table = Table(name, metadata, *columns)
    for cols in indexes:
        Index(f"ix_{name}_{'_'.join(cols)}", *[table.c[c] for c in cols])
    return table


signin_events = _event_table(
    "signin_events",
    NormSignin,
    [("user_id", "event_time"), ("person", "event_time"), ("src_ip", "event_time"),
     ("dst_host", "event_time"), ("assigned_ip", "event_time"), ("event_time",)],
)  # fmt: skip
flow_events = _event_table(
    "flow_events",
    NormFlow,
    [("src_ip", "event_time"), ("dst_ip", "event_time"), ("src_host", "event_time"),
     ("dst_host", "event_time"), ("event_time",)],
)  # fmt: skip
process_events = _event_table(
    "process_events",
    NormProcess,
    [
        ("host_id", "event_time"),
        ("user_id", "event_time"),
        ("person", "event_time"),
        ("event_time",),
    ],
)
EVENT_TABLES: dict[str, Table] = {
    "signin": signin_events,
    "flow": flow_events,
    "process": process_events,
}

dead_letters = Table(
    "dead_letters",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("topic", String(32), nullable=False),
    Column("key", Text),
    Column("raw", Text, nullable=False),
    Column("error_code", String(32), nullable=False),
    Column("error_detail", Text, nullable=False),
    Column("received_at", UTCDateTime, nullable=False, index=True),
)

alerts = Table(
    "alerts",
    metadata,
    Column("alert_id", String(64), primary_key=True),
    Column("detector", String(32), nullable=False, index=True),
    Column("model_version", String(64)),
    Column("stream", String(16), nullable=False),
    Column("window_start", UTCDateTime, nullable=False),
    Column("window_end", UTCDateTime, nullable=False, index=True),
    Column("score", Float, nullable=False),
    Column("threshold", Float, nullable=False),
    Column("severity", String(16), nullable=False),
    Column("entity_keys", Text, nullable=False),  # " user:x host:y " for LIKE filters
    Column("entities", JSON, nullable=False),
    Column("event_ids", JSON, nullable=False),
    Column("top_features", JSON, nullable=False),
    Column("techniques", JSON, nullable=False),
    Column("summary", Text),
    Column("incident_id", String(64), index=True),
    Column("created_at", UTCDateTime, nullable=False),
)

incidents = Table(
    "incidents",
    metadata,
    Column("incident_id", String(64), primary_key=True),
    Column("status", String(24), nullable=False, index=True),
    Column("risk", Float, nullable=False),
    Column("priority", Integer, nullable=False),
    Column("created_at", UTCDateTime, nullable=False),
    Column("updated_at", UTCDateTime, nullable=False, index=True),
    Column("first_seen", UTCDateTime, nullable=False),
    Column("last_seen", UTCDateTime, nullable=False),
    Column("entity_keys", Text, nullable=False),
    Column("entities", JSON, nullable=False),
    Column("alert_ids", JSON, nullable=False),
    Column("detectors", JSON, nullable=False),
    Column("streams", JSON, nullable=False),
    Column("techniques", JSON, nullable=False),
    Column("route", String(16)),
    Column("summary", Text),
    Column("verdict", String(16)),
    Column("decided_by", String(16)),
    Column("confidence", Float),
)

actions = Table(
    "actions",
    metadata,
    Column("action_id", String(64), primary_key=True),
    Column("incident_id", String(64), index=True),
    Column("type", String(32), nullable=False),
    Column("target", Text, nullable=False),
    Column("impact", String(8), nullable=False),
    Column("status", String(24), nullable=False, index=True),
    Column("requested_by", String(16), nullable=False),
    Column("approved_by", Text),
    Column("justification", Text),
    Column("evidence_ids", JSON, nullable=False),
    Column("created_at", UTCDateTime, nullable=False),
    Column("updated_at", UTCDateTime, nullable=False),
    Column("executed_at", UTCDateTime),
)

decisions = Table(
    "decisions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("decided_by", String(16), nullable=False),
    Column("model", Text),
    Column("verdict", String(16), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("decision", JSON, nullable=False),
    Column("latency_s", Float, nullable=False),
    Column("created_at", UTCDateTime, nullable=False),
)

tool_calls = Table(
    "tool_calls",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("step", Integer, nullable=False),
    Column("tool", String(64), nullable=False),
    Column("arguments", JSON, nullable=False),
    Column("result", JSON),
    Column("ok", Boolean, nullable=False),
    Column("error", Text),
    Column("latency_ms", Float, nullable=False),
    Column("created_at", UTCDateTime, nullable=False),
)

evidence = Table(
    "evidence",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("kind", String(16), nullable=False),  # event, alert, tool_call, baseline
    Column("ref_id", Text, nullable=False),
    Column("stream", String(16)),
    Column("entity", Text),
    Column("detector", String(32)),
    Column("time", UTCDateTime),
    Column("data", JSON, nullable=False),
    Column("cited", Boolean, nullable=False, default=False),
)

feedback = Table(
    "feedback",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), index=True),
    Column("alert_id", String(64), index=True),
    Column("analyst", Text, nullable=False),
    Column("verdict", String(24), nullable=False),  # true_positive, false_positive, benign_positive
    Column("comment", Text),
    Column("created_at", UTCDateTime, nullable=False),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("ts", UTCDateTime, nullable=False, index=True),
    Column("actor", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("object_type", String(32), nullable=False),
    Column("object_id", Text, nullable=False, index=True),
    Column("details", JSON, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("hash", String(64), nullable=False),
)
