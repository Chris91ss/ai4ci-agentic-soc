"""DuckDB over the Parquet lake: views, analytics and ordered replays of normalised events."""

from __future__ import annotations

import heapq
from collections.abc import Iterator
from dataclasses import fields
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa

from agentic_soc.ingestion.models import NormEventT, NormFlow, NormProcess, NormSignin

EVENT_CLASSES: dict[str, type] = {"signin": NormSignin, "flow": NormFlow, "process": NormProcess}
_FIELDS = {stream: [f.name for f in fields(cls)] for stream, cls in EVENT_CLASSES.items()}


def connect(lake_root: str | Path = "data/lake") -> duckdb.DuckDBPyConnection:
    """In-memory DuckDB with one view per lake table (``run`` and ``date`` partition columns)."""
    root = Path(lake_root).resolve()
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    for table in ("signin", "flow", "process", "dead_letter"):
        pattern = root / "run=*" / table / "date=*" / "*.parquet"
        if list(root.glob(f"run=*/{table}/date=*/*.parquet")):
            con.execute(
                f"CREATE OR REPLACE VIEW {table} AS SELECT * FROM read_parquet('{pattern}', "
                "hive_partitioning = true, union_by_name = true)"
            )
    labels = list(root.glob("run=*/meta/labels.parquet"))
    if labels:
        con.execute(
            "CREATE OR REPLACE VIEW labels AS SELECT * FROM read_parquet("
            f"'{root}/run=*/meta/labels.parquet', hive_partitioning = true)"
        )
    return con


def arrow(con: duckdb.DuckDBPyConnection, sql: str, params: list[Any] | None = None) -> pa.Table:
    return con.sql(sql, params=params or None).to_arrow_table()


def rows(
    con: duckdb.DuckDBPyConnection, sql: str, params: list[Any] | None = None
) -> list[dict[str, Any]]:
    return arrow(con, sql, params).to_pylist()


def _stream_reader(
    lake_root: Path, run: str, stream: str, start: datetime | None, end: datetime | None, batch: int
) -> Iterator[NormEventT]:
    con = connect(lake_root)
    columns = ", ".join(_FIELDS[stream])
    where = ["run = ?"]
    params: list[Any] = [run]
    if start is not None:
        where.append("ingest_time >= ?")
        params.append(start)
    if end is not None:
        where.append("ingest_time < ?")
        params.append(end)
    relation = con.sql(
        f"SELECT {columns} FROM {stream} WHERE {' AND '.join(where)} ORDER BY ingest_time, event_id",
        params=params,
    )
    cls = EVENT_CLASSES[stream]
    for record_batch in relation.to_arrow_reader(batch):
        for row in record_batch.to_pylist():
            yield cls(**row)
    con.close()


def replay_events(
    lake_root: str | Path,
    run: str,
    start: datetime | None = None,
    end: datetime | None = None,
    batch: int = 50_000,
) -> Iterator[NormEventT]:
    """Normalised events of a run merged across streams in arrival order (deterministic)."""
    root = Path(lake_root)
    readers = [_stream_reader(root, run, stream, start, end, batch) for stream in EVENT_CLASSES]
    yield from heapq.merge(*readers, key=lambda e: (e.ingest_time, e.event_id))


# ---------------------------------------------------------------------------- analytics


def run_overview(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    return rows(
        con,
        """
        SELECT run,
               (SELECT count(*) FROM signin s WHERE s.run = r.run) AS signins,
               (SELECT count(*) FROM flow f WHERE f.run = r.run) AS flows,
               (SELECT count(*) FROM process p WHERE p.run = r.run) AS processes,
               (SELECT count(*) FROM labels l WHERE l.run = r.run AND l.malicious) AS malicious,
               (SELECT min(event_time) FROM flow f WHERE f.run = r.run) AS first_event,
               (SELECT max(event_time) FROM flow f WHERE f.run = r.run) AS last_event
        FROM (SELECT DISTINCT run FROM labels) r
        ORDER BY first_event
        """,
    )


def hourly_volume(con: duckdb.DuckDBPyConnection, run: str, timezone: str) -> list[dict[str, Any]]:
    """Events per stream and local hour of day (diurnal profile check)."""
    return rows(
        con,
        f"""
        SELECT stream, hour, count(*) AS n FROM (
            SELECT 'signin' AS stream, hour(timezone('{timezone}', event_time)) AS hour FROM signin WHERE run = ?
            UNION ALL SELECT 'flow', hour(timezone('{timezone}', event_time)) FROM flow WHERE run = ?
            UNION ALL SELECT 'process', hour(timezone('{timezone}', event_time)) FROM process WHERE run = ?
        ) GROUP BY stream, hour ORDER BY stream, hour
        """,
        [run, run, run],
    )


def signin_failures(con: duckdb.DuckDBPyConnection, run: str) -> list[dict[str, Any]]:
    return rows(
        con,
        """
        SELECT coalesce(failure_reason, 'success') AS outcome, src_category, count(*) AS n
        FROM signin WHERE run = ? GROUP BY ALL ORDER BY n DESC
        """,
        [run],
    )


def top_external_destinations(
    con: duckdb.DuckDBPyConnection, run: str, limit: int = 20
) -> list[dict[str, Any]]:
    return rows(
        con,
        """
        SELECT dst_org, dst_category, count(*) AS flows, count(DISTINCT src_ip) AS sources,
               sum(bytes_out) AS bytes_out
        FROM flow WHERE run = ? AND direction = 'outbound'
        GROUP BY ALL ORDER BY bytes_out DESC LIMIT ?
        """,
        [run, limit],
    )


def labelled_stage_counts(con: duckdb.DuckDBPyConnection, run: str) -> list[dict[str, Any]]:
    return rows(
        con,
        """
        SELECT coalesce(stage, tag) AS stage, malicious, stream, count(*) AS n, min(time) AS first
        FROM labels WHERE run = ? GROUP BY ALL ORDER BY first
        """,
        [run],
    )
