"""Cold store: Parquet files partitioned by stream and event date (a small data lake).

Layout ``<root>/<table>/date=YYYY-MM-DD/part-<n>.parquet`` is read by DuckDB with Hive
partitioning for offline ETL, training sets and deterministic replays.
"""

from __future__ import annotations

import types
import typing
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import fields
from datetime import datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from agentic_soc.ingestion.models import NormEventT, NormFlow, NormProcess, NormSignin
from agentic_soc.schemas import DeadLetter

_ARROW = {str: pa.string(), int: pa.int64(), bool: pa.bool_(), float: pa.float64()}


def _arrow_type(annotation: object) -> pa.DataType:
    if isinstance(annotation, types.UnionType) or typing.get_origin(annotation) is typing.Union:
        annotation = next(a for a in typing.get_args(annotation) if a is not type(None))
    if annotation is datetime:
        return pa.timestamp("us", tz="UTC")
    return _ARROW[annotation]  # type: ignore[index]


def arrow_schema(cls: type) -> pa.Schema:
    hints = typing.get_type_hints(cls)
    return pa.schema([(f.name, _arrow_type(hints[f.name])) for f in fields(cls)])


SCHEMAS: dict[str, pa.Schema] = {
    "signin": arrow_schema(NormSignin),
    "flow": arrow_schema(NormFlow),
    "process": arrow_schema(NormProcess),
    "dead_letter": pa.schema(
        [
            ("topic", pa.string()),
            ("key", pa.string()),
            ("raw", pa.string()),
            ("error_code", pa.string()),
            ("error_detail", pa.string()),
            ("received_at", pa.timestamp("us", tz="UTC")),
        ]
    ),
}
TIME_COLUMN = {
    "signin": "event_time",
    "flow": "event_time",
    "process": "event_time",
    "dead_letter": "received_at",
}


class ColdStore:
    def __init__(self, root: str | Path, flush_rows: int = 100_000) -> None:
        self.root = Path(root)
        self.flush_rows = flush_rows
        self._buffers: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.files_written = 0
        self.rows_written = 0

    def write_events(self, events: Iterable[NormEventT]) -> None:
        for event in events:
            self._buffers[event.stream].append(event.row())
        self._maybe_flush()

    def write_dead_letters(self, letters: Iterable[DeadLetter]) -> None:
        self._buffers["dead_letter"].extend(letter.model_dump() for letter in letters)
        self._maybe_flush()

    def _maybe_flush(self) -> None:
        for table, rows in self._buffers.items():
            if len(rows) >= self.flush_rows:
                self._flush_table(table)

    def _flush_table(self, table: str) -> None:
        rows = self._buffers.get(table)
        if not rows:
            return
        by_date: dict[str, list[dict[str, Any]]] = defaultdict(list)
        column = TIME_COLUMN[table]
        for row in rows:
            by_date[row[column].strftime("%Y-%m-%d")].append(row)
        for date, part in by_date.items():
            directory = self.root / table / f"date={date}"
            directory.mkdir(parents=True, exist_ok=True)
            arrow = pa.Table.from_pylist(part, schema=SCHEMAS[table])
            pq.write_table(
                arrow, directory / f"part-{uuid.uuid4().hex[:12]}.parquet", compression="zstd"
            )
            self.files_written += 1
            self.rows_written += len(part)
        self._buffers[table] = []

    def flush(self) -> None:
        for table in list(self._buffers):
            self._flush_table(table)

    def close(self) -> None:
        self.flush()


def read_table(root: str | Path, table: str) -> pa.Table:
    """Whole cold table (all partitions) as an Arrow table."""
    import pyarrow.dataset as ds

    path = Path(root) / table
    if not path.exists():
        return SCHEMAS[table].empty_table()
    dataset = ds.dataset(path, format="parquet", partitioning="hive", schema=SCHEMAS[table])
    return dataset.to_table()
