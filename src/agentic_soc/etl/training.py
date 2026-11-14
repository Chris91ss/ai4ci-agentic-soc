"""Feature tables for training and model-level evaluation, built from lake replays.

Each run is replayed in arrival order through the same :class:`FeaturePipeline` the live system
uses; rows of re-fired windows are reduced to their final version; ground-truth labels are
joined by event ID (a window is malicious if any of its events is). Rows are streamed to
Parquet in chunks to keep memory bounded on multi-day runs.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from agentic_soc.etl.duck import connect, replay_events, rows
from agentic_soc.etl.lake import Lake
from agentic_soc.features import FEATURES, FeaturePipeline, FeatureRow, Profiles, WindowConfig
from agentic_soc.ingestion.models import NormSignin

DETECTORS = tuple(FEATURES)
META_COLUMNS = [
    ("run", pa.string()),
    ("detector", pa.string()),
    ("key", pa.string()),
    ("window_start", pa.timestamp("us", tz="UTC")),
    ("window_end", pa.timestamp("us", tz="UTC")),
    ("late", pa.bool_()),
    ("label", pa.bool_()),
    ("stage", pa.string()),
    ("tag", pa.string()),
    ("users", pa.list_(pa.string())),
    ("hosts", pa.list_(pa.string())),
    ("ips", pa.list_(pa.string())),
    ("n_events", pa.int64()),
    ("event_ids", pa.list_(pa.string())),
    ("context", pa.string()),
]


def feature_schema(detector: str) -> pa.Schema:
    return pa.schema(META_COLUMNS + [(f"f_{name}", pa.float64()) for name in FEATURES[detector]])


def build_profiles(lake: Lake, run: str, until: datetime | None = None) -> Profiles:
    """Sign-in baselines from a (benign) run, optionally only from events before ``until``."""
    signins = (e for e in replay_events(lake.root, run, end=until) if isinstance(e, NormSignin))
    profiles = Profiles.build(signins, lake.inventory(run).timezone)
    profiles.built_from["run"] = run
    return profiles


class _Labels:
    def __init__(self, lake: Lake, run: str) -> None:
        con = connect(lake.root)
        self.malicious: dict[str, str] = {}
        self.tags: dict[str, str] = {}
        for row in rows(
            con, "SELECT event_id, malicious, stage, tag FROM labels WHERE run = ?", [run]
        ):
            if row["malicious"]:
                self.malicious[row["event_id"]] = row["stage"] or "unknown"
            elif row["tag"]:
                self.tags[row["event_id"]] = row["tag"]
        con.close()

    def label(self, event_ids: list[str]) -> tuple[bool, str | None, str | None]:
        stages = Counter(self.malicious[e] for e in event_ids if e in self.malicious)
        if stages:
            return True, stages.most_common(1)[0][0], None
        tags = Counter(self.tags[e] for e in event_ids if e in self.tags)
        return False, None, tags.most_common(1)[0][0] if tags else None


class FeatureWriter:
    """Accumulates the latest version of every window and writes it once it can no longer change."""

    def __init__(
        self,
        out_dir: Path,
        run: str,
        labels: _Labels,
        detectors: tuple[str, ...],
        chunk: int = 20_000,
    ) -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.run = run
        self.labels = labels
        self.detectors = detectors
        self.chunk = chunk
        self._pending: dict[str, dict[tuple[str, datetime], FeatureRow]] = {
            d: {} for d in detectors
        }
        self._writers: dict[str, pq.ParquetWriter] = {}
        self.counts: Counter[str] = Counter()
        self.positives: Counter[str] = Counter()

    def add(self, row: FeatureRow) -> None:
        if row.detector in self._pending:
            self._pending[row.detector][(row.key, row.window_start)] = row

    def flush_before(self, horizon: datetime) -> None:
        for detector, pending in self._pending.items():
            ready = [k for k, r in pending.items() if r.window_end <= horizon]
            if len(ready) >= self.chunk:
                self._write(detector, [pending.pop(k) for k in ready])

    def close(self) -> dict[str, int]:
        for detector, pending in self._pending.items():
            if pending:
                self._write(detector, list(pending.values()))
                pending.clear()
        for writer in self._writers.values():
            writer.close()
        return dict(self.counts)

    def _write(self, detector: str, batch: list[FeatureRow]) -> None:
        batch.sort(key=lambda r: (r.window_start, r.key))
        columns: dict[str, list[Any]] = {name: [] for name, _ in META_COLUMNS}
        names = FEATURES[detector]
        feature_columns: dict[str, list[float]] = {f"f_{n}": [] for n in names}
        for row in batch:
            label, stage, tag = self.labels.label(row.event_ids)
            columns["run"].append(self.run)
            columns["detector"].append(detector)
            columns["key"].append(row.key)
            columns["window_start"].append(row.window_start)
            columns["window_end"].append(row.window_end)
            columns["late"].append(row.late)
            columns["label"].append(label)
            columns["stage"].append(stage)
            columns["tag"].append(tag)
            columns["users"].append(row.users)
            columns["hosts"].append(row.hosts)
            columns["ips"].append(row.ips)
            columns["n_events"].append(len(row.event_ids))
            columns["event_ids"].append(row.event_ids)
            columns["context"].append(json.dumps(row.context) if row.context else None)
            for n in names:
                feature_columns[f"f_{n}"].append(float(row.features[n]))
            self.positives[detector] += label
        table = pa.table(columns | feature_columns, schema=feature_schema(detector))
        if detector not in self._writers:
            self._writers[detector] = pq.ParquetWriter(
                self.out_dir / f"{detector}.parquet", table.schema, compression="zstd"
            )
        self._writers[detector].write_table(table)
        self.counts[detector] += len(batch)


def featurize_run(
    lake: Lake,
    run: str,
    profiles: Profiles,
    out_root: Path,
    detectors: tuple[str, ...] = DETECTORS,
    window_config: WindowConfig | None = None,
) -> dict[str, Any]:
    """Replay ``run`` through the feature pipeline and write ``<out_root>/<run>/<detector>.parquet``."""
    inventory = lake.inventory(run)
    pipeline = FeaturePipeline(inventory, profiles, window_config, detectors=set(detectors))
    writer = FeatureWriter(Path(out_root) / run, run, _Labels(lake, run), detectors)
    retention = pipeline.cfg.retention_s
    batch: list = []
    for event in replay_events(lake.root, run):
        batch.append(event)
        if len(batch) >= 5_000:
            pipeline.add(batch)
            batch.clear()
            for row in pipeline.advance().rows():
                writer.add(row)
            if pipeline.clock is not None:
                writer.flush_before(pipeline.clock - timedelta(seconds=retention + 3600))
    pipeline.add(batch)
    for row in pipeline.advance().rows() + pipeline.flush().rows():
        writer.add(row)
    counts = writer.close()
    return {
        "run": run,
        "rows": counts,
        "positives": dict(writer.positives),
        "pipeline": pipeline.stats(),
    }


def load_features(root: str | Path, runs: list[str], detector: str) -> pa.Table:
    tables = []
    for run in runs:
        path = Path(root) / run / f"{detector}.parquet"
        if path.exists():
            tables.append(pq.read_table(path))
    if not tables:
        return feature_schema(detector).empty_table()
    return pa.concat_tables(tables)
