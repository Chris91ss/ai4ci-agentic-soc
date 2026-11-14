"""Ground-truth label store.

Only labelled events are stored: campaign events (``malicious=True``) and tagged benign
look-alikes. Every other event is benign by definition, which keeps the store small even for
multi-day runs.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from agentic_soc.simulator.model import SimEvent

LABEL_SCHEMA = pa.schema(
    [
        ("event_id", pa.string()),
        ("stream", pa.string()),
        ("time", pa.timestamp("ms", tz="UTC")),
        ("malicious", pa.bool_()),
        ("stage", pa.string()),
        ("technique", pa.string()),
        ("campaign_id", pa.string()),
        ("tag", pa.string()),
    ]
)


class LabelStore:
    def __init__(self) -> None:
        self._cols: dict[str, list] = {name: [] for name in LABEL_SCHEMA.names}

    def add(self, events: Iterable[SimEvent]) -> None:
        cols = self._cols
        for event in events:
            label = event.label
            if label is None:
                continue
            cols["event_id"].append(event.event_id)
            cols["stream"].append(event.stream)
            cols["time"].append(event.time)
            cols["malicious"].append(label.malicious)
            cols["stage"].append(label.stage)
            cols["technique"].append(label.technique)
            cols["campaign_id"].append(label.campaign_id)
            cols["tag"].append(label.tag)

    def __len__(self) -> int:
        return len(self._cols["event_id"])

    def malicious_ids(self) -> set[str]:
        return {
            e for e, m in zip(self._cols["event_id"], self._cols["malicious"], strict=True) if m
        }

    def table(self) -> pa.Table:
        return pa.table(self._cols, schema=LABEL_SCHEMA)

    def write(self, path: Path) -> None:
        pq.write_table(self.table(), path, compression="zstd")


def read_labels(path: Path) -> pa.Table:
    return pq.read_table(path)
