"""Storage: TimescaleDB/SQLite hot store, Parquet cold store, labels and the audit log."""

from __future__ import annotations

from collections.abc import Iterable

from agentic_soc.ingestion.models import NormEventT
from agentic_soc.schemas import DeadLetter
from agentic_soc.storage.cold import ColdStore, read_table
from agentic_soc.storage.hot import Store


class StorageSink:
    """Ingestion sink writing to the hot store and/or the cold store."""

    def __init__(self, hot: Store | None = None, cold: ColdStore | None = None) -> None:
        self.hot = hot
        self.cold = cold

    def write_events(self, events: list[NormEventT]) -> None:
        if self.hot is not None:
            self.hot.write_events(events)
        if self.cold is not None:
            self.cold.write_events(events)

    def write_dead_letters(self, letters: Iterable[DeadLetter]) -> None:
        letters = list(letters)
        if self.hot is not None:
            self.hot.write_dead_letters(letters)
        if self.cold is not None:
            self.cold.write_dead_letters(letters)

    def close(self) -> None:
        if self.cold is not None:
            self.cold.close()


__all__ = ["ColdStore", "StorageSink", "Store", "read_table"]
