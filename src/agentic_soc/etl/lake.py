"""The Parquet data lake: one Hive partition per simulation run.

Layout under ``data/lake``::

    run=<name>/signin|flow|process|dead_letter/date=YYYY-MM-DD/part-*.parquet
    run=<name>/meta/{labels.parquet, truth.json, inventory.json, config.yaml}
"""

from __future__ import annotations

import shutil
from pathlib import Path

from agentic_soc.ingestion import IngestionStage, Inventory, replay_run
from agentic_soc.storage import ColdStore, StorageSink

META_FILES = ("labels.parquet", "truth.json", "inventory.json", "config.yaml")


class Lake:
    def __init__(self, root: str | Path = "data/lake") -> None:
        self.root = Path(root)

    def run_dir(self, run: str) -> Path:
        return self.root / f"run={run}"

    def meta(self, run: str) -> Path:
        return self.run_dir(run) / "meta"

    def runs(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(
            p.name.split("=", 1)[1] for p in self.root.glob("run=*") if (p / "meta").exists()
        )

    def has(self, run: str) -> bool:
        return (self.meta(run) / "truth.json").exists()

    def inventory(self, run: str) -> Inventory:
        return Inventory.from_file(self.meta(run) / "inventory.json")

    def import_run(
        self, run: str, raw_dir: Path, batch: int = 20_000
    ) -> dict[str, dict[str, object]]:
        """Ingest a raw run directory (``soc simulate``) into the lake partition ``run``."""
        target = self.run_dir(run)
        if target.exists():
            shutil.rmtree(target)
        meta = self.meta(run)
        meta.mkdir(parents=True)
        for name in META_FILES:
            shutil.copy(raw_dir / name, meta / name)
        stage = IngestionStage(Inventory.from_file(raw_dir / "inventory.json"))
        sink = StorageSink(cold=ColdStore(target, flush_rows=250_000))
        pending: list = []
        for message in replay_run(raw_dir):
            pending.append(message)
            if len(pending) >= batch:
                result = stage.process_batch(pending)
                sink.write_events(result.events)
                sink.write_dead_letters(result.dead_letters)
                pending.clear()
        result = stage.process_batch(pending)
        sink.write_events(result.events)
        sink.write_dead_letters(result.dead_letters)
        sink.close()
        return stage.summary()
