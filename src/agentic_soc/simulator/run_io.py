"""Run directories: raw broker messages per topic plus ground truth, for offline replay.

Layout of ``data/runs/<name>/``::

    raw/<topic>.jsonl      messages in arrival order: {"ts", "key", "value"} (value as sent)
    labels.parquet         ground-truth labels of malicious and look-alike events
    truth.json             campaign truth, delivery statistics and applied actions
    inventory.json         asset and identity inventory (what the CMDB/IdP would export)
    config.yaml            the resolved simulator configuration
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import IO, Any

import orjson
import yaml

from agentic_soc.simulator.delivery import Delivery
from agentic_soc.simulator.engine import Simulator
from agentic_soc.simulator.model import iso
from agentic_soc.topics import STREAM_TOPICS


class RunWriter:
    def __init__(self, out_dir: Path) -> None:
        self.dir = Path(out_dir)
        (self.dir / "raw").mkdir(parents=True, exist_ok=True)
        self._files: dict[str, IO[bytes]] = {
            topic: open(self.dir / "raw" / f"{topic}.jsonl", "wb")  # noqa: SIM115
            for topic in STREAM_TOPICS.values()
        }
        self.messages = 0

    def write(self, deliveries: Iterable[Delivery]) -> None:
        for d in deliveries:
            record = {
                "ts": iso(d.deliver_at),
                "key": d.key,
                "value": d.value.decode("utf-8", "replace"),
            }
            self._files[d.topic].write(orjson.dumps(record) + b"\n")
            self.messages += 1

    def close(self, sim: Simulator) -> None:
        for handle in self._files.values():
            handle.close()
        sim.labels.write(self.dir / "labels.parquet")
        (self.dir / "truth.json").write_text(json.dumps(sim.truth(), indent=2) + "\n")
        (self.dir / "inventory.json").write_text(json.dumps(sim.ent.inventory(), indent=1) + "\n")
        config = sim.config.model_dump(mode="json")
        (self.dir / "config.yaml").write_text(yaml.safe_dump(config, sort_keys=False, width=100))


def read_raw(run_dir: Path, topic: str) -> Iterator[dict[str, Any]]:
    """Messages of one topic in arrival order."""
    with open(Path(run_dir) / "raw" / f"{topic}.jsonl", "rb") as handle:
        for line in handle:
            yield orjson.loads(line)


def simulate_to_dir(sim: Simulator, out_dir: Path) -> RunWriter:
    writer = RunWriter(out_dir)
    for batch in sim.run():
        writer.write(batch)
    writer.close(sim)
    return writer
