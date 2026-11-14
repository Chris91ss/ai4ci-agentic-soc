"""Dataset plan: which runs of the simulated company feed baselines, training, validation and
tests, in strictly increasing time (time-ordered splits, no future data in training).

All runs share ``org_seed`` (the same company, users, hosts and weak accounts); each has its
own activity seed, start date and campaign.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from agentic_soc.etl.lake import Lake
from agentic_soc.etl.training import DETECTORS, build_profiles, featurize_run
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.simulator.run_io import simulate_to_dir

log = logging.getLogger(__name__)


class RunSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    seed: int
    start: AwareDatetime
    hours: float = 48.0
    campaign: bool = True
    scenarios: list[str] = Field(default_factory=list)
    overrides: dict[str, Any] = Field(default_factory=dict)


class DatasetPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_seed: int = 7
    history: RunSpec
    profile_split_h: float = Field(
        96.0, description="Profiles for M1 training use history before this."
    )
    train: list[RunSpec]
    validation: list[RunSpec]
    test: list[RunSpec] = Field(default_factory=list)

    def all_runs(self) -> list[RunSpec]:
        return [self.history, *self.train, *self.validation, *self.test]

    def check_time_order(self) -> None:
        """Every split must end before the next one starts (no temporal leakage)."""
        groups = [[self.history], self.train, self.validation, self.test]
        previous_end = None
        for group in groups:
            if not group:
                continue
            start = min(r.start for r in group)
            end = max(r.start + timedelta(hours=r.hours) for r in group)
            if previous_end is not None and start < previous_end:
                raise ValueError(
                    f"split starting {start} overlaps the previous split ending {previous_end}"
                )
            previous_end = end


def load_plan(path: str | Path = "config/datasets.yaml") -> DatasetPlan:
    plan = DatasetPlan.model_validate(yaml.safe_load(Path(path).read_text()))
    plan.check_time_order()
    return plan


def simulate_spec(spec: RunSpec, org_seed: int, raw_root: Path) -> Path:
    overrides: dict[str, Any] = {
        "seed": spec.seed,
        "org_seed": org_seed,
        "start": spec.start.isoformat(),
        "duration_h": spec.hours,
        **spec.overrides,
    }
    if not spec.campaign:
        overrides["campaign"] = {"enabled": False}
    cfg = load_config(None, *spec.scenarios, overrides=overrides)
    out = raw_root / spec.name
    simulate_to_dir(Simulator(cfg), out)
    return out


def build(
    plan: DatasetPlan,
    data_root: Path = Path("data"),
    force: bool = False,
    keep_raw: bool = False,
) -> dict[str, Any]:
    """Simulate missing runs into the lake, build baselines and feature tables."""
    lake = Lake(data_root / "lake")
    raw_root = data_root / "raw"
    features_root = data_root / "features"
    report: dict[str, Any] = {"runs": {}}
    for spec in plan.all_runs():
        if lake.has(spec.name) and not force:
            continue
        started = time.perf_counter()
        raw = simulate_spec(spec, plan.org_seed, raw_root)
        summary = lake.import_run(spec.name, raw)
        if not keep_raw:
            shutil.rmtree(raw)
        report["runs"][spec.name] = {
            "seconds": round(time.perf_counter() - started, 1),
            "ingest": summary,
        }
        log.info("lake run %s ready", spec.name)
    if raw_root.exists() and not any(raw_root.iterdir()):
        raw_root.rmdir()

    history = plan.history.name
    split = plan.history.start + timedelta(hours=plan.profile_split_h)
    early = build_profiles(lake, history, until=split)
    full = build_profiles(lake, history)
    features_root.mkdir(parents=True, exist_ok=True)
    early.save(features_root / "profiles-early.json")
    full.save(features_root / "profiles.json")

    # M1 trains on history windows after the split, scored against early baselines.
    report["features"] = {
        history: featurize_run(lake, history, early, features_root, ("M1-user", "M1-ip"))
    }
    for spec in [*plan.train, *plan.validation, *plan.test]:
        report["features"][spec.name] = featurize_run(
            lake, spec.name, full, features_root, DETECTORS
        )
    report["splits"] = {
        "history": [history],
        "train": [r.name for r in plan.train],
        "validation": [r.name for r in plan.validation],
        "test": [r.name for r in plan.test],
        "profile_split": split.isoformat(),
    }
    (features_root / "splits.json").write_text(json.dumps(report["splits"], indent=2) + "\n")
    return report
