from __future__ import annotations

import json
from datetime import UTC, datetime

import pyarrow.parquet as pq
import pytest

from agentic_soc.etl import Lake, connect, duck, replay_events
from agentic_soc.etl.datasets import DatasetPlan, RunSpec, build
from agentic_soc.etl.training import load_features
from agentic_soc.features import FEATURES, Profiles

SMALL = {"org": {"users": 40}}
CAMPAIGN = SMALL | {
    "campaign": {"start_offset_h": 1, "start_jitter_h": 0, "dwell_scale": 0.3, "spray_targets": 25}
}


def spec(name: str, seed: int, day: int, hours: float, campaign: bool = True) -> RunSpec:
    return RunSpec(
        name=name, seed=seed, start=datetime(2026, 2, day, tzinfo=UTC), hours=hours,
        campaign=campaign, overrides=CAMPAIGN if campaign else SMALL,
    )  # fmt: skip


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("data")
    plan = DatasetPlan(
        org_seed=3,
        history=spec("history", 900, 2, 12, campaign=False),
        profile_split_h=6,
        train=[spec("train-1", 101, 3, 7)],
        validation=[spec("val-1", 102, 4, 4)],
    )
    plan.check_time_order()
    report = build(plan, root)
    return root, plan, report


def test_lake_and_duckdb_views(built) -> None:
    root, _, report = built
    lake = Lake(root / "lake")
    assert lake.runs() == ["history", "train-1", "val-1"]
    con = connect(root / "lake")
    overview = {r["run"]: r for r in duck.run_overview(con)}
    for name, info in report["runs"].items():
        valid = sum(s["valid"] for s in info["ingest"].values())
        o = overview[name]
        assert o["signins"] + o["flows"] + o["processes"] == valid
    assert overview["history"]["malicious"] == 0 and overview["train-1"]["malicious"] > 100
    assert duck.hourly_volume(con, "history", "Europe/Bucharest")
    assert duck.signin_failures(con, "train-1") and duck.top_external_destinations(con, "train-1")
    stages = {r["stage"] for r in duck.labelled_stage_counts(con, "train-1") if r["malicious"]}
    assert {"spray", "initial_access"} <= stages
    assert not (root / "raw").exists()


def test_replay_is_ordered_and_deterministic(built) -> None:
    root, _, _ = built
    first = [(e.ingest_time, e.event_id) for e in replay_events(root / "lake", "val-1")]
    assert first == sorted(first)
    assert first == [(e.ingest_time, e.event_id) for e in replay_events(root / "lake", "val-1")]
    assert {e.stream for e in replay_events(root / "lake", "val-1")} == {
        "signin",
        "flow",
        "process",
    }


def test_profiles_and_feature_tables(built) -> None:
    root, _, report = built
    features = root / "features"
    early = Profiles.load(features / "profiles-early.json")
    full = Profiles.load(features / "profiles.json")
    assert len(full.accounts) > len(early.accounts) > 5
    assert sum(p.n for p in full.accounts.values()) > sum(p.n for p in early.accounts.values())
    splits = json.loads((features / "splits.json").read_text())
    assert splits["train"] == ["train-1"] and splits["validation"] == ["val-1"]
    history = report["features"]["history"]["rows"]
    assert set(history) == {"M1-user", "M1-ip"}
    train = load_features(features, ["train-1"], "M2")
    assert (
        train.num_rows > 1000
        and pq.read_schema(features / "train-1" / "M2.parquet").names[0] == "run"
    )
    assert sum(train.column("label").to_pylist()) > 5
    for detector in FEATURES:
        table = load_features(features, ["train-1"], detector)
        assert table.num_rows > 0, detector
        keys = list(
            zip(
                table.column("key").to_pylist(),
                table.column("window_start").to_pylist(),
                strict=True,
            )
        )
        assert len(keys) == len(set(keys)), f"duplicate windows in {detector}"
    m1_ip = load_features(features, ["train-1"], "M1-ip").to_pylist()
    spray = [r for r in m1_ip if r["label"]]
    assert spray and all(r["stage"] in {"spray", "initial_access"} for r in spray)


def test_overlapping_splits_are_rejected() -> None:
    plan = DatasetPlan(
        history=spec("history", 1, 2, 48, campaign=False),
        train=[spec("train-1", 2, 3, 6)],
        validation=[spec("val-1", 3, 5, 6)],
    )
    with pytest.raises(ValueError, match="overlaps"):
        plan.check_time_order()
