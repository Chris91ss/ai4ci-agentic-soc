from __future__ import annotations

import hashlib
from datetime import timedelta

import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from agentic_soc.cli import app
from agentic_soc.schemas import SchemaError, parse_event
from agentic_soc.simulator import Simulator, load_config
from agentic_soc.simulator.run_io import read_raw, simulate_to_dir

FAST = {
    "org": {"users": 60},
    "duration_h": 6,
    "campaign": {
        "start_offset_h": 0.5,
        "start_jitter_h": 0,
        "dwell_scale": 0.3,
        "spray_targets": 30,
    },
}


def fast_config(**extra):
    return load_config(overrides=FAST | extra)


@pytest.fixture(scope="module")
def run_dir(tmp_path_factory):
    sim = Simulator(fast_config())
    out = tmp_path_factory.mktemp("run")
    writer = simulate_to_dir(sim, out)
    return sim, writer, out


def test_run_directory_layout(run_dir) -> None:
    sim, writer, out = run_dir
    for name in ("labels.parquet", "truth.json", "inventory.json", "config.yaml"):
        assert (out / name).exists(), name
    total = sum(1 for topic in ("signin", "flow", "process") for _ in read_raw(out, topic))
    assert total == writer.messages == sim.delivery.stats.delivered
    assert sim.delivery.pending() == 0


def test_raw_messages_replay_through_the_schema_registry(run_dir) -> None:
    sim, _, out = run_dir
    valid = invalid = 0
    for topic in ("signin", "flow", "process"):
        for record in read_raw(out, topic):
            try:
                parse_event(topic, record["value"])
                valid += 1
            except SchemaError:
                invalid += 1
    assert valid > 10_000
    assert invalid == sim.delivery.stats.malformed


def test_labels_cover_the_campaign(run_dir) -> None:
    sim, _, out = run_dir
    labels = pq.read_table(out / "labels.parquet").to_pylist()
    malicious = [row for row in labels if row["malicious"]]
    assert len(malicious) == sim.campaign.n_events > 100
    assert {row["stage"] for row in malicious} >= {"spray", "initial_access", "exfiltration"}
    assert sim.truth()["campaign"]["status"] == "completed"
    assert any(row["tag"] == "edr_heartbeat" for row in labels)


def test_runs_are_reproducible(tmp_path) -> None:
    digests = []
    for name in ("a", "b"):
        cfg = fast_config(duration_h=2)
        simulate_to_dir(Simulator(cfg), tmp_path / name)
        digests.append(
            hashlib.sha256((tmp_path / name / "raw" / "signin.jsonl").read_bytes()).hexdigest()
        )
    assert digests[0] == digests[1]


def test_actions_are_normalised_and_applied() -> None:
    sim = Simulator(fast_config(duration_h=1))
    user = sim.ent.users[0]
    host = sim.ent.hosts_by_id[user.workstation]
    assert sim.apply_action("disable_account", f"CORP\\{user.user_id.upper()}")
    assert sim.apply_action("revoke_sessions", user.upn)
    assert sim.apply_action("isolate_host", host.fqdn.upper())
    assert sim.apply_action("block_ip", "2001:DB8:0::1")
    assert sim.ctx.control.is_blocked("2001:db8::1", sim.clock)
    assert not sim.apply_action("isolate_host", host.host_id.lower())  # already isolated
    assert sim.ctx.control.is_disabled(user.user_id, sim.clock)
    assert sim.ctx.control.is_isolated(host.host_id, sim.clock)
    assert [a["target"] for a in sim.actions][:3] == [user.user_id, user.user_id, host.host_id]
    assert not sim.apply_action("format_disk", "x")


def test_containment_during_a_run_stops_the_campaign() -> None:
    sim = Simulator(fast_config())
    while not sim.finished:
        sim.tick()
        if "command_and_control" in sim.campaign.stage_times and not sim.actions:
            sim.apply_action("isolate_host", sim.campaign.ws.host_id)
    truth = sim.truth()
    assert truth["campaign"]["status"] == "stalled"
    assert truth["campaign"]["exfil_bytes"] == 0
    assert truth["actions"][0]["applied"]
    assert sim.clock >= sim.config.start + timedelta(hours=6)


def test_simulate_cli(tmp_path) -> None:
    out = tmp_path / "cli"
    result = CliRunner().invoke(
        app, ["simulate", "--hours", "1", "--seed", "3", "--no-campaign", "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert (out / "truth.json").exists()
    assert "disabled" in result.output
