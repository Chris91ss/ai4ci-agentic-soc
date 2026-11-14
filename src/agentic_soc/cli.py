"""Command-line entry point: ``soc <command>``."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from agentic_soc import __version__

app = typer.Typer(
    name="soc",
    help="Agentic SOC: simulator, pipeline, detectors, triage agent and evaluation.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.callback()
def main() -> None:
    """Agentic SOC command-line interface."""


@app.command()
def version() -> None:
    """Print the package version."""
    console.print(f"agentic-soc {__version__}")


@app.command()
def schemas(
    out: Path = typer.Option(Path("docs/schemas"), help="Directory for the JSON Schema files."),
) -> None:
    """Export JSON Schemas of the telemetry events and the agent decision."""
    from agentic_soc.schemas import Action, Alert, Decision, Incident, json_schemas

    out.mkdir(parents=True, exist_ok=True)
    documents = json_schemas() | {
        "alert": Alert.model_json_schema(),
        "incident": Incident.model_json_schema(),
        "action": Action.model_json_schema(),
        "decision": Decision.model_json_schema(),
    }
    for name, schema in documents.items():
        (out / f"{name}.schema.json").write_text(json.dumps(schema, indent=2) + "\n")
    console.print(f"wrote {len(documents)} schemas to {out}")


def _sim_config(
    config: Path | None,
    scenario: list[Path] | None,
    seed: int | None,
    hours: float | None,
    no_campaign: bool,
    extra: dict | None = None,
):
    from agentic_soc.simulator.config import load_config

    overrides: dict = dict(extra or {})
    if seed is not None:
        overrides["seed"] = seed
    if hours is not None:
        overrides["duration_h"] = hours
    if no_campaign:
        overrides["campaign"] = {"enabled": False}
    return load_config(config, *(scenario or []), overrides=overrides)


@app.command()
def simulate(
    config: Path | None = typer.Option(
        None, help="Base YAML config (default config/simulator.yaml)."
    ),
    scenario: list[Path] | None = typer.Option(None, help="Scenario overlay(s), applied in order."),
    seed: int | None = typer.Option(None, help="Override the seed."),
    hours: float | None = typer.Option(None, help="Override the duration in hours."),
    no_campaign: bool = typer.Option(False, "--no-campaign", help="Benign activity only."),
    out: Path | None = typer.Option(None, help="Run directory (default data/runs/seed<seed>)."),
    broker: str | None = typer.Option(
        None, help="Publish live to a broker (kafka://localhost:19092) instead of writing files."
    ),
    speed: float = typer.Option(
        60.0, help="Live mode: simulated seconds per wall second (0 = max)."
    ),
) -> None:
    """Run the simulator offline (run directory) or live (publishing to the event broker)."""
    import time

    from rich.table import Table

    from agentic_soc.simulator.engine import Simulator
    from agentic_soc.simulator.run_io import simulate_to_dir, write_ground_truth

    cfg = _sim_config(config, scenario, seed, hours, no_campaign)
    out = out or Path("data/runs") / f"seed{cfg.seed}"
    started = time.perf_counter()
    sim = Simulator(cfg)
    if broker:
        from agentic_soc.broker import connect
        from agentic_soc.simulator.live import LiveSimulator

        live = LiveSimulator(sim, connect(broker), speed=speed)
        console.print(
            f"publishing to {broker} at {speed:g}x; actions are applied from the actions topic"
        )
        try:
            live.run()
        except KeyboardInterrupt:
            console.print("[yellow]stopped[/yellow]")
        write_ground_truth(sim, out)
        messages = live.published
    else:
        messages = simulate_to_dir(sim, out).messages
    elapsed = time.perf_counter() - started
    truth = sim.truth()
    table = Table(title=f"simulation seed={cfg.seed} {cfg.duration_h:g}h -> {out}")
    table.add_column("metric")
    table.add_column("value", justify="right")
    for stream, count in sorted(truth["run"]["events"].items()):
        table.add_row(f"events: {stream}", f"{count:,}")
    for key, value in truth["run"]["delivery"].items():
        table.add_row(f"delivery: {key}", f"{value:,}")
    table.add_row("messages", f"{messages:,}")
    camp = truth["campaign"]
    table.add_row("campaign", f"{camp['status']} ({camp['events']:,} events)")
    for stage, when in camp["stage_times"].items():
        table.add_row(f"  {stage}", when)
    table.add_row("wall time", f"{elapsed:.1f}s")
    console.print(table)


@app.command("db-init")
def db_init(
    db: str = typer.Option(
        None, help="Database URL (default $SOC_DB or sqlite:///data/soc.sqlite)."
    ),
    reset: bool = typer.Option(False, help="Drop and recreate every table."),
) -> None:
    """Create the hot-store schema (TimescaleDB hypertables on PostgreSQL)."""
    from agentic_soc.storage import Store

    store = Store(db)
    store.reset() if reset else store.init_schema()
    console.print(f"schema ready on {store.dialect} ({store.url.split('@')[-1]})")


@app.command()
def ingest(
    run: Path = typer.Argument(..., help="Run directory written by `soc simulate`."),
    db: str | None = typer.Option(None, help="Also write to this hot store (database URL)."),
    lake: Path | None = typer.Option(None, help="Also write Parquet files to this cold store."),
) -> None:
    """Replay a run directory through ingestion and report stream health."""
    import time

    from rich.table import Table

    from agentic_soc.ingestion import IngestionStage, Inventory, replay_run
    from agentic_soc.storage import ColdStore, StorageSink, Store

    stage = IngestionStage(Inventory.from_file(run / "inventory.json"))
    hot = Store(db) if db else None
    if hot is not None:
        hot.init_schema()
    sink = StorageSink(hot, ColdStore(lake) if lake else None)
    started = time.perf_counter()
    batch: list = []

    def process() -> None:
        result = stage.process_batch(batch)
        sink.write_events(result.events)
        sink.write_dead_letters(result.dead_letters)
        batch.clear()

    for message in replay_run(run):
        batch.append(message)
        if len(batch) >= 5000:
            process()
    process()
    sink.close()
    elapsed = time.perf_counter() - started
    table = Table(title=f"ingestion of {run} ({elapsed:.1f}s)")
    columns = ["received", "valid", "invalid", "duplicates", "legacy", "delay_p50_s", "delay_p95_s"]
    table.add_column("stream")
    for column in columns:
        table.add_column(column, justify="right")
    for stream, summary in stage.summary().items():
        table.add_row(stream, *[f"{summary[c]:,}" for c in columns])
    console.print(table)


etl_app = typer.Typer(
    help="Offline ETL: lake, DuckDB analytics, datasets, replays.", no_args_is_help=True
)
app.add_typer(etl_app, name="etl")


@etl_app.command("build")
def etl_build(
    plan: Path = typer.Option(Path("config/datasets.yaml"), help="Dataset plan."),
    data: Path = typer.Option(Path("data"), help="Data root (lake, features)."),
    force: bool = typer.Option(False, help="Re-simulate runs already in the lake."),
) -> None:
    """Simulate the dataset plan into the lake and build baselines and feature tables."""
    import logging
    import time

    from agentic_soc.etl.datasets import build, load_plan

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    started = time.perf_counter()
    report = build(load_plan(plan), data, force=force)
    for run, info in report["features"].items():
        console.print(f"{run}: rows={info['rows']} positives={info['positives']}")
    console.print(f"splits: {report['splits']}  ({time.perf_counter() - started:.0f}s)")


@etl_app.command("stats")
def etl_stats(
    data: Path = typer.Option(Path("data"), help="Data root."),
    run: str | None = typer.Option(None, help="Details for one run."),
) -> None:
    """Analytics over the lake with DuckDB."""
    from rich.table import Table

    from agentic_soc.etl import duck

    con = duck.connect(data / "lake")
    sections = {"runs": duck.run_overview(con)}
    if run:
        sections["sign-in outcomes"] = duck.signin_failures(con, run)
        sections["top external destinations"] = duck.top_external_destinations(con, run, 10)
        sections["labelled stages"] = duck.labelled_stage_counts(con, run)
    for title, records in sections.items():
        if not records:
            continue
        table = Table(title=title)
        for column in records[0]:
            table.add_column(column)
        for record in records:
            table.add_row(*[str(v) for v in record.values()])
        console.print(table)


@etl_app.command("replay")
def etl_replay(
    run: str = typer.Argument(..., help="Lake run to replay."),
    data: Path = typer.Option(Path("data"), help="Data root."),
    out: Path = typer.Option(..., help="JSON-lines file of normalised events in arrival order."),
    hours: float | None = typer.Option(None, help="Only the first N hours of arrivals."),
) -> None:
    """Deterministic replay of a lake run (normalised events in arrival order)."""
    from datetime import timedelta

    import orjson

    from agentic_soc.etl import duck

    start = end = None
    events = duck.replay_events(data / "lake", run)
    written = 0
    with open(out, "wb") as handle:
        for event in events:
            if hours is not None:
                start = start or event.ingest_time
                end = end or start + timedelta(hours=hours)
                if event.ingest_time >= end:
                    break
            handle.write(orjson.dumps({"stream": event.stream, **event.row()}) + b"\n")
            written += 1
    console.print(f"replayed {written:,} events of {run} to {out}")


@app.command()
def train(
    data: Path = typer.Option(Path("data"), help="Data root built by `soc etl build`."),
    models: Path = typer.Option(Path("models"), help="Model registry."),
    only: list[str] | None = typer.Option(None, help="Train only these detectors (M1, M2, M3)."),
    promote: bool = typer.Option(True, help="Promote the new versions."),
    seed: int = typer.Option(0, help="Training seed."),
) -> None:
    """Train M1-M3 on the time-split datasets and store them in the model registry."""
    import time

    from rich.table import Table

    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.detectors.training import train_m1, train_m2, train_m3

    registry = ModelRegistry(models)
    features = data / "features"
    jobs = {
        "M1": lambda: train_m1(features, seed=seed),
        "M2": lambda: train_m2(features, seed=seed),
        "M3": lambda: train_m3(features, data / "lake"),
    }
    table = Table(title="validation week (thresholds at target FPR)")
    for column in (
        "detector",
        "version",
        "kind",
        "threshold",
        "TP",
        "FP",
        "positives",
        "rows",
        "seconds",
    ):
        table.add_column(column)
    for name, job in jobs.items():
        if only and name not in only:
            continue
        started = time.perf_counter()
        detector, report = job()
        registry.save(detector, promote=promote)
        validation = report["validation"]
        per_kind = validation if name == "M1" else {name: validation}
        for kind, v in per_kind.items():
            table.add_row(name, detector.version, kind, f"{v['threshold']:.5f}", str(v["true_positives"]),
                          str(v["false_positives"]), str(v["positives"]), f"{v['rows']:,}",
                          f"{time.perf_counter() - started:.1f}")  # fmt: skip
    console.print(table)


@app.command()
def models(
    models: Path = typer.Option(Path("models"), help="Model registry."),
    promote: str | None = typer.Option(None, help="Promote DETECTOR:VERSION (rollback)."),
) -> None:
    """List model versions or promote one."""
    from agentic_soc.detectors.registry import ModelRegistry

    registry = ModelRegistry(models)
    if promote:
        name, version = promote.split(":", 1)
        registry.promote(name, version)
        console.print(f"promoted {name} {version}")
    for name in ("M1", "M2", "M3"):
        for info in registry.versions(name):
            marker = "*" if info["current"] else " "
            console.print(f"{marker} {name} {info['version']} thresholds={info['thresholds']}")


@app.command("serve-detectors")
def serve_detectors(
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8001),
    models: Path = typer.Option(Path("models"), help="Model registry."),
) -> None:
    """Serve M1-M3 over REST (POST /score/{M1|M2|M3})."""
    import uvicorn

    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.detectors.service import create_app

    uvicorn.run(create_app(ModelRegistry(models)), host=host, port=port, log_level="info")


@app.command()
def mcp(
    http: bool = typer.Option(False, "--http", help="Serve streamable HTTP instead of stdio."),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8002),
    db: str | None = typer.Option(None, help="Hot store URL (default $SOC_DB)."),
    models: Path = typer.Option(Path("models"), help="Model registry."),
    inventory: Path = typer.Option(..., help="inventory.json of the monitored enterprise."),
    detectors_url: str | None = typer.Option(
        None, help="Detector REST service (default: in-process models)."
    ),
) -> None:
    """Serve the SOC tools to an MCP client (the triage agent)."""
    from datetime import UTC, datetime

    from agentic_soc.actions import ActionManager, BrokerActionSink, PolicyGate
    from agentic_soc.broker import connect
    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.detectors.service import HttpDetectorClient, LocalDetectorClient
    from agentic_soc.ingestion import Inventory
    from agentic_soc.mcp_server import SocContext, SocTools, build_server
    from agentic_soc.storage import Store

    inv = Inventory.from_file(inventory)
    store = Store(db)
    registry = ModelRegistry(models)
    detectors = registry.load_set()
    client = HttpDetectorClient(detectors_url) if detectors_url else LocalDetectorClient(detectors)
    actions = ActionManager(PolicyGate(inv), BrokerActionSink(connect().producer()), store)
    ctx = SocContext(
        store, inv, detectors.profiles, client, actions, clock=lambda: datetime.now(UTC)
    )
    server = build_server(SocTools(ctx))
    if http:
        server.run(transport="streamable-http", host=host, port=port)
    else:
        server.run()


@app.command()
def calibrate(
    lanl_auth: Path | None = typer.Option(None, help="LANL auth.txt[.gz]"),
    lanl_flows: Path | None = typer.Option(None, help="LANL flows.txt[.gz]"),
    lanl_proc: Path | None = typer.Option(None, help="LANL proc.txt[.gz]"),
    rba: Path | None = typer.Option(None, help="RBA login dataset (rba-dataset.csv)"),
    base: str = typer.Option("default", help="Calibration to start from."),
    max_rows: int = typer.Option(5_000_000, help="Records to read from each file."),
    out: Path = typer.Option(Path("config/calibration/fitted.yaml")),
) -> None:
    """Fit the simulator's activity model on the LANL and RBA datasets."""
    from agentic_soc.simulator.calibration import calibrate as fit
    from agentic_soc.simulator.calibration import dump_calibration, load_calibration

    if not any([lanl_auth, lanl_flows, lanl_proc, rba]):
        raise typer.BadParameter("pass at least one dataset file")
    result = fit(load_calibration(base), lanl_auth, lanl_flows, lanl_proc, rba, max_rows)
    dump_calibration(result, out)
    console.print(f"[green]calibration written to {out}[/green]: {result.source}")


if __name__ == "__main__":
    app()
