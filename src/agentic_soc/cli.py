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
        out.mkdir(parents=True, exist_ok=True)  # the SOC needs the asset inventory up front
        (out / "inventory.json").write_text(json.dumps(sim.ent.inventory(), indent=1) + "\n")
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


def _progress_line(pipeline, sim=None) -> str:
    executed = sum(1 for a in pipeline.actions.actions.values() if a.status == "executed")
    line = (
        f"{pipeline.now():%a %H:%M} events={pipeline.stats['events']:,} "
        f"alerts={len(pipeline.correlation.alert_incident):,} "
        f"incidents={len(pipeline.correlation.incidents)} queue={pipeline.router.queue_length} "
        f"decisions={len(pipeline.decisions)} actions={executed}"
    )
    if sim is not None and sim.campaign.status != "disabled":
        stage = next(reversed(sim.campaign.stage_times), "-")
        line += f" | campaign {sim.campaign.status}: {stage}"
    return line


def _write_run(out: Path, summary: dict, truth: dict | None, pipeline) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str) + "\n")
    if truth is not None:
        (out / "truth.json").write_text(json.dumps(truth, indent=2, default=str) + "\n")
    with (out / "log.jsonl").open("w") as fh:
        for entry in pipeline.log:
            fh.write(json.dumps(entry, default=str) + "\n")


@app.command()
def run(
    config: Path | None = typer.Option(
        None, help="Base YAML config (default config/simulator.yaml)."
    ),
    scenario: list[Path] | None = typer.Option(None, help="Scenario overlay(s), applied in order."),
    seed: int = typer.Option(201, help="Activity seed of the run."),
    org_seed: int = typer.Option(7, help="Company seed (the dataset and models use 7)."),
    start: str = typer.Option(
        "2026-03-09T00:00:00Z", help="Start time (after the dataset's test weeks)."
    ),
    hours: float = typer.Option(48.0, help="Duration in hours."),
    no_campaign: bool = typer.Option(False, "--no-campaign", help="Benign activity only."),
    mode: str = typer.Option("agent", help="agent (triage agent) or detectors (playbooks only)."),
    llm: str = typer.Option(
        "scripted", help="scripted or ollama[:model] (e.g. ollama:gpt-oss:20b)."
    ),
    models: Path = typer.Option(Path("models"), help="Model registry."),
    out: Path | None = typer.Option(
        None, help="Run directory (default data/soc-runs/<mode>-seed<seed>)."
    ),
    db: str | None = typer.Option(None, help="Store URL (default: soc.db in the run directory)."),
    approval_delay: float = typer.Option(
        0.0,
        help="High-impact actions: 0 = auto-approved (unattended run), else seconds before a "
        "simulated analyst approves them.",
    ),
    retrain_on_drift: bool = typer.Option(
        False, "--retrain-on-drift", help="Retrain M1 offline when the drift monitor alarms."
    ),
    verifier: bool = typer.Option(
        False, "--verifier", help="Veto agent actions the cited evidence does not justify."
    ),
) -> None:
    """Closed-loop run: simulator and SOC in one process, containment flowing back to the attack."""
    import time

    from rich.table import Table

    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.pipeline import InProcessRun, PipelineConfig
    from agentic_soc.simulator.engine import Simulator
    from agentic_soc.storage import Store

    if mode not in {"agent", "detectors", "rules"}:
        raise typer.BadParameter("mode must be agent, detectors or rules")
    cfg = _sim_config(config, scenario, seed, hours, no_campaign,
                      extra={"org_seed": org_seed, "start": start})  # fmt: skip
    out = out or Path("data/soc-runs") / f"{mode}-seed{cfg.seed}"
    db_path = out / "soc.db"
    if db is None and db_path.exists():
        db_path.unlink()
    store = Store(db or f"sqlite:///{db_path}")
    store.init_schema()
    sim = Simulator(cfg)
    pipeline_cfg = PipelineConfig(mode=mode, llm=llm, approval_delay_s=approval_delay,  # type: ignore[arg-type]
                                  retrain_on_drift=retrain_on_drift, verifier=verifier)  # fmt: skip
    runner = InProcessRun(sim, ModelRegistry(models).load_set(), pipeline_cfg, store)
    console.print(f"closed-loop run: {mode} ({llm if mode == 'agent' else 'playbooks'}), "
                  f"seed {cfg.seed}, org {org_seed}, {cfg.duration_h:g}h from {cfg.start:%Y-%m-%d %H:%M} -> {out}")  # fmt: skip
    started = time.perf_counter()
    outcome = runner.run(lambda p, s: console.print(_progress_line(p, s)), every=180)
    summary = outcome.summary | {"wall_s": round(time.perf_counter() - started, 1),
                                 "seed": cfg.seed, "org_seed": org_seed}  # fmt: skip
    _write_run(out, summary, outcome.truth, outcome.pipeline)
    (out / "inventory.json").write_text(json.dumps(sim.ent.inventory(), indent=1) + "\n")
    camp = outcome.truth["campaign"]
    table = Table(title=f"{mode} run seed={cfg.seed}")
    table.add_column("metric")
    table.add_column("value", justify="right")
    for key in ("events", "alerts", "incidents", "alert_to_incident_ratio"):
        table.add_row(key, f"{summary[key]:,}")
    table.add_row("decisions", ", ".join(f"{k}: {v}" for k, v in summary["decisions"].items()))
    table.add_row("verdicts", ", ".join(f"{k}: {v}" for k, v in summary["verdicts"].items()))
    for action in summary["actions"]:
        if action["status"] == "executed":
            when = (action["executed_at"] or "")[5:16].replace("T", " ")
            table.add_row(f"  {action['type']}", f"{action['target']} @ {when}")
    table.add_row("campaign", f"{camp['status']} {camp.get('stall_reason') or ''}".strip())
    table.add_row("exfiltrated", f"{camp['exfil_bytes'] / 1e9:.2f} GB")
    table.add_row("wall time", f"{summary['wall_s']:.0f}s")
    console.print(table)


@app.command()
def pipeline(
    broker: str = typer.Option("kafka://localhost:19092", help="Event broker URL."),
    db: str | None = typer.Option(None, help="Hot store URL (default $SOC_DB)."),
    models: Path = typer.Option(Path("models"), help="Model registry."),
    inventory: Path = typer.Option(..., help="inventory.json of the monitored enterprise."),
    mode: str = typer.Option("agent", help="agent or detectors (playbooks only)."),
    llm: str = typer.Option("ollama", help="ollama[:model] or scripted."),
    detectors_url: str | None = typer.Option(
        None, help="Detector REST service (default: in-process models)."
    ),
    idle_exit: float | None = typer.Option(
        None, help="Stop after the stream has been idle this many seconds."
    ),
    out: Path | None = typer.Option(None, help="Write summary.json and log.jsonl here at exit."),
    api_port: int | None = typer.Option(None, help="Also serve the console API on this port."),
) -> None:
    """Live SOC pipeline on the event broker (run the simulator with `soc simulate --broker`)."""
    import logging

    from agentic_soc.broker import connect
    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.detectors.service import HttpDetectorClient, LocalDetectorClient
    from agentic_soc.ingestion import Inventory
    from agentic_soc.pipeline import PipelineConfig, SocPipeline
    from agentic_soc.pipeline.service import run_live
    from agentic_soc.storage import Store

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    detectors = ModelRegistry(models).load_set()
    client = HttpDetectorClient(detectors_url) if detectors_url else LocalDetectorClient(detectors)
    store = Store(db)
    store.init_schema()
    config = PipelineConfig(mode=mode, llm=llm, worker="threaded", auto_approve=False)  # type: ignore[arg-type]
    bus = connect(broker)
    soc = SocPipeline(
        Inventory.from_file(inventory), client, detectors.profiles, store, bus, config
    )
    if api_port is not None:
        import threading

        from agentic_soc.api import ConsoleService

        service = ConsoleService(
            store, pipeline=soc, broker=bus, run={"name": "live", "mode": mode}
        )
        threading.Thread(
            target=_serve, args=(service, "127.0.0.1", api_port, None), daemon=True
        ).start()
        console.print(f"console API on http://127.0.0.1:{api_port}/api")
    console.print(f"SOC pipeline ({mode}) consuming {broker}; Ctrl-C to stop")
    try:
        run_live(soc, on_report=lambda p: console.print(_progress_line(p)), idle_exit_s=idle_exit)
    except KeyboardInterrupt:
        console.print("[yellow]stopped[/yellow]")
    if out is not None:
        _write_run(out, soc.summary(), None, soc)


def _serve(service, host: str, port: int, cors: list[str] | None) -> None:
    import uvicorn

    from agentic_soc.api import create_app

    uvicorn.run(create_app(service, cors), host=host, port=port, log_level="warning")


def _recorded_service(run_dir: Path | None, db: str | None, models: Path):
    """The console service over a recorded run (`soc run` output) or a store."""
    from agentic_soc.api import ConsoleService
    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.ingestion import Inventory
    from agentic_soc.storage import Store

    if db is None and run_dir is not None:
        db = f"sqlite:///{run_dir / 'soc.db'}"
    inventory = profiles = None
    run_info: dict = {}
    log: list = []
    if run_dir is not None:
        if (run_dir / "inventory.json").exists():
            inventory = Inventory.from_file(run_dir / "inventory.json")
        if (run_dir / "log.jsonl").exists():
            with (run_dir / "log.jsonl").open() as fh:
                log = [json.loads(line) for line in fh if line.strip()]
        if (run_dir / "summary.json").exists():
            summary = json.loads((run_dir / "summary.json").read_text())
            run_info = {"name": run_dir.name} | {
                k: summary.get(k) for k in ("mode", "llm", "seed", "org_seed")
            }
    if models.exists():
        profiles = ModelRegistry(models).load_set().profiles
    service = ConsoleService(Store(db), inventory, profiles, run=run_info, log=log,
                             evaluation_dir=Path("docs/evaluation"))  # fmt: skip
    return service, run_info.get("name", db)


@app.command()
def api(
    run_dir: Path | None = typer.Option(None, "--run", help="Run directory written by `soc run`."),
    db: str | None = typer.Option(None, help="Store URL (default: soc.db of --run, else $SOC_DB)."),
    models: Path = typer.Option(Path("models"), help="Model registry (account baselines)."),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000),
    cors: list[str] | None = typer.Option(None, help="Allowed console origins."),
) -> None:
    """Serve the console API over a recorded run (read-only)."""
    service, name = _recorded_service(run_dir, db, models)
    console.print(f"console API on http://{host}:{port}/api (read-only {name})")
    _serve(service, host, port, cors)


@app.command("export")
def export_run(
    run_dir: Path = typer.Option(..., "--run", help="Run directory written by `soc run`."),
    out: Path = typer.Option(Path("web/public/data"), help="Static data directory of the console."),
    models: Path = typer.Option(Path("models"), help="Model registry (account baselines)."),
    timeline_hours: float = typer.Option(72.0, help="Hours of entity timeline to include."),
    timeline_limit: int = typer.Option(50, help="Newest events per entity timeline."),
) -> None:
    """Export a recorded run as static JSON for the console (the GitHub Pages demo)."""
    from agentic_soc.api.export import export_static

    service, name = _recorded_service(run_dir, None, models)
    result = export_static(service, out, timeline_hours, timeline_limit)
    console.print(f"exported {name}: {result['incidents']} incidents, {result['entities']} entities, "
                  f"{result['bytes'] / 1e6:.1f} MB into {out}")  # fmt: skip


@app.command()
def demo(
    seed: int = typer.Option(201, help="Activity seed."),
    org_seed: int = typer.Option(7, help="Company seed (the models use 7)."),
    start: str = typer.Option(
        "2026-03-09T05:00:00Z",
        help="Start time (UTC). Starting before the working day lets the pipeline see the "
        "morning sign-ins, which it needs to map IP addresses to hosts.",
    ),
    hours: float = typer.Option(24.0, help="Duration in hours."),
    attack_after: float = typer.Option(4.0, help="Hours until the campaign starts."),
    speed: float = typer.Option(120.0, help="Simulated seconds per wall-clock second."),
    mode: str = typer.Option("agent", help="agent or detectors (playbooks only)."),
    llm: str = typer.Option("scripted", help="scripted or ollama[:model] (use a low --speed)."),
    models: Path = typer.Option(Path("models"), help="Model registry."),
    approval_delay: float | None = typer.Option(
        None, help="Auto-approve held actions after this many simulated seconds (default: analyst)."
    ),
    out: Path = typer.Option(Path("data/soc-runs/demo"), help="Directory of the demo store."),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000),
    cors: list[str] | None = typer.Option(None, help="Allowed console origins."),
) -> None:
    """Live demo: simulator, SOC pipeline and console API in one process."""
    from agentic_soc.api import ConsoleService
    from agentic_soc.detectors.registry import ModelRegistry
    from agentic_soc.pipeline import PipelineConfig
    from agentic_soc.pipeline.demo import LiveDemo
    from agentic_soc.simulator.engine import Simulator
    from agentic_soc.storage import Store

    campaign = {"start_offset_h": attack_after, "start_jitter_h": 0.0}
    cfg = _sim_config(None, None, seed, hours, False,
                      extra={"org_seed": org_seed, "start": start, "campaign": campaign})  # fmt: skip
    out.mkdir(parents=True, exist_ok=True)
    (out / "soc.db").unlink(missing_ok=True)
    store = Store(f"sqlite:///{out / 'soc.db'}")
    store.init_schema()
    config = PipelineConfig(mode=mode, llm=llm, auto_approve=approval_delay is not None,  # type: ignore[arg-type]
                            approval_delay_s=max(1.0, approval_delay or 0.0))  # fmt: skip
    sim = Simulator(cfg)
    (out / "inventory.json").write_text(json.dumps(sim.ent.inventory(), indent=1) + "\n")
    runner = LiveDemo(sim, ModelRegistry(models).load_set(), config, store, speed=speed)
    service = ConsoleService(store, pipeline=runner.pipeline, broker=runner.broker,
                             run={"name": "live demo", "mode": mode, "seed": seed, "speed": speed},
                             evaluation_dir=Path("docs/evaluation"))  # fmt: skip
    runner.start()
    console.print(
        f"live demo at {speed:g}x: console API on http://{host}:{port}/api; Ctrl-C to stop"
    )
    try:
        _serve(service, host, port, cors)
    finally:
        runner.close()
        (out / "truth.json").write_text(json.dumps(sim.truth(), indent=2, default=str) + "\n")


eval_app = typer.Typer(
    help="Evaluation: model level, end to end, S1 drift, S2 load (results in docs/evaluation).",
    no_args_is_help=True,
)
app.add_typer(eval_app, name="evaluate")
EVAL_DIR = Path("docs/evaluation")


def _seeds(text: str) -> list[int]:
    out: list[int] = []
    for part in text.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            out += list(range(int(lo), int(hi) + 1))
        elif part.strip():
            out.append(int(part))
    return out


def _update_results(section: str, value, out: Path) -> Path:
    from datetime import UTC, datetime

    from agentic_soc.evaluation.report import write

    path = out / "results.json"
    results = json.loads(path.read_text()) if path.exists() else {}
    results[section] = value
    results["generated"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return write(results, out)


def _progress(row: dict, done: int, total: int) -> None:
    if "error" in row:
        console.print(f"[red]{done}/{total} {row['name']} failed: {row['error']}[/red]")
        return
    console.print(f"{done}/{total} {row['name']}: stage {row['furthest_stage']}, exfil {row['exfil_gb']} GB, "
                  f"false containments {row['false_containments']}, MTTC {row['mttc_min']} min ({row['wall_s']:.0f}s)")  # fmt: skip


@eval_app.command("models")
def evaluate_models_cmd(
    data: Path = typer.Option(Path("data"), help="Data root built by `soc etl build`."),
    models: Path = typer.Option(Path("models"), help="Model registry."),
    out: Path = typer.Option(EVAL_DIR, help="Results directory."),
) -> None:
    """PR-AUC, recall at 1% FPR, FP/day and detection delay of M1-M3 on the test weeks."""
    from agentic_soc.evaluation import evaluate_models

    result = evaluate_models(data / "features", models, data / "lake")
    for kind, m in result["kinds"].items():
        console.print(f"{kind}: PR-AUC {m['pr_auc']}, recall@1%FPR {m['recall_at_1pct_fpr']}, "
                      f"recall@thr {m['recall_at_threshold']}, FP/day {m['false_positives_per_day']}")  # fmt: skip
    console.print(f"report: {_update_results('models', result, out)}")


@eval_app.command("e2e")
def evaluate_e2e(
    seeds: str = typer.Option("401-410", help="Seeds, e.g. 401-410 or 401,402."),
    modes: str = typer.Option("agent,detectors,rules", help="Configurations to run."),
    hours: float = typer.Option(48.0),
    workers: int = typer.Option(4, help="Parallel worker processes."),
    models: Path = typer.Option(Path("models")),
    out: Path = typer.Option(EVAL_DIR),
) -> None:
    """Closed-loop runs of the agent and the baselines on the same seeds."""
    from agentic_soc.evaluation import aggregate, compare, run_many, specs_for

    specs = specs_for(modes.split(","), _seeds(seeds), hours, str(models))
    console.print(f"{len(specs)} runs on {workers} workers")
    rows = run_many(specs, workers, _progress)
    # Runs of other configurations or seeds from an earlier call are kept.
    path = out / "results.json"
    earlier = json.loads(path.read_text()).get("e2e", {}).get("runs", []) if path.exists() else []
    fresh = {(r.get("config"), r.get("seed")) for r in rows}
    rows = [r for r in earlier if (r.get("config"), r.get("seed")) not in fresh] + rows
    rows.sort(key=lambda r: (r.get("config", ""), r.get("seed", 0)))
    result = {"runs": rows, "summary": aggregate(rows), "tests": compare(rows)}
    console.print(f"report: {_update_results('e2e', result, out)}")


@eval_app.command("llm")
def evaluate_llm(
    seeds: str = typer.Option("401-403", help="Seeds (same as the end-to-end runs)."),
    llm: str = typer.Option("ollama:gpt-oss:20b"),
    hours: float = typer.Option(48.0),
    workers: int = typer.Option(1, help="Parallel runs (one local LLM serves them all)."),
    verifier: bool = typer.Option(
        False, help="Check the agent's actions with the evidence verifier."
    ),
    models: Path = typer.Option(Path("models")),
    out: Path = typer.Option(EVAL_DIR),
) -> None:
    """The agent on a local LLM through Ollama (latency charged in simulated time)."""
    from agentic_soc.evaluation import aggregate, run_many
    from agentic_soc.evaluation.e2e import RunSpec, seed_start

    seed_list = _seeds(seeds)
    all_seeds = _seeds("401-410")
    specs = [RunSpec(mode="agent", seed=s, hours=hours, llm=llm, models=str(models), verifier=verifier,
                     start=seed_start(all_seeds.index(s) if s in all_seeds else i))
             for i, s in enumerate(seed_list)]  # fmt: skip
    rows = run_many(specs, workers, _progress)
    path = out / "results.json"
    earlier = json.loads(path.read_text()) if path.exists() else {}
    # Earlier runs of other configurations or seeds are kept, and the scripted analyst on the
    # same seeds (from `soc evaluate e2e`) is added for a paired comparison.
    fresh = {(r.get("config"), r.get("seed")) for r in rows}
    rows = [
        r
        for r in earlier.get("llm", {}).get("runs", [])
        if (r.get("config"), r.get("seed")) not in fresh
    ] + rows
    seeds_run = {r.get("seed") for r in rows}
    scripted = [
        r
        for r in earlier.get("e2e", {}).get("runs", [])
        if r.get("config") == "agent" and r["seed"] in seeds_run
    ]
    result = {"runs": rows, "summary": aggregate(rows + scripted)}
    console.print(f"report: {_update_results('llm', result, out)}")


@eval_app.command("s1")
def evaluate_s1(
    seeds: str = typer.Option("301-303"),
    workers: int = typer.Option(4),
    models: Path = typer.Option(Path("models")),
    out: Path = typer.Option(EVAL_DIR),
) -> None:
    """Scenario S1: the move to remote work, without and with M1 retraining on drift."""
    from agentic_soc.evaluation import aggregate, run_many
    from agentic_soc.evaluation.e2e import RunSpec

    scenario = ("config/scenarios/s1-remote-work.yaml",)
    specs = [RunSpec(mode="agent", seed=s, hours=72, scenarios=scenario, retrain_on_drift=retrain,
                     models=str(models), start="2026-03-09T00:00:00Z")
             for s in _seeds(seeds) for retrain in (False, True)]  # fmt: skip
    rows = run_many(specs, workers, _progress)
    for row in rows:
        if row.get("drift"):
            d = row["drift"]
            console.print(f"{row['name']}: alarm after {d['alarm_delay_h']} h, false M1 alerts/h "
                          f"{d['false_alerts_per_h_before']} -> {d['false_alerts_per_h_next_day']}, recovered after {d['recovery_h']} h")  # fmt: skip
    console.print(
        f"report: {_update_results('s1', {'runs': rows, 'summary': aggregate(rows)}, out)}"
    )


@eval_app.command("s2")
def evaluate_s2(
    broker: str = typer.Option("kafka://localhost:19092", help="Event broker (make up)."),
    speed: float = typer.Option(60.0, help="Simulated seconds per wall-clock second."),
    hours: float = typer.Option(6.0),
    factor: float = typer.Option(
        11.5, help="User-activity multiplier (about 10x the total event rate)."
    ),
    triage_s: float = typer.Option(
        60.0, help="Simulated seconds per agent triage (local-LLM latency)."
    ),
    slowdowns: str = typer.Option(
        "1,4", help="LLM slowdown factors during the burst, one run each."
    ),
    models: Path = typer.Option(Path("models")),
    out: Path = typer.Option(EVAL_DIR),
) -> None:
    """Scenario S2: a 10x event burst through Redpanda; consumer lag, latency and load shedding."""
    from agentic_soc.evaluation.load import run_s2

    variants = []
    for slowdown in [float(x) for x in slowdowns.split(",")]:
        console.print(f"S2 at {speed:g}x, LLM x{slowdown:g} during the burst ...")
        result = run_s2(str(models), broker, speed=speed, hours=hours, factor=factor, triage_s=triage_s,
                        llm_slowdown=slowdown)  # fmt: skip
        samples = result.pop("samples")
        out.mkdir(parents=True, exist_ok=True)
        (out / f"s2-samples-x{slowdown:g}.json").write_text(json.dumps(samples) + "\n")
        burst = result["phases"].get("burst", {})
        console.print(f"  event rate x{result['event_rate_multiplier']}, stream lag p95 {burst.get('stream_lag_s_p95')} sim s, "
                      f"consumer lag max {burst.get('consumer_lag_max')}, shed {result['shed_to_playbooks']}")  # fmt: skip
        variants.append(result)
    console.print(f"report: {_update_results('s2', variants, out)}")


@eval_app.command("report")
def evaluate_report(out: Path = typer.Option(EVAL_DIR)) -> None:
    """Re-render the Markdown report from results.json."""
    from agentic_soc.evaluation.report import write

    console.print(f"report: {write(json.loads((out / 'results.json').read_text()), out)}")


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
