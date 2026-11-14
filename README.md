# ai4ci-agentic-soc

Agentic SOC for a simulated enterprise: correlates asynchronous sign-in, network-flow and endpoint event streams; a local-LLM triage agent orchestrates ML detectors over MCP and takes containment actions that feed back into the simulator. AI4CI course project.

RFC: [docs/rfc/0001-agentic-soc.pdf](docs/rfc/0001-agentic-soc.pdf) (source: [docs/rfc/0001-agentic-soc.md](docs/rfc/0001-agentic-soc.md))

![Architecture](docs/rfc/figures/architecture.svg)

## Components

| Component | Package | Status |
|-----------|---------|--------|
| Seeded enterprise simulator (sign-ins, flows, processes, ATT&CK campaign) | `agentic_soc.simulator` | done |
| Kafka-compatible event broker (Redpanda) | `agentic_soc.broker` | done |
| Ingestion: schema validation, dead-letter, dedupe, normalise, enrich | `agentic_soc.ingestion` | done |
| Storage: TimescaleDB (hot), Parquet (cold), labels, audit log | `agentic_soc.storage` | done |
| Offline ETL in DuckDB, drift checks (PSI/KS), retraining | `agentic_soc.etl`, `agentic_soc.drift` | done |
| Online inference: event-time windows, entity resolution, M1–M3 | `agentic_soc.features`, `agentic_soc.detectors` | done |
| Correlation engine, risk router and playbooks | `agentic_soc.correlation`, `agentic_soc.routing` | done |
| MCP server and policy gate | `agentic_soc.mcp_server`, `agentic_soc.actions` | done |
| Local-LLM triage agent (ReAct) | `agentic_soc.agent` | done |
| Closed-loop pipeline (in-process and live on the broker) | `agentic_soc.pipeline` | done |
| Evidence bundles behind every verdict, analyst feedback and FP statistics | `agentic_soc.evidence` | done |
| FastAPI backend (REST + server-sent events) and Next.js SOC console | `agentic_soc.api`, `web/` | done |
| Evaluation (model level, end to end, S1 drift, S2 load) | `agentic_soc.evaluation` | planned |

## Development

Requirements: Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
make install   # uv sync
make test      # fast unit tests
make lint      # ruff
uv run soc --help
```

On macOS, LightGBM needs OpenMP: `brew install libomp`.

## Running the SOC

```bash
uv run soc etl build          # simulate the dataset plan into data/ (lake + feature tables)
uv run soc train              # train M1-M3 into the model registry (models/)
uv run soc run                # closed loop: simulator + SOC in one process (scripted analyst)
uv run soc run --llm ollama:gpt-oss:20b          # the triage agent on a local LLM (Ollama)
uv run soc run --mode detectors                  # baseline: detectors + playbooks, no agent
```

Scenario S1 (drift) moves most staff to remote work through a newly adopted ZTNA service, so
sign-ins come from new networks abroad and later in the day. The drift monitor compares the
live M1 feature windows with M1's training distribution (PSI and KS) and alarms; with
`--retrain-on-drift` M1 is retrained offline on the recent sign-ins with refreshed baselines and
swapped in:

```bash
uv run soc run --scenario config/scenarios/s1-remote-work.yaml --hours 72 --retrain-on-drift
```

Scenario S2 (high load) adds a one-hour burst of user activity, about ten times the usual event
rate, on a working-day morning while the intrusion is under way. Streamed live through Redpanda
it shows consumer lag, end-to-end latency and the router shedding incidents to the playbooks
when the agent cannot keep up (`--scenario config/scenarios/s2-burst.yaml`).

`soc run` writes `data/soc-runs/<mode>-seed<seed>/` with the SOC store (`soc.db`), the run
summary, the pipeline log and the simulator's ground truth. The agent's latency is charged in
simulated time, so the attack keeps going while it investigates; high-impact actions are
auto-approved in these unattended runs (`--approval-delay` models an analyst's response time).

The console API (FastAPI) serves a recorded run read-only, or a live demo in which the
simulator, the pipeline and the API share one process and an analyst approves or rejects held
actions:

```bash
uv run soc api --run data/soc-runs/agent-seed201   # http://127.0.0.1:8000/api, read-only
uv run soc demo --speed 120                        # live: attack 1.5 h in, analyst approvals
```

The SOC console (`web/`, Next.js with Tabler icons and framer-motion) shows stream health,
the incident queue, incident timelines with the agent's tool trace and evidence, approvals,
analyst feedback, metrics and the audit log; see [web/README.md](web/README.md):

```bash
cd web && npm install && npm run dev               # http://localhost:3000
```

Endpoints: `/api/health`, `/api/stream-health`, `/api/incidents[/{id}[/evidence|/trace|/feedback]]`,
`/api/entities/{entity}[/timeline]`, `/api/actions[/{id}/approve|/reject]`, `/api/metrics`,
`/api/audit[/verify]` and `/api/events` (server-sent events of the live pipeline).

Live mode streams through Redpanda instead (`make up` starts it and TimescaleDB):

```bash
uv run soc simulate --broker kafka://localhost:19092 --speed 60 --out data/runs/live
uv run soc pipeline --inventory data/runs/live/inventory.json --db $SOC_DB --api-port 8000
```
