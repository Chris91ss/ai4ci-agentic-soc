# ai4ci-agentic-soc

Agentic SOC for a simulated enterprise: correlates asynchronous sign-in, network-flow and endpoint event streams; a local-LLM triage agent orchestrates ML detectors over MCP and takes containment actions that feed back into the simulator. AI4CI course project.

RFC: [docs/rfc/0001-agentic-soc.pdf](docs/rfc/0001-agentic-soc.pdf) (source: [docs/rfc/0001-agentic-soc.md](docs/rfc/0001-agentic-soc.md))

![Architecture](docs/rfc/figures/architecture.svg)

## Components

| Component | Package | Status |
|-----------|---------|--------|
| Seeded enterprise simulator (sign-ins, flows, processes, ATT&CK campaign) | `agentic_soc.simulator` | planned |
| Kafka-compatible event broker (Redpanda) | `agentic_soc.broker` | planned |
| Ingestion: schema validation, dead-letter, dedupe, normalise, enrich | `agentic_soc.ingestion` | planned |
| Storage: TimescaleDB (hot), Parquet (cold), labels, audit log | `agentic_soc.storage` | planned |
| Offline ETL in DuckDB, drift checks, retraining | `agentic_soc.etl` | planned |
| Online inference: event-time windows, entity resolution, M1–M3 | `agentic_soc.features`, `agentic_soc.detectors` | planned |
| Correlation engine and risk router | `agentic_soc.correlation` | planned |
| MCP server and policy gate | `agentic_soc.mcp_server` | planned |
| Local-LLM triage agent (ReAct) | `agentic_soc.agent` | planned |
| FastAPI backend and Next.js SOC console | `agentic_soc.api`, `web/` | planned |
| Evaluation (model level, end to end, S1 drift, S2 load) | `agentic_soc.evaluation` | planned |

## Development

Requirements: Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
make install   # uv sync
make test      # fast unit tests
make lint      # ruff
uv run soc --help
```
