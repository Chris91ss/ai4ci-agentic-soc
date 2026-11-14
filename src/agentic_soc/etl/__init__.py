"""Offline ETL: Parquet lake, DuckDB analytics, time-split datasets and deterministic replays."""

from agentic_soc.etl.duck import connect, replay_events
from agentic_soc.etl.lake import Lake

__all__ = ["Lake", "connect", "replay_events"]
