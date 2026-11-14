"""Orchestration of the SOC pipeline (in-process closed loop or against a broker)."""

from agentic_soc.pipeline.core import PipelineConfig, SocPipeline, make_llm
from agentic_soc.pipeline.inprocess import InProcessRun, RunOutcome
from agentic_soc.pipeline.worker import ThreadedAgentWorker, TriageJob, VirtualTimeAgentWorker

__all__ = [
    "InProcessRun",
    "PipelineConfig",
    "RunOutcome",
    "SocPipeline",
    "ThreadedAgentWorker",
    "TriageJob",
    "VirtualTimeAgentWorker",
    "make_llm",
]
