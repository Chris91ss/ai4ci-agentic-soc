"""Evaluation: model-level metrics, end-to-end closed-loop runs, S1 drift and S2 load."""

from agentic_soc.evaluation.e2e import RunSpec, aggregate, compare, run_many, run_one, specs_for
from agentic_soc.evaluation.m3_variants import evaluate_m3_variants
from agentic_soc.evaluation.metrics import STAGES, run_metrics
from agentic_soc.evaluation.model_level import evaluate_models
from agentic_soc.evaluation.report import render, write

__all__ = [
    "STAGES",
    "RunSpec",
    "aggregate",
    "compare",
    "evaluate_m3_variants",
    "evaluate_models",
    "render",
    "run_many",
    "run_metrics",
    "run_one",
    "specs_for",
    "write",
]
