"""Correlation of detector alerts into incidents with a risk score."""

from agentic_soc.correlation.engine import (
    CorrelationEngine,
    IncidentState,
    IncidentUpdate,
    make_alert,
)
from agentic_soc.correlation.risk import RiskBreakdown, incident_risk, priority_of

__all__ = [
    "CorrelationEngine",
    "IncidentState",
    "IncidentUpdate",
    "RiskBreakdown",
    "incident_risk",
    "make_alert",
    "priority_of",
]
