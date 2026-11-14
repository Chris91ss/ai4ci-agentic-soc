"""Incident risk: how likely an incident is a real intrusion, and how urgent it is.

Risk combines (1) detector evidence weighted by each detector's reliability and the margin of
its strongest alert above threshold, (2) corroboration across independent detectors (weak
signals from identity, network and endpoint data that agree), (3) kill-chain breadth and
late-stage tactics (credential access, lateral movement, collection, C2, exfiltration) and
(4) what is at stake: host criticality and privileged accounts. The result is in [0, 1].
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from agentic_soc.schemas.attack import tactic_of

RELIABILITY = {"M1-user": 0.35, "M1-ip": 0.55, "M2": 0.65, "M3": 0.3}
LATE_TACTICS = {
    "credential-access",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
}


@dataclass(frozen=True, slots=True)
class RiskBreakdown:
    risk: float
    evidence: float
    corroboration: float
    kill_chain: float
    stakes: float

    def as_dict(self) -> dict[str, float]:
        return {
            k: round(getattr(self, k), 4)
            for k in ("risk", "evidence", "corroboration", "kill_chain", "stakes")
        }


def priority_of(risk: float) -> int:
    if risk >= 0.85:
        return 1
    if risk >= 0.7:
        return 2
    if risk >= 0.5:
        return 3
    return 4


def incident_risk(
    margins: dict[str, float],
    techniques: set[str],
    max_criticality: int,
    admin_involved: bool,
) -> RiskBreakdown:
    """``margins``: strongest normalised margin above threshold per detector kind (0..1)."""
    evidence = sum(RELIABILITY.get(kind, 0.3) * (0.5 + 0.5 * m) for kind, m in margins.items())
    sources = {kind.split("-")[0] for kind in margins}
    corroboration = 0.25 * (len(sources) - 1)
    tactics = {t for t in (tactic_of(x) for x in techniques) if t}
    kill_chain = 0.08 * max(0, len(tactics) - 1) + (0.15 if tactics & LATE_TACTICS else 0.0)
    stakes = 0.05 * max(0, max_criticality - 3) + (0.1 if admin_involved else 0.0)
    total = evidence + corroboration + kill_chain + stakes
    return RiskBreakdown(1.0 - math.exp(-total), evidence, corroboration, kill_chain, stakes)
