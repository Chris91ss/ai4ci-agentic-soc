"""Agent proposals during a virtual-time triage.

The agent may call the ``propose_action`` MCP tool while it investigates. In a virtual-time run
the triage happens instantly in wall-clock terms but takes the agent's latency in simulated time,
so its proposals must not touch the environment before that latency has elapsed. The policy
gate's verdict is returned at once (the agent can adapt to a denial); execution is deferred
until the pipeline applies the agent's decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agentic_soc.actions import ActionManager
from agentic_soc.actions.manager import OPEN
from agentic_soc.schemas import ACTION_IMPACT, Action


@dataclass
class StagedProposal:
    incident_id: str | None
    action_type: str
    target: str
    justification: str
    evidence_ids: list[str] = field(default_factory=list)


class StagedActions:
    """Wraps the action manager for the MCP tools; ``staging`` defers agent proposals."""

    def __init__(self, manager: ActionManager) -> None:
        self.manager = manager
        self.staging = False
        self.staged: list[StagedProposal] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.manager, name)

    def take(self) -> list[StagedProposal]:
        staged, self.staged = self.staged, []
        return staged

    def propose(
        self,
        incident_id: str | None,
        action_type: str,
        target: str,
        requested_by: str,
        now: datetime,
        justification: str = "",
        evidence_ids: list[str] | None = None,
    ) -> Action:
        if not self.staging:
            return self.manager.propose(
                incident_id, action_type, target, requested_by, now, justification, evidence_ids
            )
        if action_type not in ACTION_IMPACT:
            raise ValueError(f"{action_type!r} is not on the action allow-list")
        open_count = sum(
            1 for a in self.manager.for_incident(incident_id or "") if a.status in OPEN
        ) + sum(1 for p in self.staged if p.incident_id == incident_id)
        verdict = self.manager.gate.evaluate(
            action_type, target, requested_by, now, open_count, dry_run=True
        )
        status = {"deny": "denied", "pending_approval": "pending_approval"}.get(
            verdict.outcome, "proposed"
        )
        note = f" [denied: {verdict.reason}]" if verdict.outcome == "deny" else ""
        if verdict.outcome != "deny":
            self.staged.append(
                StagedProposal(
                    incident_id,
                    action_type,
                    verdict.target,
                    justification,
                    list(evidence_ids or []),
                )
            )
        return Action(
            action_id=self.manager._id(incident_id, action_type, verdict.target),
            incident_id=incident_id,
            type=action_type,  # type: ignore[arg-type]
            target=verdict.target,
            impact=ACTION_IMPACT[action_type],
            status=status,  # type: ignore[arg-type]
            requested_by=requested_by,  # type: ignore[arg-type]
            justification=f"{justification}{note}"[:2000],
            evidence_ids=list(evidence_ids or [])[:50],
            created_at=now,
        )
