"""Security objects produced downstream of ingestion: alerts, incidents, actions, decisions."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from agentic_soc.schemas.attack import TECHNIQUE_ID

Stream = Literal["signin", "flow", "process"]
Severity = Literal["low", "medium", "high", "critical"]
TechniqueId = Annotated[str, Field(pattern=TECHNIQUE_ID.pattern)]

ActionType = Literal["revoke_sessions", "disable_account", "isolate_host", "block_ip"]
ACTION_TYPES: tuple[str, ...] = ("revoke_sessions", "disable_account", "isolate_host", "block_ip")
# Allow-list with impact levels (RFC §4 "Routing and guardrails").
ACTION_IMPACT: dict[str, Literal["low", "high"]] = {
    "revoke_sessions": "low",
    "block_ip": "low",
    "disable_account": "high",
    "isolate_host": "high",
}
# Which entity kind each action targets.
ACTION_TARGET_KIND: dict[str, Literal["user", "host", "ip"]] = {
    "revoke_sessions": "user",
    "disable_account": "user",
    "isolate_host": "host",
    "block_ip": "ip",
}
ActionStatus = Literal[
    "proposed", "pending_approval", "approved", "rejected", "denied", "executed", "failed"
]
Requester = Literal["agent", "playbook", "analyst"]

IncidentStatus = Literal[
    "open", "logged", "queued", "triaging", "awaiting_approval", "contained", "dismissed", "closed"
]
Route = Literal["log", "agent", "playbook", "analyst"]
Verdict = Literal["malicious", "suspicious", "benign"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeadLetter(_Model):
    """Payload that failed validation, published to the ``dead-letter`` topic."""

    topic: str
    key: str | None = None
    raw: str = Field(max_length=4096)
    error_code: str
    error_detail: str
    received_at: AwareDatetime


class EntityRefs(_Model):
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)

    def keys(self) -> set[str]:
        return (
            {f"user:{u}" for u in self.users}
            | {f"host:{h}" for h in self.hosts}
            | {f"ip:{i}" for i in self.ips}
        )


class FeatureContribution(_Model):
    name: str
    value: float | str
    contribution: float


class Alert(_Model):
    """A detector (M1-M3) or rule firing on one entity window."""

    alert_id: str
    detector: str = Field(description="M1, M2, M3 or rule:<id>.")
    model_version: str = ""
    stream: Stream
    window_start: AwareDatetime
    window_end: AwareDatetime
    score: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    severity: Severity
    entities: EntityRefs
    event_ids: list[str] = Field(default_factory=list)
    top_features: list[FeatureContribution] = Field(default_factory=list)
    techniques: list[TechniqueId] = Field(default_factory=list)
    summary: str = ""


class Incident(_Model):
    """Alerts linked by shared entities and time, with a risk score."""

    incident_id: str
    status: IncidentStatus = "open"
    risk: float = Field(ge=0.0, le=1.0)
    priority: int = Field(ge=1, le=4, description="1 = most urgent.")
    created_at: AwareDatetime
    updated_at: AwareDatetime
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    entities: EntityRefs
    alert_ids: list[str]
    detectors: list[str]
    streams: list[Stream]
    techniques: list[TechniqueId] = Field(default_factory=list)
    route: Route | None = None
    summary: str = ""


class Action(_Model):
    """Containment action; executed actions are published on the ``actions`` topic."""

    action_id: str
    incident_id: str | None = None
    type: ActionType
    target: str
    impact: Literal["low", "high"]
    status: ActionStatus = "proposed"
    requested_by: Requester
    approved_by: str | None = None
    justification: str = Field(default="", max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: AwareDatetime
    executed_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _impact_matches_allow_list(self) -> Action:
        if ACTION_IMPACT[self.type] != self.impact:
            raise ValueError(f"impact of {self.type} must be {ACTION_IMPACT[self.type]}")
        return self


class EvidenceRef(_Model):
    """Pointer to the data behind a verdict, cited by ID in the explanation."""

    id: str = Field(min_length=1, max_length=128)
    kind: Literal["event", "alert", "tool_call", "baseline"]
    note: str = Field(default="", max_length=300)


class ProposedAction(_Model):
    type: Literal["none", "revoke_sessions", "disable_account", "isolate_host", "block_ip"]
    target: str | None = None


class Decision(_Model):
    """Structured verdict returned by the triage agent (validated against this JSON Schema)."""

    incident_id: str
    verdict: Verdict
    techniques: list[TechniqueId] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    action: ProposedAction
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(default="", max_length=1500)

    @model_validator(mode="after")
    def _guardrails(self) -> Decision:
        if self.verdict == "benign" and not self.evidence:
            raise ValueError(
                "a benign verdict (dismissal) must cite at least one piece of evidence"
            )
        if self.verdict == "benign" and self.action.type != "none":
            raise ValueError("a benign verdict cannot carry a containment action")
        if self.action.type != "none" and not self.action.target:
            raise ValueError("a containment action needs a target")
        return self


class DecisionRecord(_Model):
    """A decision as stored, whoever made it (agent, playbook or analyst)."""

    incident_id: str
    decided_by: Literal["agent", "playbook", "analyst"]
    decision: Decision
    created_at: datetime
    latency_s: float = 0.0
    model: str | None = None
