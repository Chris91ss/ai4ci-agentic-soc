"""Containment actions: proposal through the policy gate, approval, execution and audit."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol

import orjson

from agentic_soc import topics
from agentic_soc.actions.policy import PolicyGate
from agentic_soc.broker.base import Producer
from agentic_soc.schemas import ACTION_IMPACT, Action
from agentic_soc.storage.hot import Store

OPEN = {"proposed", "pending_approval", "approved", "executed"}


class ActionSink(Protocol):
    def execute(self, action: Action) -> bool: ...


class BrokerActionSink:
    """Publishes approved actions to the ``actions`` topic (the simulator applies them)."""

    def __init__(self, producer: Producer) -> None:
        self.producer = producer

    def execute(self, action: Action) -> bool:
        self.producer.send(topics.ACTIONS, orjson.dumps(action.model_dump(mode="json") | {"status": "approved"}),
                           key=action.target)  # fmt: skip
        self.producer.flush(5)
        return True


class CallbackActionSink:
    """Applies actions directly (single-process pipeline: ``simulator.apply_action``)."""

    def __init__(self, apply: Callable[[str, str, str], bool]) -> None:
        self.apply = apply

    def execute(self, action: Action) -> bool:
        self.apply(action.type, action.target, action.action_id)
        return True


class ActionManager:
    def __init__(
        self, gate: PolicyGate, sink: ActionSink | None, store: Store | None = None
    ) -> None:
        self.gate = gate
        self.sink = sink
        self.store = store
        self.actions: dict[str, Action] = {}
        self.by_key: dict[tuple[str, str], str] = {}
        self.listeners: list[Callable[[Action], None]] = []

    # ------------------------------------------------------------------ helpers
    def _id(self, incident_id: str | None, action_type: str, target: str) -> str:
        digest = hashlib.blake2b(
            f"{incident_id}|{action_type}|{target}".encode(), digest_size=5
        ).hexdigest()
        return f"ACT-{digest}"

    def _save(self, action: Action, now: datetime) -> None:
        self.actions[action.action_id] = action
        if self.store is not None:
            self.store.upsert_action(action.model_dump() | {"updated_at": now})
        for listener in self.listeners:
            listener(action)

    def _audit(self, actor: str, verb: str, action: Action, now: datetime, **details: Any) -> None:
        if self.store is not None:
            self.store.audit(actor, verb, "action", action.action_id,
                             {"type": action.type, "target": action.target, "incident_id": action.incident_id,
                              "status": action.status, **details}, ts=now)  # fmt: skip

    def for_incident(self, incident_id: str) -> list[Action]:
        return [a for a in self.actions.values() if a.incident_id == incident_id]

    def taken(self) -> set[tuple[str, str]]:
        return {
            (a.type, a.target)
            for a in self.actions.values()
            if a.status in {"approved", "executed", "pending_approval"}
        }

    def pending(self) -> list[Action]:
        return [a for a in self.actions.values() if a.status == "pending_approval"]

    # ------------------------------------------------------------------ lifecycle
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
        """Run a proposal through the policy gate; executes, parks for approval or denies."""
        if action_type not in ACTION_IMPACT:
            if self.store is not None:
                self.store.audit(requested_by, "propose_rejected", "action", f"{incident_id}:{action_type}",
                                 {"target": target, "reason": "not on the action allow-list"}, ts=now)  # fmt: skip
            raise ValueError(f"{action_type!r} is not on the action allow-list")
        open_count = sum(1 for a in self.for_incident(incident_id or "") if a.status in OPEN)
        verdict = self.gate.evaluate(action_type, target, requested_by, now, open_count)
        key = (action_type, verdict.target)
        existing_id = self.by_key.get(key)
        if existing_id and self.actions[existing_id].status in OPEN:
            return self.actions[existing_id]
        action = Action(
            action_id=self._id(incident_id, action_type, verdict.target),
            incident_id=incident_id,
            type=action_type,  # type: ignore[arg-type]
            target=verdict.target,
            impact=ACTION_IMPACT[action_type],
            status="proposed",
            requested_by=requested_by,  # type: ignore[arg-type]
            justification=justification[:2000],
            evidence_ids=list(evidence_ids or [])[:50],
            created_at=now,
        )
        self._audit(requested_by, "propose", action, now, policy=verdict.reason)
        if verdict.outcome == "deny":
            action = action.model_copy(
                update={
                    "status": "denied",
                    "justification": f"{justification} [denied: {verdict.reason}]"[:2000],
                }
            )
            self._save(action, now)
            self._audit("policy-gate", "deny", action, now, reason=verdict.reason)
            return action
        self.by_key[key] = action.action_id
        if verdict.outcome == "pending_approval":
            action = action.model_copy(update={"status": "pending_approval"})
            self._save(action, now)
            self._audit("policy-gate", "hold_for_approval", action, now, reason=verdict.reason)
            return action
        approver = "analyst" if requested_by == "analyst" else "policy:auto"
        return self._execute(
            action.model_copy(update={"status": "approved", "approved_by": approver}), now
        )

    def _execute(self, action: Action, now: datetime) -> Action:
        ok = self.sink.execute(action) if self.sink is not None else True
        status = "executed" if ok else "failed"
        action = action.model_copy(update={"status": status, "executed_at": now if ok else None})
        self._save(action, now)
        self._audit("executor", status, action, now)
        return action

    def approve(self, action_id: str, analyst: str, now: datetime) -> Action:
        action = self.actions[action_id]
        if action.status != "pending_approval":
            raise ValueError(f"{action_id} is {action.status}, not pending approval")
        self._audit(f"analyst:{analyst}", "approve", action, now)
        return self._execute(
            action.model_copy(update={"status": "approved", "approved_by": analyst}), now
        )

    def reject(self, action_id: str, analyst: str, now: datetime, reason: str = "") -> Action:
        action = self.actions[action_id]
        if action.status != "pending_approval":
            raise ValueError(f"{action_id} is {action.status}, not pending approval")
        action = action.model_copy(update={"status": "rejected", "approved_by": analyst})
        self.by_key.pop((action.type, action.target), None)
        self._save(action, now)
        self._audit(f"analyst:{analyst}", "reject", action, now, reason=reason)
        return action

    def approve_all_pending(self, approver: str, now: datetime) -> list[Action]:
        """Unattended evaluation runs: an automatic 'analyst' approves held actions."""
        return [self.approve(a.action_id, approver, now) for a in self.pending()]
