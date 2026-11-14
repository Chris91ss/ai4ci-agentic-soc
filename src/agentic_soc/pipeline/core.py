"""The SOC pipeline: ingestion -> storage -> features -> M1-M3 -> correlation -> routing ->
agent or playbook -> policy gate -> containment (published to the actions topic)."""

from __future__ import annotations

import json
import threading
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from agentic_soc.actions import ActionManager, BrokerActionSink, PolicyConfig, PolicyGate
from agentic_soc.agent import OllamaLLM, ScriptedLLM, TriageAgent, dismissal_guardrail
from agentic_soc.agent.react import compact_json
from agentic_soc.broker.base import Broker
from agentic_soc.correlation import CorrelationEngine, IncidentState, IncidentUpdate
from agentic_soc.detectors.base import Score
from agentic_soc.detectors.m1 import M1Detector
from agentic_soc.detectors.service import DetectorClient
from agentic_soc.drift import DriftConfig as DriftSettings
from agentic_soc.drift import DriftMonitor, recent_signins, retrain_m1
from agentic_soc.evidence import EvidenceBuilder
from agentic_soc.features import FeatureBatch, FeaturePipeline, FeatureRow, Profiles, WindowConfig
from agentic_soc.ingestion import IngestionService, IngestionStage, IngestResult, Inventory
from agentic_soc.mcp_server import SocContext, SocTools, build_server
from agentic_soc.pipeline.staging import StagedActions
from agentic_soc.pipeline.worker import ThreadedAgentWorker, TriageJob, VirtualTimeAgentWorker
from agentic_soc.routing import RiskRouter, RouteDecision, RouterConfig, playbook_decision
from agentic_soc.rules import RuleEngine
from agentic_soc.schemas import Action, Decision
from agentic_soc.storage import StorageSink, Store

Mode = Literal["agent", "detectors", "rules"]
EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


@dataclass
class PipelineConfig:
    mode: Mode = "agent"  # baselines: "detectors" (M1-M3 + playbooks), "rules" (rules + playbooks)
    llm: str = "scripted"  # "scripted" or "ollama[:model]"
    seconds_per_llm_call: float = 15.0  # simulated cost of one scripted-analyst LLM call
    wall_time_scale: float = 1.0  # real LLM: simulated seconds per wall-clock second
    agent_max_steps: int = 12
    # Unattended runs approve high-impact actions automatically: at once through the policy gate
    # (approval_delay_s = 0), or after a simulated analyst's response time.
    auto_approve: bool = True
    approval_delay_s: float = 0.0
    worker: Literal["virtual", "threaded"] = "virtual"  # threaded: live mode on a broker
    # Drift (scenario S1): PSI/KS of M1 features against the training reference, checked
    # every hour; on an alarm M1 can be retrained offline and swapped in after a delay.
    drift_monitor: bool = True
    drift_check_every_h: float = 1.0
    retrain_on_drift: bool = False
    retrain_delay_h: float = 3.0
    retrain_window_h: float = 24.0
    drift: DriftSettings = field(default_factory=DriftSettings)
    router: RouterConfig = field(default_factory=RouterConfig)
    windows: WindowConfig = field(default_factory=WindowConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)


def make_llm(spec: str) -> Any:
    if spec == "scripted":
        return ScriptedLLM()
    if spec.startswith("ollama"):
        _, _, model = spec.partition(":")
        return OllamaLLM(model) if model else OllamaLLM()
    raise ValueError(f"unknown LLM {spec!r} (use scripted or ollama[:model])")


def _clip(value: Any, limit: int = 12_000) -> Any:
    """A tool result for the trace store: kept as valid JSON, long lists shortened."""
    text = compact_json(value, limit)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"_clipped": text}


class SocPipeline:
    def __init__(
        self,
        inventory: Inventory,
        detectors: DetectorClient,
        profiles: Profiles,
        store: Store,
        broker: Broker,
        config: PipelineConfig | None = None,
    ) -> None:
        self.cfg = cfg = config or PipelineConfig()
        cfg.router.agent = cfg.mode == "agent"
        if cfg.auto_approve and cfg.approval_delay_s <= 0:
            cfg.policy = replace(cfg.policy, auto_approve_high_impact=True)
        self.inv = inventory
        self.store = store
        self.detectors = detectors
        self.ingestion = IngestionService(broker, IngestionStage(inventory), StorageSink(store))
        rules = cfg.mode == "rules"
        self.features = FeaturePipeline(
            inventory, profiles, cfg.windows, detectors=set() if rules else None
        )
        self.rules = RuleEngine(inventory, self.features.resolver, cfg.windows) if rules else None
        self.correlation = CorrelationEngine(inventory)
        self.router = RiskRouter(cfg.router)
        gate = PolicyGate(inventory, cfg.policy)
        self.actions = ActionManager(gate, BrokerActionSink(broker.producer()), store)
        self.actions.listeners.append(self._on_action)
        self.staged_actions = StagedActions(self.actions)
        self.clock: datetime | None = None
        self.lock = threading.RLock()
        threaded = cfg.worker == "threaded"
        self.ctx = SocContext(
            store=store,
            inventory=inventory,
            profiles=profiles,
            detectors=detectors,
            actions=self.staged_actions,  # type: ignore[arg-type]
            clock=self.now,
            correlation=self.correlation,
            resolver=self.features.resolver,
            feature_config=cfg.windows,
            lock=self.lock if threaded else None,
        )
        self.mcp = build_server(SocTools(self.ctx))
        self.evidence = EvidenceBuilder(store, inventory, profiles, self.features.resolver)
        m1 = self.local_m1()
        self.drift: DriftMonitor | None = None
        if cfg.drift_monitor and m1 is not None and m1.references:
            self.drift = DriftMonitor(dict(m1.references), cfg.drift)
        self._next_drift_check: datetime | None = None
        self._retrain_at: datetime | None = None
        self.worker: VirtualTimeAgentWorker | ThreadedAgentWorker | None = None
        if cfg.mode == "agent":
            llm = make_llm(cfg.llm)
            agent = TriageAgent(llm, self.mcp, max_steps=cfg.agent_max_steps)
            if threaded:
                self.worker = ThreadedAgentWorker(self, agent)
            else:
                per_call = cfg.seconds_per_llm_call if isinstance(llm, ScriptedLLM) else None
                self.worker = VirtualTimeAgentWorker(self, agent, per_call, cfg.wall_time_scale)
        self._approvals: dict[str, datetime] = {}
        self.stats: Counter[str] = Counter()
        self.decisions: list[dict[str, Any]] = []
        self.log: list[dict[str, Any]] = []  # pipeline events for reports and the console

    # ------------------------------------------------------------------ time
    def now(self) -> datetime:
        return self.clock or EPOCH

    def _log(self, kind: str, **data: Any) -> None:
        self.log.append({"time": self.now(), "kind": kind, **data})

    # ------------------------------------------------------------------ main loop
    def step(
        self, clock: datetime | None = None, max_messages: int = 50_000, timeout: float = 0.0
    ) -> int:
        """Ingest what is available, fire due windows, score, correlate, route and decide.

        ``clock`` is the simulation time (closed-loop runs); without it the pipeline follows
        the newest arrival time it has seen (live mode). Returns the number of events ingested."""
        result = self.ingestion.poll_once(max_messages=max_messages, timeout=timeout)
        with self.lock:
            return self._process(result, clock)

    def _process(self, result: IngestResult, clock: datetime | None) -> int:
        self.stats["events"] += len(result.events)
        self.stats["dead_letters"] += len(result.dead_letters)
        if result.events:
            if self.rules is not None:
                self.rules.add(result.events)
            self.features.add(result.events)
        if clock is not None:
            self.clock = clock
        elif self.features.clock is not None:
            self.clock = max(self.clock or EPOCH, self.features.clock)
        if self.clock is None:
            return 0
        self.handle(self.features.advance(self.clock))
        if self.rules is not None:
            self.correlate(self.rules.advance(self.clock))
        if self.worker is not None:
            self.worker.tick(self.clock)
        self._tick_approvals()
        self._tick_drift()
        return len(result.events)

    def flush(self) -> None:
        """End of a run: fire every remaining window."""
        with self.lock:
            self.handle(self.features.flush())
            if self.rules is not None:
                self.correlate(self.rules.flush())

    def close(self) -> None:
        if isinstance(self.worker, ThreadedAgentWorker):
            self.worker.close()

    def score(self, batch: FeatureBatch) -> list[tuple[FeatureRow, Score]]:
        scored: list[tuple[FeatureRow, Score]] = []
        for name, rows in (
            ("M1", batch.m1_user + batch.m1_ip),
            ("M2", batch.m2),
            ("M3", batch.m3),
        ):
            if rows:
                scored += list(zip(rows, self.detectors.score(name, rows), strict=True))
                self.stats[f"windows_{name}"] += len(rows)
        return scored

    def handle(self, batch: FeatureBatch) -> None:
        if len(batch) == 0:
            return
        if self.drift is not None:
            self.drift.observe(batch.m1_user + batch.m1_ip)
        self.correlate(self.score(batch))

    def correlate(self, scored: list[tuple[FeatureRow, Score]]) -> None:
        if not scored:
            return
        self.stats["alerts"] += sum(1 for _, s in scored if s.alert)
        for update in self.correlation.ingest(scored, self.now()):
            self._persist_update(update)
            self._dispatch(self.router.route(update, self.now()), update.incident)

    def _dispatch(self, decision: RouteDecision, state: IncidentState) -> None:
        if decision.route != "none":
            self._log("route", incident_id=decision.incident_id, route=decision.route,
                      reason=decision.reason)  # fmt: skip
        if decision.route == "playbook":
            self.decide_by_playbook(state, decision.reason)
        elif decision.route in {"log", "agent"}:
            self.persist_incident(state)

    # ------------------------------------------------------------------ persistence
    def _persist_update(self, update: IncidentUpdate) -> None:
        state = update.incident
        for alert in update.new_alerts:
            self.store.upsert_alert(
                alert.model_dump() | {
                    "incident_id": state.incident_id,
                    "entity_keys": " " + " ".join(sorted(alert.entities.keys())) + " ",
                    "created_at": self.now(),
                }
            )  # fmt: skip
            self._log("alert", alert_id=alert.alert_id, incident_id=state.incident_id,
                      detector=alert.model_version or alert.detector)  # fmt: skip
        for merged in update.merged:
            self.router.drop(merged)
            self.store.reassign_alerts(merged, state.incident_id)
            gone = self.store.get_incident(merged)
            if gone is not None:
                note = f"merged into {state.incident_id}"
                self.store.upsert_incident(
                    gone | {"status": "closed", "route": "merged", "summary": note}
                )
            self._log("merge", incident_id=state.incident_id, merged=merged)
        record = state.to_record()
        if update.created:
            self._log("incident", incident_id=state.incident_id, risk=record["risk"],
                      entities=record["entity_keys"].split())  # fmt: skip
        self.store.upsert_incident(record)

    def persist_incident(self, state: IncidentState) -> None:
        self.store.upsert_incident(state.to_record())

    # ------------------------------------------------------------------ decisions
    def decide_by_playbook(self, state: IncidentState, reason: str = "") -> None:
        decision = playbook_decision(state, self.inv, done=self.actions.taken())
        self.apply_decision(state, decision, "playbook", latency_s=0.0, model=None, note=reason)

    def finish_triage(self, job: TriageJob, now: datetime) -> None:
        """Apply an agent decision once its (simulated) latency has elapsed."""
        result = job.result
        self.ctx.tool_calls.clear()
        self.store.add_tool_calls([
            {"incident_id": job.incident_id, "step": s.index, "tool": s.tool or s.kind,
             "arguments": s.arguments or {}, "result": _clip(s.result), "ok": s.ok, "error": s.error,
             "latency_ms": s.latency_ms, "created_at": job.started}
            for s in result.steps
        ])  # fmt: skip
        self.stats["agent_runs"] += 1
        self.stats["agent_llm_calls"] += result.llm_calls
        self.stats["agent_tool_calls"] += result.tool_calls
        self.stats["agent_invalid_tool_calls"] += result.invalid_tool_calls
        self.stats["agent_repairs"] += result.repairs
        self.stats["agent_prompt_tokens"] += result.prompt_tokens
        self.stats["agent_output_tokens"] += result.output_tokens
        state = self.correlation.get(job.incident_id)
        if state is None:  # merged away while the agent worked; the survivor gets re-routed
            return
        if job.timed_out or not result.ok:
            self.router.agent_result(False, now)
            self.stats["agent_timeouts" if job.timed_out else "agent_failures"] += 1
            reason = "agent timed out" if job.timed_out else f"agent failed: {result.error}"
            self._log("agent_fallback", incident_id=job.incident_id, reason=reason)
            state.route = "playbook"
            self.decide_by_playbook(state, reason)
            return
        self.router.agent_result(True, now)
        assert result.decision is not None
        risk = state.risk.risk if state.risk else 0.0
        effective, note = dismissal_guardrail(
            result.decision, risk, state.detectors, set(state.tactics())
        )
        if note:
            self.stats["dismissals_escalated"] += 1
        if effective.verdict != "benign":
            for p in job.staged:
                self._propose(p.incident_id or state.incident_id, p.action_type, p.target, "agent",
                              p.justification, p.evidence_ids)  # fmt: skip
        self.apply_decision(
            state,
            effective,
            "agent",
            latency_s=(job.done_at - job.started).total_seconds(),
            model=result.model,
            note=note or "",
            original=result.decision,
            injection_seen=result.injection_seen,
            steps=result.steps,
            started=job.started,
        )
        # The decision reflects the incident as the agent first saw it; anything that arrived
        # meanwhile (a new tactic, a jump in risk) sends it back to the queue.
        self.router.mark_triaged(state, job.risk, job.tactics)
        self._dispatch(self.router.recheck(state, now), state)

    def apply_decision(
        self,
        state: IncidentState,
        decision: Decision,
        decided_by: str,
        latency_s: float,
        model: str | None,
        note: str = "",
        original: Decision | None = None,
        injection_seen: bool = False,
        steps: list[Any] | None = None,
        started: datetime | None = None,
    ) -> None:
        now = self.now()
        evidence_ids = [e.id for e in decision.evidence]
        if decision.verdict != "benign":
            for action in decision.all_actions():
                self._propose(state.incident_id, action.type, action.target or "", decided_by,
                              decision.rationale[:600], evidence_ids)  # fmt: skip
        state.verdict, state.decided_by = decision.verdict, decided_by
        state.confidence = decision.confidence
        if decision.verdict == "suspicious":
            state.route = "analyst"
        self.router.mark_triaged(state)
        self._refresh_status(state)
        extra = {
            "note": note,
            "original_verdict": original.verdict if original else None,
            "injection_seen": injection_seen,
        }
        record = {
            "incident_id": state.incident_id,
            "decided_by": decided_by,
            "model": model,
            "verdict": decision.verdict,
            "confidence": decision.confidence,
            "decision": decision.model_dump(mode="json") | extra,
            "latency_s": round(latency_s, 2),
            "created_at": now,
        }
        record["id"] = self.store.add_decision(record)
        self.decisions.append(record)
        bundle = self.evidence.build(state, decision, record["id"], steps, started or now)
        self.store.upsert_evidence(bundle.items)
        self.stats["evidence_items"] += len(bundle.items)
        if bundle.missing:
            self.stats["evidence_missing"] += len(bundle.missing)
            self._log("evidence_missing", incident_id=state.incident_id, ids=bundle.missing)
        actor = f"agent:{model}" if decided_by == "agent" else decided_by
        actions = [a.model_dump() for a in decision.all_actions()]
        self.store.audit(actor, "decide", "incident", state.incident_id,
                         {"verdict": decision.verdict, "actions": actions, "note": note}, ts=now)  # fmt: skip
        self._log("decision", incident_id=state.incident_id, decided_by=decided_by,
                  verdict=decision.verdict, actions=[[a["type"], a["target"]] for a in actions],
                  latency_s=round(latency_s, 1), note=note)  # fmt: skip
        self.persist_incident(state)

    def _propose(
        self,
        incident_id: str,
        action_type: str,
        target: str,
        requested_by: str,
        justification: str,
        evidence_ids: list[str],
    ) -> None:
        try:
            self.actions.propose(incident_id, action_type, target, requested_by, self.now(),
                                 justification=justification, evidence_ids=evidence_ids)  # fmt: skip
        except ValueError as exc:
            self._log("action_rejected", incident_id=incident_id, error=str(exc))

    def _refresh_status(self, state: IncidentState) -> None:
        if state.verdict == "benign":
            state.status = "dismissed"
            return
        actions = self.actions.for_incident(state.incident_id)
        if any(a.status == "pending_approval" for a in actions):
            state.status = "awaiting_approval"
        elif any(a.status == "executed" for a in actions):
            state.status = "contained"
        elif state.verdict is not None:
            state.status = "open"

    def _on_action(self, action: Action) -> None:
        self._log("action", action_id=action.action_id, incident_id=action.incident_id,
                  type=action.type, target=action.target, status=action.status,
                  requested_by=action.requested_by)  # fmt: skip
        self.stats[f"actions_{action.status}"] += 1
        if action.status == "pending_approval" and self.cfg.auto_approve:
            self._approvals[action.action_id] = self.now() + timedelta(
                seconds=self.cfg.approval_delay_s
            )
        if action.incident_id and action.status in {"executed", "rejected", "failed"}:
            state = self.correlation.get(action.incident_id)
            if state is not None and state.verdict is not None:
                self._refresh_status(state)
                self.persist_incident(state)

    def _tick_approvals(self) -> None:
        now = self.now()
        for action_id, due in list(self._approvals.items()):
            if due <= now:
                del self._approvals[action_id]
                if self.actions.actions[action_id].status == "pending_approval":
                    self.actions.approve(action_id, "auto-analyst", now)

    # ------------------------------------------------------------------ drift and retraining
    def local_m1(self) -> M1Detector | None:
        detector_set = getattr(self.detectors, "detectors", None)
        m1 = getattr(detector_set, "detectors", {}).get("M1") if detector_set is not None else None
        return m1 if isinstance(m1, M1Detector) else None

    def _tick_drift(self) -> None:
        if self.drift is None:
            return
        now = self.now()
        every = timedelta(hours=self.cfg.drift_check_every_h)
        if self._next_drift_check is None:
            self._next_drift_check = now + every
        if now >= self._next_drift_check:
            self._next_drift_check = now + every
            was = self.drift.alarm
            for check in self.drift.check(now):
                summary = check.to_dict(top=4)
                self._log("drift_check", feature_kind=check.kind, rows=check.rows, max_psi=summary["max_psi"],
                          drifted=check.drifted[:6], top_psi=summary["top_psi"])  # fmt: skip
            if self.drift.alarm and not was:
                self.stats["drift_alarms"] += 1
                latest = {c.kind: c for c in self.drift.history[-len(self.drift.references) :]}
                self._log("drift_alarm", features={k: c.drifted[:6] for k, c in latest.items()},
                          max_psi={k: round(c.max_psi, 3) for k, c in latest.items()})  # fmt: skip
                if self.cfg.retrain_on_drift and self._retrain_at is None:
                    self._retrain_at = now + timedelta(hours=self.cfg.retrain_delay_h)
                    self._log("retrain_scheduled", at=self._retrain_at)
        if self._retrain_at is not None and now >= self._retrain_at:
            self._retrain_at = None
            self.retrain(now)

    def malicious_event_ids(self) -> set[str]:
        """Events behind incidents judged malicious or alerts analysts confirmed."""
        out: set[str] = set()
        for state in self.correlation.incidents.values():
            if state.verdict == "malicious":
                for alert in state.alerts.values():
                    out.update(alert.event_ids)
        confirmed = [
            f["alert_id"]
            for f in self.store.list_feedback(limit=1_000_000)
            if f["verdict"] == "true_positive"
        ]
        for alert in self.store.alerts_by_ids(confirmed):
            out.update(alert["event_ids"])
        return out

    def retrain(self, now: datetime) -> dict[str, Any] | None:
        """Retrain M1 offline on the recent sign-ins and swap it in with its new baselines."""
        current = self.local_m1()
        if current is None:
            return None
        try:
            new, report = retrain_m1(current, recent_signins(self.store, now, self.cfg.retrain_window_h),
                                     self.inv, self.malicious_event_ids(), self.cfg.windows)  # fmt: skip
        except ValueError as exc:
            self._log("retrain_failed", error=str(exc))
            return None
        self.detectors.detectors.detectors["M1"] = new  # type: ignore[attr-defined]
        self.features.profiles = self.features.extractor.profiles = new.profiles
        self.ctx.profiles = self.evidence.profiles = new.profiles
        if self.drift is not None:
            self.drift.reset(dict(new.references))
            self._next_drift_check = now + timedelta(hours=self.cfg.drift_check_every_h)
        self.stats["retrains"] += 1
        self._log("retrain", **report)
        return report

    # ------------------------------------------------------------------ reporting
    def summary(self) -> dict[str, Any]:
        corr = self.correlation.stats()
        return {
            "mode": self.cfg.mode,
            "llm": self.cfg.llm if self.cfg.mode == "agent" else None,
            "events": self.stats["events"],
            "dead_letters": self.stats["dead_letters"],
            "alerts": corr["alerts"],
            "incidents": corr["incidents"],
            "alert_to_incident_ratio": corr["alert_to_incident_ratio"],
            "routes": dict(self.router.stats),
            "breaker_trips": self.router.breaker.trips,
            "drift": {
                "alarms": [e["time"] for e in self.log if e["kind"] == "drift_alarm"],
                "retrains": [e["time"] for e in self.log if e["kind"] == "retrain"],
                "models": self.detectors.versions(),
            },
            "decisions": dict(Counter(d["decided_by"] for d in self.decisions)),
            "verdicts": dict(Counter(d["verdict"] for d in self.decisions)),
            "actions": [
                {
                    "action_id": a.action_id,
                    "incident_id": a.incident_id,
                    "type": a.type,
                    "target": a.target,
                    "status": a.status,
                    "requested_by": a.requested_by,
                    "created_at": a.created_at.isoformat(),
                    "executed_at": a.executed_at.isoformat() if a.executed_at else None,
                }
                for a in self.actions.actions.values()
            ],
            "stats": dict(self.stats),
        }
