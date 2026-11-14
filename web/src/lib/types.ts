// Shapes of the console API (agentic_soc.api); timestamps are ISO 8601 strings in UTC.

export type Stream = "signin" | "flow" | "process";
export type Detector = "M1" | "M2" | "M3" | string;
export type IncidentStatus =
  | "open"
  | "logged"
  | "queued"
  | "triaging"
  | "awaiting_approval"
  | "contained"
  | "dismissed"
  | "closed";
export type Verdict = "malicious" | "suspicious" | "benign";
export type ActionStatus =
  | "proposed"
  | "pending_approval"
  | "approved"
  | "rejected"
  | "denied"
  | "executed"
  | "failed";
export type ActionType = "block_ip" | "revoke_sessions" | "disable_account" | "isolate_host" | "none";

export interface EntityRefs {
  users: string[];
  hosts: string[];
  ips: string[];
}

export interface Health {
  status: string;
  live: boolean;
  now: string;
  store: string;
  run: Record<string, unknown>;
  mode?: string;
  llm?: string | null;
  models?: Record<string, string>;
  breaker?: "closed" | "open" | "half_open";
  queue?: string[];
  agent_busy?: boolean;
}

export interface StreamCount {
  stream: Stream;
  bucket: string;
  count: number;
}

export interface StreamHealth {
  now: string;
  window: [string, string];
  bucket_s: number;
  counts: StreamCount[];
  totals: Record<Stream, number>;
  dead_letters: { topic: string; error_code: string; n: number }[];
  recent_dead_letters: { id: number; topic: string; error_code: string; error_detail: string; raw: string; received_at?: string }[];
  ingestion?: Record<string, { received: number; valid: number; invalid: number; duplicates: number; legacy: number; delay_p50_s: number; delay_p95_s: number }>;
  windows?: Record<string, { open: number; watermark: string | null; fired?: number; late?: number }>;
  consumer_lag?: Record<string, number>;
}

export interface IncidentSummary {
  incident_id: string;
  status: IncidentStatus;
  risk: number;
  priority: number;
  created_at: string;
  updated_at: string;
  first_seen: string;
  last_seen: string;
  entities: EntityRefs;
  detectors: string[];
  techniques: string[];
  alerts: number;
  route: string | null;
  verdict: Verdict | null;
  decided_by: string | null;
  confidence: number | null;
  summary: string;
  actions: number;
}

export interface FeatureContribution {
  name: string;
  value: number | string;
  contribution: number;
}

export interface Alert {
  alert_id: string;
  detector: Detector;
  model_version: string;
  stream: Stream;
  window_start: string;
  window_end: string;
  score: number;
  threshold: number;
  severity: string;
  entity_keys: string;
  entities: EntityRefs;
  event_ids: string[];
  top_features: FeatureContribution[];
  techniques: string[];
  summary: string;
  incident_id: string;
  created_at: string;
}

export interface ProposedAction {
  type: ActionType;
  target: string | null;
}

export interface DecisionBody {
  incident_id: string;
  verdict: Verdict;
  techniques: string[];
  evidence: { id: string; kind: string; note: string }[];
  action: ProposedAction;
  extra_actions: ProposedAction[];
  confidence: number;
  rationale: string;
  note?: string;
  original_verdict?: Verdict | null;
  injection_seen?: boolean;
}

export interface DecisionRecord {
  id: number;
  incident_id: string;
  decided_by: "agent" | "playbook" | string;
  model: string | null;
  verdict: Verdict;
  confidence: number;
  decision: DecisionBody;
  latency_s: number;
  created_at: string;
}

export interface Action {
  action_id: string;
  incident_id: string | null;
  type: ActionType;
  target: string;
  impact: "low" | "high";
  status: ActionStatus;
  requested_by: string;
  approved_by: string | null;
  justification: string;
  evidence_ids: string[];
  created_at: string;
  updated_at?: string;
  executed_at: string | null;
}

export interface Feedback {
  id: number;
  incident_id: string;
  alert_id: string;
  analyst: string;
  verdict: "true_positive" | "false_positive" | "benign_positive";
  comment: string;
  created_at: string;
}

export interface IncidentRecord extends Omit<IncidentSummary, "alerts" | "actions"> {
  alert_ids: string[];
  streams: string[];
  entity_keys: string;
}

export interface IncidentDetail {
  incident: IncidentRecord;
  alerts: Alert[];
  decisions: DecisionRecord[];
  actions: Action[];
  feedback: Feedback[];
  evidence_counts: Record<string, number>;
  cited: string[];
}

export interface EvidenceItem {
  id: number;
  incident_id: string;
  kind: "alert" | "event" | "baseline" | "tool_call";
  ref_id: string;
  stream: Stream | null;
  entity: string | null;
  detector: string | null;
  time: string | null;
  data: Record<string, unknown>;
  cited: boolean;
}

export interface ToolCall {
  id: number;
  incident_id: string;
  step: number;
  tool: string;
  arguments: Record<string, unknown>;
  result: unknown;
  ok: boolean;
  error: string | null;
  latency_ms: number;
  created_at: string;
}

export interface Trace {
  decisions: DecisionRecord[];
  tool_calls: ToolCall[];
}

export interface TimelineEvent {
  stream: Stream;
  event_id: string;
  event_time: string;
  [field: string]: unknown;
}

export interface Timeline {
  entity: string;
  window: [string, string];
  addresses: string[];
  events: TimelineEvent[];
  alerts: Alert[];
}

export interface EntityDetail {
  entity: string;
  kind: "user" | "host" | "ip";
  account_kind?: string;
  user?: { display_name: string; role: string; department: string; office: string; workstation: string; admin_account: string | null };
  host?: { kind: string; role: string; zone: string; os: string; criticality: number; office: string | null; owner: string | null; static_ip: string | null };
  zone?: string;
  geo?: { country: string; city: string; asn: number; org: string; category: string };
  baseline?: {
    successful_signins: number;
    failed_signins: number;
    usual_countries: Record<string, number>;
    local_hours: number[];
    devices: number;
    logon_types: string[];
    apps: string[];
  };
  incidents: IncidentSummary[];
  actions: Action[];
}

export interface DetectorFeedback {
  detector: string;
  kind: string;
  alerts: number;
  reviewed: number;
  true_positive: number;
  false_positive: number;
  benign_positive: number;
  false_positive_share: number | null;
  precision: number | null;
}

export interface Metrics {
  now: string;
  events: Record<Stream, number>;
  alerts: number;
  alerts_by_detector: { detector: string; model_version: string; alerts: number }[];
  incidents: number;
  incidents_by_status: Partial<Record<IncidentStatus, number>>;
  incidents_by_priority: Record<string, number>;
  active_incidents: number;
  alert_to_incident_ratio: number | null;
  decisions_by: Record<string, number>;
  verdicts: Partial<Record<Verdict, number>>;
  actions_by_status: Partial<Record<ActionStatus, number>>;
  actions_by_type: Partial<Record<ActionType, number>>;
  pending_approvals: number;
  agent: {
    decisions: number;
    latency_mean_s: number | null;
    latency_p95_s: number | null;
    tool_calls: number;
    invalid_tool_call_rate: number | null;
    escalated_dismissals: number;
    injection_seen: number;
  };
  detector_feedback: DetectorFeedback[];
  pipeline?: { breaker: string; breaker_trips: number; queue: number; routes: Record<string, number> };
  cursor?: number;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  object_type: string;
  object_id: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface PipelineEvent {
  time: string;
  kind: "alert" | "incident" | "route" | "decision" | "action" | "merge" | "agent_fallback" | "action_rejected" | "evidence_missing" | string;
  incident_id?: string;
  [field: string]: unknown;
}
