import type {
  Action,
  AuditEntry,
  EntityDetail,
  EvidenceItem,
  Health,
  IncidentDetail,
  IncidentSummary,
  Metrics,
  PipelineEvent,
  StreamHealth,
  Timeline,
  Trace,
} from "./types";
import { withBase } from "./utils";

/** "api": the FastAPI backend (live demo or recorded run). "static": JSON exported from a
 * recorded run (`soc export`), served with the console, e.g. on GitHub Pages. */
export const DATA_MODE: "api" | "static" = process.env.NEXT_PUBLIC_DATA === "static" ? "static" : "api";
export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000/api").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

export class ReadOnlyError extends ApiError {
  constructor() {
    super("This is a recorded run: actions and feedback are read-only.", 409);
  }
}

type Params = Record<string, string | number | boolean | string[] | null | undefined>;

function query(params: Params = {}) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new ApiError(detail, response.status);
  }
  return response.json() as Promise<T>;
}

const staticCache = new Map<string, Promise<unknown>>();

function staticJSON<T>(file: string): Promise<T> {
  if (!staticCache.has(file)) {
    staticCache.set(
      file,
      fetch(withBase(`/data/${file}`)).then((r) => {
        if (!r.ok) throw new ApiError(`not part of the recorded run (${file})`, r.status);
        return r.json();
      }),
    );
  }
  return staticCache.get(file) as Promise<T>;
}

export function entityFile(entity: string) {
  return entity.replace(/[^A-Za-z0-9._-]/g, "_");
}

interface StaticIncident {
  detail: IncidentDetail;
  evidence: EvidenceItem[];
  trace: Trace;
}

interface StaticEntity {
  detail: EntityDetail;
  timeline: Timeline;
}

export interface IncidentFilters {
  status?: string[];
  min_risk?: number;
  entity?: string;
  limit?: number;
}

export interface EvidenceFilters {
  kind?: string;
  entity?: string;
  stream?: string;
  detector?: string;
  start?: string;
  end?: string;
  cited?: boolean;
}

function between(time: string | null, start?: string, end?: string) {
  if (!time) return !start && !end;
  return (!start || time >= start) && (!end || time < end);
}

export const api = {
  health: () => (DATA_MODE === "static" ? staticJSON<Health>("health.json") : request<Health>("/health")),

  streamHealth: (hours = 6, bucket_s = 300) =>
    DATA_MODE === "static"
      ? staticJSON<StreamHealth>("stream-health.json")
      : request<StreamHealth>(`/stream-health${query({ hours, bucket_s })}`),

  incidents: async (filters: IncidentFilters = {}) => {
    if (DATA_MODE === "api") return request<IncidentSummary[]>(`/incidents${query({ ...filters })}`);
    const all = await staticJSON<IncidentSummary[]>("incidents.json");
    return all
      .filter((i) => !filters.status?.length || filters.status.includes(i.status))
      .filter((i) => i.risk >= (filters.min_risk ?? 0))
      .filter((i) => {
        if (!filters.entity) return true;
        const [kind, value] = filters.entity.split(":", 2);
        const list = kind === "user" ? i.entities.users : kind === "host" ? i.entities.hosts : i.entities.ips;
        return list.includes(value);
      })
      .slice(0, filters.limit ?? 200);
  },

  incident: async (id: string) =>
    DATA_MODE === "static"
      ? (await staticJSON<StaticIncident>(`incidents/${id}.json`)).detail
      : request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`),

  evidence: async (id: string, filters: EvidenceFilters = {}) => {
    if (DATA_MODE === "api") return request<EvidenceItem[]>(`/incidents/${encodeURIComponent(id)}/evidence${query({ ...filters, limit: 5000 })}`);
    const { evidence } = await staticJSON<StaticIncident>(`incidents/${id}.json`);
    return evidence.filter(
      (e) =>
        (!filters.kind || e.kind === filters.kind) &&
        (!filters.entity || e.entity === filters.entity) &&
        (!filters.stream || e.stream === filters.stream) &&
        (!filters.detector || e.detector === filters.detector) &&
        (filters.cited === undefined || e.cited === filters.cited) &&
        between(e.time, filters.start, filters.end),
    );
  },

  trace: async (id: string) =>
    DATA_MODE === "static"
      ? (await staticJSON<StaticIncident>(`incidents/${id}.json`)).trace
      : request<Trace>(`/incidents/${encodeURIComponent(id)}/trace`),

  entity: async (entity: string) =>
    DATA_MODE === "static"
      ? (await staticJSON<StaticEntity>(`entities/${entityFile(entity)}.json`)).detail
      : request<EntityDetail>(`/entities/${encodeURIComponent(entity)}`),

  timeline: async (entity: string, start?: string, end?: string, streams?: string[]) => {
    if (DATA_MODE === "api")
      return request<Timeline>(`/entities/${encodeURIComponent(entity)}/timeline${query({ start, end, streams, limit: 400 })}`);
    const { timeline } = await staticJSON<StaticEntity>(`entities/${entityFile(entity)}.json`);
    return {
      ...timeline,
      events: timeline.events.filter((e) => between(e.event_time, start, end) && (!streams?.length || streams.includes(e.stream))),
    };
  },

  actions: async (status?: string[]) => {
    if (DATA_MODE === "api") return request<Action[]>(`/actions${query({ status })}`);
    const all = await staticJSON<Action[]>("actions.json");
    return all.filter((a) => !status?.length || status.includes(a.status));
  },

  metrics: () => (DATA_MODE === "static" ? staticJSON<Metrics>("metrics.json") : request<Metrics>("/metrics")),

  audit: async (object_id?: string, limit = 300) => {
    if (DATA_MODE === "api") return request<AuditEntry[]>(`/audit${query({ object_id, limit })}`);
    const all = await staticJSON<AuditEntry[]>("audit.json");
    return all.filter((a) => !object_id || a.object_id === object_id).slice(0, limit);
  },

  verifyAudit: () =>
    DATA_MODE === "static"
      ? staticJSON<{ ok: boolean; first_broken: number | null }>("audit-verify.json")
      : request<{ ok: boolean; first_broken: number | null }>("/audit/verify"),

  pipelineLog: () =>
    DATA_MODE === "static" ? staticJSON<PipelineEvent[]>("log.json") : request<PipelineEvent[]>("/log"),

  approve: (actionId: string, analyst: string) => {
    if (DATA_MODE === "static") return Promise.reject(new ReadOnlyError());
    return request<Action>(`/actions/${encodeURIComponent(actionId)}/approve`, {
      method: "POST",
      body: JSON.stringify({ analyst }),
    });
  },

  reject: (actionId: string, analyst: string, reason: string) => {
    if (DATA_MODE === "static") return Promise.reject(new ReadOnlyError());
    return request<Action>(`/actions/${encodeURIComponent(actionId)}/reject`, {
      method: "POST",
      body: JSON.stringify({ analyst, reason }),
    });
  },

  feedback: (incidentId: string, body: { analyst: string; verdict: string; comment?: string }) => {
    if (DATA_MODE === "static") return Promise.reject(new ReadOnlyError());
    return request<{ incident_id: string; verdict: string; alerts: number }>(
      `/incidents/${encodeURIComponent(incidentId)}/feedback`,
      { method: "POST", body: JSON.stringify(body) },
    );
  },

  eventsUrl: (cursor = 0) => `${API_URL}/events${query({ cursor, interval_s: 1 })}`,
};
