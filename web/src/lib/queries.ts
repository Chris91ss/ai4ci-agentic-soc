"use client";

import { useQuery } from "@tanstack/react-query";

import { api, DATA_MODE, type EvidenceFilters, type IncidentFilters } from "./api";

// Live data refreshes on a short interval and on pipeline events (see LiveProvider);
// a recorded run never changes.
const live = DATA_MODE === "api";
const every = (ms: number) => (live ? ms : false);

export const keys = {
  health: ["health"] as const,
  streamHealth: (hours: number) => ["stream-health", hours] as const,
  incidents: (filters: IncidentFilters) => ["incidents", filters] as const,
  incident: (id: string) => ["incident", id] as const,
  evidence: (id: string, filters: EvidenceFilters) => ["evidence", id, filters] as const,
  trace: (id: string) => ["trace", id] as const,
  entity: (entity: string) => ["entity", entity] as const,
  timeline: (entity: string, start?: string, end?: string) => ["timeline", entity, start, end] as const,
  actions: (status?: string[]) => ["actions", status ?? []] as const,
  metrics: ["metrics"] as const,
  audit: (objectId?: string) => ["audit", objectId ?? ""] as const,
  verifyAudit: ["audit-verify"] as const,
};

export const useHealth = () => useQuery({ queryKey: keys.health, queryFn: api.health, refetchInterval: every(5_000) });

export const useStreamHealth = (hours = 6) =>
  useQuery({ queryKey: keys.streamHealth(hours), queryFn: () => api.streamHealth(hours), refetchInterval: every(10_000) });

export const useIncidents = (filters: IncidentFilters = {}) =>
  useQuery({ queryKey: keys.incidents(filters), queryFn: () => api.incidents(filters), refetchInterval: every(8_000) });

export const useIncident = (id: string | null) =>
  useQuery({ queryKey: keys.incident(id ?? ""), queryFn: () => api.incident(id!), enabled: !!id, refetchInterval: every(8_000) });

export const useEvidence = (id: string | null, filters: EvidenceFilters = {}) =>
  useQuery({ queryKey: keys.evidence(id ?? "", filters), queryFn: () => api.evidence(id!, filters), enabled: !!id });

export const useTrace = (id: string | null) =>
  useQuery({ queryKey: keys.trace(id ?? ""), queryFn: () => api.trace(id!), enabled: !!id, refetchInterval: every(10_000) });

export const useEntity = (entity: string | null) =>
  useQuery({ queryKey: keys.entity(entity ?? ""), queryFn: () => api.entity(entity!), enabled: !!entity });

export const useTimeline = (entity: string | null, start?: string, end?: string) =>
  useQuery({
    queryKey: keys.timeline(entity ?? "", start, end),
    queryFn: () => api.timeline(entity!, start, end),
    enabled: !!entity,
  });

export const useActions = (status?: string[]) =>
  useQuery({ queryKey: keys.actions(status), queryFn: () => api.actions(status), refetchInterval: every(6_000) });

export const useMetrics = () => useQuery({ queryKey: keys.metrics, queryFn: api.metrics, refetchInterval: every(10_000) });

export const useAudit = (objectId?: string) =>
  useQuery({ queryKey: keys.audit(objectId), queryFn: () => api.audit(objectId), refetchInterval: every(15_000) });

export const useAuditVerification = () => useQuery({ queryKey: keys.verifyAudit, queryFn: api.verifyAudit });
