"use client";

import {
  IconAlertOctagon,
  IconBan,
  IconCircleCheck,
  IconCircleDot,
  IconCircleX,
  IconClock,
  IconCpu,
  IconEye,
  IconFingerprint,
  IconHourglass,
  IconLogout,
  IconNetwork,
  IconPlugConnectedX,
  IconRobot,
  IconShieldCheck,
  IconSitemap,
  IconUser,
  IconUserOff,
} from "@tabler/icons-react";
import type { ReactNode } from "react";

import { Badge, type Tone } from "@/components/ui/badge";
import type { ActionStatus, ActionType, IncidentStatus, Stream, Verdict } from "@/lib/types";
import { titleCase } from "@/lib/format";

export const STREAM_META: Record<Stream, { label: string; tone: Tone; icon: ReactNode; color: string }> = {
  signin: { label: "Sign-ins", tone: "signin", icon: <IconFingerprint size={13} />, color: "#a78bfa" },
  flow: { label: "Flows", tone: "flow", icon: <IconNetwork size={13} />, color: "#22d3ee" },
  process: { label: "Processes", tone: "process", icon: <IconCpu size={13} />, color: "#fbbf24" },
};

export const DETECTOR_META: Record<string, { label: string; tone: Tone; stream: Stream; long: string }> = {
  M1: { label: "M1", tone: "signin", stream: "signin", long: "M1 · sign-in anomalies (Isolation Forest)" },
  M2: { label: "M2", tone: "flow", stream: "flow", long: "M2 · network flows (LightGBM)" },
  M3: { label: "M3", tone: "process", stream: "process", long: "M3 · rare process chains" },
};

export function DetectorBadge({ detector, kind }: { detector: string; kind?: string | null }) {
  const meta = DETECTOR_META[detector] ?? { label: detector, tone: "neutral" as Tone, stream: "flow", long: detector };
  return (
    <Badge tone={meta.tone} icon={STREAM_META[meta.stream as Stream]?.icon} title={meta.long}>
      {kind && kind !== detector ? kind : meta.label}
    </Badge>
  );
}

export function StreamBadge({ stream }: { stream: Stream | null }) {
  if (!stream) return null;
  const meta = STREAM_META[stream];
  return (
    <Badge tone={meta.tone} icon={meta.icon}>
      {meta.label}
    </Badge>
  );
}

const PRIORITY: Record<number, { tone: Tone; label: string }> = {
  1: { tone: "danger", label: "P1" },
  2: { tone: "warn", label: "P2" },
  3: { tone: "info", label: "P3" },
  4: { tone: "neutral", label: "P4" },
};

export function PriorityBadge({ priority }: { priority: number }) {
  const meta = PRIORITY[priority] ?? PRIORITY[4];
  return (
    <Badge tone={meta.tone} className="font-mono">
      {meta.label}
    </Badge>
  );
}

const STATUS: Record<IncidentStatus, { tone: Tone; icon: ReactNode }> = {
  open: { tone: "warn", icon: <IconCircleDot size={12} /> },
  logged: { tone: "neutral", icon: <IconEye size={12} /> },
  queued: { tone: "info", icon: <IconHourglass size={12} /> },
  triaging: { tone: "brand", icon: <IconRobot size={12} /> },
  awaiting_approval: { tone: "warn", icon: <IconClock size={12} /> },
  contained: { tone: "ok", icon: <IconShieldCheck size={12} /> },
  dismissed: { tone: "neutral", icon: <IconCircleX size={12} /> },
  closed: { tone: "neutral", icon: <IconCircleCheck size={12} /> },
};

export function StatusBadge({ status }: { status: IncidentStatus }) {
  const meta = STATUS[status] ?? STATUS.open;
  return (
    <Badge tone={meta.tone} icon={meta.icon}>
      {titleCase(status)}
    </Badge>
  );
}

export function VerdictBadge({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <Badge>Untriaged</Badge>;
  const tone: Tone = verdict === "malicious" ? "danger" : verdict === "suspicious" ? "warn" : "ok";
  const icon = verdict === "malicious" ? <IconAlertOctagon size={12} /> : verdict === "suspicious" ? <IconEye size={12} /> : <IconCircleCheck size={12} />;
  return (
    <Badge tone={tone} icon={icon}>
      {titleCase(verdict)}
    </Badge>
  );
}

export function DecidedBy({ by, model }: { by: string | null; model?: string | null }) {
  if (!by) return null;
  if (by === "agent")
    return (
      <Badge tone="brand" icon={<IconRobot size={12} />} title={model ?? undefined}>
        Agent{model ? ` · ${model}` : ""}
      </Badge>
    );
  if (by === "playbook")
    return (
      <Badge tone="info" icon={<IconSitemap size={12} />}>
        Playbook
      </Badge>
    );
  return (
    <Badge icon={<IconUser size={12} />}>
      {titleCase(by)}
    </Badge>
  );
}

export const ACTION_META: Record<ActionType, { label: string; icon: ReactNode }> = {
  block_ip: { label: "Block IP", icon: <IconBan size={14} /> },
  revoke_sessions: { label: "Revoke sessions", icon: <IconLogout size={14} /> },
  disable_account: { label: "Disable account", icon: <IconUserOff size={14} /> },
  isolate_host: { label: "Isolate host", icon: <IconPlugConnectedX size={14} /> },
  none: { label: "No action", icon: <IconCircleDot size={14} /> },
};

const ACTION_STATUS: Record<ActionStatus, Tone> = {
  proposed: "info",
  pending_approval: "warn",
  approved: "brand",
  rejected: "neutral",
  denied: "danger",
  executed: "ok",
  failed: "danger",
};

export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  return <Badge tone={ACTION_STATUS[status] ?? "neutral"}>{titleCase(status)}</Badge>;
}
