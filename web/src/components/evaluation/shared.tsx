import { IconBolt, IconBrain, IconCpu2, IconListCheck, IconRadar2, IconRefresh, IconShieldCheck } from "@tabler/icons-react";
import type { ReactNode } from "react";

import type { Tone } from "@/components/ui/badge";

export const tooltipStyle = { background: "#151b26", border: "1px solid #2e394c", borderRadius: 10, fontSize: 12 };
export const axis = { stroke: "#64708a", fontSize: 11, tickLine: false, axisLine: false } as const;

export const CONFIG_META: Record<string, { label: string; short: string; color: string; tone: Tone; icon: ReactNode }> = {
  agent: { label: "Agent (scripted analyst)", short: "Agent", color: "#22d3ee", tone: "brand", icon: <IconBrain size={15} /> },
  detectors: { label: "Detectors + playbooks", short: "Detectors", color: "#818cf8", tone: "info", icon: <IconRadar2 size={15} /> },
  rules: { label: "Sigma-style rules", short: "Rules", color: "#f59e0b", tone: "warn", icon: <IconListCheck size={15} /> },
  "agent+retrain": { label: "Agent + retraining on drift", short: "Retrain", color: "#10b981", tone: "ok", icon: <IconRefresh size={15} /> },
  "agent+fastblock": { label: "Agent + fast spray block", short: "Fast block", color: "#f472b6", tone: "brand", icon: <IconBolt size={15} /> },
};

export function configMeta(config: string) {
  if (CONFIG_META[config]) return CONFIG_META[config];
  if (config.startsWith("agent:")) {
    const [model, ...flags] = config.slice(6).split("+");
    if (flags.includes("verifier"))
      return { label: `Agent on ${model} + verifier`, short: `${model} + verifier`, color: "#10b981", tone: "ok" as Tone, icon: <IconShieldCheck size={15} /> };
    return { label: `Agent on ${model}`, short: model, color: "#a78bfa", tone: "signin" as Tone, icon: <IconCpu2 size={15} /> };
  }
  return { label: config, short: config, color: "#9aa5b8", tone: "neutral" as Tone, icon: <IconBrain size={15} /> };
}

export const STAGES = [
  "spray",
  "initial_access",
  "discovery",
  "execution",
  "command_and_control",
  "credential_access",
  "lateral_movement",
  "collection",
  "exfiltration",
] as const;

export const STAGE_LABEL: Record<string, string> = {
  none: "Not started",
  spray: "Password spray",
  initial_access: "Initial access",
  discovery: "Discovery",
  execution: "Execution",
  command_and_control: "C2 beacon",
  credential_access: "Credential access",
  lateral_movement: "Lateral movement",
  collection: "Collection",
  exfiltration: "Exfiltration",
};

/** Early stages green, late stages red: how far the attacker got. */
export const STAGE_COLOR: Record<string, string> = {
  none: "#334155",
  spray: "#10b981",
  initial_access: "#34d399",
  discovery: "#a3e635",
  execution: "#facc15",
  command_and_control: "#fbbf24",
  credential_access: "#fb923c",
  lateral_movement: "#f97316",
  collection: "#f43f5e",
  exfiltration: "#be123c",
};

export function fmtMinutes(minutes: number | null | undefined) {
  if (minutes === null || minutes === undefined) return "—";
  if (minutes < 90) return `${minutes.toFixed(minutes < 10 ? 1 : 0)} min`;
  return `${(minutes / 60).toFixed(1)} h`;
}

export function fmtNum(value: number | null | undefined, digits = 2) {
  if (value === null || value === undefined) return "—";
  return Number.isInteger(value) ? value.toLocaleString("en") : value.toFixed(digits);
}

export function fmtP(p: number | null | undefined) {
  if (p === null || p === undefined) return "—";
  return p < 0.001 ? "< 0.001" : p.toFixed(3);
}
