"use client";

import { motion } from "framer-motion";

import { fmtTime } from "@/lib/format";
import type { Alert } from "@/lib/types";

import { DetectorBadge, STREAM_META } from "../soc/badges";
import { EntityChip, TechniqueChip } from "../soc/entities";

/** One alert with its score against the threshold and the features that drove it. */
export function AlertCard({ alert }: { alert: Alert }) {
  const color = STREAM_META[alert.stream]?.color ?? "#22d3ee";
  const top = alert.top_features.slice(0, 5);
  const maxContribution = Math.max(...top.map((f) => Math.abs(f.contribution)), 1e-9);
  const entities = [
    ...alert.entities.users.map((u) => `user:${u}`),
    ...alert.entities.hosts.map((h) => `host:${h}`),
    ...alert.entities.ips.map((i) => `ip:${i}`),
  ];
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-line bg-raised/40 p-4"
    >
      <div className="flex flex-wrap items-center gap-2">
        <DetectorBadge detector={alert.detector} kind={alert.model_version} />
        <span className="font-mono text-xs text-ink">{alert.alert_id}</span>
        <span className="font-mono text-[11px] text-faint">
          {fmtTime(alert.window_start, "EEE HH:mm")} – {fmtTime(alert.window_end, "HH:mm")}
        </span>
        <div className="ml-auto flex flex-wrap gap-1">
          {alert.techniques.map((t) => (
            <TechniqueChip key={t} technique={t} />
          ))}
        </div>
      </div>
      <p className="mt-2 text-sm text-dim">{alert.summary}</p>
      <div className="mt-3 grid gap-4 md:grid-cols-[200px_1fr]">
        <div>
          <div className="flex justify-between text-[11px] text-faint">
            <span>score</span>
            <span className="font-mono">
              <span style={{ color }}>{alert.score.toFixed(3)}</span> / threshold {alert.threshold.toFixed(3)}
            </span>
          </div>
          <div className="relative mt-1.5 h-2 rounded-full bg-canvas ring-1 ring-line">
            <motion.div
              className="h-full rounded-full"
              style={{ background: color }}
              initial={{ width: 0 }}
              animate={{ width: `${alert.score * 100}%` }}
              transition={{ duration: 0.8 }}
            />
            <span className="absolute -top-1 h-4 w-0.5 rounded bg-ink" style={{ left: `${alert.threshold * 100}%` }} />
          </div>
          <div className="mt-3 flex flex-wrap gap-1">
            {entities.slice(0, 6).map((e) => (
              <EntityChip key={e} entity={e} />
            ))}
            {entities.length > 6 ? <span className="text-xs text-faint">+{entities.length - 6}</span> : null}
          </div>
        </div>
        <div className="space-y-1.5">
          <div className="text-[11px] uppercase tracking-wider text-faint">Top contributing features</div>
          {top.map((feature) => (
            <div key={feature.name} className="grid grid-cols-[minmax(0,1fr)_auto_90px] items-center gap-2 text-xs">
              <span className="truncate font-mono text-dim">{feature.name}</span>
              <span className="font-mono text-faint">{typeof feature.value === "number" ? Number(feature.value.toFixed(3)) : feature.value}</span>
              <div className="h-1.5 rounded-full bg-canvas">
                <motion.div
                  className="h-full rounded-full bg-brand/80"
                  initial={{ width: 0 }}
                  animate={{ width: `${(Math.abs(feature.contribution) / maxContribution) * 100}%` }}
                  transition={{ duration: 0.6 }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
