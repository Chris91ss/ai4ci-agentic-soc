"use client";

import { IconAlarm, IconRefresh, IconTrendingDown, IconWorld } from "@tabler/icons-react";
import { motion } from "framer-motion";
import { CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import type { Evaluation, EvalRun } from "@/lib/types";

import { ConfigCard, sortConfigs } from "./e2e";
import { axis, fmtNum, tooltipStyle } from "./shared";

const WITHOUT = "#f43f5e";
const WITH = "#10b981";

const hoursSince = (iso: string, onset: string) => (Date.parse(iso) - Date.parse(onset)) / 3_600_000;

function SeedPanel({ seed, without, retrain, index }: { seed: number; without?: EvalRun; retrain?: EvalRun; index: number }) {
  const base = without?.drift ?? retrain?.drift;
  if (!base) return null;
  const onset = base.onset;
  const byHour = new Map<number, { h: number; without?: number; with?: number }>();
  for (const [key, run] of [["without", without], ["with", retrain]] as const) {
    for (const point of run?.drift?.hourly_false_alerts ?? []) {
      const h = Math.round(hoursSince(point.hour, onset));
      byHour.set(h, { ...(byHour.get(h) ?? { h }), [key]: point.false_alerts });
    }
  }
  const data = [...byHour.values()].sort((a, b) => a.h - b.h);
  const retrains = (retrain?.drift?.retrains ?? []).map((t) => hoursSince(t, onset));
  const alarm = base.alarm_delay_h;
  const row = (label: string, a?: number | null, b?: number | null, unit = "") => (
    <div className="flex items-center justify-between gap-2 text-xs">
      <span className="text-faint">{label}</span>
      <span className="font-mono">
        <span style={{ color: WITHOUT }}>{a === undefined || a === null ? "—" : `${fmtNum(a, 1)}${unit}`}</span>
        <span className="mx-1.5 text-faint">/</span>
        <span style={{ color: WITH }}>{b === undefined || b === null ? "—" : `${fmtNum(b, 1)}${unit}`}</span>
      </span>
    </div>
  );
  return (
    <Card transition={{ delay: index * 0.08, duration: 0.35 }}>
      <CardHeader
        icon={<IconWorld size={16} />}
        title={`Seed ${seed}`}
        subtitle="False M1 alerts per hour around the move to remote work (hour 0)"
        action={
          <div className="flex gap-1.5">
            {alarm !== null ? (
              <Badge tone="warn" icon={<IconAlarm size={12} />}>
                alarm +{fmtNum(alarm, 1)} h
              </Badge>
            ) : (
              <Badge>no alarm</Badge>
            )}
            {retrains.length ? (
              <Badge tone="ok" icon={<IconRefresh size={12} />}>
                {retrains.length} retrain{retrains.length > 1 ? "s" : ""}
              </Badge>
            ) : null}
          </div>
        }
      />
      <CardBody className="grid gap-4 lg:grid-cols-[1fr_220px]">
        <div className="h-56">
          <ResponsiveContainer>
            <LineChart data={data} margin={{ left: -18, right: 8 }}>
              <CartesianGrid stroke="#222b3a" vertical={false} />
              <XAxis dataKey="h" type="number" domain={["dataMin", "dataMax"]} {...axis} tickFormatter={(h) => `${h > 0 ? "+" : ""}${h}h`} />
              <YAxis {...axis} />
              <Tooltip contentStyle={tooltipStyle} labelFormatter={(h) => `hour ${Number(h) > 0 ? "+" : ""}${h}`} />
              <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
              <ReferenceLine x={0} stroke="#9aa5b8" strokeDasharray="4 4" label={{ value: "shift", fill: "#9aa5b8", fontSize: 10, position: "top" }} />
              {alarm !== null ? <ReferenceLine x={alarm} stroke="#f59e0b" strokeDasharray="4 4" /> : null}
              {retrains.map((h) => (
                <ReferenceLine key={h} x={h} stroke={WITH} strokeDasharray="2 3" />
              ))}
              <Line dataKey="without" name="Without retraining" stroke={WITHOUT} dot={false} strokeWidth={2} animationDuration={900} />
              <Line dataKey="with" name="With retraining" stroke={WITH} dot={false} strokeWidth={2} animationDuration={900} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="space-y-2 rounded-lg bg-raised/50 p-3 ring-1 ring-line/70">
          <div className="flex items-center gap-1.5 text-[11px] text-dim">
            <IconTrendingDown size={13} />
            without <span style={{ color: WITHOUT }}>●</span> / with <span style={{ color: WITH }}>●</span> retraining
          </div>
          {row("False alerts/h before", without?.drift?.false_alerts_per_h_before, retrain?.drift?.false_alerts_per_h_before)}
          {row("First 6 h after", without?.drift?.false_alerts_per_h_first_6h, retrain?.drift?.false_alerts_per_h_first_6h)}
          {row("Next day (+24-36 h)", without?.drift?.false_alerts_per_h_next_day, retrain?.drift?.false_alerts_per_h_next_day)}
          {row("Recovered after", without?.drift?.recovery_h, retrain?.drift?.recovery_h, " h")}
          {row("False containments", without?.false_containments, retrain?.false_containments)}
          {row("Furthest stage (of 9)", without?.furthest_stage_index, retrain?.furthest_stage_index)}
        </div>
      </CardBody>
    </Card>
  );
}

export function DriftS1({ s1 }: { s1: NonNullable<Evaluation["s1"]> }) {
  const seeds = [...new Set(s1.runs.map((r) => r.seed))].sort((a, b) => a - b);
  const configs = sortConfigs(Object.keys(s1.summary));
  return (
    <div className="space-y-4">
      <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-xs text-dim">
        Scenario S1: on day 2 most of the company moves to remote work behind a ZTNA egress, so sign-ins come from new IPs, ASNs and a new
        country. The drift monitor compares the live feature distributions with the training reference (PSI per feature, hourly); with
        retraining enabled an alarm refreshes the M1 baselines from recent, attack-free traffic.
      </motion.p>
      <div className="grid gap-4 xl:grid-cols-2">
        {configs.map((c, i) => (
          <ConfigCard key={c} config={c} s={s1.summary[c]} index={i} />
        ))}
      </div>
      {seeds.map((seed, i) => (
        <SeedPanel
          key={seed}
          seed={seed}
          index={i}
          without={s1.runs.find((r) => r.seed === seed && r.config === "agent")}
          retrain={s1.runs.find((r) => r.seed === seed && r.config === "agent+retrain")}
        />
      ))}
    </div>
  );
}
