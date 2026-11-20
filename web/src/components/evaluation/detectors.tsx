"use client";

import { IconClockHour4, IconFlask2, IconGauge, IconTable } from "@tabler/icons-react";
import { motion } from "framer-motion";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { fmtPercent } from "@/lib/format";
import type { Evaluation, M3Variant, ModelKind } from "@/lib/types";
import { cn } from "@/lib/utils";

import { STAGE_LABEL, STAGES, axis, fmtMinutes, fmtNum, tooltipStyle } from "./shared";

const KIND_COLOR: Record<string, string> = { "M1-user": "#a78bfa", "M1-ip": "#c4b5fd", M2: "#22d3ee", M3: "#fbbf24" };
const KIND_LONG: Record<string, string> = {
  "M1-user": "Sign-ins per account (Isolation Forest)",
  "M1-ip": "Sign-ins per source IP (Isolation Forest)",
  M2: "Network flows (LightGBM)",
  M3: "Process sequences (n-gram rarity)",
};

function median(values: number[]) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function KindCard({ kind, m, index }: { kind: string; m: ModelKind; index: number }) {
  const color = KIND_COLOR[kind] ?? "#9aa5b8";
  const rows: [string, string][] = [
    ["ROC-AUC", fmtNum(m.roc_auc, 3)],
    ["Recall at 1% FPR", fmtPercent(m.recall_at_1pct_fpr, 1)],
    ["Recall at threshold", fmtPercent(m.recall_at_threshold, 1)],
    ["Precision at threshold", fmtPercent(m.precision_at_threshold, 1)],
    ["False positives / day", fmtNum(m.false_positives_per_day, 1)],
    ["Test windows", `${m.rows.toLocaleString("en")} (${m.positives} malicious)`],
  ];
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.07, type: "spring", stiffness: 220, damping: 26 }}
      className="relative overflow-hidden rounded-[var(--radius-card)] border border-line bg-panel/80 p-4"
    >
      <div className="pointer-events-none absolute -right-10 -top-10 size-28 rounded-full opacity-15 blur-2xl" style={{ background: color }} />
      <div className="flex items-baseline justify-between">
        <span className="font-mono text-sm font-semibold" style={{ color }}>
          {kind}
        </span>
        <span className="text-[11px] text-faint">PR-AUC</span>
      </div>
      <div className="mt-1 flex items-baseline justify-between gap-2">
        <span className="truncate text-xs text-dim">{KIND_LONG[kind] ?? kind}</span>
        <span className="font-mono text-2xl font-semibold text-ink">{fmtNum(m.pr_auc, 3)}</span>
      </div>
      <dl className="mt-3 space-y-1.5 text-xs">
        {rows.map(([label, value]) => (
          <div key={label} className="flex justify-between gap-2">
            <dt className="text-faint">{label}</dt>
            <dd className="font-mono text-ink">{value}</dd>
          </div>
        ))}
      </dl>
    </motion.div>
  );
}

function heat(value: number) {
  return `rgba(16, 185, 129, ${0.08 + value * 0.42})`;
}

// A variant's value with its difference from the promoted M3, green when it is better.
function Compared({ value, base, digits, lowerIsBetter = false }: { value: number; base: number; digits: number; lowerIsBetter?: boolean }) {
  const diff = value - base;
  const better = lowerIsBetter ? diff < 0 : diff > 0;
  return (
    <span className="font-mono">
      {value.toFixed(digits)}
      {Math.abs(diff) >= 10 ** -digits / 2 ? (
        <span className={cn("ml-1.5 text-[10px]", better ? "text-ok" : "text-danger")}>
          {diff > 0 ? "+" : "−"}
          {Math.abs(diff).toFixed(digits)}
        </span>
      ) : null}
    </span>
  );
}

function M3Variants({ m3 }: { m3: NonNullable<Evaluation["m3_variants"]> }) {
  const promoted: M3Variant = m3.variants[0];
  return (
    <Card>
      <CardHeader
        icon={<IconFlask2 size={16} />}
        title="M3 with its window features"
        subtitle={`Parameter chosen on the validation week (${m3.positives.validation} attack windows), result on the test weeks (${m3.positives.test})`}
      />
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-faint">
            <tr className="border-b border-line">
              {["Variant", "Parameter", "Validation PR-AUC", "Test PR-AUC", "Test FP / day", "Test precision"].map((h) => (
                <th key={h} className="px-4 py-2 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line/60">
            {m3.variants.map((v, i) => (
              <motion.tr key={v.name} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}>
                <td className="px-4 py-2 text-ink">
                  {v.name}
                  {i === 0 ? (
                    <Badge tone="brand" className="ml-2">
                      in use
                    </Badge>
                  ) : null}
                </td>
                <td className="px-4 py-2 font-mono text-dim">{v.parameter || "·"}</td>
                <td className="px-4 py-2">
                  <Compared value={v.validation_pr_auc} base={promoted.validation_pr_auc} digits={3} />
                </td>
                <td className="px-4 py-2">
                  <Compared value={v.test.pr_auc} base={promoted.test.pr_auc} digits={3} />
                </td>
                <td className="px-4 py-2">
                  <Compared value={v.test.false_positives_per_day} base={promoted.test.false_positives_per_day} digits={1} lowerIsBetter />
                </td>
                <td className="px-4 py-2">
                  <Compared value={v.test.precision_at_threshold} base={promoted.test.precision_at_threshold} digits={3} />
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function Detectors({ models, m3 }: { models: NonNullable<Evaluation["models"]>; m3?: Evaluation["m3_variants"] }) {
  const kinds = Object.keys(models.kinds);
  const chart = kinds.map((kind) => ({
    kind,
    "PR-AUC": models.kinds[kind].pr_auc,
    "Recall at 1% FPR": models.kinds[kind].recall_at_1pct_fpr,
    "Precision at threshold": models.kinds[kind].precision_at_threshold,
  }));
  const stages = STAGES.filter((stage) => kinds.some((k) => stage in models.kinds[k].recall_by_stage));
  return (
    <div className="space-y-4">
      <p className="text-xs text-dim">
        Window-level scores on the held-out test weeks ({models.test_runs.join(", ")}, {models.test_days} days of traffic with injected attacks),
        at the thresholds calibrated on the validation weeks.
      </p>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {kinds.map((kind, i) => (
          <KindCard key={kind} kind={kind} m={models.kinds[kind]} index={i} />
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader icon={<IconGauge size={16} />} title="Ranking and operating point" subtitle="Higher is better" />
          <CardBody className="h-64">
            <ResponsiveContainer>
              <BarChart data={chart} margin={{ left: -16 }}>
                <CartesianGrid stroke="#222b3a" vertical={false} />
                <XAxis dataKey="kind" {...axis} />
                <YAxis {...axis} domain={[0, 1]} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2230" }} formatter={(v) => (typeof v === "number" ? v.toFixed(3) : String(v))} />
                <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
                <Bar dataKey="PR-AUC" fill="#22d3ee" radius={[4, 4, 0, 0]} animationDuration={800} />
                <Bar dataKey="Recall at 1% FPR" fill="#a78bfa" radius={[4, 4, 0, 0]} animationDuration={800} />
                <Bar dataKey="Precision at threshold" fill="#10b981" radius={[4, 4, 0, 0]} animationDuration={800} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<IconTable size={16} />} title="Recall by attack stage" subtitle="Share of malicious windows above the threshold, and median detection delay" />
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-faint">
                <tr className="border-b border-line">
                  <th className="px-4 py-2 font-medium">Stage</th>
                  {kinds.map((k) => (
                    <th key={k} className="px-3 py-2 font-mono font-medium">
                      {k}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-line/60">
                {stages.map((stage) => (
                  <tr key={stage}>
                    <td className="px-4 py-1.5 text-ink">{STAGE_LABEL[stage]}</td>
                    {kinds.map((k) => {
                      const recall = models.kinds[k].recall_by_stage[stage];
                      const delay = median(models.kinds[k].detection_delay_min[stage] ?? []);
                      if (recall === undefined) return <td key={k} className="px-3 py-1.5 text-faint">·</td>;
                      return (
                        <td key={k} className="px-3 py-1.5">
                          <span className="inline-flex min-w-12 justify-center rounded px-1.5 py-0.5 font-mono text-ink" style={{ background: heat(recall) }}>
                            {fmtPercent(recall)}
                          </span>
                          {delay !== null ? (
                            <span className="ml-1.5 inline-flex items-center gap-0.5 font-mono text-[10px] text-faint">
                              <IconClockHour4 size={10} />
                              {fmtMinutes(delay)}
                            </span>
                          ) : null}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
      {m3?.variants.length ? <M3Variants m3={m3} /> : null}
    </div>
  );
}
