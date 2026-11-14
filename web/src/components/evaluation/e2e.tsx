"use client";

import { IconChartArrows, IconFlask, IconScale, IconShieldCheck, IconTargetArrow } from "@tabler/icons-react";
import { motion } from "framer-motion";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { fmtDuration, fmtPercent } from "@/lib/format";
import type { ConfigSummary, Evaluation, EvalRun } from "@/lib/types";
import { cn } from "@/lib/utils";

import { STAGE_COLOR, STAGE_LABEL, STAGES, axis, configMeta, fmtMinutes, fmtNum, fmtP, tooltipStyle } from "./shared";

const ORDER = ["agent", "detectors", "rules"];
const TEST_LABEL: Record<string, string> = {
  false_containments: "False containments",
  furthest_stage_index: "Furthest attack stage",
  exfil_gb: "Exfiltrated GB",
  mttc_min: "Time to containment (min)",
  incidents: "Incidents",
};

export function sortConfigs(configs: string[]) {
  return [...configs].sort((a, b) => (ORDER.indexOf(a) + 1 || 99) - (ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b));
}

function Metric({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: "ok" | "danger" | "warn" }) {
  return (
    <div className="rounded-lg bg-raised/60 px-3 py-2 ring-1 ring-line/70">
      <div className="text-[11px] text-faint">{label}</div>
      <div
        className={cn(
          "mt-0.5 font-mono text-lg font-semibold text-ink",
          tone === "ok" && "text-ok",
          tone === "danger" && "text-danger",
          tone === "warn" && "text-warn",
        )}
      >
        {value}
      </div>
      {hint ? <div className="truncate text-[11px] text-faint">{hint}</div> : null}
    </div>
  );
}

export function ConfigCard({ config, s, index }: { config: string; s: ConfigSummary; index: number }) {
  const meta = configMeta(config);
  const stopped = Math.round(s.stopped_before_exfiltration * s.runs);
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.08, type: "spring", stiffness: 220, damping: 26 }}
      className="relative overflow-hidden rounded-[var(--radius-card)] border border-line bg-panel/80 p-4"
    >
      <div className="pointer-events-none absolute -right-10 -top-10 size-32 rounded-full opacity-10 blur-2xl" style={{ background: meta.color }} />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span className="grid size-8 place-items-center rounded-lg ring-1 ring-line" style={{ color: meta.color, background: `${meta.color}1a` }}>
            {meta.icon}
          </span>
          <div>
            <div className="text-sm font-semibold text-ink">{meta.label}</div>
            <div className="text-[11px] text-faint">{s.runs} seeds</div>
          </div>
        </div>
        <Badge tone={stopped === s.runs ? "ok" : stopped === 0 ? "danger" : "warn"}>
          {stopped}/{s.runs} stopped
        </Badge>
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-raised">
        <motion.div
          className="h-full rounded-full"
          style={{ background: meta.color }}
          initial={{ width: 0 }}
          animate={{ width: `${s.stopped_before_exfiltration * 100}%` }}
          transition={{ duration: 0.9, delay: 0.2 + index * 0.08, ease: [0.22, 1, 0.36, 1] }}
        />
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <Metric label="Detection (MTTD, median)" value={fmtMinutes(s.mttd_min_median)} hint={`detected in ${fmtPercent(s.detected)}`} />
        <Metric label="Containment (MTTC, median)" value={fmtMinutes(s.mttc_min_median)} hint={`contained in ${fmtPercent(s.contained)}`} />
        <Metric
          label="False containments"
          value={String(s.false_containments_total)}
          hint={`${fmtNum(s.false_containments_mean)} per run · ${fmtPercent(s.runs_without_false_containment)} runs clean`}
          tone={s.false_containments_total === 0 ? "ok" : "danger"}
        />
        <Metric label="Exfiltrated (mean)" value={`${fmtNum(s.exfil_gb_mean)} GB`} hint={`furthest stage ${fmtNum(s.furthest_stage_mean, 1)} / 9`} tone={s.exfil_gb_mean ? "danger" : "ok"} />
        <Metric label="Incidents per run" value={fmtNum(s.incidents_mean, 1)} hint={`${fmtNum(s.alerts_mean, 0)} alerts · ${fmtPercent(s.alert_reduction_mean)} reduction`} />
        <Metric label="Actions executed per run" value={fmtNum(s.actions_executed_mean, 1)} hint={`${fmtDuration(s.wall_s_mean)} wall per run`} />
      </div>
      {s.agent ? (
        <div className="mt-3 flex flex-wrap gap-1.5">
          <Badge tone="brand">verdict F1 {fmtNum(s.agent.verdict.f1)}</Badge>
          <Badge>precision {fmtNum(s.agent.verdict.precision)}</Badge>
          <Badge>recall {fmtNum(s.agent.verdict.recall)}</Badge>
          <Badge>{s.agent.decisions} decisions</Badge>
          <Badge>action correctness {fmtPercent(s.agent.action_correctness_mean)}</Badge>
          <Badge>invalid tool calls {fmtPercent(s.agent.invalid_tool_call_rate, 1)}</Badge>
          <Badge>latency {fmtDuration(s.agent.latency_mean_s)} (p95 {fmtDuration(s.agent.latency_p95_s)})</Badge>
          {s.agent.timeouts ? <Badge tone="warn">{s.agent.timeouts} timeouts</Badge> : null}
        </div>
      ) : null}
    </motion.div>
  );
}

function StageChart({ summary, configs }: { summary: Record<string, ConfigSummary>; configs: string[] }) {
  const stages = ["none", ...STAGES].filter((stage) => configs.some((c) => summary[c].furthest_stage[stage]));
  const data = configs.map((c) => ({ config: configMeta(c).short, ...summary[c].furthest_stage }));
  return (
    <Card>
      <CardHeader icon={<IconTargetArrow size={16} />} title="How far the attack got" subtitle="Furthest kill-chain stage reached, per run" />
      <CardBody className="h-64">
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical" margin={{ left: 4, right: 12 }}>
            <XAxis type="number" {...axis} allowDecimals={false} />
            <YAxis type="category" dataKey="config" {...axis} width={72} />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2230" }} />
            <Legend
              wrapperStyle={{ fontSize: 11 }}
              iconType="circle"
              iconSize={8}
              itemSorter={(item) => ["none", ...STAGES].indexOf(String(item.dataKey))}
            />
            {stages.map((stage) => (
              <Bar key={stage} dataKey={stage} name={STAGE_LABEL[stage]} stackId="runs" fill={STAGE_COLOR[stage]} animationDuration={800} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </CardBody>
    </Card>
  );
}

function FalseContainmentChart({ runs, configs }: { runs: EvalRun[]; configs: string[] }) {
  const seeds = [...new Set(runs.map((r) => r.seed))].sort((a, b) => a - b);
  const data = seeds.map((seed) => {
    const row: Record<string, number | string> = { seed: String(seed) };
    for (const c of configs) {
      const run = runs.find((r) => r.seed === seed && r.config === c);
      if (run) row[c] = run.false_containments;
    }
    return row;
  });
  return (
    <Card>
      <CardHeader icon={<IconShieldCheck size={16} />} title="False containments per seed" subtitle="Executed actions on entities outside the attack" />
      <CardBody className="h-64">
        <ResponsiveContainer>
          <BarChart data={data} margin={{ left: -16 }}>
            <CartesianGrid stroke="#222b3a" vertical={false} />
            <XAxis dataKey="seed" {...axis} />
            <YAxis {...axis} allowDecimals={false} />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2230" }} />
            <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
            {configs.map((c) => (
              <Bar key={c} dataKey={c} name={configMeta(c).short} fill={configMeta(c).color} radius={[4, 4, 0, 0]} animationDuration={800} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </CardBody>
    </Card>
  );
}

function OutcomeGrid({ runs, configs }: { runs: EvalRun[]; configs: string[] }) {
  const seeds = [...new Set(runs.map((r) => r.seed))].sort((a, b) => a - b);
  return (
    <Card>
      <CardHeader icon={<IconChartArrows size={16} />} title="Outcome by seed" subtitle="Furthest stage, exfiltration, time to containment and false containments" />
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-faint">
            <tr className="border-b border-line">
              <th className="px-4 py-2 font-medium">Seed</th>
              {configs.map((c) => (
                <th key={c} className="px-4 py-2 font-medium">
                  {configMeta(c).short}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line/60">
            {seeds.map((seed, i) => (
              <motion.tr key={seed} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }}>
                <td className="px-4 py-2 font-mono text-ink">{seed}</td>
                {configs.map((c) => {
                  const run = runs.find((r) => r.seed === seed && r.config === c);
                  if (!run) return <td key={c} className="px-4 py-2 text-faint">—</td>;
                  if (run.error) return <td key={c} className="px-4 py-2 text-danger" title={run.error}>failed</td>;
                  const stage = run.furthest_stage ?? "none";
                  return (
                    <td key={c} className="px-4 py-2">
                      <div className="flex items-center gap-2">
                        <span className="size-2 shrink-0 rounded-full" style={{ background: STAGE_COLOR[stage] }} />
                        <span className="text-ink">{STAGE_LABEL[stage]}</span>
                        {run.exfil_gb ? <span className="font-mono text-danger">{run.exfil_gb} GB</span> : null}
                      </div>
                      <div className="mt-0.5 flex gap-3 font-mono text-[11px] text-faint">
                        <span>MTTC {fmtMinutes(run.mttc_min)}</span>
                        <span className={run.false_containments ? "text-danger" : undefined}>FC {run.false_containments}</span>
                      </div>
                    </td>
                  );
                })}
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Tests({ tests }: { tests: NonNullable<Evaluation["e2e"]>["tests"] }) {
  return (
    <Card>
      <CardHeader
        icon={<IconScale size={16} />}
        title="Agent against the baselines"
        subtitle="Paired Wilcoxon signed-rank tests over the seeds (median difference: agent minus baseline)"
      />
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-faint">
            <tr className="border-b border-line">
              {["Baseline", "Metric", "Pairs", "Median difference", "p-value", ""].map((h) => (
                <th key={h} className="px-4 py-2 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line/60">
            {Object.entries(tests).flatMap(([pair, metrics]) =>
              Object.entries(metrics).map(([metric, t]) => (
                <tr key={`${pair}-${metric}`}>
                  <td className="px-4 py-2 text-ink">{configMeta(pair.replace(/^agent_vs_/, "")).short}</td>
                  <td className="px-4 py-2">{TEST_LABEL[metric] ?? metric}</td>
                  <td className="px-4 py-2 font-mono">{t.n}</td>
                  <td className="px-4 py-2 font-mono">{fmtNum(t.median_difference)}</td>
                  <td className="px-4 py-2 font-mono">{fmtP(t.p_value)}</td>
                  <td className="px-4 py-2">
                    {t.p_value !== null && t.p_value < 0.05 ? <Badge tone="ok">significant</Badge> : <Badge>n.s.</Badge>}
                  </td>
                </tr>
              )),
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function EndToEnd({ e2e }: { e2e: NonNullable<Evaluation["e2e"]> }) {
  const configs = sortConfigs(Object.keys(e2e.summary));
  return (
    <div className="space-y-4">
      <p className="flex items-center gap-2 text-xs text-dim">
        <IconFlask size={14} className="text-brand" />
        Each seed is one 48-hour closed loop: the simulator, the detectors, correlation and the response configuration react to each other,
        so containment changes what the attacker can do next.
      </p>
      <div className="grid gap-4 xl:grid-cols-3">
        {configs.map((c, i) => (
          <ConfigCard key={c} config={c} s={e2e.summary[c]} index={i} />
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <StageChart summary={e2e.summary} configs={configs} />
        <FalseContainmentChart runs={e2e.runs} configs={configs} />
      </div>
      <OutcomeGrid runs={e2e.runs} configs={configs} />
      {Object.keys(e2e.tests ?? {}).length ? <Tests tests={e2e.tests} /> : null}
    </div>
  );
}
