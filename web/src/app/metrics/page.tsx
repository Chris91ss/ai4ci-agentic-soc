"use client";

import { IconBrain, IconChartBar, IconClockHour4, IconRoute, IconShieldExclamation, IconTool, IconUserCheck } from "@tabler/icons-react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { ACTION_META, DETECTOR_META, STREAM_META } from "@/components/soc/badges";
import { DriftCard } from "@/components/soc/drift-card";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Stat } from "@/components/ui/stat";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { fmtDuration, fmtPercent, titleCase } from "@/lib/format";
import { useMetrics } from "@/lib/queries";

const tooltipStyle = { background: "#151b26", border: "1px solid #2e394c", borderRadius: 10, fontSize: 12 };
const PRIORITY_COLORS: Record<string, string> = { "1": "#f43f5e", "2": "#f59e0b", "3": "#818cf8", "4": "#64708a" };

function detectorColor(detector: string) {
  const stream = DETECTOR_META[detector]?.stream;
  return stream ? STREAM_META[stream].color : "#22d3ee";
}

export default function MetricsPage() {
  const { data: m, error, isLoading } = useMetrics();
  if (error) return <ErrorState error={error} />;
  if (isLoading || !m)
    return (
      <div className="grid gap-4 md:grid-cols-2">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-72" />
        ))}
      </div>
    );
  const byKind = m.alerts_by_detector
    .map((r) => ({ kind: r.model_version || r.detector, detector: r.detector, alerts: r.alerts }))
    .sort((a, b) => a.kind.localeCompare(b.kind));
  const priorities = ["1", "2", "3", "4"].map((p) => ({ priority: `P${p}`, key: p, n: m.incidents_by_priority[p] ?? 0 }));
  const actions = Object.entries(m.actions_by_type).map(([type, n]) => ({ type: ACTION_META[type as keyof typeof ACTION_META]?.label ?? type, n }));

  return (
    <>
      <div className="mb-5">
        <h1 className="text-gradient text-2xl font-semibold tracking-tight">Metrics</h1>
        <p className="mt-1 text-sm text-dim">How the detectors, the correlation engine and the triage agent are doing.</p>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Agent decisions" value={m.agent.decisions} icon={<IconBrain size={15} />} tone="brand" />
        <Stat label="Mean latency" value={m.agent.latency_mean_s} decimals={1} format={fmtDuration} icon={<IconClockHour4 size={15} />} tone="info" />
        <Stat label="p95 latency" value={m.agent.latency_p95_s} decimals={1} format={fmtDuration} icon={<IconClockHour4 size={15} />} tone="info" />
        <Stat label="MCP tool calls" value={m.agent.tool_calls} icon={<IconTool size={15} />} tone="flow" />
        <Stat
          label="Invalid tool calls"
          value={m.agent.invalid_tool_call_rate}
          decimals={4}
          format={(n) => fmtPercent(n, 1)}
          icon={<IconTool size={15} />}
          tone="process"
        />
        <Stat
          label="Escalated dismissals"
          value={m.agent.escalated_dismissals}
          icon={<IconShieldExclamation size={15} />}
          tone="danger"
          hint={`${m.agent.injection_seen} prompt injections seen`}
        />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader icon={<IconChartBar size={16} />} title="Alerts by detector" subtitle={`${m.alerts} alerts, ${m.incidents} incidents (${m.alert_to_incident_ratio ?? "—"} per incident)`} />
          <CardBody className="h-64">
            <ResponsiveContainer>
              <BarChart data={byKind} margin={{ left: -12 }}>
                <XAxis dataKey="kind" stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2230" }} />
                <Bar dataKey="alerts" radius={[6, 6, 0, 0]} animationDuration={800}>
                  {byKind.map((row) => (
                    <Cell key={row.kind} fill={detectorColor(row.detector)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<IconUserCheck size={16} />} title="Analyst feedback per detector" subtitle="False-positive statistics from analyst verdicts" />
          {m.detector_feedback.some((r) => r.reviewed) ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-faint">
                  <tr className="border-b border-line">
                    {["Detector", "Alerts", "Reviewed", "True +", "False +", "Benign +", "FP share", "Precision"].map((h) => (
                      <th key={h} className="px-4 py-2 font-medium">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/60">
                  {m.detector_feedback.map((row) => (
                    <tr key={`${row.detector}-${row.kind}`}>
                      <td className="px-4 py-2 font-mono text-ink">{row.kind}</td>
                      <td className="px-4 py-2 font-mono">{row.alerts}</td>
                      <td className="px-4 py-2 font-mono">{row.reviewed}</td>
                      <td className="px-4 py-2 font-mono text-danger">{row.true_positive}</td>
                      <td className="px-4 py-2 font-mono text-ok">{row.false_positive}</td>
                      <td className="px-4 py-2 font-mono">{row.benign_positive}</td>
                      <td className="px-4 py-2 font-mono">{fmtPercent(row.false_positive_share)}</td>
                      <td className="px-4 py-2 font-mono">{fmtPercent(row.precision)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState icon={<IconUserCheck size={20} />} title="No analyst feedback yet">
              Label incidents as true, false or benign positives in their Response tab.
            </EmptyState>
          )}
        </Card>
        <Card>
          <CardHeader icon={<IconRoute size={16} />} title="Incidents by priority" subtitle="Routed incidents; priority follows the risk" />
          <CardBody className="h-56">
            <ResponsiveContainer>
              <BarChart data={priorities} layout="vertical" margin={{ left: -8 }}>
                <XAxis type="number" stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="priority" stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} width={40} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2230" }} />
                <Bar dataKey="n" radius={[0, 6, 6, 0]} animationDuration={800}>
                  {priorities.map((p) => (
                    <Cell key={p.key} fill={PRIORITY_COLORS[p.key]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<IconShieldExclamation size={16} />} title="Decisions and containment" subtitle="Who decided, what they concluded and what executed" />
          <CardBody className="space-y-4">
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(m.decisions_by).map(([by, n]) => (
                <Badge key={by} tone={by === "agent" ? "brand" : "info"}>
                  {titleCase(by)} · {n}
                </Badge>
              ))}
              {Object.entries(m.verdicts).map(([v, n]) => (
                <Badge key={v} tone={v === "malicious" ? "danger" : v === "suspicious" ? "warn" : "ok"}>
                  {titleCase(v)} · {n}
                </Badge>
              ))}
              {Object.entries(m.actions_by_status).map(([s, n]) => (
                <Badge key={s}>
                  {titleCase(s)} · {n}
                </Badge>
              ))}
            </div>
            <div className="h-40">
              <ResponsiveContainer>
                <BarChart data={actions} margin={{ left: -12 }}>
                  <XAxis dataKey="type" stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1a2230" }} />
                  <Bar dataKey="n" fill="#10b981" radius={[6, 6, 0, 0]} animationDuration={800} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            {m.pipeline ? (
              <div className="flex flex-wrap gap-1.5 text-xs">
                <Badge tone={m.pipeline.breaker === "closed" ? "ok" : "danger"}>breaker {m.pipeline.breaker}</Badge>
                <Badge>{m.pipeline.breaker_trips} trips</Badge>
                {Object.entries(m.pipeline.routes).map(([route, n]) => (
                  <Badge key={route}>
                    {route} · {n}
                  </Badge>
                ))}
              </div>
            ) : null}
          </CardBody>
        </Card>
        <DriftCard />
      </div>
    </>
  );
}
