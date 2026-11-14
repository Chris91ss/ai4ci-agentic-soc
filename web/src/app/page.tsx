"use client";

import {
  IconActivity,
  IconAlertTriangle,
  IconBolt,
  IconBroadcast,
  IconClockHour4,
  IconFilter,
  IconGauge,
  IconHourglass,
  IconRobot,
  IconShieldCheck,
  IconStack2,
  IconTool,
} from "@tabler/icons-react";
import { motion } from "framer-motion";
import Link from "next/link";
import { useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";

import { PriorityBadge, StatusBadge, VerdictBadge } from "@/components/soc/badges";
import { EntityList, KillChain } from "@/components/soc/entities";
import { LiveFeed } from "@/components/soc/live-feed";
import { RiskBar } from "@/components/soc/risk";
import { StreamChart } from "@/components/soc/stream-chart";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Stat } from "@/components/ui/stat";
import { ErrorState, Skeleton } from "@/components/ui/states";
import { Segmented } from "@/components/ui/tabs";
import { DATA_MODE } from "@/lib/api";
import { fmtDuration, fmtNumber, fmtPercent, titleCase } from "@/lib/format";
import { useLive } from "@/lib/live";
import { useHealth, useIncidents, useMetrics, useStreamHealth } from "@/lib/queries";
import { incidentHref } from "@/lib/utils";

const FEED_FILTERS = {
  important: ["incident", "decision", "action", "agent_fallback"],
  all: undefined,
  alerts: ["alert"],
} as const;

const STATUS_COLORS: Record<string, string> = {
  open: "#f59e0b",
  queued: "#818cf8",
  triaging: "#22d3ee",
  awaiting_approval: "#fb923c",
  contained: "#10b981",
  dismissed: "#64708a",
  closed: "#3b4558",
  logged: "#2e394c",
};

function PageTitle() {
  const { data: health } = useHealth();
  const run = health?.run ?? {};
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <motion.h1
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-gradient text-2xl font-semibold tracking-tight"
        >
          Security overview
        </motion.h1>
        <p className="mt-1 text-sm text-dim">
          Streams, detections and the agent&apos;s decisions across the simulated enterprise.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {DATA_MODE === "static" ? <Badge tone="info">Recorded run · replay</Badge> : null}
        {typeof run.name === "string" ? <Badge>{run.name}</Badge> : null}
        {health?.mode ? (
          <Badge tone="brand" icon={<IconRobot size={12} />}>
            {health.mode === "agent" ? `Agent · ${health.llm ?? ""}` : "Detectors + playbooks"}
          </Badge>
        ) : null}
        {typeof run.seed === "number" ? <Badge className="font-mono">seed {run.seed}</Badge> : null}
      </div>
    </div>
  );
}

function Kpis() {
  const { data: m } = useMetrics();
  const events = m ? m.events.signin + m.events.flow + m.events.process : undefined;
  const executed = m?.actions_by_status.executed ?? 0;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
      <Stat label="Events" value={events} icon={<IconActivity size={15} />} tone="flow" format={(n) => fmtNumber(n, { compact: true })} hint="sign-ins · flows · processes" />
      <Stat label="Alerts" value={m?.alerts} icon={<IconAlertTriangle size={15} />} tone="warn" hint="M1 · M2 · M3" />
      <Stat label="Incidents" value={m?.incidents} icon={<IconStack2 size={15} />} tone="info" hint={`${m?.active_incidents ?? 0} active`} />
      <Stat
        label="Alerts per incident"
        value={m?.alert_to_incident_ratio ?? null}
        icon={<IconFilter size={15} />}
        tone="signin"
        format={(n) => n.toFixed(1)}
        decimals={1}
        hint="correlation reduction"
      />
      <Stat label="Containments" value={executed} icon={<IconShieldCheck size={15} />} tone="ok" hint="executed actions" />
      <Stat label="Awaiting approval" value={m?.pending_approvals} icon={<IconHourglass size={15} />} tone="danger" hint="high-impact actions" />
      <Stat
        label="Agent p95 latency"
        value={m?.agent.latency_p95_s ?? null}
        icon={<IconClockHour4 size={15} />}
        tone="brand"
        format={(n) => fmtDuration(n)}
        decimals={1}
        hint={`${m?.agent.decisions ?? 0} agent decisions`}
      />
      <Stat
        label="Invalid tool calls"
        value={m?.agent.invalid_tool_call_rate ?? null}
        icon={<IconTool size={15} />}
        tone="process"
        format={(n) => fmtPercent(n, 1)}
        decimals={4}
        hint={`${fmtNumber(m?.agent.tool_calls ?? 0)} MCP calls`}
      />
    </div>
  );
}

function StreamHealthCard() {
  const { data, error, isLoading } = useStreamHealth(12);
  return (
    <Card className="xl:col-span-2">
      <CardHeader
        icon={<IconBroadcast size={16} />}
        title="Stream health"
        subtitle="Events ingested per 5 minutes, last 12 h of simulated time"
        action={
          data ? (
            <div className="flex gap-1.5">
              {data.dead_letters.length ? (
                <Badge tone="danger">{fmtNumber(data.dead_letters.reduce((s, d) => s + d.n, 0))} dead letters</Badge>
              ) : (
                <Badge tone="ok">no dead letters</Badge>
              )}
              {data.consumer_lag ? (
                <Badge tone={Object.values(data.consumer_lag).some((v) => v > 1000) ? "warn" : "neutral"}>
                  lag {fmtNumber(Object.values(data.consumer_lag).reduce((a, b) => a + b, 0))}
                </Badge>
              ) : null}
            </div>
          ) : null
        }
      />
      <CardBody>
        {error ? <ErrorState error={error} /> : isLoading || !data ? <Skeleton className="h-60 w-full" /> : <StreamChart counts={data.counts} />}
      </CardBody>
    </Card>
  );
}

function StatusDonut() {
  const { data: m } = useMetrics();
  const rows = Object.entries(m?.incidents_by_status ?? {})
    .filter(([status]) => status !== "logged")
    .map(([status, value]) => ({ status, value: value ?? 0 }));
  const total = rows.reduce((s, r) => s + r.value, 0);
  return (
    <Card>
      <CardHeader icon={<IconGauge size={16} />} title="Incident status" subtitle={`${total} routed incidents (low-risk ones are only logged)`} />
      <CardBody className="flex items-center gap-4">
        <div className="relative size-40 shrink-0">
          <ResponsiveContainer>
            <PieChart>
              <Pie data={rows} dataKey="value" nameKey="status" innerRadius={50} outerRadius={72} paddingAngle={2} stroke="none" animationDuration={900}>
                {rows.map((r) => (
                  <Cell key={r.status} fill={STATUS_COLORS[r.status] ?? "#64708a"} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
            <div>
              <div className="font-mono text-2xl font-semibold">{total}</div>
              <div className="text-[10px] uppercase tracking-widest text-faint">incidents</div>
            </div>
          </div>
        </div>
        <ul className="flex-1 space-y-1.5 text-xs">
          {rows
            .sort((a, b) => b.value - a.value)
            .map((r) => (
              <li key={r.status} className="flex items-center gap-2">
                <span className="size-2 rounded-full" style={{ background: STATUS_COLORS[r.status] ?? "#64708a" }} />
                <span className="flex-1 text-dim">{titleCase(r.status)}</span>
                <span className="font-mono text-ink">{r.value}</span>
              </li>
            ))}
        </ul>
      </CardBody>
    </Card>
  );
}

function TopIncidents() {
  const { data, error, isLoading } = useIncidents({ min_risk: 0.5, limit: 8 });
  return (
    <Card className="xl:col-span-2">
      <CardHeader
        icon={<IconStack2 size={16} />}
        title="Highest-priority incidents"
        subtitle="Correlated alerts ranked by priority and risk"
        action={
          <Link href="/incidents" className="text-xs text-brand hover:underline">
            View queue →
          </Link>
        }
      />
      {error ? (
        <ErrorState error={error} />
      ) : isLoading ? (
        <div className="space-y-2 p-5">
          {Array.from({ length: 5 }, (_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : (
        <ul className="divide-y divide-line/60">
          {(data ?? []).map((incident, i) => (
            <motion.li
              key={incident.incident_id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.04 }}
            >
              <Link href={incidentHref(incident.incident_id)} className="grid grid-cols-[auto_1fr_auto] items-center gap-4 px-5 py-3 transition-colors hover:bg-raised/50">
                <PriorityBadge priority={incident.priority} />
                <div className="min-w-0 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-brand">{incident.incident_id}</span>
                    <StatusBadge status={incident.status} />
                    <VerdictBadge verdict={incident.verdict} />
                  </div>
                  <p className="truncate text-xs text-dim">{incident.summary}</p>
                  <div className="max-w-md">
                    <KillChain techniques={incident.techniques} />
                  </div>
                </div>
                <div className="flex flex-col items-end gap-2">
                  <RiskBar risk={incident.risk} />
                  <div className="hidden md:block">
                    <EntityList entities={incident.entities} max={3} linked={false} />
                  </div>
                </div>
              </Link>
            </motion.li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function ActivityFeed() {
  const live = useLive();
  const [filter, setFilter] = useState<keyof typeof FEED_FILTERS>("important");
  const kinds = FEED_FILTERS[filter] as readonly string[] | undefined;
  return (
    <Card className="flex max-h-[560px] flex-col">
      <CardHeader
        icon={<IconBolt size={16} />}
        title={live.mode === "replay" ? "Activity replay" : "Live activity"}
        subtitle="Pipeline events as they happen"
        action={
          <Segmented
            id="feed"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "important", label: "Key" },
              { value: "alerts", label: "Alerts" },
              { value: "all", label: "All" },
            ]}
          />
        }
      />
      {live.mode === "replay" ? (
        <div className="h-0.5 bg-raised">
          <motion.div className="h-full bg-brand" animate={{ width: `${live.progress * 100}%` }} transition={{ ease: "linear" }} />
        </div>
      ) : null}
      <div className="flex-1 overflow-y-auto">
        <LiveFeed events={live.events} kinds={kinds ? [...kinds] : undefined} />
      </div>
    </Card>
  );
}

function AgentCard() {
  const { data: m } = useMetrics();
  const { data: health } = useHealth();
  const decisions = m?.decisions_by ?? {};
  const total = Object.values(decisions).reduce((a, b) => a + b, 0) || 1;
  return (
    <Card>
      <CardHeader icon={<IconRobot size={16} />} title="Triage" subtitle="Who decided, and how" />
      <CardBody className="space-y-4">
        <div className="space-y-2">
          {Object.entries(decisions).map(([by, n]) => (
            <div key={by} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-dim">{titleCase(by)}</span>
                <span className="font-mono text-ink">{n}</span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-raised">
                <motion.div
                  className={by === "agent" ? "h-full bg-brand" : "h-full bg-info"}
                  initial={{ width: 0 }}
                  animate={{ width: `${(n / total) * 100}%` }}
                  transition={{ duration: 0.8 }}
                />
              </div>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(m?.verdicts ?? {}).map(([verdict, n]) => (
            <Badge key={verdict} tone={verdict === "malicious" ? "danger" : verdict === "suspicious" ? "warn" : "ok"}>
              {titleCase(verdict)} · {n}
            </Badge>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="rounded-lg bg-raised/60 p-3 ring-1 ring-line">
            <div className="text-faint">Escalated dismissals</div>
            <div className="mt-1 font-mono text-lg text-ink">{m?.agent.escalated_dismissals ?? 0}</div>
          </div>
          <div className="rounded-lg bg-raised/60 p-3 ring-1 ring-line">
            <div className="text-faint">Prompt injections seen</div>
            <div className="mt-1 font-mono text-lg text-ink">{m?.agent.injection_seen ?? 0}</div>
          </div>
        </div>
        {health?.breaker ? (
          <div className="flex items-center justify-between text-xs">
            <span className="text-dim">Circuit breaker</span>
            <Badge tone={health.breaker === "closed" ? "ok" : "danger"}>{titleCase(health.breaker)}</Badge>
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}

export default function OverviewPage() {
  return (
    <>
      <PageTitle />
      <Kpis />
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <StreamHealthCard />
        <StatusDonut />
        <TopIncidents />
        <ActivityFeed />
        <AgentCard />
      </div>
    </>
  );
}
