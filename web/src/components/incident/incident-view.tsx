"use client";

import {
  IconArrowLeft,
  IconBolt,
  IconDatabase,
  IconFileSearch,
  IconRobot,
  IconShieldCheck,
  IconTimeline,
} from "@tabler/icons-react";
import { motion } from "framer-motion";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { DecidedBy, DetectorBadge, PriorityBadge, StatusBadge, VerdictBadge } from "@/components/soc/badges";
import { EntityChip, KillChain, TechniqueChip } from "@/components/soc/entities";
import { RiskGauge } from "@/components/soc/risk";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { TabPanel, Tabs } from "@/components/ui/tabs";
import { fmtDateTime, fmtSince } from "@/lib/format";
import { useIncident, useTrace } from "@/lib/queries";
import type { Alert } from "@/lib/types";

import { AlertCard } from "./alert-card";
import { AlertLanes } from "./alert-lanes";
import { EvidenceExplorer } from "./evidence";
import { ActionsPanel, FeedbackPanel } from "./response";
import { AgentTrace } from "./trace";

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wider text-faint">{label}</div>
      <div className="mt-1 text-sm text-ink">{children}</div>
    </div>
  );
}

export function IncidentView() {
  const id = useSearchParams().get("id");
  const { data, error, isLoading } = useIncident(id);
  const { data: trace } = useTrace(id);
  const [tab, setTab] = useState("timeline");
  const [selected, setSelected] = useState<Alert | null>(null);
  const truthCited = useMemo(() => new Set(data?.cited ?? []), [data]);

  if (!id) return <EmptyState title="No incident selected">Pick one from the incident queue.</EmptyState>;
  if (error) return <ErrorState error={error} />;
  if (isLoading || !data)
    return (
      <div className="space-y-4">
        <Skeleton className="h-44 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );

  const { incident, alerts, decisions, actions, feedback } = data;
  const entities = [
    ...incident.entities.users.map((u) => `user:${u}`),
    ...incident.entities.hosts.map((h) => `host:${h}`),
    ...incident.entities.ips.map((i) => `ip:${i}`),
  ];
  const latest = decisions[decisions.length - 1];
  const focus = selected ?? alerts[0];

  return (
    <div className="space-y-4">
      <Link href="/incidents" className="inline-flex items-center gap-1 text-xs text-dim hover:text-ink">
        <IconArrowLeft size={14} /> Incident queue
      </Link>
      <Card className="relative overflow-hidden">
        <div className="pointer-events-none absolute -right-20 -top-20 size-64 rounded-full bg-danger/10 blur-3xl" style={{ opacity: incident.risk }} />
        <div className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1fr)_auto]">
          <div className="min-w-0 space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <PriorityBadge priority={incident.priority} />
              <motion.h1 initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} className="font-mono text-xl font-semibold tracking-tight">
                {incident.incident_id}
              </motion.h1>
              <StatusBadge status={incident.status} />
              <VerdictBadge verdict={incident.verdict} />
              <DecidedBy by={incident.decided_by} model={latest?.model} />
              {incident.confidence !== null ? <Badge>confidence {Math.round((incident.confidence ?? 0) * 100)}%</Badge> : null}
            </div>
            <p className="max-w-3xl text-sm leading-relaxed text-dim">{incident.summary}</p>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Fact label="First seen">{fmtDateTime(incident.first_seen)}</Fact>
              <Fact label="Last seen">{fmtDateTime(incident.last_seen)}</Fact>
              <Fact label="Span">{fmtSince(incident.first_seen, incident.last_seen)}</Fact>
              <Fact label="Alerts">
                {alerts.length} <span className="text-faint">from {incident.detectors.join(", ")}</span>
              </Fact>
            </div>
            <div className="space-y-2">
              <div className="flex flex-wrap gap-1">
                {incident.detectors.map((d) => (
                  <DetectorBadge key={d} detector={d} />
                ))}
                {incident.techniques.map((t) => (
                  <TechniqueChip key={t} technique={t} />
                ))}
              </div>
              <div className="max-w-xl">
                <KillChain techniques={incident.techniques} />
              </div>
            </div>
            <div className="flex flex-wrap gap-1">
              {entities.slice(0, 24).map((e) => (
                <EntityChip key={e} entity={e} />
              ))}
              {entities.length > 24 ? <span className="self-center text-xs text-faint">+{entities.length - 24} more</span> : null}
            </div>
          </div>
          <div className="flex flex-col items-center justify-center gap-2">
            <RiskGauge risk={incident.risk} size={156} />
            <div className="text-xs text-faint">route: {incident.route ?? "—"}</div>
          </div>
        </div>
      </Card>

      <Card>
        <Tabs
          id="incident"
          value={tab}
          onValueChange={setTab}
          items={[
            { value: "timeline", label: "Timeline", icon: <IconTimeline size={15} />, count: alerts.length },
            { value: "trace", label: "Agent trace", icon: <IconRobot size={15} />, count: decisions.length },
            { value: "evidence", label: "Evidence", icon: <IconDatabase size={15} />, count: Object.values(data.evidence_counts).reduce((a, b) => a + b, 0) },
            { value: "response", label: "Response", icon: <IconShieldCheck size={15} />, count: actions.length },
          ]}
        >
          <TabPanel value="timeline" className="space-y-4 p-5">
            <AlertLanes alerts={alerts} decisions={decisions} actions={actions} onSelect={setSelected} selected={focus?.alert_id} />
            {focus ? <AlertCard alert={focus} /> : null}
            <div>
              <div className="mb-2 text-[11px] uppercase tracking-wider text-faint">Strongest alerts</div>
              <div className="grid gap-2 md:grid-cols-2">
                {alerts.slice(0, 8).map((alert) => (
                  <button
                    key={alert.alert_id}
                    onClick={() => setSelected(alert)}
                    className="flex items-center gap-2 rounded-lg bg-raised/40 px-3 py-2 text-left text-xs ring-1 ring-line transition-colors hover:bg-raised"
                  >
                    <DetectorBadge detector={alert.detector} />
                    <span className="truncate text-dim">{alert.summary}</span>
                    {truthCited.has(alert.alert_id) ? <Badge tone="brand">cited</Badge> : null}
                    <span className="ml-auto font-mono text-ink">{alert.score.toFixed(3)}</span>
                  </button>
                ))}
              </div>
            </div>
          </TabPanel>
          <TabPanel value="trace" className="p-5">
            <AgentTrace decisions={trace?.decisions ?? decisions} calls={trace?.tool_calls ?? []} />
          </TabPanel>
          <TabPanel value="evidence">
            <EvidenceExplorer incidentId={incident.incident_id} cited={data.cited} />
          </TabPanel>
          <TabPanel value="response" className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_380px]">
            <div className="border-line lg:border-r">
              <CardHeader icon={<IconBolt size={16} />} title="Containment" subtitle="Through the policy gate; high-impact actions need approval" />
              <ActionsPanel actions={actions} />
            </div>
            <div>
              <CardHeader icon={<IconFileSearch size={16} />} title="Analyst verdict" subtitle="Feedback on the incident's alerts" />
              <CardBody className="p-0">
                <FeedbackPanel incidentId={incident.incident_id} feedback={feedback} />
              </CardBody>
            </div>
          </TabPanel>
        </Tabs>
      </Card>
    </div>
  );
}
