"use client";

import { IconBolt, IconSearch, IconStack2 } from "@tabler/icons-react";
import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import { useMemo, useState } from "react";

import { DecidedBy, DetectorBadge, PriorityBadge, StatusBadge, VerdictBadge } from "@/components/soc/badges";
import { EntityList, KillChain, TechniqueChip } from "@/components/soc/entities";
import { RiskBar } from "@/components/soc/risk";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { Segmented } from "@/components/ui/tabs";
import { fmtSince, fmtTime } from "@/lib/format";
import { useIncidents } from "@/lib/queries";
import type { IncidentSummary } from "@/lib/types";
import { incidentHref } from "@/lib/utils";

const VIEWS = {
  active: ["open", "queued", "triaging", "awaiting_approval"],
  contained: ["contained"],
  dismissed: ["dismissed", "closed"],
  logged: ["logged"],
  all: undefined,
} as const;

const RISK = { all: 0, medium: 0.5, high: 0.7, critical: 0.85 } as const;

function matches(incident: IncidentSummary, text: string) {
  if (!text) return true;
  const needle = text.toLowerCase();
  return [
    incident.incident_id,
    incident.summary,
    ...incident.entities.users,
    ...incident.entities.hosts,
    ...incident.entities.ips,
    ...incident.techniques,
  ].some((v) => v.toLowerCase().includes(needle));
}

function Row({ incident, index }: { incident: IncidentSummary; index: number }) {
  return (
    <motion.li
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, x: -10 }}
      transition={{ duration: 0.3, delay: Math.min(index, 12) * 0.025 }}
    >
      <Link
        href={incidentHref(incident.incident_id)}
        className="group grid gap-3 px-5 py-4 transition-colors hover:bg-raised/50 md:grid-cols-[auto_minmax(0,1fr)_auto]"
      >
        <div className="flex items-start gap-3 md:block">
          <PriorityBadge priority={incident.priority} />
        </div>
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-sm font-medium text-brand group-hover:underline">{incident.incident_id}</span>
            <StatusBadge status={incident.status} />
            <VerdictBadge verdict={incident.verdict} />
            <DecidedBy by={incident.decided_by} />
            {incident.actions ? (
              <span className="inline-flex items-center gap-1 text-xs text-ok">
                <IconBolt size={12} />
                {incident.actions}
              </span>
            ) : null}
          </div>
          <p className="line-clamp-2 text-sm text-dim">{incident.summary || "—"}</p>
          <div className="flex flex-wrap items-center gap-1">
            {incident.detectors.map((d) => (
              <DetectorBadge key={d} detector={d} />
            ))}
            {incident.techniques.slice(0, 6).map((t) => (
              <TechniqueChip key={t} technique={t} />
            ))}
            {incident.techniques.length > 6 ? <span className="text-xs text-faint">+{incident.techniques.length - 6}</span> : null}
          </div>
          <div className="max-w-lg">
            <KillChain techniques={incident.techniques} />
          </div>
        </div>
        <div className="flex flex-col items-start gap-2 md:items-end">
          <RiskBar risk={incident.risk} />
          <div className="text-right font-mono text-[11px] text-faint">
            {fmtTime(incident.first_seen)} → {fmtTime(incident.last_seen, "HH:mm")}
            <span className="ml-1.5 text-dim">({fmtSince(incident.first_seen, incident.last_seen)})</span>
          </div>
          <div className="text-[11px] text-faint">{incident.alerts} alerts</div>
          <div className="hidden max-w-xs md:block">
            <EntityList entities={incident.entities} max={4} linked={false} />
          </div>
        </div>
      </Link>
    </motion.li>
  );
}

export default function IncidentsPage() {
  const [view, setView] = useState<keyof typeof VIEWS>("all");
  const [risk, setRisk] = useState<keyof typeof RISK>("medium");
  const [text, setText] = useState("");
  const status = VIEWS[view];
  const { data, error, isLoading } = useIncidents({ status: status ? [...status] : undefined, min_risk: RISK[risk], limit: 1000 });
  const shown = useMemo(() => (data ?? []).filter((i) => matches(i, text)), [data, text]);

  return (
    <>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-gradient text-2xl font-semibold tracking-tight">Incident queue</h1>
          <p className="mt-1 text-sm text-dim">
            Alerts the correlation engine linked by shared entities and time, ranked by priority and risk.
          </p>
        </div>
        <div className="relative w-full max-w-xs">
          <IconSearch size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Filter by ID, entity, technique…"
            className="h-9 w-full rounded-lg bg-raised pl-9 pr-3 text-sm text-ink outline-none ring-1 ring-line placeholder:text-faint focus:ring-brand/60"
          />
        </div>
      </div>
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3">
          <Segmented
            id="incident-view"
            value={view}
            onChange={setView}
            options={[
              { value: "all", label: "All" },
              { value: "active", label: "Active" },
              { value: "contained", label: "Contained" },
              { value: "dismissed", label: "Dismissed / closed" },
              { value: "logged", label: "Logged" },
            ]}
          />
          <Segmented
            id="incident-risk"
            value={risk}
            onChange={setRisk}
            options={[
              { value: "all", label: "Any risk" },
              { value: "medium", label: "≥ 0.5" },
              { value: "high", label: "≥ 0.7" },
              { value: "critical", label: "≥ 0.85" },
            ]}
          />
          <span className="ml-auto text-xs text-faint">{shown.length} incidents</span>
        </div>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <div className="space-y-3 p-5">
            {Array.from({ length: 6 }, (_, i) => (
              <Skeleton key={i} className="h-24 w-full" />
            ))}
          </div>
        ) : shown.length ? (
          <ul className="divide-y divide-line/60">
            <AnimatePresence initial={false}>
              {shown.map((incident, i) => (
                <Row key={incident.incident_id} incident={incident} index={i} />
              ))}
            </AnimatePresence>
          </ul>
        ) : (
          <EmptyState icon={<IconStack2 size={20} />} title="No incidents match">
            Low-risk incidents are only logged; widen the risk filter to see them.
          </EmptyState>
        )}
      </Card>
    </>
  );
}
