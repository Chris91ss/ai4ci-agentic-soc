"use client";

import { IconChevronDown, IconDatabase, IconFileSearch, IconStar, IconStarFilled, IconTool, IconUserCheck } from "@tabler/icons-react";
import { AnimatePresence, motion } from "framer-motion";
import { useMemo, useState, type ReactNode } from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";

import { Badge } from "@/components/ui/badge";
import { JsonView } from "@/components/ui/json-view";
import { EmptyState, Skeleton } from "@/components/ui/states";
import { Segmented } from "@/components/ui/tabs";
import { fmtBytes, fmtNumber, fmtTime } from "@/lib/format";
import { useEvidence } from "@/lib/queries";
import type { EvidenceItem } from "@/lib/types";
import { cn } from "@/lib/utils";

import { DetectorBadge, StreamBadge } from "../soc/badges";
import { EntityChip } from "../soc/entities";

const KIND_META: Record<string, { label: string; icon: ReactNode }> = {
  alert: { label: "Alert", icon: <IconFileSearch size={14} /> },
  event: { label: "Event", icon: <IconDatabase size={14} /> },
  baseline: { label: "Baseline", icon: <IconUserCheck size={14} /> },
  tool_call: { label: "Tool call", icon: <IconTool size={14} /> },
};

function summary(item: EvidenceItem): string {
  const d = item.data as Record<string, unknown>;
  switch (item.kind) {
    case "alert":
      return String(d.summary ?? "");
    case "event": {
      if (item.stream === "signin")
        return `${d.user_id ?? ""} ${d.logon_type ?? ""} ${d.outcome ?? ""} from ${d.src_ip ?? ""}${d.src_country ? ` (${d.src_country})` : ""}`;
      if (item.stream === "flow")
        return `${d.src_ip ?? ""} → ${d.dst_ip ?? ""}:${d.dst_port ?? ""} ${d.service ?? ""} · ${fmtBytes(Number(d.bytes_out ?? 0))} out`;
      return `${d.parent_name ?? ""} → ${d.process_name ?? ""} on ${d.host_id ?? ""} as ${d.user_id ?? ""}`;
    }
    case "baseline":
      if ("usual_countries" in d) return `usual countries ${Object.keys((d.usual_countries as object) ?? {}).join(", ") || "—"} · ${d.successful_signins ?? 0} sign-ins in the baseline`;
      if ("traffic_before" in d) {
        const before = d.traffic_before as Record<string, number>;
        const during = d.traffic_during as Record<string, number>;
        return `${d.role ?? ""} · ${fmtNumber(before.flows)} flows in the 24 h before, ${fmtNumber(during.flows)} during`;
      }
      if ("geo" in d && d.geo) {
        const geo = d.geo as Record<string, string>;
        return `${geo.org} · ${geo.city}, ${geo.country} · ${geo.category}`;
      }
      return String(d.note ?? "");
    case "tool_call":
      return `${d.tool}(${Object.entries((d.arguments as object) ?? {})
        .filter(([, v]) => v !== null)
        .map(([k, v]) => `${k}=${String(v).slice(0, 24)}`)
        .join(", ")})`;
    default:
      return "";
  }
}

function HoursChart({ hours }: { hours: number[] }) {
  const data = hours.map((n, h) => ({ h, n }));
  return (
    <div className="h-28">
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
          <XAxis dataKey="h" stroke="#64708a" fontSize={10} tickLine={false} axisLine={false} interval={3} />
          <Tooltip
            cursor={{ fill: "#1a2230" }}
            contentStyle={{ background: "#151b26", border: "1px solid #2e394c", borderRadius: 8, fontSize: 11 }}
            labelFormatter={(h) => `${h}:00 local`}
            formatter={(v) => [v, "sign-ins"]}
          />
          <Bar dataKey="n" fill="#a78bfa" radius={[3, 3, 0, 0]} animationDuration={700} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TrafficCompare({ before, during }: { before: Record<string, number>; during: Record<string, number> }) {
  const rate = (v: Record<string, number>, key: string) => (v[key] ?? 0) / Math.max(v.hours ?? 1, 0.01);
  const rows = [
    { key: "flows", label: "flows / h" },
    { key: "bytes_out", label: "bytes out / h", bytes: true },
    { key: "external_destinations", label: "external destinations / h" },
  ];
  return (
    <div className="space-y-2">
      {rows.map((row) => {
        const a = rate(before, row.key);
        const b = rate(during, row.key);
        const max = Math.max(a, b, 1e-9);
        return (
          <div key={row.key} className="grid grid-cols-[150px_1fr] items-center gap-3 text-xs">
            <span className="text-faint">{row.label}</span>
            <div className="space-y-1">
              {[
                ["before", a, "bg-line-strong"],
                ["during", b, b > a * 3 ? "bg-danger" : "bg-flow"],
              ].map(([label, value, color]) => (
                <div key={String(label)} className="flex items-center gap-2">
                  <span className="w-12 text-faint">{String(label)}</span>
                  <div className="h-2 flex-1 rounded-full bg-canvas">
                    <motion.div className={cn("h-full rounded-full", String(color))} initial={{ width: 0 }} animate={{ width: `${(Number(value) / max) * 100}%` }} />
                  </div>
                  <span className="w-20 text-right font-mono text-dim">{row.bytes ? fmtBytes(Number(value)) : fmtNumber(Number(value))}</span>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Row({ item }: { item: EvidenceItem }) {
  const [open, setOpen] = useState(false);
  const d = item.data as Record<string, unknown>;
  return (
    <li className={cn("px-4 py-2.5", item.cited && "bg-brand/[0.04]")}>
      <button onClick={() => setOpen(!open)} className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 text-left">
        <span className={cn("grid size-7 place-items-center rounded-lg ring-1", item.cited ? "bg-brand/10 text-brand ring-brand/30" : "bg-raised text-faint ring-line")}>
          {KIND_META[item.kind]?.icon}
        </span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-xs text-ink">{item.ref_id}</span>
            {item.cited ? (
              <Badge tone="brand" icon={<IconStarFilled size={10} />}>
                cited
              </Badge>
            ) : null}
            <StreamBadge stream={item.stream} />
            {item.detector ? <DetectorBadge detector={item.detector} /> : null}
          </div>
          <p className="mt-0.5 truncate text-xs text-dim">{summary(item)}</p>
        </div>
        <div className="flex items-center gap-2">
          {item.entity ? <EntityChip entity={item.entity} className="hidden md:inline-flex" /> : null}
          <span className="font-mono text-[11px] text-faint">{fmtTime(item.time, "EEE HH:mm:ss")}</span>
          <motion.span animate={{ rotate: open ? 180 : 0 }} className="text-faint">
            <IconChevronDown size={14} />
          </motion.span>
        </div>
      </button>
      <AnimatePresence initial={false}>
        {open ? (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="mt-3 space-y-3 pl-10">
              {Array.isArray(d.local_hours) ? (
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-wider text-faint">Usual sign-in hours (local time)</div>
                  <HoursChart hours={d.local_hours as number[]} />
                </div>
              ) : null}
              {d.traffic_before && d.traffic_during ? (
                <TrafficCompare before={d.traffic_before as Record<string, number>} during={d.traffic_during as Record<string, number>} />
              ) : null}
              <JsonView value={item.data} className="max-h-80" defaultOpen={1} />
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </li>
  );
}

/** Everything behind the verdicts of an incident, filterable as the RFC asks. */
export function EvidenceExplorer({ incidentId, cited }: { incidentId: string; cited: string[] }) {
  const [kind, setKind] = useState("all");
  const [only, setOnly] = useState("all");
  const [stream, setStream] = useState("all");
  const [detector, setDetector] = useState("all");
  const [entity, setEntity] = useState("");
  const { data, isLoading } = useEvidence(incidentId, {});
  const entities = useMemo(() => [...new Set((data ?? []).map((e) => e.entity).filter(Boolean) as string[])].sort(), [data]);
  const shown = useMemo(
    () =>
      (data ?? []).filter(
        (e) =>
          (kind === "all" || e.kind === kind) &&
          (only === "all" || e.cited) &&
          (stream === "all" || e.stream === stream) &&
          (detector === "all" || e.detector === detector) &&
          (!entity || e.entity === entity),
      ),
    [data, kind, only, stream, detector, entity],
  );
  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const e of data ?? []) out[e.kind] = (out[e.kind] ?? 0) + 1;
    return out;
  }, [data]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        <Segmented
          id="ev-kind"
          value={kind}
          onChange={setKind}
          options={[
            { value: "all", label: `All ${data?.length ?? ""}` },
            ...Object.entries(KIND_META).map(([k, meta]) => ({ value: k, label: `${meta.label}s ${counts[k] ?? 0}` })),
          ]}
        />
        <Segmented
          id="ev-cited"
          value={only}
          onChange={setOnly}
          options={[
            { value: "all", label: "Everything" },
            { value: "cited", label: <span className="inline-flex items-center gap-1"><IconStar size={11} />Cited {cited.length}</span> },
          ]}
        />
        <Segmented
          id="ev-stream"
          value={stream}
          onChange={setStream}
          options={[
            { value: "all", label: "All streams" },
            { value: "signin", label: "Sign-ins" },
            { value: "flow", label: "Flows" },
            { value: "process", label: "Processes" },
          ]}
        />
        <Segmented
          id="ev-detector"
          value={detector}
          onChange={setDetector}
          options={[
            { value: "all", label: "Any detector" },
            { value: "M1", label: "M1" },
            { value: "M2", label: "M2" },
            { value: "M3", label: "M3" },
          ]}
        />
        <select
          value={entity}
          onChange={(e) => setEntity(e.target.value)}
          className="h-8 max-w-52 rounded-lg bg-raised px-2 font-mono text-xs text-dim outline-none ring-1 ring-line"
        >
          <option value="">Any entity</option>
          {entities.map((e) => (
            <option key={e} value={e}>
              {e}
            </option>
          ))}
        </select>
        <span className="ml-auto text-xs text-faint">{shown.length} items</span>
      </div>
      {isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-11 w-full" />
          ))}
        </div>
      ) : shown.length ? (
        <ul className="max-h-[70vh] divide-y divide-line/50 overflow-y-auto">
          {shown.slice(0, 400).map((item) => (
            <Row key={`${item.kind}-${item.ref_id}`} item={item} />
          ))}
        </ul>
      ) : (
        <EmptyState icon={<IconDatabase size={20} />} title="No evidence matches the filters">
          Evidence bundles are stored with every decision; undecided incidents have none yet.
        </EmptyState>
      )}
    </div>
  );
}
