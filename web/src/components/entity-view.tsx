"use client";

import {
  IconArrowLeft,
  IconBolt,
  IconCpu,
  IconDeviceDesktop,
  IconFingerprint,
  IconNetwork,
  IconServer,
  IconStack2,
  IconTimeline,
  IconUser,
  IconWorld,
} from "@tabler/icons-react";
import { motion } from "framer-motion";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";

import { ActionRow } from "@/components/incident/response";
import { PriorityBadge, StatusBadge, STREAM_META, VerdictBadge } from "@/components/soc/badges";
import { RiskBar } from "@/components/soc/risk";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { Segmented } from "@/components/ui/tabs";
import { fmtBytes, fmtTime } from "@/lib/format";
import { useEntity, useHealth, useTimeline } from "@/lib/queries";
import type { TimelineEvent } from "@/lib/types";
import { cn, incidentHref } from "@/lib/utils";

function Info({ label, value }: { label: string; value: ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex justify-between gap-3 py-1.5 text-sm">
      <span className="text-faint">{label}</span>
      <span className="truncate text-right font-mono text-ink">{value}</span>
    </div>
  );
}

function describe(e: TimelineEvent): string {
  const d = e as Record<string, unknown>;
  if (e.stream === "signin")
    return `${d.user_id} · ${d.logon_type} ${d.outcome}${d.failure_reason ? ` (${d.failure_reason})` : ""} from ${d.src_ip}${d.src_country ? ` ${d.src_country}` : ""}${d.dst_host ? ` → ${d.dst_host}` : ""}`;
  if (e.stream === "flow")
    return `${d.src_ip} → ${d.dst_ip}:${d.dst_port} ${d.service ?? ""} · ${fmtBytes(Number(d.bytes_out ?? 0))} out / ${fmtBytes(Number(d.bytes_in ?? 0))} in${d.dst_org ? ` · ${d.dst_org}` : ""}`;
  const cmd = d.command_line as unknown;
  const text = typeof cmd === "object" && cmd && "$untrusted" in cmd ? String((cmd as { $untrusted: string }).$untrusted) : String(cmd ?? "");
  return `${d.parent_name} → ${d.process_name} as ${d.user_id} · ${text}`;
}

const STREAM_ICON: Record<string, ReactNode> = {
  signin: <IconFingerprint size={13} />,
  flow: <IconNetwork size={13} />,
  process: <IconCpu size={13} />,
};

function EntityTimeline({ entity }: { entity: string }) {
  const { data: health } = useHealth();
  const [hours, setHours] = useState("24");
  const end = health?.now;
  const start = end ? new Date(Date.parse(end) - Number(hours) * 3_600_000).toISOString() : undefined;
  const { data, isLoading } = useTimeline(end ? entity : null, start, end);
  const [stream, setStream] = useState("all");
  const events = useMemo(() => (data?.events ?? []).filter((e) => stream === "all" || e.stream === stream), [data, stream]);
  return (
    <Card>
      <CardHeader
        icon={<IconTimeline size={16} />}
        title="Timeline"
        subtitle={data?.addresses.length ? `addresses used: ${data.addresses.join(", ")}` : "events across the three streams"}
        action={
          <div className="flex gap-2">
            <Segmented
              id="tl-stream"
              value={stream}
              onChange={setStream}
              options={[
                { value: "all", label: "All" },
                { value: "signin", label: "Sign-ins" },
                { value: "flow", label: "Flows" },
                { value: "process", label: "Processes" },
              ]}
            />
            <Segmented
              id="tl-hours"
              value={hours}
              onChange={setHours}
              options={[
                { value: "6", label: "6 h" },
                { value: "24", label: "24 h" },
                { value: "72", label: "72 h" },
              ]}
            />
          </div>
        }
      />
      {isLoading ? (
        <div className="space-y-2 p-5">
          {Array.from({ length: 8 }, (_, i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </div>
      ) : events.length ? (
        <ol className="relative max-h-[640px] overflow-y-auto px-5 py-3">
          <span className="absolute bottom-3 left-[33px] top-3 w-px bg-line" />
          {events.slice(0, 300).map((event, i) => {
            const meta = STREAM_META[event.stream];
            return (
              <motion.li
                key={event.event_id}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: Math.min(i, 30) * 0.012 }}
                className="relative flex items-start gap-3 py-1.5"
              >
                <span className="z-10 mt-0.5 grid size-6 shrink-0 place-items-center rounded-md bg-canvas ring-1 ring-line" style={{ color: meta.color }}>
                  {STREAM_ICON[event.stream]}
                </span>
                <span className="w-24 shrink-0 font-mono text-[11px] leading-6 text-faint">{fmtTime(event.event_time, "EEE HH:mm:ss")}</span>
                <span className="min-w-0 flex-1 truncate text-xs leading-6 text-dim" title={describe(event)}>
                  {describe(event)}
                </span>
              </motion.li>
            );
          })}
        </ol>
      ) : (
        <EmptyState icon={<IconTimeline size={20} />} title="No events in this window" />
      )}
    </Card>
  );
}

export function EntityView() {
  const entity = useSearchParams().get("e");
  const { data, error, isLoading } = useEntity(entity);
  if (!entity) return <EmptyState title="No entity selected" />;
  if (error) return <ErrorState error={error} />;
  if (isLoading || !data) return <Skeleton className="h-96 w-full" />;
  const value = entity.split(":").slice(1).join(":");
  const icon =
    data.kind === "user" ? <IconUser size={22} /> : data.kind === "host" ? (value.startsWith("WS-") ? <IconDeviceDesktop size={22} /> : <IconServer size={22} />) : <IconWorld size={22} />;
  const hours = (data.baseline?.local_hours ?? []).map((n, h) => ({ h, n }));
  return (
    <div className="space-y-4">
      <Link href="/entities" className="inline-flex items-center gap-1 text-xs text-dim hover:text-ink">
        <IconArrowLeft size={14} /> Entities
      </Link>
      <div className="grid gap-4 xl:grid-cols-[380px_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card>
            <CardBody className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="grid size-12 place-items-center rounded-xl bg-brand/10 text-brand ring-1 ring-brand/30">{icon}</span>
                <div className="min-w-0">
                  <h1 className="truncate font-mono text-lg font-semibold">{value}</h1>
                  <div className="flex flex-wrap gap-1">
                    <Badge>{data.kind}</Badge>
                    {data.account_kind ? <Badge tone={data.account_kind === "admin" ? "warn" : "neutral"}>{data.account_kind}</Badge> : null}
                    {data.host ? <Badge tone={data.host.criticality >= 4 ? "danger" : "neutral"}>criticality {data.host.criticality}</Badge> : null}
                  </div>
                </div>
              </div>
              <div className="divide-y divide-line/60">
                {data.user ? (
                  <>
                    <Info label="Name" value={data.user.display_name} />
                    <Info label="Role" value={data.user.role} />
                    <Info label="Department" value={data.user.department} />
                    <Info label="Office" value={data.user.office} />
                    <Info label="Workstation" value={data.user.workstation} />
                    <Info label="Admin account" value={data.user.admin_account} />
                  </>
                ) : null}
                {data.host ? (
                  <>
                    <Info label="Kind" value={data.host.kind} />
                    <Info label="Role" value={data.host.role} />
                    <Info label="Zone" value={data.host.zone} />
                    <Info label="OS" value={data.host.os} />
                    <Info label="Owner" value={data.host.owner} />
                    <Info label="Static IP" value={data.host.static_ip} />
                    <Info label="Office" value={data.host.office} />
                  </>
                ) : null}
                {data.kind === "ip" ? (
                  <>
                    <Info label="Zone" value={data.zone} />
                    <Info label="Organisation" value={data.geo?.org} />
                    <Info label="Location" value={data.geo ? `${data.geo.city}, ${data.geo.country}` : null} />
                    <Info label="ASN" value={data.geo?.asn} />
                    <Info label="Category" value={data.geo?.category} />
                  </>
                ) : null}
              </div>
            </CardBody>
          </Card>
          {data.baseline ? (
            <Card>
              <CardHeader icon={<IconFingerprint size={16} />} title="Sign-in baseline" subtitle={`${data.baseline.successful_signins} successful sign-ins in the history`} />
              <CardBody className="space-y-3">
                <div className="h-28">
                  <ResponsiveContainer>
                    <BarChart data={hours}>
                      <XAxis dataKey="h" stroke="#64708a" fontSize={10} tickLine={false} axisLine={false} interval={3} />
                      <Tooltip
                        cursor={{ fill: "#1a2230" }}
                        contentStyle={{ background: "#151b26", border: "1px solid #2e394c", borderRadius: 8, fontSize: 11 }}
                        labelFormatter={(h) => `${h}:00 local`}
                      />
                      <Bar dataKey="n" fill="#a78bfa" radius={[3, 3, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap gap-1">
                  {Object.entries(data.baseline.usual_countries).map(([country, n]) => (
                    <Badge key={country} tone="signin">
                      {country} · {n}
                    </Badge>
                  ))}
                  {data.baseline.logon_types.map((t) => (
                    <Badge key={t}>{t}</Badge>
                  ))}
                </div>
              </CardBody>
            </Card>
          ) : null}
          <Card>
            <CardHeader icon={<IconBolt size={16} />} title="Actions on this entity" subtitle={`${data.actions.length} actions`} />
            {data.actions.length ? (
              <ul className="divide-y divide-line/60">
                {data.actions.map((a) => (
                  <ActionRow key={a.action_id} action={a} compact />
                ))}
              </ul>
            ) : (
              <EmptyState title="Never contained" />
            )}
          </Card>
        </div>
        <div className="space-y-4">
          <Card>
            <CardHeader icon={<IconStack2 size={16} />} title="Incidents" subtitle={`${data.incidents.length} incidents involve ${value}`} />
            {data.incidents.length ? (
              <ul className="divide-y divide-line/60">
                {data.incidents.map((incident) => (
                  <li key={incident.incident_id}>
                    <Link href={incidentHref(incident.incident_id)} className={cn("flex flex-wrap items-center gap-2 px-5 py-3 transition-colors hover:bg-raised/50")}>
                      <PriorityBadge priority={incident.priority} />
                      <span className="font-mono text-sm text-brand">{incident.incident_id}</span>
                      <StatusBadge status={incident.status} />
                      <VerdictBadge verdict={incident.verdict} />
                      <span className="min-w-0 flex-1 truncate text-xs text-dim">{incident.summary}</span>
                      <RiskBar risk={incident.risk} />
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="No incidents" />
            )}
          </Card>
          <EntityTimeline entity={entity} />
        </div>
      </div>
    </div>
  );
}
