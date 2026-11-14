"use client";

import { IconDeviceDesktop, IconSearch, IconServer, IconUser, IconUsers, IconWorld } from "@tabler/icons-react";
import { motion } from "framer-motion";
import Link from "next/link";
import { useMemo, useState } from "react";

import { RiskBar } from "@/components/soc/risk";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { Segmented } from "@/components/ui/tabs";
import { useActions, useIncidents } from "@/lib/queries";
import { entityHref } from "@/lib/utils";

interface Row {
  entity: string;
  kind: "user" | "host" | "ip";
  value: string;
  incidents: number;
  maxRisk: number;
  actions: number;
  malicious: number;
}

const ICON = {
  user: <IconUser size={15} />,
  host: <IconDeviceDesktop size={15} />,
  ip: <IconWorld size={15} />,
};

export default function EntitiesPage() {
  const { data: incidents, error, isLoading } = useIncidents({ limit: 5000 });
  const { data: actions } = useActions();
  const [kind, setKind] = useState<"all" | "user" | "host" | "ip">("all");
  const [text, setText] = useState("");

  const rows = useMemo(() => {
    const map = new Map<string, Row>();
    const touch = (kind: Row["kind"], value: string, risk: number, malicious: boolean) => {
      const entity = `${kind}:${value}`;
      const row = map.get(entity) ?? { entity, kind, value, incidents: 0, maxRisk: 0, actions: 0, malicious: 0 };
      row.incidents += 1;
      row.maxRisk = Math.max(row.maxRisk, risk);
      row.malicious += malicious ? 1 : 0;
      map.set(entity, row);
    };
    for (const incident of incidents ?? []) {
      const bad = incident.verdict === "malicious";
      incident.entities.users.forEach((u) => touch("user", u, incident.risk, bad));
      incident.entities.hosts.forEach((h) => touch("host", h, incident.risk, bad));
      incident.entities.ips.forEach((i) => touch("ip", i, incident.risk, bad));
    }
    for (const action of actions ?? []) {
      for (const row of map.values()) if (row.value === action.target && action.status === "executed") row.actions += 1;
    }
    return [...map.values()].sort((a, b) => b.maxRisk - a.maxRisk || b.incidents - a.incidents);
  }, [incidents, actions]);

  const shown = rows.filter((r) => (kind === "all" || r.kind === kind) && (!text || r.value.toLowerCase().includes(text.toLowerCase())));

  return (
    <>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-gradient text-2xl font-semibold tracking-tight">Entities</h1>
          <p className="mt-1 text-sm text-dim">Accounts, hosts and addresses involved in incidents, by the highest risk they were part of.</p>
        </div>
        <div className="relative w-full max-w-xs">
          <IconSearch size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Find an account, host or IP…"
            className="h-9 w-full rounded-lg bg-raised pl-9 pr-3 text-sm text-ink outline-none ring-1 ring-line placeholder:text-faint focus:ring-brand/60"
          />
        </div>
      </div>
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3">
          <Segmented
            id="entity-kind"
            value={kind}
            onChange={setKind}
            options={[
              { value: "all", label: `All ${rows.length}` },
              { value: "user", label: <span className="inline-flex items-center gap-1"><IconUsers size={12} />Accounts</span> },
              { value: "host", label: <span className="inline-flex items-center gap-1"><IconServer size={12} />Hosts</span> },
              { value: "ip", label: <span className="inline-flex items-center gap-1"><IconWorld size={12} />Addresses</span> },
            ]}
          />
          <span className="ml-auto text-xs text-faint">{shown.length} entities</span>
        </div>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <div className="grid gap-2 p-5 md:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 9 }, (_, i) => (
              <Skeleton key={i} className="h-20" />
            ))}
          </div>
        ) : shown.length ? (
          <div className="grid gap-2 p-5 md:grid-cols-2 xl:grid-cols-3">
            {shown.slice(0, 300).map((row, i) => (
              <motion.div key={row.entity} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i, 18) * 0.02 }}>
                <Link
                  href={entityHref(row.entity)}
                  className="flex items-center gap-3 rounded-xl border border-line bg-raised/30 p-3 transition-colors hover:border-line-strong hover:bg-raised/70"
                >
                  <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-canvas text-dim ring-1 ring-line">{ICON[row.kind]}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-sm text-ink">{row.value}</div>
                    <div className="mt-0.5 text-[11px] text-faint">
                      {row.incidents} incident{row.incidents === 1 ? "" : "s"}
                      {row.malicious ? <span className="text-danger"> · {row.malicious} malicious</span> : null}
                      {row.actions ? <span className="text-ok"> · {row.actions} contained</span> : null}
                    </div>
                  </div>
                  <RiskBar risk={row.maxRisk} />
                </Link>
              </motion.div>
            ))}
          </div>
        ) : (
          <EmptyState icon={<IconUsers size={20} />} title="No entities match" />
        )}
      </Card>
    </>
  );
}
