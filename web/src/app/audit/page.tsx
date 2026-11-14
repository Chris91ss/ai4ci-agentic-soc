"use client";

import { IconFingerprint, IconLink, IconShieldCheck, IconShieldX } from "@tabler/icons-react";
import { motion } from "framer-motion";
import Link from "next/link";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { Segmented } from "@/components/ui/tabs";
import { fmtDateTime, titleCase } from "@/lib/format";
import { useAudit, useAuditVerification } from "@/lib/queries";
import { incidentHref } from "@/lib/utils";

function actorTone(actor: string) {
  if (actor.startsWith("agent")) return "brand" as const;
  if (actor.startsWith("analyst")) return "warn" as const;
  if (actor === "playbook") return "info" as const;
  if (actor === "policy-gate") return "danger" as const;
  return "neutral" as const;
}

export default function AuditPage() {
  const { data, error, isLoading } = useAudit();
  const { data: verification } = useAuditVerification();
  const [who, setWho] = useState("all");
  const shown = useMemo(
    () =>
      (data ?? []).filter(
        (e) =>
          who === "all" ||
          (who === "agent" && e.actor.startsWith("agent")) ||
          (who === "analyst" && e.actor.startsWith("analyst")) ||
          (who === "machine" && !e.actor.startsWith("agent") && !e.actor.startsWith("analyst")),
      ),
    [data, who],
  );
  return (
    <>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-gradient text-2xl font-semibold tracking-tight">Audit log</h1>
          <p className="mt-1 text-sm text-dim">
            Every decision, proposal, approval and execution, in a hash chain: each entry&apos;s hash covers the previous one.
          </p>
        </div>
        {verification ? (
          <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}>
            <Badge
              tone={verification.ok ? "ok" : "danger"}
              icon={verification.ok ? <IconShieldCheck size={13} /> : <IconShieldX size={13} />}
              className="h-8 px-3 text-xs"
            >
              {verification.ok ? "Hash chain verified" : `Chain broken at entry ${verification.first_broken}`}
            </Badge>
          </motion.div>
        ) : null}
      </div>
      <Card>
        <CardHeader
          icon={<IconFingerprint size={16} />}
          title="Entries"
          subtitle="Newest first"
          action={
            <Segmented
              id="audit-who"
              value={who}
              onChange={setWho}
              options={[
                { value: "all", label: "Everyone" },
                { value: "agent", label: "Agent" },
                { value: "analyst", label: "Analysts" },
                { value: "machine", label: "Playbooks · gate · executor" },
              ]}
            />
          }
        />
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <div className="space-y-2 p-5">
            {Array.from({ length: 8 }, (_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : shown.length ? (
          <ol className="divide-y divide-line/60">
            {shown.map((entry, i) => {
              const details = entry.details as Record<string, unknown>;
              const incident = (details.incident_id as string | undefined) ?? (entry.object_type === "incident" ? entry.object_id : undefined);
              return (
                <motion.li
                  key={entry.seq}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: Math.min(i, 20) * 0.015 }}
                  className="grid gap-2 px-5 py-3 md:grid-cols-[70px_170px_minmax(0,1fr)_auto]"
                >
                  <span className="font-mono text-xs text-faint">#{entry.seq}</span>
                  <span className="font-mono text-xs text-dim">{fmtDateTime(entry.ts)}</span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge tone={actorTone(entry.actor)}>{entry.actor}</Badge>
                      <span className="text-sm text-ink">{titleCase(entry.action)}</span>
                      <span className="font-mono text-xs text-faint">
                        {entry.object_type} {entry.object_id}
                      </span>
                      {incident ? (
                        <Link href={incidentHref(incident)} className="font-mono text-xs text-brand hover:underline">
                          {incident}
                        </Link>
                      ) : null}
                    </div>
                    <p className="mt-0.5 truncate font-mono text-[11px] text-faint">
                      {Object.entries(details)
                        .filter(([k]) => k !== "incident_id")
                        .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
                        .join("  ")}
                    </p>
                  </div>
                  <span className="flex items-center gap-1 font-mono text-[10px] text-faint" title={`prev ${entry.prev_hash}\nhash ${entry.hash}`}>
                    <IconLink size={12} />
                    {entry.prev_hash.slice(0, 6)}→{entry.hash.slice(0, 6)}
                  </span>
                </motion.li>
              );
            })}
          </ol>
        ) : (
          <EmptyState icon={<IconFingerprint size={20} />} title="Nothing audited yet" />
        )}
      </Card>
    </>
  );
}
