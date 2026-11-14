"use client";

import { IconBolt, IconHourglass } from "@tabler/icons-react";
import { useMemo, useState } from "react";

import { ActionRow } from "@/components/incident/response";
import { ACTION_META } from "@/components/soc/badges";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { Segmented } from "@/components/ui/tabs";
import { DATA_MODE } from "@/lib/api";
import { useActions } from "@/lib/queries";

const VIEWS = {
  pending: ["pending_approval"],
  executed: ["executed"],
  refused: ["denied", "rejected", "failed"],
  all: undefined,
} as const;

export default function ActionsPage() {
  const [view, setView] = useState<keyof typeof VIEWS>("all");
  const { data, error, isLoading } = useActions();
  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const a of data ?? []) out[a.status] = (out[a.status] ?? 0) + 1;
    return out;
  }, [data]);
  const statuses = VIEWS[view] as readonly string[] | undefined;
  const shown = (data ?? []).filter((a) => !statuses || statuses.includes(a.status));
  const byType = useMemo(() => {
    const out: Record<string, number> = {};
    for (const a of data ?? []) if (a.status === "executed") out[a.type] = (out[a.type] ?? 0) + 1;
    return out;
  }, [data]);

  return (
    <>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-gradient text-2xl font-semibold tracking-tight">Containment actions</h1>
          <p className="mt-1 text-sm text-dim">
            Everything the agent and the playbooks proposed, as the policy gate decided it. High-impact actions wait for an analyst
            {DATA_MODE === "static" ? " (read-only in this recorded run)" : ""}.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(byType).map(([type, n]) => (
            <Badge key={type} tone="ok" icon={ACTION_META[type as keyof typeof ACTION_META]?.icon}>
              {ACTION_META[type as keyof typeof ACTION_META]?.label ?? type} · {n}
            </Badge>
          ))}
        </div>
      </div>
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3">
          <Segmented
            id="action-view"
            value={view}
            onChange={setView}
            options={[
              { value: "all", label: `All ${data?.length ?? 0}` },
              {
                value: "pending",
                label: (
                  <span className="inline-flex items-center gap-1">
                    <IconHourglass size={12} />
                    Awaiting approval {counts.pending_approval ?? 0}
                  </span>
                ),
              },
              { value: "executed", label: `Executed ${counts.executed ?? 0}` },
              { value: "refused", label: `Denied / rejected ${(counts.denied ?? 0) + (counts.rejected ?? 0) + (counts.failed ?? 0)}` },
            ]}
          />
        </div>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <div className="space-y-2 p-5">
            {Array.from({ length: 5 }, (_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : shown.length ? (
          <ul className="divide-y divide-line/60">
            {shown.map((action) => (
              <ActionRow key={action.action_id} action={action} />
            ))}
          </ul>
        ) : (
          <EmptyState icon={<IconBolt size={20} />} title="No actions here" />
        )}
      </Card>
    </>
  );
}
