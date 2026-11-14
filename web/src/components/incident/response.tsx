"use client";

import { IconCheck, IconMessageReport, IconThumbDown, IconThumbUp, IconUserCircle, IconX } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/states";
import { api, DATA_MODE } from "@/lib/api";
import { fmtTime, titleCase } from "@/lib/format";
import type { Action, Feedback } from "@/lib/types";
import { cn } from "@/lib/utils";

import { ACTION_META, ActionStatusBadge } from "../soc/badges";

export const ANALYST = "soc-analyst";

function useRefresh() {
  const client = useQueryClient();
  return () =>
    ["incident", "incidents", "actions", "metrics", "trace", "audit"].forEach((key) => client.invalidateQueries({ queryKey: [key] }));
}

export function ActionRow({ action, compact = false }: { action: Action; compact?: boolean }) {
  const refresh = useRefresh();
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");
  const approve = useMutation({
    mutationFn: () => api.approve(action.action_id, ANALYST),
    onSuccess: (a) => {
      toast.success(`${ACTION_META[a.type]?.label ?? a.type} ${a.target} approved`, { description: `status: ${a.status}` });
      refresh();
    },
    onError: (e) => toast.error("Approval failed", { description: e instanceof Error ? e.message : String(e) }),
  });
  const reject = useMutation({
    mutationFn: () => api.reject(action.action_id, ANALYST, reason),
    onSuccess: (a) => {
      toast(`${ACTION_META[a.type]?.label ?? a.type} ${a.target} rejected`);
      setRejecting(false);
      refresh();
    },
    onError: (e) => toast.error("Rejection failed", { description: e instanceof Error ? e.message : String(e) }),
  });
  const pending = action.status === "pending_approval";
  return (
    <motion.li layout initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className={cn("px-4 py-3", pending && "bg-warn/[0.05]")}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn("grid size-8 place-items-center rounded-lg ring-1", action.impact === "high" ? "bg-danger/10 text-danger ring-danger/30" : "bg-ok/10 text-ok ring-ok/30")}>
          {ACTION_META[action.type]?.icon}
        </span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-sm font-medium text-ink">{ACTION_META[action.type]?.label ?? action.type}</span>
            <span className="font-mono text-sm text-brand">{action.target}</span>
            <ActionStatusBadge status={action.status} />
            <Badge tone={action.impact === "high" ? "danger" : "neutral"}>{action.impact} impact</Badge>
          </div>
          <div className="mt-0.5 font-mono text-[11px] text-faint">
            {action.action_id} · requested by {action.requested_by} {fmtTime(action.created_at, "EEE HH:mm")}
            {action.approved_by ? ` · approved by ${action.approved_by}` : ""}
            {action.executed_at ? ` · executed ${fmtTime(action.executed_at, "HH:mm")}` : ""}
            {!compact && action.incident_id ? ` · ${action.incident_id}` : ""}
          </div>
        </div>
        {pending ? (
          <div className="ml-auto flex gap-1.5">
            <Button size="sm" variant="ok" icon={<IconCheck size={13} />} loading={approve.isPending} onClick={() => approve.mutate()}>
              Approve
            </Button>
            <Button size="sm" variant="danger" icon={<IconX size={13} />} onClick={() => setRejecting(!rejecting)}>
              Reject
            </Button>
          </div>
        ) : null}
      </div>
      {!compact && action.justification ? <p className="mt-2 line-clamp-2 pl-10 text-xs text-dim">{action.justification}</p> : null}
      <AnimatePresence>
        {rejecting ? (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="mt-2 flex gap-2 pl-10">
              <input
                autoFocus
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why? (e.g. the host owner confirmed the activity)"
                className="h-8 flex-1 rounded-lg bg-raised px-3 text-xs text-ink outline-none ring-1 ring-line focus:ring-danger/60"
              />
              <Button size="sm" variant="danger" loading={reject.isPending} onClick={() => reject.mutate()}>
                Confirm
              </Button>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </motion.li>
  );
}

export function ActionsPanel({ actions }: { actions: Action[] }) {
  if (!actions.length)
    return <EmptyState title="No containment for this incident">The agent or a playbook proposes actions when it decides.</EmptyState>;
  const order = { pending_approval: 0, executed: 1, approved: 2, proposed: 3, denied: 4, rejected: 5, failed: 6 } as const;
  return (
    <ul className="divide-y divide-line/60">
      {[...actions]
        .sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9))
        .map((action) => (
          <ActionRow key={action.action_id} action={action} compact />
        ))}
    </ul>
  );
}

const VERDICTS = [
  { value: "true_positive", label: "True positive", icon: <IconThumbUp size={14} />, variant: "danger" as const },
  { value: "false_positive", label: "False positive", icon: <IconThumbDown size={14} />, variant: "ok" as const },
  { value: "benign_positive", label: "Benign positive", icon: <IconMessageReport size={14} />, variant: "secondary" as const },
];

export function FeedbackPanel({ incidentId, feedback }: { incidentId: string; feedback: Feedback[] }) {
  const refresh = useRefresh();
  const [comment, setComment] = useState("");
  const send = useMutation({
    mutationFn: (verdict: string) => api.feedback(incidentId, { analyst: ANALYST, verdict, comment }),
    onSuccess: (r) => {
      toast.success(`Labelled ${r.alerts} alerts as ${titleCase(r.verdict)}`, { description: "Feeds per-detector FP statistics and retraining." });
      setComment("");
      refresh();
    },
    onError: (e) => toast.error("Feedback failed", { description: e instanceof Error ? e.message : String(e) }),
  });
  const latest = new Map<string, Feedback>();
  feedback.forEach((f) => latest.set(f.alert_id, f));
  const tally: Record<string, number> = {};
  latest.forEach((f) => (tally[f.verdict] = (tally[f.verdict] ?? 0) + 1));
  return (
    <div className="space-y-3 px-4 py-4">
      <p className="text-xs text-dim">
        Your verdict labels every alert of the incident. Labels drive the detectors&apos; false-positive statistics and become training
        labels for retraining.
      </p>
      <textarea
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        rows={2}
        placeholder="Optional comment (e.g. confirmed business travel with the employee)"
        disabled={DATA_MODE === "static"}
        className="w-full resize-none rounded-lg bg-raised px-3 py-2 text-xs text-ink outline-none ring-1 ring-line placeholder:text-faint focus:ring-brand/60 disabled:opacity-50"
      />
      <div className="flex flex-wrap gap-2">
        {VERDICTS.map((v) => (
          <Button
            key={v.value}
            size="sm"
            variant={v.variant}
            icon={v.icon}
            loading={send.isPending && send.variables === v.value}
            disabled={DATA_MODE === "static"}
            onClick={() => send.mutate(v.value)}
          >
            {v.label}
          </Button>
        ))}
      </div>
      {latest.size ? (
        <div className="flex flex-wrap items-center gap-2 text-xs text-faint">
          <IconUserCircle size={14} />
          {Object.entries(tally).map(([verdict, n]) => (
            <Badge key={verdict} tone={verdict === "true_positive" ? "danger" : verdict === "false_positive" ? "ok" : "neutral"}>
              {titleCase(verdict)} · {n} alerts
            </Badge>
          ))}
        </div>
      ) : null}
    </div>
  );
}
