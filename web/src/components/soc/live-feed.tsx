"use client";

import {
  IconAlertTriangle,
  IconArrowsShuffle,
  IconBolt,
  IconGitMerge,
  IconRobot,
  IconRoute,
  IconSitemap,
  IconStack2,
} from "@tabler/icons-react";
import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import type { ReactNode } from "react";

import { fmtTime, titleCase } from "@/lib/format";
import type { PipelineEvent } from "@/lib/types";
import { cn, incidentHref } from "@/lib/utils";

const KIND: Record<string, { icon: ReactNode; color: string; label: string }> = {
  alert: { icon: <IconAlertTriangle size={14} />, color: "text-warn bg-warn/10 ring-warn/25", label: "Alert" },
  incident: { icon: <IconStack2 size={14} />, color: "text-info bg-info/10 ring-info/25", label: "Incident" },
  route: { icon: <IconRoute size={14} />, color: "text-dim bg-raised ring-line", label: "Routed" },
  decision: { icon: <IconRobot size={14} />, color: "text-brand bg-brand/10 ring-brand/25", label: "Decision" },
  action: { icon: <IconBolt size={14} />, color: "text-ok bg-ok/10 ring-ok/25", label: "Action" },
  merge: { icon: <IconGitMerge size={14} />, color: "text-dim bg-raised ring-line", label: "Merged" },
  agent_fallback: { icon: <IconSitemap size={14} />, color: "text-danger bg-danger/10 ring-danger/25", label: "Fallback" },
};

function describe(event: PipelineEvent): ReactNode {
  switch (event.kind) {
    case "alert":
      return (
        <>
          <span className="font-mono text-ink">{String(event.detector)}</span> alert{" "}
          <span className="font-mono text-faint">{String(event.alert_id)}</span>
        </>
      );
    case "incident":
      return (
        <>
          new incident, risk <span className="font-mono text-ink">{Number(event.risk).toFixed(2)}</span>
        </>
      );
    case "route":
      return (
        <>
          → <span className="text-ink">{String(event.route)}</span> <span className="text-faint">({String(event.reason)})</span>
        </>
      );
    case "decision": {
      const actions = (event.actions as [string, string][] | undefined) ?? [];
      return (
        <>
          <span className="text-ink">{String(event.decided_by)}</span>:{" "}
          <span
            className={cn(
              event.verdict === "malicious" ? "text-danger" : event.verdict === "benign" ? "text-ok" : "text-warn",
              "font-medium",
            )}
          >
            {String(event.verdict)}
          </span>
          {actions.length ? (
            <span className="text-faint"> · {actions.map(([t, target]) => `${titleCase(t)} ${target}`).join(", ")}</span>
          ) : null}
        </>
      );
    }
    case "action":
      return (
        <>
          {titleCase(String(event.type))} <span className="font-mono text-ink">{String(event.target)}</span>{" "}
          <span className="text-faint">· {titleCase(String(event.status))}</span>
        </>
      );
    case "merge":
      return (
        <>
          absorbed <span className="font-mono text-faint">{String(event.merged)}</span>
        </>
      );
    case "agent_fallback":
      return <span className="text-danger">{String(event.reason)}</span>;
    default:
      return <span className="text-faint">{event.kind}</span>;
  }
}

export function LiveFeed({ events, kinds, empty }: { events: PipelineEvent[]; kinds?: string[]; empty?: ReactNode }) {
  const shown = (kinds ? events.filter((e) => kinds.includes(e.kind)) : events).slice(0, 60);
  if (!shown.length) return <div className="px-5 py-10 text-center text-sm text-faint">{empty ?? "Waiting for events…"}</div>;
  return (
    <ul className="relative divide-y divide-line/60">
      <AnimatePresence initial={false}>
        {shown.map((event, i) => {
          const meta = KIND[event.kind] ?? { icon: <IconArrowsShuffle size={14} />, color: "text-dim bg-raised ring-line", label: event.kind };
          const key = `${event.time}-${event.kind}-${event.incident_id ?? ""}-${String(event.alert_id ?? event.action_id ?? event.merged ?? i)}`;
          return (
            <motion.li
              key={key}
              layout
              initial={{ opacity: 0, x: -12, backgroundColor: "rgba(34,211,238,0.08)" }}
              animate={{ opacity: 1, x: 0, backgroundColor: "rgba(34,211,238,0)" }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
              className="flex items-center gap-3 px-5 py-2.5 text-xs"
            >
              <span className={cn("grid size-7 shrink-0 place-items-center rounded-lg ring-1", meta.color)}>{meta.icon}</span>
              <div className="min-w-0 flex-1 truncate text-dim">
                {event.incident_id ? (
                  <Link href={incidentHref(String(event.incident_id))} className="mr-1.5 font-mono text-brand hover:underline">
                    {String(event.incident_id)}
                  </Link>
                ) : null}
                {describe(event)}
              </div>
              <span className="shrink-0 font-mono text-[11px] text-faint">{fmtTime(event.time, "HH:mm:ss")}</span>
            </motion.li>
          );
        })}
      </AnimatePresence>
    </ul>
  );
}
