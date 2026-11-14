"use client";

import {
  IconAlertTriangle,
  IconChartDots,
  IconCheck,
  IconChevronDown,
  IconFileSearch,
  IconFingerprint,
  IconInfoCircle,
  IconNetwork,
  IconQuote,
  IconRobot,
  IconShieldExclamation,
  IconSitemap,
  IconTimeline,
  IconTool,
  IconX,
} from "@tabler/icons-react";
import { AnimatePresence, motion } from "framer-motion";
import { useMemo, useState, type ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { JsonView } from "@/components/ui/json-view";
import { EmptyState } from "@/components/ui/states";
import { fmtDuration, fmtTime, titleCase } from "@/lib/format";
import type { DecisionRecord, ToolCall } from "@/lib/types";
import { cn } from "@/lib/utils";

import { ACTION_META, DecidedBy, VerdictBadge } from "../soc/badges";
import { TechniqueChip } from "../soc/entities";

const TOOL_ICON: Record<string, ReactNode> = {
  get_incident: <IconFileSearch size={14} />,
  get_entity_timeline: <IconTimeline size={14} />,
  get_asset_context: <IconInfoCircle size={14} />,
  score_signins: <IconFingerprint size={14} />,
  score_flows: <IconNetwork size={14} />,
  score_processes: <IconChartDots size={14} />,
  propose_action: <IconShieldExclamation size={14} />,
  decision: <IconRobot size={14} />,
  repair: <IconTool size={14} />,
};

function ConfidenceRing({ value }: { value: number }) {
  const r = 16;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative size-11">
      <svg viewBox="0 0 40 40" className="size-11 -rotate-90">
        <circle cx="20" cy="20" r={r} fill="none" stroke="#222b3a" strokeWidth="4" />
        <motion.circle
          cx="20"
          cy="20"
          r={r}
          fill="none"
          stroke="#22d3ee"
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c * (1 - value) }}
          transition={{ duration: 0.9 }}
        />
      </svg>
      <span className="absolute inset-0 grid place-items-center font-mono text-[10px] text-ink">{Math.round(value * 100)}%</span>
    </div>
  );
}

function Step({ call, index }: { call: ToolCall; index: number }) {
  const [open, setOpen] = useState(false);
  const args = Object.entries(call.arguments ?? {}).filter(([, v]) => v !== null && v !== undefined && v !== "");
  const isDecision = call.tool === "decision" || call.tool === "repair";
  return (
    <motion.li
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      className="relative pl-10"
    >
      <span
        className={cn(
          "absolute left-0 top-1 grid size-7 place-items-center rounded-lg ring-1",
          !call.ok ? "bg-danger/15 text-danger ring-danger/40" : isDecision ? "bg-brand/15 text-brand ring-brand/40" : "bg-raised text-dim ring-line",
        )}
      >
        {TOOL_ICON[call.tool] ?? <IconTool size={14} />}
      </span>
      <button onClick={() => setOpen(!open)} className="flex w-full flex-wrap items-center gap-2 text-left">
        <span className="font-mono text-xs text-faint">#{call.step}</span>
        <span className="font-mono text-sm text-ink">{call.tool}</span>
        {args.map(([key, value]) => (
          <span key={key} className="rounded bg-raised px-1.5 font-mono text-[11px] text-dim ring-1 ring-line">
            {key}=<span className="text-ink">{Array.isArray(value) ? value.join(",") : String(value).replace(/T(\d\d:\d\d).*/, " $1")}</span>
          </span>
        ))}
        <span className="ml-auto flex items-center gap-2">
          {call.ok ? (
            <IconCheck size={14} className="text-ok" />
          ) : (
            <Badge tone="danger" icon={<IconX size={11} />}>
              invalid
            </Badge>
          )}
          <span className="font-mono text-[11px] text-faint">{call.latency_ms.toFixed(0)} ms</span>
          <motion.span animate={{ rotate: open ? 180 : 0 }} className="text-faint">
            <IconChevronDown size={14} />
          </motion.span>
        </span>
      </button>
      {call.error ? <p className="mt-1 text-xs text-danger">{call.error}</p> : null}
      <AnimatePresence initial={false}>
        {open ? (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <JsonView value={call.result} className="mt-2 max-h-96" />
          </motion.div>
        ) : null}
      </AnimatePresence>
    </motion.li>
  );
}

function DecisionCard({ decision, calls }: { decision: DecisionRecord; calls: ToolCall[] }) {
  const body = decision.decision;
  const actions = [body.action, ...(body.extra_actions ?? [])].filter((a) => a.type !== "none");
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-line bg-raised/30">
      <div className="flex flex-wrap items-center gap-3 border-b border-line/70 px-4 py-3">
        <span className={cn("grid size-9 place-items-center rounded-xl ring-1", decision.decided_by === "agent" ? "bg-brand/10 text-brand ring-brand/30" : "bg-info/10 text-info ring-info/30")}>
          {decision.decided_by === "agent" ? <IconRobot size={18} /> : <IconSitemap size={18} />}
        </span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <DecidedBy by={decision.decided_by} model={decision.model} />
            <VerdictBadge verdict={decision.verdict} />
            {body.original_verdict && body.original_verdict !== decision.verdict ? (
              <Badge tone="danger" icon={<IconAlertTriangle size={11} />}>
                agent said {body.original_verdict}
              </Badge>
            ) : null}
            {body.injection_seen ? (
              <Badge tone="danger" icon={<IconShieldExclamation size={11} />}>
                prompt injection seen
              </Badge>
            ) : null}
          </div>
          <div className="mt-1 font-mono text-[11px] text-faint">
            decided {fmtTime(decision.created_at, "EEE HH:mm:ss")} · took {fmtDuration(decision.latency_s)} · {calls.filter((c) => c.tool !== "decision").length} tool calls
          </div>
        </div>
        <div className="ml-auto">
          <ConfidenceRing value={decision.confidence} />
        </div>
      </div>
      <div className="space-y-3 px-4 py-3">
        {body.note ? (
          <p className="rounded-lg bg-warn/10 px-3 py-2 text-xs text-warn ring-1 ring-warn/30">{body.note}</p>
        ) : null}
        <div className="flex gap-2 text-sm text-dim">
          <IconQuote size={16} className="mt-0.5 shrink-0 text-faint" />
          <p className="leading-relaxed">{body.rationale}</p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {actions.map((a) => (
            <Badge key={`${a.type}-${a.target}`} tone="ok" icon={ACTION_META[a.type]?.icon}>
              {ACTION_META[a.type]?.label ?? titleCase(a.type)} <span className="font-mono">{a.target}</span>
            </Badge>
          ))}
          {body.techniques.slice(0, 8).map((t) => (
            <TechniqueChip key={t} technique={t} />
          ))}
        </div>
        {body.evidence.length ? (
          <div>
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-faint">Cited evidence</div>
            <div className="flex flex-wrap gap-1.5">
              {body.evidence.map((e) => (
                <span key={e.id} title={e.note} className="rounded-md bg-canvas px-2 py-0.5 font-mono text-[11px] text-brand ring-1 ring-brand/25">
                  {e.id}
                </span>
              ))}
            </div>
          </div>
        ) : null}
        {calls.length ? (
          <div>
            <div className="mb-2 text-[11px] uppercase tracking-wider text-faint">ReAct steps over MCP</div>
            <ol className="relative space-y-3 before:absolute before:bottom-2 before:left-3.5 before:top-2 before:w-px before:bg-line">
              {calls.map((call, i) => (
                <Step key={call.id} call={call} index={i} />
              ))}
            </ol>
          </div>
        ) : null}
      </div>
    </motion.div>
  );
}

/** Decisions with the tool calls behind each of them (an agent triage, or a playbook). */
export function AgentTrace({ decisions, calls }: { decisions: DecisionRecord[]; calls: ToolCall[] }) {
  const paired = useMemo(() => {
    const groups = new Map<string, ToolCall[]>();
    for (const call of calls) groups.set(call.created_at, [...(groups.get(call.created_at) ?? []), call]);
    const starts = [...groups.keys()].sort();
    const used = new Set<string>();
    return [...decisions]
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .map((decision) => {
        const start = [...starts].reverse().find((s) => s <= decision.created_at && !used.has(s));
        if (start && decision.decided_by === "agent") used.add(start);
        return { decision, calls: start && decision.decided_by === "agent" ? (groups.get(start) ?? []).sort((a, b) => a.step - b.step) : [] };
      });
  }, [decisions, calls]);
  if (!decisions.length) return <EmptyState icon={<IconRobot size={20} />} title="Not triaged yet">Low-risk incidents are only logged; others wait in the agent queue.</EmptyState>;
  return (
    <div className="space-y-4">
      {paired.map(({ decision, calls: steps }) => (
        <DecisionCard key={decision.id} decision={decision} calls={steps} />
      ))}
    </div>
  );
}
