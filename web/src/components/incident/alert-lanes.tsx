"use client";

import { IconBolt, IconRobot, IconSitemap } from "@tabler/icons-react";
import { motion } from "framer-motion";
import { useMemo, useState } from "react";

import { fmtTime } from "@/lib/format";
import type { Action, Alert, DecisionRecord } from "@/lib/types";
import { cn } from "@/lib/utils";

import { DETECTOR_META, STREAM_META } from "../soc/badges";

const LANES = ["M1", "M2", "M3"] as const;

/** The incident as it unfolded: alerts per detector over time, decisions and containment. */
export function AlertLanes({
  alerts,
  decisions,
  actions,
  onSelect,
  selected,
}: {
  alerts: Alert[];
  decisions: DecisionRecord[];
  actions: Action[];
  onSelect?: (alert: Alert) => void;
  selected?: string | null;
}) {
  const [hover, setHover] = useState<Alert | null>(null);
  const { start, end } = useMemo(() => {
    const times = [
      ...alerts.map((a) => Date.parse(a.window_end)),
      ...decisions.map((d) => Date.parse(d.created_at)),
      ...actions.filter((a) => a.executed_at).map((a) => Date.parse(a.executed_at!)),
    ].filter(Number.isFinite);
    const lo = Math.min(...times);
    const hi = Math.max(...times);
    const pad = Math.max(10 * 60_000, (hi - lo) * 0.04);
    return { start: lo - pad, end: hi + pad };
  }, [alerts, decisions, actions]);
  const x = (t: string) => ((Date.parse(t) - start) / Math.max(1, end - start)) * 100;
  const ticks = useMemo(() => Array.from({ length: 6 }, (_, i) => start + ((end - start) * i) / 5), [start, end]);
  const lanes = LANES.filter((lane) => alerts.some((a) => a.detector === lane));

  return (
    <div className="relative select-none">
      <div className="relative ml-24 h-6 text-[10px] text-faint">
        {ticks.map((t, i) => (
          <span
            key={t}
            className={cn(
              "absolute whitespace-nowrap font-mono",
              i === 0 ? "" : i === ticks.length - 1 ? "-translate-x-full" : "-translate-x-1/2",
            )}
            style={{ left: `${((t - start) / (end - start)) * 100}%` }}
          >
            {fmtTime(new Date(t).toISOString(), "EEE HH:mm")}
          </span>
        ))}
      </div>
      <div className="space-y-2">
        {lanes.map((lane) => {
          const meta = DETECTOR_META[lane];
          const stream = STREAM_META[meta.stream];
          const laneAlerts = alerts.filter((a) => a.detector === lane);
          return (
            <div key={lane} className="flex items-center gap-3">
              <div className="flex w-21 shrink-0 items-center gap-1.5 text-xs" style={{ color: stream.color }}>
                {stream.icon}
                <span className="font-mono">{lane}</span>
                <span className="text-faint">· {laneAlerts.length}</span>
              </div>
              <div className="relative h-9 flex-1 rounded-lg bg-raised/50 ring-1 ring-line">
                {ticks.map((t) => (
                  <span key={t} className="absolute inset-y-0 w-px bg-line/60" style={{ left: `${((t - start) / (end - start)) * 100}%` }} />
                ))}
                {laneAlerts.map((alert, i) => {
                  const size = 8 + alert.score * 8;
                  return (
                    <motion.button
                      key={alert.alert_id}
                      initial={{ scale: 0, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      transition={{ delay: Math.min(i, 40) * 0.015, type: "spring", stiffness: 300, damping: 20 }}
                      whileHover={{ scale: 1.5 }}
                      onMouseEnter={() => setHover(alert)}
                      onMouseLeave={() => setHover(null)}
                      onClick={() => onSelect?.(alert)}
                      className={cn("absolute top-1/2 rounded-full ring-2 ring-canvas", selected === alert.alert_id && "ring-ink")}
                      style={{
                        left: `calc(${x(alert.window_end)}% - ${size / 2}px)`,
                        marginTop: -size / 2,
                        width: size,
                        height: size,
                        background: stream.color,
                        opacity: 0.35 + alert.score * 0.65,
                        boxShadow: `0 0 10px ${stream.color}88`,
                      }}
                    />
                  );
                })}
              </div>
            </div>
          );
        })}
        <div className="flex items-center gap-3">
          <div className="flex w-21 shrink-0 items-center gap-1.5 text-xs text-brand">
            <IconRobot size={13} />
            Response
          </div>
          <div className="relative h-9 flex-1 rounded-lg bg-raised/50 ring-1 ring-line">
            {decisions.map((d) => (
              <motion.span
                key={`d-${d.id}`}
                initial={{ y: -6, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                title={`${d.decided_by}: ${d.verdict} (${fmtTime(d.created_at, "HH:mm")})`}
                className={cn(
                  "absolute top-1/2 grid size-6 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-md ring-1",
                  d.decided_by === "agent" ? "bg-brand/15 text-brand ring-brand/40" : "bg-info/15 text-info ring-info/40",
                )}
                style={{ left: `${x(d.created_at)}%` }}
              >
                {d.decided_by === "agent" ? <IconRobot size={13} /> : <IconSitemap size={13} />}
              </motion.span>
            ))}
            {actions
              .filter((a) => a.executed_at)
              .map((a) => (
                <motion.span
                  key={a.action_id}
                  initial={{ scaleY: 0 }}
                  animate={{ scaleY: 1 }}
                  title={`${a.type} ${a.target} (${fmtTime(a.executed_at, "HH:mm")})`}
                  className="absolute inset-y-1 w-0.5 rounded-full bg-ok shadow-[0_0_8px_#10b981]"
                  style={{ left: `${x(a.executed_at!)}%` }}
                >
                  <IconBolt size={11} className="absolute -top-1 left-1 text-ok" />
                </motion.span>
              ))}
          </div>
        </div>
      </div>
      <div className="mt-3 h-10 text-xs">
        {hover ? (
          <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} className="flex items-center gap-2 text-dim">
            <span className="font-mono text-ink">{hover.alert_id}</span>
            <span className="font-mono text-faint">{fmtTime(hover.window_end, "EEE HH:mm")}</span>
            <span className="font-mono" style={{ color: STREAM_META[hover.stream]?.color }}>
              {hover.score.toFixed(3)}
            </span>
            <span className="truncate">{hover.summary}</span>
          </motion.div>
        ) : (
          <span className="text-faint">Hover an alert for details, click to inspect it. Dot size and brightness follow the score.</span>
        )}
      </div>
    </div>
  );
}
