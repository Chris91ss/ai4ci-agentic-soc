"use client";

import {
  IconBroadcast,
  IconClock,
  IconCommand,
  IconPlayerPause,
  IconPlayerPlay,
  IconPlayerSkipForward,
  IconRefresh,
  IconRobot,
  IconSearch,
} from "@tabler/icons-react";
import { motion } from "framer-motion";

import { Badge, Dot } from "@/components/ui/badge";
import { Segmented, Tooltip } from "@/components/ui/tabs";
import { fmtTime } from "@/lib/format";
import { useLive } from "@/lib/live";
import { useHealth } from "@/lib/queries";

export function Topbar({ onSearch }: { onSearch: () => void }) {
  const live = useLive();
  const { data: health } = useHealth();
  const clock = live.mode === "replay" ? live.clock : (live.clock ?? health?.now ?? null);
  const breakerOpen = health?.breaker === "open";
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-canvas/75 px-4 backdrop-blur-xl lg:px-6">
      <button
        onClick={onSearch}
        className="flex h-8 min-w-0 max-w-xs flex-1 items-center gap-2 rounded-lg bg-raised px-3 text-sm text-faint ring-1 ring-line transition-colors hover:text-dim hover:ring-line-strong"
      >
        <IconSearch size={15} className="shrink-0" />
        <span className="flex-1 truncate text-left">Search incidents, entities…</span>
        <kbd className="hidden items-center gap-0.5 rounded bg-panel px-1.5 font-mono text-[10px] ring-1 ring-line sm:inline-flex">
          <IconCommand size={11} />K
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-2">
        {breakerOpen ? (
          <Badge tone="danger" icon={<IconRobot size={12} />}>
            Agent breaker open · playbooks
          </Badge>
        ) : null}
        {health?.agent_busy ? (
          <Badge tone="brand" icon={<motion.span animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: "linear" }}><IconRobot size={12} /></motion.span>}>
            {health.run?.pause_for_agent ? "Agent triaging · clock paused" : "Agent triaging"}
          </Badge>
        ) : null}

        {live.mode === "replay" ? (
          <div className="flex items-center gap-1.5">
            <Tooltip content={live.playing ? "Pause the replay" : "Play the replay"}>
              <button
                onClick={() => live.setPlaying(!live.playing)}
                className="grid size-8 place-items-center rounded-lg bg-raised text-dim ring-1 ring-line hover:text-ink"
              >
                {live.playing ? <IconPlayerPause size={15} /> : <IconPlayerPlay size={15} />}
              </button>
            </Tooltip>
            <Tooltip content="Restart the replay">
              <button onClick={live.restart} className="grid size-8 place-items-center rounded-lg bg-raised text-dim ring-1 ring-line hover:text-ink">
                <IconRefresh size={15} />
              </button>
            </Tooltip>
            <Segmented
              id="replay-speed"
              value={String(live.speed)}
              onChange={(v) => live.setSpeed(Number(v))}
              options={[
                { value: "300", label: "5 min/s" },
                { value: "900", label: "15 min/s" },
                { value: "3600", label: <span className="inline-flex items-center gap-1"><IconPlayerSkipForward size={12} />1 h/s</span> },
              ]}
            />
          </div>
        ) : null}

        <div className="flex h-8 shrink-0 items-center gap-2 whitespace-nowrap rounded-lg bg-raised px-3 ring-1 ring-line">
          <IconClock size={14} className="text-faint" />
          <span className="font-mono text-xs tabular-nums text-ink">{fmtTime(clock, "EEE d MMM HH:mm")}</span>
          <span className="text-[10px] text-faint">UTC</span>
        </div>

        {live.mode === "live" ? (
          <Badge tone={live.connected ? "ok" : "danger"} icon={<Dot tone={live.connected ? "ok" : "danger"} pulse={live.connected} />}>
            {live.connected ? (health?.live ? "Live" : "Recorded run") : "Disconnected"}
          </Badge>
        ) : (
          <Badge tone="info" icon={<IconBroadcast size={12} />}>
            Replay
          </Badge>
        )}
      </div>
    </header>
  );
}
