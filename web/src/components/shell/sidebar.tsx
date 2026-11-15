"use client";

import {
  IconBolt,
  IconBrandGithub,
  IconChartBar,
  IconFingerprint,
  IconFlask,
  IconLayoutDashboard,
  IconRobot,
  IconShieldHalfFilled,
  IconStack2,
  IconUsers,
} from "@tabler/icons-react";
import { motion } from "framer-motion";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import { Dot } from "@/components/ui/badge";
import { Tooltip } from "@/components/ui/tabs";
import { useLive } from "@/lib/live";
import { useActions, useHealth, useIncidents } from "@/lib/queries";
import { cn } from "@/lib/utils";

const REPOSITORY = "https://github.com/Chris91ss/ai4ci-agentic-soc";

const NAV: { href: string; label: string; icon: ReactNode; match: string[] }[] = [
  { href: "/", label: "Overview", icon: <IconLayoutDashboard size={18} />, match: ["/"] },
  { href: "/incidents", label: "Incidents", icon: <IconStack2 size={18} />, match: ["/incidents", "/incident"] },
  { href: "/entities", label: "Entities", icon: <IconUsers size={18} />, match: ["/entities", "/entity"] },
  { href: "/actions", label: "Actions", icon: <IconBolt size={18} />, match: ["/actions"] },
  { href: "/metrics", label: "Metrics", icon: <IconChartBar size={18} />, match: ["/metrics"] },
  { href: "/evaluation", label: "Evaluation", icon: <IconFlask size={18} />, match: ["/evaluation"] },
  { href: "/audit", label: "Audit log", icon: <IconFingerprint size={18} />, match: ["/audit"] },
];

function Counter({ value, tone }: { value: number; tone: "danger" | "warn" }) {
  if (!value) return null;
  return (
    <motion.span
      key={value}
      initial={{ scale: 0.6, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={cn(
        "ml-auto rounded-md px-1.5 font-mono text-[10px] leading-5 ring-1",
        tone === "danger" ? "bg-danger/15 text-danger ring-danger/30" : "bg-warn/15 text-warn ring-warn/30",
      )}
    >
      {value}
    </motion.span>
  );
}

/** What the console is showing: the live pipeline or a recorded run, its agent, and how far the replay is. */
function RunCard() {
  const live = useLive();
  const { data: health } = useHealth();
  const run = health?.run ?? {};
  const isLive = live.mode === "live";
  const llm = String(health?.llm ?? run.llm ?? "scripted");
  const agent = llm === "scripted" ? "scripted analyst" : llm.replace(/^ollama:/, "");
  const name = typeof run.name === "string" ? run.name : isLive ? "live pipeline" : "recorded run";
  const progress = Math.round(live.progress * 100);
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="m-3 rounded-xl border border-line bg-raised/50 p-3"
    >
      <div className="flex items-center gap-2">
        <Dot tone={isLive ? (live.connected ? "ok" : "danger") : "brand"} pulse={isLive ? live.connected : live.playing} />
        <span className="text-[10px] font-medium uppercase tracking-wider text-faint">
          {isLive ? (live.connected ? "Live pipeline" : "Disconnected") : "Recorded run"}
        </span>
        <Tooltip content="Source code on GitHub">
          <a
            href={REPOSITORY}
            target="_blank"
            rel="noreferrer"
            aria-label="Source code on GitHub"
            className="ml-auto grid size-6 place-items-center rounded-md text-faint transition-colors hover:bg-hover hover:text-ink"
          >
            <IconBrandGithub size={14} />
          </a>
        </Tooltip>
      </div>
      <div className="mt-1.5 truncate font-mono text-xs text-ink" title={name}>
        {name}
      </div>
      {isLive ? null : (
        <div className="mt-2.5">
          <div className="h-1 overflow-hidden rounded-full bg-hover">
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-brand-strong to-brand"
              animate={{ width: `${progress}%` }}
              transition={{ ease: "linear", duration: 0.25 }}
            />
          </div>
          <div className="mt-1 flex justify-between font-mono text-[10px] text-faint">
            <span>{live.playing ? "replaying" : progress >= 100 ? "replayed" : "paused"}</span>
            <span>{progress}%</span>
          </div>
        </div>
      )}
      <div className="mt-2.5 flex items-center gap-1.5 text-[11px] text-dim">
        <IconRobot size={13} className="shrink-0 text-brand" />
        <span className="truncate">{agent}</span>
        {run.seed !== undefined ? <span className="ml-auto shrink-0 font-mono text-faint">seed {String(run.seed)}</span> : null}
      </div>
    </motion.div>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  const { data: active } = useIncidents({ status: ["open", "queued", "triaging", "awaiting_approval"], min_risk: 0.5 });
  const { data: pending } = useActions(["pending_approval"]);
  const counters: Record<string, ReactNode> = {
    "/incidents": <Counter value={active?.length ?? 0} tone="danger" />,
    "/actions": <Counter value={pending?.length ?? 0} tone="warn" />,
  };
  return (
    <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col border-r border-line bg-panel/60 backdrop-blur-xl lg:flex">
      <Link href="/" className="flex items-center gap-2.5 px-5 py-5">
        <motion.span
          className="grid size-9 place-items-center rounded-xl bg-brand/15 text-brand ring-1 ring-brand/40"
          animate={{ boxShadow: ["0 0 0px rgba(34,211,238,0.0)", "0 0 22px rgba(34,211,238,0.35)", "0 0 0px rgba(34,211,238,0.0)"] }}
          transition={{ duration: 3.2, repeat: Infinity }}
        >
          <IconShieldHalfFilled size={20} />
        </motion.span>
        <div>
          <div className="text-sm font-semibold tracking-tight">Agentic SOC</div>
          <div className="text-[11px] text-faint">Example Corp · AI4CI</div>
        </div>
      </Link>
      <nav className="flex flex-1 flex-col gap-0.5 px-3">
        {NAV.map((item) => {
          const on = item.match.some((m) => (m === "/" ? pathname === "/" : pathname.startsWith(m)));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "relative flex h-9 items-center gap-3 rounded-lg px-3 text-sm transition-colors",
                on ? "text-ink" : "text-dim hover:bg-raised/60 hover:text-ink",
              )}
            >
              {on ? (
                <motion.span
                  layoutId="nav-active"
                  className="absolute inset-0 rounded-lg bg-raised ring-1 ring-line-strong"
                  transition={{ type: "spring", stiffness: 420, damping: 34 }}
                >
                  <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-brand" />
                </motion.span>
              ) : null}
              <span className={cn("relative", on && "text-brand")}>{item.icon}</span>
              <span className="relative">{item.label}</span>
              <span className="relative ml-auto">{counters[item.href]}</span>
            </Link>
          );
        })}
      </nav>
      <RunCard />
    </aside>
  );
}

/** Below the large breakpoint the sidebar collapses into a scrollable strip under the top bar. */
export function MobileNav() {
  const pathname = usePathname();
  return (
    <nav className="sticky top-14 z-20 flex gap-1 overflow-x-auto border-b border-line bg-canvas/80 px-3 py-2 backdrop-blur-xl lg:hidden">
      {NAV.map((item) => {
        const on = item.match.some((m) => (m === "/" ? pathname === "/" : pathname.startsWith(m)));
        return (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "relative flex h-8 shrink-0 items-center gap-1.5 rounded-lg px-3 text-xs transition-colors",
              on ? "text-ink" : "text-dim hover:text-ink",
            )}
          >
            {on ? (
              <motion.span
                layoutId="mobile-nav-active"
                className="absolute inset-0 rounded-lg bg-raised ring-1 ring-line-strong"
                transition={{ type: "spring", stiffness: 420, damping: 34 }}
              />
            ) : null}
            <span className={cn("relative", on && "text-brand")}>{item.icon}</span>
            <span className="relative">{item.label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
