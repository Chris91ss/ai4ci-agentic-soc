"use client";

import { animate, motion, useMotionValue, useTransform } from "framer-motion";
import { useEffect, type ReactNode } from "react";

import { cn } from "@/lib/utils";

/** A number that counts up to its new value (KPI cards). */
export function AnimatedNumber({
  value,
  format,
  decimals = 0,
}: {
  value: number;
  format?: (n: number) => string;
  decimals?: number;
}) {
  const motionValue = useMotionValue(0);
  const text = useTransform(motionValue, (latest) => {
    const rounded = Number(latest.toFixed(decimals));
    return format ? format(rounded) : rounded.toLocaleString("en");
  });
  useEffect(() => {
    const controls = animate(motionValue, value, { duration: 0.9, ease: [0.22, 1, 0.36, 1] });
    return () => controls.stop();
  }, [motionValue, value]);
  return <motion.span>{text}</motion.span>;
}

export function Stat({
  label,
  value,
  format,
  decimals = 0,
  icon,
  hint,
  tone = "brand",
  className,
}: {
  label: string;
  value: number | null | undefined;
  format?: (n: number) => string;
  decimals?: number;
  icon: ReactNode;
  hint?: ReactNode;
  tone?: "brand" | "danger" | "warn" | "ok" | "info" | "signin" | "flow" | "process";
  className?: string;
}) {
  const color = {
    brand: "text-brand bg-brand/10 ring-brand/25",
    danger: "text-danger bg-danger/10 ring-danger/25",
    warn: "text-warn bg-warn/10 ring-warn/25",
    ok: "text-ok bg-ok/10 ring-ok/25",
    info: "text-info bg-info/10 ring-info/25",
    signin: "text-signin bg-signin/10 ring-signin/25",
    flow: "text-flow bg-flow/10 ring-flow/25",
    process: "text-process bg-process/10 ring-process/25",
  }[tone];
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2 }}
      transition={{ type: "spring", stiffness: 260, damping: 24 }}
      className={cn("group relative overflow-hidden rounded-[var(--radius-card)] border border-line bg-panel/80 p-4", className)}
    >
      <div className="pointer-events-none absolute -right-8 -top-8 size-24 rounded-full bg-current opacity-[0.04] blur-2xl transition-opacity group-hover:opacity-[0.08]" />
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-dim">{label}</span>
        <span className={cn("grid size-7 place-items-center rounded-lg ring-1", color)}>{icon}</span>
      </div>
      <div className="mt-3 font-mono text-2xl font-semibold tracking-tight text-ink">
        {value === null || value === undefined ? "—" : <AnimatedNumber value={value} format={format} decimals={decimals} />}
      </div>
      {hint ? <div className="mt-1 truncate text-xs text-faint">{hint}</div> : null}
    </motion.div>
  );
}
