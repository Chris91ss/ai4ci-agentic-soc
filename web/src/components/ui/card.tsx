"use client";

import { motion, type HTMLMotionProps } from "framer-motion";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export function Card({ className, children, ...props }: HTMLMotionProps<"div">) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className={cn("rounded-[var(--radius-card)] border border-line bg-panel/80 backdrop-blur-sm", className)}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function CardHeader({
  icon,
  title,
  subtitle,
  action,
  className,
}: {
  icon?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-3 border-b border-line/70 px-5 py-4", className)}>
      <div className="flex min-w-0 items-center gap-3">
        {icon ? (
          <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-raised text-brand ring-1 ring-line">{icon}</span>
        ) : null}
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold tracking-tight text-ink">{title}</h3>
          {subtitle ? <p className="truncate text-xs text-faint">{subtitle}</p> : null}
        </div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function CardBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("px-5 py-4", className)}>{children}</div>;
}
