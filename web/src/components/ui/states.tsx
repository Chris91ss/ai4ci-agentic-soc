"use client";

import { IconDatabaseExport, IconMoodEmpty } from "@tabler/icons-react";
import { motion } from "framer-motion";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-raised", className)} />;
}

export function EmptyState({
  icon,
  title,
  children,
  className,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      className={cn("flex flex-col items-center justify-center gap-2 px-6 py-10 text-center", className)}
    >
      <span className="grid size-10 place-items-center rounded-xl bg-raised text-faint ring-1 ring-line">
        {icon ?? <IconMoodEmpty size={20} />}
      </span>
      <p className="text-sm font-medium text-dim">{title}</p>
      {children ? <div className="max-w-sm text-xs text-faint">{children}</div> : null}
    </motion.div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <EmptyState icon={<IconDatabaseExport size={20} />} title="Could not load data">
      {message}. Is the console API running (<code className="font-mono">soc demo</code> or{" "}
      <code className="font-mono">soc api --run …</code>)?
    </EmptyState>
  );
}
