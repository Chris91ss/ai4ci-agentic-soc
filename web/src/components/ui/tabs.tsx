"use client";

import { Tabs as TabsPrimitive, Tooltip as TooltipPrimitive } from "radix-ui";
import { motion } from "framer-motion";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export function Tooltip({ content, children, side = "top" }: { content: ReactNode; children: ReactNode; side?: "top" | "bottom" | "left" | "right" }) {
  return (
    <TooltipPrimitive.Root delayDuration={150}>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={6}
          className="z-50 max-w-xs rounded-md border border-line-strong bg-raised px-2.5 py-1.5 text-xs text-ink shadow-xl"
        >
          {content}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

export interface TabItem {
  value: string;
  label: string;
  icon?: ReactNode;
  count?: number;
}

/** Tabs with an animated indicator that glides between triggers. */
export function Tabs({
  items,
  value,
  onValueChange,
  children,
  className,
  id,
}: {
  items: TabItem[];
  value: string;
  onValueChange: (value: string) => void;
  children: ReactNode;
  className?: string;
  id: string;
}) {
  return (
    <TabsPrimitive.Root value={value} onValueChange={onValueChange} className={className}>
      <TabsPrimitive.List className="flex gap-1 overflow-x-auto border-b border-line px-2">
        {items.map((item) => (
          <TabsPrimitive.Trigger
            key={item.value}
            value={item.value}
            className={cn(
              "relative flex h-10 items-center gap-1.5 whitespace-nowrap px-3 text-sm text-dim outline-none transition-colors hover:text-ink",
              value === item.value && "text-ink",
            )}
          >
            {item.icon}
            {item.label}
            {item.count !== undefined ? (
              <span className="rounded bg-raised px-1.5 font-mono text-[10px] text-faint ring-1 ring-line">{item.count}</span>
            ) : null}
            {value === item.value ? (
              <motion.span
                layoutId={`tab-indicator-${id}`}
                className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-brand"
                transition={{ type: "spring", stiffness: 400, damping: 32 }}
              />
            ) : null}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {children}
    </TabsPrimitive.Root>
  );
}

export const TabPanel = TabsPrimitive.Content;

/** A row of toggle chips, e.g. for filters. */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  id,
}: {
  options: { value: T; label: ReactNode }[];
  value: T;
  onChange: (value: T) => void;
  id: string;
}) {
  return (
    <div className="inline-flex rounded-lg bg-raised p-0.5 ring-1 ring-line">
      {options.map((option) => (
        <button
          key={option.value}
          onClick={() => onChange(option.value)}
          className={cn(
            "relative h-7 rounded-md px-2.5 text-xs font-medium text-dim transition-colors hover:text-ink",
            value === option.value && "text-ink",
          )}
        >
          {value === option.value ? (
            <motion.span
              layoutId={`segment-${id}`}
              className="absolute inset-0 rounded-md bg-hover ring-1 ring-line-strong"
              transition={{ type: "spring", stiffness: 400, damping: 32 }}
            />
          ) : null}
          <span className="relative">{option.label}</span>
        </button>
      ))}
    </div>
  );
}
