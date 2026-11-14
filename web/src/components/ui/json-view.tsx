"use client";

import { IconChevronRight } from "@tabler/icons-react";
import { motion } from "framer-motion";
import { useState } from "react";

import { cn } from "@/lib/utils";

function isUntrusted(value: unknown): value is { $untrusted: string } {
  return typeof value === "object" && value !== null && "$untrusted" in value && Object.keys(value).length === 1;
}

function Leaf({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-faint">null</span>;
  if (typeof value === "string") return <span className="break-all text-ok">&quot;{value}&quot;</span>;
  if (typeof value === "number") return <span className="text-process">{value}</span>;
  if (typeof value === "boolean") return <span className="text-info">{String(value)}</span>;
  return <span className="text-dim">{String(value)}</span>;
}

function Node({ name, value, depth, defaultOpen }: { name?: string; value: unknown; depth: number; defaultOpen: number }) {
  const [open, setOpen] = useState(depth < defaultOpen);
  const label = name !== undefined ? <span className="text-signin">{name}</span> : null;
  if (isUntrusted(value)) {
    return (
      <div className="flex gap-1.5" style={{ paddingLeft: depth * 14 }}>
        {label}
        {label ? <span className="text-faint">:</span> : null}
        <span
          title="Raw log data an attacker may control: quoted for the LLM, never followed"
          className="break-all rounded bg-danger/10 px-1 text-danger ring-1 ring-danger/30"
        >
          untrusted: &quot;{value.$untrusted}&quot;
        </span>
      </div>
    );
  }
  if (value === null || typeof value !== "object") {
    return (
      <div className="flex gap-1.5" style={{ paddingLeft: depth * 14 }}>
        {label}
        {label ? <span className="text-faint">:</span> : null}
        <Leaf value={value} />
      </div>
    );
  }
  const entries = Array.isArray(value) ? value.map((v, i) => [String(i), v] as const) : Object.entries(value as Record<string, unknown>);
  const brackets = Array.isArray(value) ? ["[", "]"] : ["{", "}"];
  return (
    <div style={{ paddingLeft: depth * 14 }}>
      <button onClick={() => setOpen(!open)} className="flex items-center gap-1 text-left hover:text-ink">
        <motion.span animate={{ rotate: open ? 90 : 0 }} className="text-faint">
          <IconChevronRight size={12} />
        </motion.span>
        {label}
        {label ? <span className="text-faint">:</span> : null}
        <span className="text-faint">
          {brackets[0]}
          {open ? "" : ` ${entries.length} ${Array.isArray(value) ? "items" : "keys"} ${brackets[1]}`}
        </span>
      </button>
      {open ? (
        <div>
          {entries.map(([key, child]) => (
            <Node key={key} name={Array.isArray(value) ? undefined : key} value={child} depth={1} defaultOpen={defaultOpen - depth - 1} />
          ))}
          <span className="text-faint">{brackets[1]}</span>
        </div>
      ) : null}
    </div>
  );
}

/** Collapsible JSON with highlighted untrusted (attacker-controllable) strings. */
export function JsonView({ value, className, defaultOpen = 2 }: { value: unknown; className?: string; defaultOpen?: number }) {
  return (
    <div className={cn("overflow-x-auto rounded-lg bg-canvas/80 p-3 font-mono text-[11px] leading-5 ring-1 ring-line", className)}>
      <Node value={value} depth={0} defaultOpen={defaultOpen} />
    </div>
  );
}
