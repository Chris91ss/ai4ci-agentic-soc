import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

const TONES = {
  neutral: "bg-raised text-dim ring-line",
  brand: "bg-brand/10 text-brand ring-brand/30",
  danger: "bg-danger/10 text-danger ring-danger/30",
  warn: "bg-warn/10 text-warn ring-warn/30",
  ok: "bg-ok/10 text-ok ring-ok/30",
  info: "bg-info/10 text-info ring-info/30",
  signin: "bg-signin/10 text-signin ring-signin/30",
  flow: "bg-flow/10 text-flow ring-flow/30",
  process: "bg-process/10 text-process ring-process/30",
} as const;

export type Tone = keyof typeof TONES;

export function Badge({
  tone = "neutral",
  icon,
  children,
  className,
  title,
}: {
  tone?: Tone;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex h-6 items-center gap-1 whitespace-nowrap rounded-md px-2 text-[11px] font-medium ring-1 ring-inset",
        TONES[tone],
        className,
      )}
    >
      {icon}
      {children}
    </span>
  );
}

export function Dot({ tone = "brand", pulse = false }: { tone?: "brand" | "danger" | "ok" | "warn" | "faint"; pulse?: boolean }) {
  const color = { brand: "text-brand", danger: "text-danger", ok: "text-ok", warn: "text-warn", faint: "text-faint" }[tone];
  return (
    <span className={cn("relative inline-flex size-2 shrink-0 rounded-full bg-current", color, pulse && "pulse-ring")} />
  );
}
