"use client";

import { IconDeviceDesktop, IconServer, IconUser, IconUserShield, IconWorld } from "@tabler/icons-react";
import Link from "next/link";

import { Tooltip } from "@/components/ui/tabs";
import { LATE_TACTICS, TACTIC_ORDER, tacticOf, techniqueName } from "@/lib/attack";
import type { EntityRefs } from "@/lib/types";
import { cn, entityHref } from "@/lib/utils";

function entityIcon(kind: string, value: string) {
  if (kind === "user") return value.startsWith("adm-") ? <IconUserShield size={13} /> : <IconUser size={13} />;
  if (kind === "host") return value.startsWith("WS-") ? <IconDeviceDesktop size={13} /> : <IconServer size={13} />;
  return <IconWorld size={13} />;
}

export function EntityChip({
  entity,
  className,
  highlight,
  linked = true,
}: {
  entity: string;
  className?: string;
  highlight?: boolean;
  linked?: boolean;
}) {
  const [kind, ...rest] = entity.split(":");
  const value = rest.join(":");
  const classes = cn(
    "inline-flex h-6 max-w-full items-center gap-1 rounded-md bg-raised px-2 font-mono text-[11px] text-dim ring-1 ring-inset ring-line transition-colors",
    linked && "hover:bg-hover hover:text-ink",
    highlight && "text-danger ring-danger/40",
    className,
  );
  const body = (
    <>
      <span className="shrink-0 text-faint">{entityIcon(kind, value)}</span>
      <span className="truncate">{value}</span>
    </>
  );
  return linked ? (
    <Link href={entityHref(entity)} className={classes}>
      {body}
    </Link>
  ) : (
    <span className={classes}>{body}</span>
  );
}

export function EntityList({ entities, max = 6, linked = true }: { entities: EntityRefs; max?: number; linked?: boolean }) {
  const all = [
    ...entities.users.map((u) => `user:${u}`),
    ...entities.hosts.map((h) => `host:${h}`),
    ...entities.ips.map((i) => `ip:${i}`),
  ];
  return (
    <div className="flex flex-wrap gap-1">
      {all.slice(0, max).map((e) => (
        <EntityChip key={e} entity={e} linked={linked} />
      ))}
      {all.length > max ? <span className="self-center text-xs text-faint">+{all.length - max}</span> : null}
    </div>
  );
}

export function TechniqueChip({ technique }: { technique: string }) {
  const tactic = tacticOf(technique);
  const late = LATE_TACTICS.has(tactic);
  return (
    <Tooltip
      content={
        <span>
          <span className="font-medium">{techniqueName(technique)}</span>
          <br />
          <span className="text-faint">{tactic}</span>
        </span>
      }
    >
      <span
        className={cn(
          "inline-flex h-6 cursor-default items-center rounded-md px-2 font-mono text-[11px] ring-1 ring-inset",
          late ? "bg-danger/10 text-danger ring-danger/30" : "bg-raised text-dim ring-line",
        )}
      >
        {technique}
      </span>
    </Tooltip>
  );
}

/** The ATT&CK tactics an incident reached, along the kill chain. */
export function KillChain({ techniques }: { techniques: string[] }) {
  const reached = new Set(techniques.map(tacticOf));
  return (
    <div className="flex items-center gap-1">
      {TACTIC_ORDER.map((tactic) => {
        const on = reached.has(tactic);
        return (
          <Tooltip key={tactic} content={tactic}>
            <span
              className={cn(
                "h-1.5 flex-1 rounded-full transition-colors",
                on ? (LATE_TACTICS.has(tactic) ? "bg-danger" : "bg-warn") : "bg-raised ring-1 ring-line",
              )}
              style={{ minWidth: 14 }}
            />
          </Tooltip>
        );
      })}
    </div>
  );
}
