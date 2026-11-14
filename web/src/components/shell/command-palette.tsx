"use client";

import { IconBolt, IconChartBar, IconFingerprint, IconLayoutDashboard, IconStack2, IconUsers } from "@tabler/icons-react";
import { Command } from "cmdk";
import { AnimatePresence, motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, type ReactNode } from "react";

import { PriorityBadge, StatusBadge } from "@/components/soc/badges";
import { useIncidents } from "@/lib/queries";
import { entityHref, incidentHref } from "@/lib/utils";

const PAGES: { label: string; href: string; icon: ReactNode }[] = [
  { label: "Overview", href: "/", icon: <IconLayoutDashboard size={16} /> },
  { label: "Incidents", href: "/incidents", icon: <IconStack2 size={16} /> },
  { label: "Entities", href: "/entities", icon: <IconUsers size={16} /> },
  { label: "Actions", href: "/actions", icon: <IconBolt size={16} /> },
  { label: "Metrics", href: "/metrics", icon: <IconChartBar size={16} /> },
  { label: "Audit log", href: "/audit", icon: <IconFingerprint size={16} /> },
];

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const router = useRouter();
  const { data: incidents } = useIncidents({ limit: 500 });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(!open);
      }
      if (e.key === "Escape") onOpenChange(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onOpenChange]);

  const entities = useMemo(() => {
    const seen = new Set<string>();
    for (const incident of incidents ?? []) {
      incident.entities.users.forEach((u) => seen.add(`user:${u}`));
      incident.entities.hosts.forEach((h) => seen.add(`host:${h}`));
      incident.entities.ips.forEach((i) => seen.add(`ip:${i}`));
    }
    return [...seen].sort();
  }, [incidents]);

  const go = (href: string) => {
    onOpenChange(false);
    router.push(href);
  };

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          className="fixed inset-0 z-50 flex items-start justify-center bg-canvas/70 px-4 pt-[12vh] backdrop-blur-sm"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={() => onOpenChange(false)}
        >
          <motion.div
            initial={{ opacity: 0, y: -12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ type: "spring", stiffness: 380, damping: 30 }}
            className="w-full max-w-xl overflow-hidden rounded-2xl border border-line-strong bg-panel shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <Command label="Search the SOC" className="[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-2 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-faint">
              <Command.Input
                autoFocus
                placeholder="Jump to an incident, an entity or a page…"
                className="h-12 w-full border-b border-line bg-transparent px-4 text-sm text-ink outline-none placeholder:text-faint"
              />
              <Command.List className="max-h-[50vh] overflow-y-auto p-2">
                <Command.Empty className="px-3 py-6 text-center text-sm text-faint">Nothing found.</Command.Empty>
                <Command.Group heading="Pages">
                  {PAGES.map((page) => (
                    <Command.Item
                      key={page.href}
                      value={`page ${page.label}`}
                      onSelect={() => go(page.href)}
                      className="flex h-9 cursor-pointer items-center gap-2.5 rounded-lg px-3 text-sm text-dim data-[selected=true]:bg-raised data-[selected=true]:text-ink"
                    >
                      {page.icon}
                      {page.label}
                    </Command.Item>
                  ))}
                </Command.Group>
                <Command.Group heading="Incidents">
                  {(incidents ?? []).slice(0, 60).map((incident) => (
                    <Command.Item
                      key={incident.incident_id}
                      value={`${incident.incident_id} ${incident.summary} ${incident.entities.users.join(" ")} ${incident.entities.hosts.join(" ")}`}
                      onSelect={() => go(incidentHref(incident.incident_id))}
                      className="flex h-10 cursor-pointer items-center gap-2.5 rounded-lg px-3 text-sm text-dim data-[selected=true]:bg-raised data-[selected=true]:text-ink"
                    >
                      <PriorityBadge priority={incident.priority} />
                      <span className="font-mono text-xs text-ink">{incident.incident_id}</span>
                      <span className="flex-1 truncate text-xs">{incident.summary}</span>
                      <StatusBadge status={incident.status} />
                    </Command.Item>
                  ))}
                </Command.Group>
                <Command.Group heading="Entities">
                  {entities.slice(0, 200).map((entity) => (
                    <Command.Item
                      key={entity}
                      value={entity}
                      onSelect={() => go(entityHref(entity))}
                      className="flex h-9 cursor-pointer items-center gap-2.5 rounded-lg px-3 font-mono text-xs text-dim data-[selected=true]:bg-raised data-[selected=true]:text-ink"
                    >
                      {entity}
                    </Command.Item>
                  ))}
                </Command.Group>
              </Command.List>
            </Command>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
