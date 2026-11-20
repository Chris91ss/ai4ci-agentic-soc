"use client";

import { IconHourglass } from "@tabler/icons-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef } from "react";
import { toast } from "sonner";

import { ACTION_META } from "@/components/soc/badges";
import { useActions, useHealth } from "@/lib/queries";
import { incidentHref } from "@/lib/utils";

// Live demo only: a held action does nothing until an analyst decides, so each one gets a toast
// that stays until it is approved or rejected (or closed).
export function ApprovalAlerts() {
  const router = useRouter();
  const { data: health } = useHealth();
  const { data: pending } = useActions(["pending_approval"]);
  const shown = useRef(new Set<string>());

  useEffect(() => {
    if (!health?.live || !pending) return;
    const waiting = new Set(pending.map((a) => a.action_id));
    shown.current.forEach((id) => {
      if (!waiting.has(id)) {
        toast.dismiss(id);
        shown.current.delete(id);
      }
    });
    pending.forEach((action) => {
      if (shown.current.has(action.action_id)) return;
      shown.current.add(action.action_id);
      const incident = action.incident_id;
      toast(`${ACTION_META[action.type]?.label ?? action.type} ${action.target} needs approval`, {
        id: action.action_id,
        icon: <IconHourglass size={16} className="text-warn" />,
        description: `${incident ?? action.action_id} · requested by ${action.requested_by}`,
        duration: Infinity,
        action: incident ? { label: "Review", onClick: () => router.push(incidentHref(incident)) } : undefined,
        actionButtonStyle: { background: "#22d3ee", color: "#090c12", fontWeight: 600 },
      });
    });
  }, [health?.live, pending, router]);

  return null;
}
