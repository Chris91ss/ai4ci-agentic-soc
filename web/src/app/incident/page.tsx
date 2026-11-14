import type { Metadata } from "next";
import { Suspense } from "react";

import { IncidentView } from "@/components/incident/incident-view";
import { Skeleton } from "@/components/ui/states";

export const metadata: Metadata = { title: "Incident" };

export default function IncidentPage() {
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <IncidentView />
    </Suspense>
  );
}
