import type { Metadata } from "next";
import { Suspense } from "react";

import { EntityView } from "@/components/entity-view";
import { Skeleton } from "@/components/ui/states";

export const metadata: Metadata = { title: "Entity" };

export default function EntityPage() {
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <EntityView />
    </Suspense>
  );
}
