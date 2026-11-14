"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Tooltip } from "radix-ui";
import { useState, type ReactNode } from "react";
import { Toaster } from "sonner";

import { LiveProvider } from "@/lib/live";

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { staleTime: 3_000, retry: 1, refetchOnWindowFocus: false } },
      }),
  );
  return (
    <QueryClientProvider client={client}>
      <Tooltip.Provider delayDuration={150}>
        <LiveProvider>{children}</LiveProvider>
        <Toaster
          theme="dark"
          position="bottom-right"
          toastOptions={{ style: { background: "#151b26", border: "1px solid #2e394c", color: "#e7ebf3" } }}
        />
      </Tooltip.Provider>
    </QueryClientProvider>
  );
}
