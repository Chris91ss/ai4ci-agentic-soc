"use client";

import { useState, type ReactNode } from "react";

import { ApprovalAlerts } from "./approval-alerts";
import { CommandPalette } from "./command-palette";
import { MobileNav, Sidebar } from "./sidebar";
import { Topbar } from "./topbar";

export function AppShell({ children }: { children: ReactNode }) {
  const [search, setSearch] = useState(false);
  return (
    <div className="relative flex min-h-dvh">
      <div className="pointer-events-none fixed inset-0 bg-grid opacity-60" />
      <div className="pointer-events-none fixed -top-40 left-1/3 size-[480px] rounded-full bg-brand/10 blur-[140px]" />
      <Sidebar />
      <div className="relative flex min-w-0 flex-1 flex-col">
        <Topbar onSearch={() => setSearch(true)} />
        <MobileNav />
        <main className="mx-auto w-full max-w-[1500px] flex-1 px-4 py-6 lg:px-8">{children}</main>
      </div>
      <CommandPalette open={search} onOpenChange={setSearch} />
      <ApprovalAlerts />
    </div>
  );
}
