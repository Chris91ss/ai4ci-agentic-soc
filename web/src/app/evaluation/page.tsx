"use client";

import { IconActivityHeartbeat, IconCpu2, IconFileAnalytics, IconFlask, IconRadar2, IconWorld } from "@tabler/icons-react";
import { useState } from "react";

import { Detectors } from "@/components/evaluation/detectors";
import { DriftS1 } from "@/components/evaluation/drift";
import { EndToEnd } from "@/components/evaluation/e2e";
import { LocalLlm } from "@/components/evaluation/llm";
import { LoadS2 } from "@/components/evaluation/load";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { TabPanel, Tabs, type TabItem } from "@/components/ui/tabs";
import { ApiError } from "@/lib/api";
import { useEvaluation } from "@/lib/queries";

const REPORT = "https://github.com/Chris91ss/ai4ci-agentic-soc/blob/main/docs/evaluation/README.md";

export default function EvaluationPage() {
  const { data, error, isLoading } = useEvaluation();
  const [tab, setTab] = useState<string | null>(null);

  const header = (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-gradient text-2xl font-semibold tracking-tight">Evaluation</h1>
        <p className="mt-1 text-sm text-dim">The agent against the baselines over many seeds, the detectors on held-out weeks, drift and load.</p>
      </div>
      {data ? (
        <div className="flex items-center gap-2">
          <Badge>generated {data.generated}</Badge>
          <a href={REPORT} target="_blank" rel="noreferrer">
            <Badge tone="brand" icon={<IconFileAnalytics size={12} />}>
              full report
            </Badge>
          </a>
        </div>
      ) : null}
    </div>
  );

  if (error instanceof ApiError && error.status === 404)
    return (
      <>
        {header}
        <EmptyState icon={<IconFlask size={20} />} title="No evaluation results yet">
          Run <code className="font-mono">soc evaluate models</code>, <code className="font-mono">e2e</code>, <code className="font-mono">s1</code>{" "}
          and <code className="font-mono">s2</code>; the results land in <code className="font-mono">docs/evaluation</code>.
        </EmptyState>
      </>
    );
  if (error) return <ErrorState error={error} />;
  if (isLoading || !data)
    return (
      <>
        {header}
        <div className="grid gap-4 xl:grid-cols-3">
          {Array.from({ length: 3 }, (_, i) => (
            <Skeleton key={i} className="h-80" />
          ))}
        </div>
      </>
    );

  const candidates: (TabItem | undefined)[] = [
    data.e2e ? { value: "e2e", label: "End to end", icon: <IconFlask size={15} />, count: data.e2e.runs.length } : undefined,
    data.models ? { value: "models", label: "Detectors", icon: <IconRadar2 size={15} />, count: Object.keys(data.models.kinds).length } : undefined,
    data.s1 ? { value: "s1", label: "Drift (S1)", icon: <IconWorld size={15} />, count: data.s1.runs.length } : undefined,
    data.s2 ? { value: "s2", label: "Load (S2)", icon: <IconActivityHeartbeat size={15} />, count: data.s2.length } : undefined,
    data.llm ? { value: "llm", label: "Local LLM", icon: <IconCpu2 size={15} />, count: data.llm.runs.length } : undefined,
  ];
  const items = candidates.filter((item): item is TabItem => item !== undefined);
  const value = tab ?? items[0]?.value ?? "e2e";

  return (
    <>
      {header}
      <Tabs id="evaluation" items={items} value={value} onValueChange={setTab}>
        <div className="pt-4">
          {data.e2e ? (
            <TabPanel value="e2e">
              <EndToEnd e2e={data.e2e} />
            </TabPanel>
          ) : null}
          {data.models ? (
            <TabPanel value="models">
              <Detectors models={data.models} />
            </TabPanel>
          ) : null}
          {data.s1 ? (
            <TabPanel value="s1">
              <DriftS1 s1={data.s1} />
            </TabPanel>
          ) : null}
          {data.s2 ? (
            <TabPanel value="s2">
              <LoadS2 s2={data.s2} samples={data.s2_samples ?? {}} />
            </TabPanel>
          ) : null}
          {data.llm ? (
            <TabPanel value="llm">
              <LocalLlm llm={data.llm} e2e={data.e2e} />
            </TabPanel>
          ) : null}
        </div>
      </Tabs>
    </>
  );
}
