"use client";

import { IconCpu2 } from "@tabler/icons-react";
import { motion } from "framer-motion";

import { Card, CardHeader } from "@/components/ui/card";
import { fmtDuration, fmtPercent } from "@/lib/format";
import type { Evaluation, EvalRun } from "@/lib/types";

import { ConfigCard, sortConfigs } from "./e2e";
import { STAGE_COLOR, STAGE_LABEL, configMeta, fmtMinutes, fmtNum } from "./shared";

function RunCell({ run }: { run?: EvalRun }) {
  if (!run) return <td className="px-4 py-2 text-faint">—</td>;
  if (run.error)
    return (
      <td className="px-4 py-2 text-danger" title={run.error}>
        failed
      </td>
    );
  const stage = run.furthest_stage ?? "none";
  return (
    <td className="px-4 py-2">
      <div className="flex items-center gap-2">
        <span className="size-2 shrink-0 rounded-full" style={{ background: STAGE_COLOR[stage] }} />
        <span className="text-ink">{STAGE_LABEL[stage]}</span>
        {run.exfil_gb ? <span className="font-mono text-danger">{run.exfil_gb} GB</span> : null}
      </div>
      <div className="mt-0.5 flex flex-wrap gap-x-3 font-mono text-[11px] text-faint">
        <span>MTTC {fmtMinutes(run.mttc_min)}</span>
        <span className={run.false_containments ? "text-danger" : undefined}>FC {run.false_containments}</span>
        {run.agent ? <span>F1 {fmtNum(run.agent.verdict.f1)}</span> : null}
        {run.agent ? <span>latency {fmtDuration(run.agent.latency_mean_s)}</span> : null}
        {run.agent?.invalid_tool_call_rate ? <span>invalid calls {fmtPercent(run.agent.invalid_tool_call_rate, 1)}</span> : null}
      </div>
    </td>
  );
}

export function LocalLlm({ llm, e2e }: { llm: NonNullable<Evaluation["llm"]>; e2e?: Evaluation["e2e"] }) {
  const configs = sortConfigs(Object.keys(llm.summary));
  const llmConfigs = configs.filter((c) => c !== "agent");
  const seeds = [...new Set(llm.runs.map((r) => r.seed))].sort((a, b) => a - b);
  const scripted = (seed: number) => e2e?.runs.find((r) => r.config === "agent" && r.seed === seed);
  return (
    <div className="space-y-4">
      <p className="text-xs text-dim">
        The same closed loop with the triage agent on a local model served by Ollama instead of the scripted reference analyst. Every LLM call
        is charged in simulated time, so slower reasoning gives the attacker more time; malformed tool calls are rejected by the MCP layer.
      </p>
      <div className="grid gap-4 xl:grid-cols-2">
        {configs.map((c, i) => (
          <ConfigCard key={c} config={c} s={llm.summary[c]} index={i} />
        ))}
      </div>
      <Card>
        <CardHeader icon={<IconCpu2 size={16} />} title="Per seed" subtitle="The scripted analyst against the local LLM on the same seeds" />
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-faint">
              <tr className="border-b border-line">
                <th className="px-4 py-2 font-medium">Seed</th>
                <th className="px-4 py-2 font-medium">{configMeta("agent").short}</th>
                {llmConfigs.map((c) => (
                  <th key={c} className="px-4 py-2 font-medium">
                    {configMeta(c).label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line/60">
              {seeds.map((seed, i) => (
                <motion.tr key={seed} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}>
                  <td className="px-4 py-2 font-mono text-ink">{seed}</td>
                  <RunCell run={scripted(seed)} />
                  {llmConfigs.map((c) => (
                    <RunCell key={c} run={llm.runs.find((r) => r.seed === seed && r.config === c)} />
                  ))}
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
