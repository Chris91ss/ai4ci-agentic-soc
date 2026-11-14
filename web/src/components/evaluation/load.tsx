"use client";

import { IconActivityHeartbeat, IconBolt, IconCircuitSwitchOpen, IconClockExclamation, IconStack3, IconTrafficLights } from "@tabler/icons-react";
import { Area, CartesianGrid, ComposedChart, Legend, Line, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Stat } from "@/components/ui/stat";
import { fmtDuration, fmtNumber, titleCase } from "@/lib/format";
import type { S2Sample, S2Variant } from "@/lib/types";

import { axis, fmtNum, tooltipStyle } from "./shared";

/** The samples taken while both ran: from the pipeline's first poll (before it, a new consumer
 * group reports the whole topic as lag) until the simulator's clock stopped at the end of the run. */
function running(samples: S2Sample[]) {
  const end = Math.max(...samples.map((s) => s.sim_t));
  const last = samples.findIndex((s) => s.sim_t >= end);
  return samples.slice(0, last < 0 ? undefined : last).filter((s) => s.pipeline_t !== null);
}

function Variant({ v, samples, index }: { v: S2Variant; samples: S2Sample[]; index: number }) {
  const shown = running(samples);
  const t0 = shown[0]?.sim_t ?? Date.parse(v.burst.start) / 1000;
  // A sample shows the lag of the simulator's one-minute tick in flight, or about zero once the
  // pipeline consumed it; the mean over ten simulated minutes is how far behind it ran on average.
  const data = shown.map((s, i) => {
    let sum = 0;
    let n = 0;
    for (let j = i; j >= 0 && shown[j].sim_t > s.sim_t - 600; j--) {
      const value = shown[j].stream_lag_s;
      if (value !== null) {
        sum += Math.max(0, value);
        n += 1;
      }
    }
    return { h: Number(((s.sim_t - t0) / 3600).toFixed(3)), lag: n ? sum / n : null, messages: s.lag_messages, queue: s.queue };
  });
  const burstStart = (Date.parse(v.burst.start) / 1000 - t0) / 3600;
  const burstEnd = (Date.parse(v.burst.end) / 1000 - t0) / 3600;
  const burst = v.phases.burst;
  const before = v.phases.before;
  return (
    <Card transition={{ delay: index * 0.08, duration: 0.35 }}>
      <CardHeader
        icon={<IconActivityHeartbeat size={16} />}
        title={v.llm_slowdown === 1 ? "Steady LLM latency" : `LLM ${fmtNum(v.llm_slowdown, 1)}× slower during the burst`}
        subtitle={`${fmtNum(v.speed, 0)}× real time · ${fmtDuration(v.triage_s)} simulated per triage · burst factor ${fmtNum(v.burst.factor, 1)}`}
        action={
          <Badge tone={v.campaign.exfil_gb ? "danger" : "ok"}>
            campaign {v.campaign.status}
            {v.campaign.exfil_gb ? ` · ${v.campaign.exfil_gb} GB out` : ""}
          </Badge>
        }
      />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          <Stat label="Event rate in the burst" value={v.event_rate_multiplier} decimals={1} format={(n) => `${n}×`} icon={<IconBolt size={15} />} tone="warn" />
          <Stat
            label="Stream lag p95 (burst)"
            value={burst?.stream_lag_s_p95}
            format={fmtDuration}
            icon={<IconClockExclamation size={15} />}
            tone="info"
            hint={`before: ${fmtDuration(before?.stream_lag_s_p95)}`}
          />
          <Stat
            label="Consumer lag max"
            value={burst?.consumer_lag_max}
            format={(n) => fmtNumber(n, { compact: true })}
            icon={<IconStack3 size={15} />}
            tone="flow"
            hint="messages behind"
          />
          <Stat label="Shed to playbooks" value={v.shed_to_playbooks} icon={<IconTrafficLights size={15} />} tone="process" hint="agent saturated or breaker open" />
          <Stat label="Agent timeouts" value={v.agent_timeouts} icon={<IconClockExclamation size={15} />} tone="danger" />
          <Stat label="Breaker trips" value={v.breaker_trips} icon={<IconCircuitSwitchOpen size={15} />} tone="danger" />
        </div>
        <div className="h-64">
          <ResponsiveContainer>
            <ComposedChart data={data} margin={{ left: -6, right: -6 }}>
              <defs>
                <linearGradient id={`lag-${index}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#222b3a" vertical={false} />
              <XAxis dataKey="h" type="number" domain={["dataMin", "dataMax"]} {...axis} tickFormatter={(h) => `${Number(h).toFixed(0)}h`} />
              <YAxis yAxisId="lag" {...axis} tickFormatter={(s) => fmtDuration(s)} />
              <YAxis yAxisId="messages" orientation="right" scale="sqrt" {...axis} tickFormatter={(n) => fmtNumber(n, { compact: true })} />
              <Tooltip
                contentStyle={tooltipStyle}
                labelFormatter={(h) => `${Number(h).toFixed(2)} h simulated`}
                formatter={(value, name) => (String(name).startsWith("Stream lag") ? fmtDuration(Number(value)) : fmtNumber(Number(value)))}
              />
              <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
              <ReferenceArea yAxisId="lag" x1={burstStart} x2={burstEnd} fill="#f59e0b" fillOpacity={0.08} stroke="#f59e0b" strokeOpacity={0.3} />
              <Area yAxisId="messages" dataKey="messages" name="Consumer lag (messages)" stroke="#22d3ee" fill={`url(#lag-${index})`} strokeWidth={1.5} animationDuration={900} />
              <Line yAxisId="lag" dataKey="lag" name="Stream lag (10-min mean)" stroke="#f43f5e" dot={false} strokeWidth={2} animationDuration={900} />
              <Line yAxisId="messages" dataKey="queue" name="Agent queue" stroke="#a78bfa" dot={false} strokeWidth={1.5} strokeDasharray="3 3" animationDuration={900} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-faint">
              <tr className="border-b border-line">
                {["Phase", "Stream lag p50", "p95", "max", "Consumer lag p95", "max", "Events / wall s", "Agent queue max"].map((h, i) => (
                  <th key={`${h}-${i}`} className="px-3 py-2 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line/60">
              {(["before", "burst", "after"] as const).map((phase) => {
                const p = v.phases[phase];
                if (!p) return null;
                return (
                  <tr key={phase}>
                    <td className="px-3 py-1.5 text-ink">{titleCase(phase)}</td>
                    <td className="px-3 py-1.5 font-mono">{fmtDuration(p.stream_lag_s_p50)}</td>
                    <td className="px-3 py-1.5 font-mono">{fmtDuration(p.stream_lag_s_p95)}</td>
                    <td className="px-3 py-1.5 font-mono">{fmtDuration(p.stream_lag_s_max)}</td>
                    <td className="px-3 py-1.5 font-mono">{fmtNumber(p.consumer_lag_p95)}</td>
                    <td className="px-3 py-1.5 font-mono">{fmtNumber(p.consumer_lag_max)}</td>
                    <td className="px-3 py-1.5 font-mono">{fmtNumber(p.events_per_wall_s)}</td>
                    <td className="px-3 py-1.5 font-mono">{p.agent_queue_max}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(v.routes).map(([route, n]) => (
            <Badge key={route}>
              {route} · {n}
            </Badge>
          ))}
          {Object.entries(v.decisions).map(([by, n]) => (
            <Badge key={by} tone={by === "agent" ? "brand" : "info"}>
              decided by {by} · {n}
            </Badge>
          ))}
        </div>
      </CardBody>
    </Card>
  );
}

export function LoadS2({ s2, samples }: { s2: S2Variant[]; samples: Record<string, S2Sample[]> }) {
  return (
    <div className="space-y-4">
      <p className="text-xs text-dim">
        Scenario S2: a one-hour burst of about ten times the normal event rate, streamed through Redpanda in real time (sped up). Stream lag is
        how far the pipeline&apos;s clock trails the simulator&apos;s; when the agent cannot keep up, the router sheds incidents to the
        deterministic playbooks.
      </p>
      {s2.map((v, i) => (
        <Variant key={`${v.llm_slowdown}-${i}`} v={v} index={i} samples={samples[String(v.llm_slowdown)] ?? []} />
      ))}
    </div>
  );
}
