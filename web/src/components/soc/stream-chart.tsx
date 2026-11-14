"use client";

import { useMemo } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { fmtNumber, fmtTime } from "@/lib/format";
import type { StreamCount } from "@/lib/types";

import { STREAM_META } from "./badges";

const STREAMS = ["signin", "flow", "process"] as const;

export function StreamChart({ counts, height = 240 }: { counts: StreamCount[]; height?: number }) {
  const data = useMemo(() => {
    const byBucket = new Map<string, Record<string, number | string>>();
    for (const row of counts) {
      const entry = byBucket.get(row.bucket) ?? { bucket: row.bucket, signin: 0, flow: 0, process: 0 };
      entry[row.stream] = row.count;
      byBucket.set(row.bucket, entry);
    }
    return [...byBucket.values()].sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)));
  }, [counts]);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -8 }}>
        <defs>
          {STREAMS.map((s) => (
            <linearGradient key={s} id={`fill-${s}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={STREAM_META[s].color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={STREAM_META[s].color} stopOpacity={0.02} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke="#222b3a" strokeDasharray="3 6" vertical={false} />
        <XAxis
          dataKey="bucket"
          tickFormatter={(v) => fmtTime(String(v), "HH:mm")}
          stroke="#64708a"
          fontSize={11}
          tickLine={false}
          axisLine={false}
          minTickGap={40}
        />
        <YAxis stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} width={48} tickFormatter={(v) => fmtNumber(Number(v), { compact: true })} />
        <Tooltip
          contentStyle={{ background: "#151b26", border: "1px solid #2e394c", borderRadius: 10, fontSize: 12 }}
          labelFormatter={(v) => fmtTime(String(v), "EEE HH:mm")}
          formatter={(value, name) => [fmtNumber(Number(value)), STREAM_META[name as keyof typeof STREAM_META]?.label ?? name]}
        />
        {STREAMS.map((s) => (
          <Area
            key={s}
            type="monotone"
            dataKey={s}
            stackId="events"
            stroke={STREAM_META[s].color}
            strokeWidth={1.5}
            fill={`url(#fill-${s})`}
            animationDuration={900}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
