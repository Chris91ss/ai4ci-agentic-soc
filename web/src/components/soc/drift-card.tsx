"use client";

import { IconAlarm, IconRefresh, IconWaveSine } from "@tabler/icons-react";
import { CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, Skeleton } from "@/components/ui/states";
import { fmtTime } from "@/lib/format";
import { useDriftLog } from "@/lib/queries";

const PSI_ALARM = 0.25;
const FLOOR = 0.001; // log scale: a PSI of 0 is drawn at the floor
const COLORS: Record<string, string> = { "M1-user": "#a78bfa", "M1-ip": "#22d3ee" };
const tooltipStyle = { background: "#151b26", border: "1px solid #2e394c", borderRadius: 10, fontSize: 12 };

/** The drift monitor: hourly PSI of the M1 feature groups against the training reference. */
export function DriftCard() {
  const { data: log, isLoading } = useDriftLog();
  if (isLoading) return <Skeleton className="h-80" />;
  const checks = (log ?? []).filter((e) => e.kind === "drift_check");
  const alarms = (log ?? []).filter((e) => e.kind === "drift_alarm");
  const retrains = (log ?? []).filter((e) => e.kind === "retrain");
  const kinds = [...new Set(checks.map((c) => String(c.feature_kind)))].sort();
  const byTime = new Map<number, Record<string, number>>();
  for (const check of checks) {
    const t = Date.parse(check.time);
    byTime.set(t, { ...(byTime.get(t) ?? { t }), [String(check.feature_kind)]: Math.max(Number(check.max_psi), FLOOR) });
  }
  // After a retrain the monitor waits for a fresh window: show the pause as a gap, not a line.
  const data: Record<string, number>[] = [];
  for (const point of [...byTime.values()].sort((a, b) => a.t - b.t)) {
    const last = data.at(-1);
    if (last && point.t - last.t > 2 * 3_600_000) data.push({ t: last.t + 3_600_000 });
    data.push(point);
  }
  const latest = kinds.map((kind) => checks.filter((c) => c.feature_kind === kind).at(-1)).filter(Boolean);
  const version = retrains.at(-1)?.version as string | undefined;

  return (
    <Card className="xl:col-span-2">
      <CardHeader
        icon={<IconWaveSine size={16} />}
        title="Drift monitor"
        subtitle={`Largest PSI per M1 feature group against the training reference (alarm: ≥2 features above ${PSI_ALARM} twice in a row)`}
        action={
          <div className="flex gap-1.5">
            <Badge>{checks.length} checks</Badge>
            <Badge tone={alarms.length ? "warn" : "ok"} icon={<IconAlarm size={12} />}>
              {alarms.length} alarm{alarms.length === 1 ? "" : "s"}
            </Badge>
            <Badge tone={retrains.length ? "ok" : "neutral"} icon={<IconRefresh size={12} />} title={version}>
              {retrains.length} retrain{retrains.length === 1 ? "" : "s"}
            </Badge>
          </div>
        }
      />
      {data.length ? (
        <CardBody className="space-y-3">
          <div className="h-64">
            <ResponsiveContainer>
              <LineChart data={data} margin={{ left: -8, right: 8 }}>
                <CartesianGrid stroke="#222b3a" vertical={false} />
                <XAxis
                  dataKey="t"
                  type="number"
                  scale="time"
                  domain={["dataMin", "dataMax"]}
                  stroke="#64708a"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(t) => fmtTime(new Date(t).toISOString())}
                />
                <YAxis scale="log" domain={[FLOOR, "auto"]} allowDataOverflow stroke="#64708a" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={tooltipStyle}
                  labelFormatter={(t) => fmtTime(new Date(Number(t)).toISOString(), "EEE HH:mm")}
                  formatter={(v) => Number(v).toFixed(3)}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
                <ReferenceLine y={PSI_ALARM} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: "alarm 0.25", fill: "#f59e0b", fontSize: 10, position: "insideTopLeft" }} />
                {alarms.map((a) => (
                  <ReferenceLine key={`alarm-${a.time}`} x={Date.parse(a.time)} stroke="#f43f5e" strokeDasharray="4 4" />
                ))}
                {retrains.map((r) => (
                  <ReferenceLine key={`retrain-${r.time}`} x={Date.parse(r.time)} stroke="#10b981" strokeDasharray="2 3" />
                ))}
                {kinds.map((kind) => (
                  <Line key={kind} dataKey={kind} name={kind} stroke={COLORS[kind] ?? "#9aa5b8"} dot={false} strokeWidth={2} animationDuration={900} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-faint">Latest top features:</span>
            {latest.flatMap((check) =>
              Object.entries((check!.top_psi ?? {}) as Record<string, number>)
                .slice(0, 3)
                .map(([feature, psi]) => (
                  <Badge key={`${check!.feature_kind}-${feature}`} tone={psi > PSI_ALARM ? "warn" : "neutral"}>
                    {String(check!.feature_kind)} · {feature} {psi.toFixed(2)}
                  </Badge>
                )),
            )}
          </div>
        </CardBody>
      ) : (
        <EmptyState icon={<IconWaveSine size={20} />} title="No drift checks yet">
          The pipeline compares the M1 features of the last 24 hours with the training reference every hour.
        </EmptyState>
      )}
    </Card>
  );
}
