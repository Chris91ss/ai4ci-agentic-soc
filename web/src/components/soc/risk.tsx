"use client";

import { motion } from "framer-motion";

import { cn } from "@/lib/utils";

export function riskColor(risk: number) {
  if (risk >= 0.85) return "#f43f5e";
  if (risk >= 0.7) return "#f59e0b";
  if (risk >= 0.5) return "#818cf8";
  return "#64708a";
}

export function RiskBar({ risk, className }: { risk: number; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-raised ring-1 ring-line">
        <motion.div
          className="h-full rounded-full"
          style={{ background: riskColor(risk) }}
          initial={{ width: 0 }}
          animate={{ width: `${Math.max(4, risk * 100)}%` }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
        />
      </div>
      <span className="font-mono text-xs tabular-nums text-dim">{risk.toFixed(2)}</span>
    </div>
  );
}

/** Half-circle gauge of an incident's risk. */
export function RiskGauge({ risk, size = 132 }: { risk: number; size?: number }) {
  const stroke = 10;
  const r = (size - stroke) / 2;
  const circumference = Math.PI * r;
  const color = riskColor(risk);
  return (
    <div className="relative" style={{ width: size, height: size / 2 + 18 }}>
      <svg width={size} height={size / 2 + stroke} viewBox={`0 0 ${size} ${size / 2 + stroke}`}>
        <path
          d={`M ${stroke / 2} ${size / 2} A ${r} ${r} 0 0 1 ${size - stroke / 2} ${size / 2}`}
          fill="none"
          stroke="#222b3a"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        <motion.path
          d={`M ${stroke / 2} ${size / 2} A ${r} ${r} 0 0 1 ${size - stroke / 2} ${size / 2}`}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference * (1 - risk) }}
          transition={{ duration: 1.1, ease: [0.22, 1, 0.36, 1] }}
          style={{ filter: `drop-shadow(0 0 8px ${color}66)` }}
        />
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center">
        <div className="font-mono text-2xl font-semibold" style={{ color }}>
          {risk.toFixed(2)}
        </div>
        <div className="text-[10px] uppercase tracking-widest text-faint">risk</div>
      </div>
    </div>
  );
}
