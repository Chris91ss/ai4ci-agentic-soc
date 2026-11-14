"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { api, DATA_MODE } from "./api";
import { useHealth } from "./queries";
import type { Metrics, PipelineEvent } from "./types";

const KINDS = ["alert", "incident", "route", "decision", "action", "merge", "agent_fallback", "action_rejected", "evidence_missing"];
const KEEP = 200;

interface LiveState {
  mode: "live" | "replay";
  connected: boolean;
  events: PipelineEvent[]; // newest first
  metrics: Metrics | null;
  clock: string | null; // simulation time of the newest event
  playing: boolean;
  speed: number; // replay: simulated seconds per second
  progress: number; // replay: 0..1
  setPlaying: (playing: boolean) => void;
  setSpeed: (speed: number) => void;
  restart: () => void;
}

const LiveContext = createContext<LiveState | null>(null);

export function useLive() {
  const value = useContext(LiveContext);
  if (!value) throw new Error("useLive outside LiveProvider");
  return value;
}

function useInvalidator() {
  const client = useQueryClient();
  const pending = useRef<Set<string>>(new Set());
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  return useCallback(
    (kind: string) => {
      const targets =
        kind === "decision" || kind === "action"
          ? ["incidents", "incident", "trace", "actions", "metrics", "evidence"]
          : kind === "incident" || kind === "merge" || kind === "route"
            ? ["incidents", "metrics"]
            : [];
      targets.forEach((t) => pending.current.add(t));
      if (!targets.length || timer.current) return;
      timer.current = setTimeout(() => {
        pending.current.forEach((key) => client.invalidateQueries({ queryKey: [key] }));
        pending.current.clear();
        timer.current = null;
      }, 800);
    },
    [client],
  );
}

function useSse(enabled: boolean) {
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [connected, setConnected] = useState(false);
  const invalidate = useInvalidator();
  const buffer = useRef<PipelineEvent[]>([]);
  const cursor = useRef(0);

  useEffect(() => {
    if (!enabled) return;
    let source: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let closed = false;
    const flush = setInterval(() => {
      if (!buffer.current.length) return;
      const batch = buffer.current.reverse();
      buffer.current = [];
      setEvents((prev) => [...batch, ...prev].slice(0, KEEP));
    }, 300);

    const connect = () => {
      source = new EventSource(api.eventsUrl(cursor.current));
      source.addEventListener("hello", () => setConnected(true));
      source.addEventListener("metrics", (e) => {
        const data = JSON.parse((e as MessageEvent).data) as Metrics;
        if (typeof data.cursor === "number") cursor.current = data.cursor;
        setMetrics(data);
      });
      KINDS.forEach((kind) =>
        source!.addEventListener(kind, (e) => {
          const data = JSON.parse((e as MessageEvent).data) as PipelineEvent;
          cursor.current += 1;
          buffer.current.push(data);
          if (buffer.current.length > KEEP) buffer.current.splice(0, buffer.current.length - KEEP);
          invalidate(kind);
        }),
      );
      source.onerror = () => {
        setConnected(false);
        source?.close();
        if (!closed) retry = setTimeout(connect, 3000);
      };
    };
    connect();
    return () => {
      closed = true;
      clearInterval(flush);
      if (retry) clearTimeout(retry);
      source?.close();
    };
  }, [enabled, invalidate]);

  return { events, metrics, connected };
}

function upperBound(times: number[], value: number) {
  let lo = 0;
  let hi = times.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (times[mid] <= value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function replayStart(log: PipelineEvent[]) {
  const firstIncident = log.find((e) => e.kind === "incident");
  const start = firstIncident ? Date.parse(firstIncident.time) - 20 * 60_000 : Date.parse(log[0]?.time ?? "");
  return Number.isFinite(start) ? start : null;
}

function useReplay(enabled: boolean) {
  const [log, setLog] = useState<PipelineEvent[]>([]);
  const [clock, setClock] = useState<number | null>(null);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(900);
  const clockRef = useRef<number | null>(null);
  const times = useMemo(() => log.map((e) => Date.parse(e.time)), [log]);

  useEffect(() => {
    if (!enabled) return;
    api
      .pipelineLog()
      .then((entries) => {
        const sorted = [...entries].sort((a, b) => a.time.localeCompare(b.time));
        clockRef.current = replayStart(sorted);
        setLog(sorted);
        setClock(clockRef.current);
      })
      .catch(() => setLog([]));
  }, [enabled]);

  useEffect(() => {
    if (!enabled || !playing || !times.length) return;
    const end = times[times.length - 1];
    const tick = setInterval(() => {
      const next = Math.min(end, (clockRef.current ?? times[0]) + speed * 250);
      clockRef.current = next;
      setClock(next);
      if (next >= end) setPlaying(false);
    }, 250);
    return () => clearInterval(tick);
  }, [enabled, playing, speed, times]);

  const index = clock === null ? 0 : upperBound(times, clock);
  const events = useMemo(() => log.slice(Math.max(0, index - KEEP), index).reverse(), [log, index]);
  const restart = useCallback(() => {
    clockRef.current = replayStart(log);
    setClock(clockRef.current);
    setPlaying(true);
  }, [log]);

  return {
    events,
    clock: clock === null ? null : new Date(clock).toISOString(),
    playing,
    setPlaying,
    speed,
    setSpeed,
    progress: log.length ? index / log.length : 0,
    restart,
  };
}

export function LiveProvider({ children }: { children: ReactNode }) {
  // A live pipeline streams its events; a recorded run (served by the API or exported as
  // static files) is replayed from its pipeline log.
  const { data: health } = useHealth();
  const streaming = DATA_MODE === "api" && health?.live === true;
  const replaying = DATA_MODE === "static" || health?.live === false;
  const sse = useSse(streaming);
  const replay = useReplay(replaying);
  const value: LiveState =
    !replaying
      ? {
          mode: "live",
          connected: sse.connected,
          events: sse.events,
          metrics: sse.metrics,
          clock: sse.metrics?.now ?? sse.events[0]?.time ?? null,
          playing: true,
          speed: 1,
          progress: 1,
          setPlaying: () => undefined,
          setSpeed: () => undefined,
          restart: () => undefined,
        }
      : {
          mode: "replay",
          connected: true,
          events: replay.events,
          metrics: null,
          clock: replay.clock,
          playing: replay.playing,
          speed: replay.speed,
          progress: replay.progress,
          setPlaying: replay.setPlaying,
          setSpeed: replay.setSpeed,
          restart: replay.restart,
        };
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}
