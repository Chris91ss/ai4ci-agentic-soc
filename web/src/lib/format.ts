import { format, formatDistanceStrict, parseISO } from "date-fns";

export function toDate(value: string | Date | null | undefined): Date | null {
  if (!value) return null;
  return value instanceof Date ? value : parseISO(value);
}

/** Simulation times are shown in UTC, the clock of the simulated enterprise's logs. */
function utc(date: Date) {
  return new Date(date.getTime() + date.getTimezoneOffset() * 60_000);
}

export function fmtTime(value: string | null | undefined, pattern = "EEE HH:mm") {
  const date = toDate(value);
  return date ? format(utc(date), pattern) : "—";
}

export function fmtDateTime(value: string | null | undefined) {
  return fmtTime(value, "EEE d MMM, HH:mm:ss");
}

export function fmtSince(from: string | null | undefined, to: string | null | undefined) {
  const a = toDate(from);
  const b = toDate(to);
  if (!a || !b) return "—";
  return formatDistanceStrict(a, b);
}

export function fmtDuration(seconds: number | null | undefined) {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return "—";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  const h = seconds / 3600;
  return `${h < 10 ? h.toFixed(1) : Math.round(h)} h`;
}

const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const plain = new Intl.NumberFormat("en");

export function fmtNumber(value: number | null | undefined, opts: { compact?: boolean } = {}) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return opts.compact && Math.abs(value) >= 10_000 ? compact.format(value) : plain.format(Math.round(value * 100) / 100);
}

export function fmtPercent(value: number | null | undefined, digits = 0) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

export function fmtBytes(bytes: number | null | undefined) {
  if (bytes === null || bytes === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 && unit ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function titleCase(text: string) {
  return text.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
