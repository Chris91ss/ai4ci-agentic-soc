import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Path under the deployment's base path (GitHub Pages serves the console from a sub-path). */
export function withBase(path: string) {
  const base = process.env.NEXT_PUBLIC_BASE_PATH ?? "";
  return `${base}${path.startsWith("/") ? path : `/${path}`}`;
}

export function entityHref(entity: string) {
  return `/entity?e=${encodeURIComponent(entity)}`;
}

export function incidentHref(id: string) {
  return `/incident?id=${encodeURIComponent(id)}`;
}
