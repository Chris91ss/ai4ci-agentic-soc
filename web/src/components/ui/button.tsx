"use client";

import { motion } from "framer-motion";
import type { ButtonHTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/utils";

const VARIANTS = {
  primary: "bg-brand text-canvas hover:bg-brand-strong shadow-[0_0_24px_-8px_rgb(34_211_238/0.7)]",
  secondary: "bg-raised text-ink ring-1 ring-line hover:bg-hover hover:ring-line-strong",
  ghost: "text-dim hover:bg-raised hover:text-ink",
  danger: "bg-danger/15 text-danger ring-1 ring-danger/40 hover:bg-danger/25",
  ok: "bg-ok/15 text-ok ring-1 ring-ok/40 hover:bg-ok/25",
} as const;

type Props = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "onAnimationStart" | "onDrag" | "onDragStart" | "onDragEnd"> & {
  variant?: keyof typeof VARIANTS;
  size?: "sm" | "md";
  icon?: ReactNode;
  loading?: boolean;
};

export function Button({ variant = "secondary", size = "md", icon, loading, className, children, disabled, ...props }: Props) {
  return (
    <motion.button
      whileTap={{ scale: 0.97 }}
      disabled={disabled || loading}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-9 px-3.5 text-sm",
        VARIANTS[variant],
        className,
      )}
      {...props}
    >
      {loading ? (
        <span className="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
      ) : (
        icon
      )}
      {children}
    </motion.button>
  );
}
