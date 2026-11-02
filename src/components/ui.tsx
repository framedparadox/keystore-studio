import React from "react";
import clsx from "clsx";

/*
 * Shared UI primitives. Compose pages from these instead of hand-rolling
 * button/card/badge classes. Rules live in DESIGN.md.
 */

type ButtonVariant = "primary" | "secondary" | "ghost";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-brand-deep text-white hover:bg-brand-deeper",
  secondary: "bg-surface text-ink border border-line-strong hover:bg-surface-2",
  ghost: "text-muted hover:bg-surface-3 hover:text-ink",
};

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  icon?: React.ElementType;
}

export const Button: React.FC<ButtonProps> = ({
  variant = "secondary",
  size = "md",
  icon: Icon,
  className,
  children,
  ...rest
}) => (
  <button
    {...rest}
    className={clsx(
      "inline-flex items-center justify-center gap-1.5 rounded-full font-semibold transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed",
      size === "sm" ? "px-3 py-1 text-[12px]" : "px-4 py-2 text-[12.5px]",
      buttonVariants[variant],
      className
    )}
  >
    {Icon && <Icon className="w-3.5 h-3.5 shrink-0" />}
    {children}
  </button>
);

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  interactive?: boolean;
}

export const Card: React.FC<CardProps> = ({ interactive, className, ...rest }) => (
  <div
    {...rest}
    className={clsx(
      "bg-surface border border-line rounded-card p-5",
      interactive && "cursor-pointer transition hover:border-brand hover:shadow-sm",
      className
    )}
  />
);

export const Badge: React.FC<{ tone?: "neutral" | "brand" | "success" | "danger"; children: React.ReactNode }> = ({
  tone = "neutral",
  children,
}) => (
  <span
    className={clsx(
      "inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold",
      tone === "neutral" && "bg-surface-3 text-muted",
      tone === "brand" && "bg-brand-soft text-brand-deep",
      tone === "success" && "bg-success-tint text-success",
      tone === "danger" && "bg-danger-tint text-danger"
    )}
  >
    {children}
  </span>
);

export const PageHeader: React.FC<{
  title: string;
  description?: string;
  actions?: React.ReactNode;
}> = ({ title, description, actions }) => (
  <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-4">
    <div>
      <h1 className="text-[24px] font-bold text-ink tracking-tight leading-tight">{title}</h1>
      {description && <p className="text-[13px] text-muted mt-1 max-w-2xl">{description}</p>}
    </div>
    {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
  </div>
);
