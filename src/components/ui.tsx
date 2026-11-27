import React, { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import clsx from "clsx";
import {
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Check,
  CheckCircle2,
  ChevronsUpDown,
  Copy,
  Eye,
  EyeOff,
  Info,
  Loader2,
  Search,
  X,
} from "lucide-react";
import { shortcutLabel } from "../lib/platform";

/*
 * Shared UI primitives. Compose pages from these instead of hand-rolling
 * button/card/badge/table classes. Rules live in DESIGN.md.
 */

/* -------------------------------------------------------------------------- */
/* Buttons                                                                     */
/* -------------------------------------------------------------------------- */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-brand text-on-accent border border-brand-deep/20 shadow-card hover:bg-brand-deep",
  secondary: "bg-surface text-ink-2 border border-line-strong shadow-card hover:bg-surface-2 hover:text-ink",
  ghost: "text-muted border border-transparent hover:bg-surface-3 hover:text-ink",
  danger: "bg-surface text-danger border border-line-strong shadow-card hover:bg-danger-tint hover:border-danger/30",
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
  type = "button",
  ...rest
}) => (
  <button
    type={type}
    {...rest}
    className={clsx(
      "inline-flex items-center justify-center gap-1.5 rounded-control font-semibold whitespace-nowrap transition cursor-pointer disabled:opacity-85 disabled:cursor-not-allowed",
      size === "sm" ? "h-7 px-2.5 text-[12px]" : "h-9 px-3.5 text-[13px]",
      buttonVariants[variant],
      className
    )}
  >
    {Icon && <Icon className={clsx("shrink-0", size === "sm" ? "w-3.5 h-3.5" : "w-4 h-4")} />}
    {children}
  </button>
);

interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  icon: React.ElementType;
  label: string;
  tone?: "neutral" | "danger";
}

/** Square icon-only button. `label` becomes both the tooltip and the accessible name. */
export const IconButton: React.FC<IconButtonProps> = ({ icon: Icon, label, tone = "neutral", className, ...rest }) => (
  <button
    type="button"
    title={label}
    aria-label={label}
    {...rest}
    className={clsx(
      "inline-flex items-center justify-center w-7 h-7 rounded-control transition cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed",
      tone === "danger" ? "text-faint hover:text-danger hover:bg-danger-tint" : "text-faint hover:text-ink hover:bg-surface-3",
      className
    )}
  >
    <Icon className="w-4 h-4" />
  </button>
);

/* -------------------------------------------------------------------------- */
/* Surfaces                                                                    */
/* -------------------------------------------------------------------------- */

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  interactive?: boolean;
  padded?: boolean;
}

export const Card: React.FC<CardProps> = ({ interactive, padded = true, className, ...rest }) => (
  <div
    {...rest}
    className={clsx(
      "bg-surface border border-line rounded-card shadow-card",
      padded && "p-5",
      interactive && "cursor-pointer transition hover:border-line-strong hover:shadow-pop",
      className
    )}
  />
);

/** Title row for a card: title + optional subtitle on the left, actions on the right. */
export const CardHeader: React.FC<{
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ElementType;
  actions?: React.ReactNode;
  className?: string;
  bordered?: boolean;
}> = ({ title, subtitle, icon: Icon, actions, className, bordered }) => (
  <div
    className={clsx(
      "flex items-start justify-between gap-3",
      bordered ? "px-5 py-3.5 border-b border-line" : "mb-4",
      className
    )}
  >
    <div className="flex items-start gap-2.5 min-w-0">
      {Icon && (
        <span className="mt-0.5 w-7 h-7 rounded-control bg-surface-3 text-muted flex items-center justify-center shrink-0">
          <Icon className="w-4 h-4" />
        </span>
      )}
      <div className="min-w-0">
        <h3 className="text-[14px] font-semibold text-ink leading-5 truncate">{title}</h3>
        {subtitle && <p className="text-[12px] text-faint leading-4 mt-0.5">{subtitle}</p>}
      </div>
    </div>
    {actions && <div className="flex items-center gap-1.5 shrink-0">{actions}</div>}
  </div>
);

export type Tone = "neutral" | "brand" | "success" | "warning" | "danger";

/** Tint, text and border of a Badge in each tone; status glyphs in narrow columns reuse them. */
export const badgeTones: Record<Tone, string> = {
  neutral: "bg-surface-3 text-ink-2 border-line",
  brand: "bg-brand-tint text-brand-deep border-brand-soft",
  success: "bg-success-tint text-success border-success/15",
  warning: "bg-warning-tint text-warning border-warning/20",
  danger: "bg-danger-tint text-danger border-danger/15",
};

const dotTones: Record<Tone, string> = {
  neutral: "bg-subtle",
  brand: "bg-brand",
  success: "bg-success-fill",
  warning: "bg-warning-fill",
  danger: "bg-danger-fill",
};

export const Badge: React.FC<{
  tone?: Tone;
  dot?: boolean;
  icon?: React.ElementType;
  className?: string;
  children: React.ReactNode;
}> = ({ tone = "neutral", dot, icon: Icon, className, children }) => (
  <span
    className={clsx(
      "inline-flex items-center gap-1 h-5 px-1.5 rounded-control border text-[11px] font-medium whitespace-nowrap",
      badgeTones[tone],
      className
    )}
  >
    {dot && <span className={clsx("w-1.5 h-1.5 rounded-full", dotTones[tone])} />}
    {Icon && <Icon className="w-3 h-3" />}
    {children}
  </span>
);

export const PageHeader: React.FC<{
  title: React.ReactNode;
  icon?: React.ElementType;
  description?: React.ReactNode;
  eyebrow?: React.ReactNode;
  actions?: React.ReactNode;
  actionsClassName?: string;
  /** Shown on the same row as the title, before it (e.g. a panel toggle). */
  leading?: React.ReactNode;
}> = ({ title, icon: Icon, description, eyebrow, actions, actionsClassName, leading }) => (
  <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 mb-6">
    <div className="min-w-0">
      {eyebrow && <div className="text-[12px] font-medium text-faint mb-1">{eyebrow}</div>}
      <div className="flex items-center gap-2.5 min-w-0">
        {leading}
        {Icon && <Icon className="w-5 h-5 text-brand shrink-0" aria-hidden="true" />}
        <h1 className="text-[22px] font-semibold text-ink tracking-[-0.01em] leading-7 min-w-0">{title}</h1>
      </div>
      {description && <p className="text-[13px] text-faint mt-1 max-w-3xl">{description}</p>}
    </div>
    {actions && <div className={clsx("flex flex-wrap items-center gap-2 shrink-0", actionsClassName)}>{actions}</div>}
  </div>
);

/** Standard scroll container for a page. */
export const Page: React.FC<{ children: React.ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className,
  ...rest
}) => (
  <div {...rest} className={clsx("relative flex-1 overflow-y-auto", className)}>
    <div className="max-w-[1440px] mx-auto px-8 py-7">{children}</div>
  </div>
);

export const SectionLabel: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <h2 className={clsx("text-[12px] font-semibold uppercase tracking-[0.06em] text-faint mb-3", className)}>{children}</h2>
);

/* -------------------------------------------------------------------------- */
/* KPI / bento figures                                                         */
/* -------------------------------------------------------------------------- */

const kpiIconTones: Record<Tone, string> = {
  neutral: "bg-surface-3 text-muted",
  brand: "bg-brand-tint text-brand",
  success: "bg-success-tint text-success",
  warning: "bg-warning-tint text-warning",
  danger: "bg-danger-tint text-danger",
};

/**
 * Stat tile: label · value · optional hint/delta · optional footer (meter, list…).
 * Value text stays ink; tone only colors the icon chip and the hint so color never carries meaning alone.
 */
export const KpiCard: React.FC<{
  label: string;
  value: React.ReactNode;
  unit?: string;
  icon?: React.ElementType;
  tone?: Tone;
  hint?: React.ReactNode;
  hintTone?: Tone;
  onClick?: () => void;
  className?: string;
  children?: React.ReactNode;
}> = ({ label, value, unit, icon: Icon, tone = "neutral", hint, hintTone, onClick, className, children }) => {
  const Comp = onClick ? "button" : "div";
  return (
    <Comp
      onClick={onClick}
      className={clsx(
        "group text-left bg-surface border border-line rounded-card shadow-card p-5 flex flex-col",
        onClick && "cursor-pointer transition hover:border-line-strong hover:shadow-pop",
        className
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[13px] font-medium text-faint">{label}</span>
        {Icon && (
          <span className={clsx("w-7 h-7 rounded-control flex items-center justify-center", kpiIconTones[tone])}>
            <Icon className="w-4 h-4" />
          </span>
        )}
      </div>
      <div className="mt-2 flex items-baseline gap-1.5">
        <span className="text-[28px] font-semibold text-ink leading-8 tracking-[-0.02em]">{value}</span>
        {unit && <span className="text-[13px] font-medium text-faint">{unit}</span>}
      </div>
      {hint && (
        <div
          className={clsx(
            "mt-1 text-[12px]",
            hintTone === "success" && "text-success",
            hintTone === "warning" && "text-warning",
            hintTone === "danger" && "text-danger",
            hintTone === "brand" && "text-brand-deep",
            (!hintTone || hintTone === "neutral") && "text-faint"
          )}
        >
          {hint}
        </div>
      )}
      {children && <div className="mt-auto pt-4">{children}</div>}
    </Comp>
  );
};

const meterFill: Record<Tone, string> = {
  neutral: "bg-subtle",
  brand: "bg-brand",
  success: "bg-success-fill",
  warning: "bg-warning-fill",
  danger: "bg-danger-fill",
};
const meterTrack: Record<Tone, string> = {
  neutral: "bg-surface-3",
  brand: "bg-brand-soft",
  success: "bg-success-tint",
  warning: "bg-warning-tint",
  danger: "bg-danger-tint",
};

/** Thin progress meter. `value` is 0–1. Fill carries severity; the track is a lighter step of the same hue. */
export const Meter: React.FC<{ value: number; tone?: Tone; className?: string; label?: string; thin?: boolean }> = ({
  value,
  tone = "brand",
  className,
  label,
  thin,
}) => (
  <div
    role="meter"
    aria-label={label}
    aria-valuemin={0}
    aria-valuemax={100}
    aria-valuenow={Math.round(Math.max(0, Math.min(1, value)) * 100)}
    className={clsx("w-full rounded-full overflow-hidden", thin ? "h-1" : "h-1.5", meterTrack[tone], className)}
  >
    <div
      className={clsx("h-full rounded-full transition-[width]", meterFill[tone])}
      style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }}
    />
  </div>
);

/** One whole split into parts. Each part is a block with a 2px surface gap; legend below names them. */
export const SegmentedBar: React.FC<{
  parts: { key: string; label: string; value: number; tone: Tone; fill?: string }[];
  label: string;
}> = ({ parts, label }) => {
  const total = parts.reduce((s, p) => s + p.value, 0) || 1;
  return (
    <div>
      <div role="img" aria-label={`${label}: ${parts.map((p) => `${p.label} ${p.value}`).join(", ")}`} className="flex h-2.5 gap-[2px]">
        {parts
          .filter((p) => p.value > 0)
          .map((p) => (
            <div
              key={p.key}
              title={`${p.label}: ${p.value}`}
              className={clsx("h-full rounded-full", p.fill ?? meterFill[p.tone])}
              style={{ width: `${(p.value / total) * 100}%` }}
            />
          ))}
      </div>
      <ul className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5">
        {parts.map((p) => (
          <li key={p.key} className="flex items-center justify-between gap-2 text-[12px]">
            <span className="flex items-center gap-1.5 text-muted min-w-0">
              <span className={clsx("w-2 h-2 rounded-xs shrink-0", p.fill ?? meterFill[p.tone])} />
              <span className="truncate">{p.label}</span>
            </span>
            <span className="font-semibold text-ink tabular-nums">{p.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};

/** Horizontal bar list — label · bar · value. Single hue: magnitude only. */
export const BarList: React.FC<{ items: { key: string; label: string; count: number }[]; total?: number }> = ({
  items,
  total,
}) => {
  const max = Math.max(1, ...items.map((i) => i.count));
  const sum = total ?? items.reduce((s, i) => s + i.count, 0);
  return (
    <ul className="space-y-2.5">
      {items.map((i) => (
        <li key={i.key} className="grid grid-cols-[88px_1fr_52px] items-center gap-3 text-[12px]" title={`${i.label}: ${i.count}`}>
          <span className="text-muted truncate">{i.label}</span>
          <span className="block h-2 rounded-full bg-surface-3 overflow-hidden">
            <span className="block h-full rounded-full bg-brand" style={{ width: `${(i.count / max) * 100}%` }} />
          </span>
          <span className="text-right tabular-nums">
            <span className="font-semibold text-ink">{i.count}</span>
            <span className="text-faint ml-1">{sum ? Math.round((i.count / sum) * 100) : 0}%</span>
          </span>
        </li>
      ))}
    </ul>
  );
};

/** Vertical column histogram for ordered buckets (e.g. key age). */
export const ColumnChart: React.FC<{ items: { key: string; label: string; count: number }[]; height?: number; label: string }> = ({
  items,
  height = 96,
  label,
}) => {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div role="img" aria-label={`${label}: ${items.map((i) => `${i.label} ${i.count}`).join(", ")}`}>
      <div className="flex items-end gap-2 border-b border-line" style={{ height }}>
        {items.map((i) => (
          <div key={i.key} className="flex-1 flex flex-col items-center justify-end h-full group" title={`${i.label}: ${i.count}`}>
            <span className="text-[11px] font-semibold text-ink tabular-nums mb-1">{i.count}</span>
            <div
              className="w-full max-w-[36px] rounded-t-[4px] bg-brand group-hover:bg-brand-deep transition-colors"
              style={{ height: `${Math.max(i.count ? 6 : 2, (i.count / max) * (height - 22))}px`, opacity: i.count ? 1 : 0.25 }}
            />
          </div>
        ))}
      </div>
      <div className="flex gap-2 mt-1.5">
        {items.map((i) => (
          <span key={i.key} className="flex-1 text-center text-[11px] text-faint truncate">
            {i.label}
          </span>
        ))}
      </div>
    </div>
  );
};

/** Circular score gauge for the single headline number on a page. */
export const ScoreRing: React.FC<{ value: number; size?: number; tone?: Tone; label: string }> = ({
  value,
  size = 112,
  tone = "brand",
  label,
}) => {
  const stroke = 10;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, value));
  const color = { neutral: "var(--color-subtle)", brand: "var(--color-brand)", success: "var(--color-success-fill)", warning: "var(--color-warning-fill)", danger: "var(--color-danger-fill)" }[tone];
  const track = { neutral: "var(--color-surface-3)", brand: "var(--color-brand-soft)", success: "var(--color-success-tint)", warning: "var(--color-warning-tint)", danger: "var(--color-danger-tint)" }[tone];
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="meter" aria-label={label} aria-valuenow={v} aria-valuemin={0} aria-valuemax={100}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={track} strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - v / 100)}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[30px] font-semibold text-ink leading-none tracking-[-0.02em]">{v}</span>
        <span className="text-[11px] text-faint mt-1">of 100</span>
      </div>
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* Inputs                                                                      */
/* -------------------------------------------------------------------------- */

export const SearchInput: React.FC<{
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  /** Accessible name and tooltip, when the placeholder is too short to say what is searched. */
  label?: string;
  className?: string;
}> = ({ value, onChange, placeholder = "Search…", label, className }) => (
  <div className={clsx("relative", className)}>
    <Search className="w-4 h-4 text-subtle absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" aria-hidden />
    <input
      type="search"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      aria-label={label ?? placeholder}
      title={label}
      className="field !pl-8 !pr-8"
    />
    {value && (
      <button
        type="button"
        onClick={() => onChange("")}
        aria-label="Clear search"
        className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded text-faint hover:text-ink cursor-pointer"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    )}
  </div>
);

/** Segmented control / filter tabs. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode; count?: number }[];
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="inline-flex items-center p-0.5 rounded-control bg-surface-3 border border-line">
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(o.value)}
            className={clsx(
              "h-7 px-2.5 rounded-control text-[13px] font-medium inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap",
              active ? "bg-surface text-ink shadow-card" : "text-faint hover:text-ink"
            )}
          >
            {o.label}
            {o.count !== undefined && (
              <span className={clsx("text-[11px] tabular-nums", active ? "text-muted" : "text-faint")}>{o.count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

/** Radio choices drawn as rows, each with a hint and an optional right-hand tag (e.g. a file extension). */
export function OptionList<T extends string>({
  value,
  onChange,
  options,
  label,
  columns = 1,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode; hint?: React.ReactNode; meta?: React.ReactNode; disabled?: boolean; testId?: string }[];
  label: string;
  columns?: 1 | 2;
}) {
  return (
    <div role="radiogroup" aria-label={label} className={clsx("grid gap-2", columns === 2 && "sm:grid-cols-2")}>
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={o.disabled}
            data-testid={o.testId}
            onClick={() => onChange(o.value)}
            className={clsx(
              "text-left rounded-control border px-3 py-2.5 flex items-start gap-2.5 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed",
              active ? "border-brand bg-brand-tint ring-2 ring-brand-soft" : "border-line bg-surface hover:border-line-strong"
            )}
          >
            <span className={clsx("mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center shrink-0", active ? "border-brand" : "border-line-strong")}>
              {active && <span className="w-2 h-2 rounded-full bg-brand" />}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-[13px] font-medium text-ink">{o.label}</span>
              {o.hint && <span className="block text-[12px] text-faint mt-0.5">{o.hint}</span>}
            </span>
            {o.meta && <span className="shrink-0 mt-0.5 text-[11px] font-mono text-faint">{o.meta}</span>}
          </button>
        );
      })}
    </div>
  );
}

/** A row of small figures in one card, e.g. the summary under a table. Lighter than a row of KpiCards. */
export const StatStrip: React.FC<{
  items: { label: string; value: React.ReactNode; hint?: React.ReactNode; hintTone?: "neutral" | "success" | "warning" | "danger" }[];
  className?: string;
  /** Names the group for screen readers, e.g. "Keystore summary". */
  label?: string;
}> = ({ items, className, label }) => (
  <div role={label ? "group" : undefined} aria-label={label} className={clsx("bg-surface border border-line rounded-card shadow-card flex flex-wrap", className)}>
    {items.map((i, idx) => (
      <div key={i.label} className={clsx("flex-1 min-w-[150px] px-4 py-3", idx > 0 && "border-l border-line")}>
        <div className="text-[11.5px] font-medium text-faint">{i.label}</div>
        <div className="text-[18px] font-semibold text-ink leading-6 mt-0.5">{i.value}</div>
        {i.hint && (
          <div
            title={typeof i.hint === "string" ? i.hint : undefined}
            className={clsx(
              "text-[12px] mt-0.5 truncate",
              i.hintTone === "danger" ? "text-danger" : i.hintTone === "warning" ? "text-warning" : i.hintTone === "success" ? "text-success" : "text-faint"
            )}
          >
            {i.hint}
          </div>
        )}
      </div>
    ))}
  </div>
);

/* -------------------------------------------------------------------------- */
/* Data table                                                                  */
/* -------------------------------------------------------------------------- */

export interface Column<T> {
  id: string;
  header: React.ReactNode;
  cell: (row: T) => React.ReactNode;
  /** Provide to make the column sortable. */
  sortValue?: (row: T) => string | number | null;
  align?: "left" | "right" | "center";
  width?: string;
  /**
   * Hide the column when the table itself is narrower than this (sm 576px, md 672px, lg 768px,
   * xl 896px, 2xl 1024px). Measured on the table, not the window: a keystore navigator or the
   * sidebar takes room the window size does not show.
   */
  hideBelow?: "sm" | "md" | "lg" | "xl" | "2xl";
  className?: string;
}

/** A column header drawn as an icon alone. The label is its tooltip and its name for screen readers. */
export const IconHeader: React.FC<{ icon: React.ElementType; label: string }> = ({ icon: Icon, label }) => (
  <span className="inline-flex items-center" title={label} data-header={label}>
    <Icon className="w-3.5 h-3.5" aria-hidden />
    <span className="sr-only">{label}</span>
  </span>
);

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  initialSort?: { id: string; dir: "asc" | "desc" };
  empty?: React.ReactNode;
  rowClassName?: (row: T) => string | undefined;
  footer?: React.ReactNode;
  label: string;
  /** Fill the parent's height and scroll the body under a sticky header. */
  fill?: boolean;
  /**
   * Rows that belong together (certificates from one file). Sorting moves a group as one and
   * keeps its own order; groups are tinted alternately, and hovering one row lights its group.
   */
  groupKey?: (row: T) => string;
}

// Container queries (the table's wrapper is an @container). Tailwind needs the literal names.
const hideCls = {
  sm: "hidden @xl:table-cell",
  md: "hidden @2xl:table-cell",
  lg: "hidden @3xl:table-cell",
  xl: "hidden @4xl:table-cell",
  "2xl": "hidden @5xl:table-cell",
};
const alignCls = { left: "text-left", right: "text-right", center: "text-center" };

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  initialSort,
  empty,
  rowClassName,
  footer,
  label,
  fill,
  groupKey,
}: DataTableProps<T>) {
  const [sort, setSort] = useState(initialSort ?? null);
  const [hoverGroup, setHoverGroup] = useState<string | null>(null);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.id === sort.id);
    if (!col?.sortValue) return rows;
    const get = col.sortValue;
    const compare = (va: string | number | null, vb: string | number | null) => {
      if (va === vb) return 0;
      if (va === null) return 1; // nulls last regardless of direction
      if (vb === null) return -1;
      const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
      return sort.dir === "asc" ? cmp : -cmp;
    };
    if (!groupKey) return [...rows].sort((a, b) => compare(get(a), get(b)));
    // A group sorts by its first member in the chosen direction; its rows keep their own order.
    const groups = new Map<string, T[]>();
    for (const r of rows) {
      const k = groupKey(r);
      const g = groups.get(k);
      if (g) g.push(r);
      else groups.set(k, [r]);
    }
    const lead = (g: T[]) => g.map(get).sort(compare)[0] ?? null;
    return [...groups.values()].sort((a, b) => compare(lead(a), lead(b))).flat();
  }, [rows, columns, sort, groupKey]);
  // Alternate tint by group, counted in the order shown.
  const groupIndex = useMemo(() => {
    const index = new Map<string, number>();
    if (groupKey) for (const r of sorted) if (!index.has(groupKey(r))) index.set(groupKey(r), index.size);
    return index;
  }, [sorted, groupKey]);

  const toggleSort = (id: string) =>
    setSort((s) => (s?.id === id ? { id, dir: s.dir === "asc" ? "desc" : "asc" } : { id, dir: "asc" }));

  return (
    <div className={clsx("@container flex flex-col min-h-0", fill && "flex-1")}>
      <div className={clsx("overflow-auto", fill && "flex-1 min-h-0")}>
        <table className="w-full border-separate border-spacing-0 text-[13px]" aria-label={label}>
          <colgroup>
            {columns.map((c) => (
              <col key={c.id} style={c.width ? { width: c.width } : undefined} />
            ))}
          </colgroup>
          <thead>
            <tr>
              {columns.map((c) => {
                const active = sort?.id === c.id;
                const SortIcon = !active ? ChevronsUpDown : sort!.dir === "asc" ? ArrowUp : ArrowDown;
                return (
                  <th
                    key={c.id}
                    scope="col"
                    aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
                    className={clsx(
                      "sticky top-0 z-10 h-9 px-4 bg-surface-2 border-b border-line text-[11.5px] font-semibold text-faint uppercase tracking-[0.04em] whitespace-nowrap first:pl-5 last:pr-5",
                      alignCls[c.align ?? "left"],
                      c.hideBelow && hideCls[c.hideBelow]
                    )}
                  >
                    {c.sortValue ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(c.id)}
                        className={clsx(
                          "inline-flex items-center gap-1 uppercase tracking-[0.04em] cursor-pointer hover:text-ink",
                          active && "text-ink",
                          c.align === "right" && "flex-row-reverse"
                        )}
                      >
                        {c.header}
                        <SortIcon className={clsx("w-3 h-3", !active && "opacity-40")} />
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {sorted.map((row, rowIndex) => {
              const key = rowKey(row);
              const selected = selectedKey === key;
              const group = groupKey?.(row);
              const groupOdd = group !== undefined && (groupIndex.get(group) ?? 0) % 2 === 1;
              const groupHovered = group !== undefined && hoverGroup === group;
              // A firmer line closes each group, so a file's rows read as one block.
              const groupEnds = group !== undefined && rowIndex < sorted.length - 1 && groupKey!(sorted[rowIndex + 1]) !== group;
              return (
                <tr
                  key={key}
                  data-group={group !== undefined ? groupIndex.get(group) : undefined}
                  onMouseEnter={group !== undefined ? () => setHoverGroup(group) : undefined}
                  onMouseLeave={group !== undefined ? () => setHoverGroup((g) => (g === group ? null : g)) : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          if (e.key === "Enter" && e.target === e.currentTarget) onRowClick(row);
                        }
                      : undefined
                  }
                  tabIndex={onRowClick ? 0 : undefined}
                  aria-selected={onRowClick ? selected : undefined}
                  className={clsx(
                    "group transition-colors",
                    onRowClick && "cursor-pointer",
                    selected ? "bg-brand-tint" : group === undefined ? "hover:bg-surface-2" : groupHovered ? "bg-surface-3" : groupOdd ? "bg-surface-2" : undefined,
                    groupEnds && "[&>td]:border-line-strong",
                    rowClassName?.(row)
                  )}
                >
                  {columns.map((c) => (
                    <td
                      key={c.id}
                      className={clsx(
                        "h-[56px] px-4 py-2 border-b border-line align-middle whitespace-nowrap first:pl-5 last:pr-5",
                        alignCls[c.align ?? "left"],
                        c.align === "right" && "tabular-nums",
                        c.hideBelow && hideCls[c.hideBelow],
                        c.className
                      )}
                    >
                      {c.cell(row)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
        {sorted.length === 0 && <div className="px-5 py-14">{empty ?? <EmptyState title="No results" />}</div>}
      </div>
      {footer && (
        <div className="shrink-0 h-10 px-5 flex items-center justify-between text-[12px] text-faint border-t border-line bg-surface">
          {footer}
        </div>
      )}
    </div>
  );
}

export const EmptyState: React.FC<{
  icon?: React.ElementType;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
}> = ({ icon: Icon, title, description, action }) => (
  <div className="flex flex-col items-center text-center">
    {Icon && (
      <span className="w-10 h-10 rounded-card border border-line bg-surface shadow-card flex items-center justify-center text-muted mb-3">
        <Icon className="w-5 h-5" />
      </span>
    )}
    <h4 className="text-[14px] font-semibold text-ink">{title}</h4>
    {description && <p className="text-[13px] text-faint mt-1 max-w-sm">{description}</p>}
    {action && <div className="mt-4 flex items-center gap-2">{action}</div>}
  </div>
);

/** Two-column definition list for detail panes. */
export const DescriptionList: React.FC<{ items: { label: string; value: React.ReactNode; mono?: boolean }[]; cols?: 1 | 2 }> = ({
  items,
  cols = 2,
}) => (
  <dl className={clsx("grid gap-x-6 gap-y-3", cols === 2 ? "grid-cols-2" : "grid-cols-1")}>
    {items.map((i) => (
      <div key={i.label} className="min-w-0">
        <dt className="text-[11.5px] font-medium text-faint">{i.label}</dt>
        <dd className={clsx("mt-0.5 text-[13px] text-ink break-words select-text", i.mono && "font-mono text-[12px]")}>{i.value}</dd>
      </div>
    ))}
  </dl>
);

/** Proper two-column table (left key, right value) for property/detail panes, as opposed to
 * DescriptionList's stacked-label grid. Rows get generous vertical padding for readability. */
export const KeyValueTable: React.FC<{ items: { label: string; value: React.ReactNode; mono?: boolean }[] }> = ({
  items,
}) => (
  <table className="w-full border border-line rounded-card overflow-hidden border-separate border-spacing-0 text-[13px]">
    <tbody>
      {items.map((i, idx) => {
        const isLast = idx === items.length - 1;
        return (
          <tr key={i.label}>
            <th
              scope="row"
              className={clsx(
                "w-[38%] align-top text-left font-medium text-faint bg-surface-2 px-3.5 py-3",
                !isLast && "border-b border-line"
              )}
            >
              {i.label}
            </th>
            <td
              className={clsx(
                "align-top px-3.5 py-3 text-ink break-words select-text",
                !isLast && "border-b border-line",
                i.mono && "font-mono text-[12px]"
              )}
            >
              {i.value}
            </td>
          </tr>
        );
      })}
    </tbody>
  </table>
);

/* -------------------------------------------------------------------------- */
/* Overlays                                                                    */
/* -------------------------------------------------------------------------- */

const modalSizes = { sm: "max-w-md", md: "max-w-xl", lg: "max-w-2xl", xl: "max-w-4xl" };

/**
 * Open modals, bottom to top. Dialogs stack (a confirmation over an inspector, a key prompt over
 * "Generate key pair"), and only the top one may answer Escape and hold focus: otherwise one
 * Escape closes every dialog at once and loses what was typed underneath.
 */
const modalStack: number[] = [];
let modalSeq = 0;
const isTopModal = (id: number) => id !== 0 && modalStack[modalStack.length - 1] === id;

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Keeps Tab and Shift+Tab inside `root`, wrapping at either end. */
function trapTab(e: KeyboardEvent, root: HTMLElement) {
  const active = document.activeElement as HTMLElement | null;
  // Focus inside another dialog layered above this one (the command palette) stays there.
  const owner = active?.closest('[role="dialog"]');
  if (owner && owner !== root) return;
  const items = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.getClientRects().length > 0);
  if (!items.length) {
    e.preventDefault();
    root.focus();
    return;
  }
  const first = items[0];
  const last = items[items.length - 1];
  if (!active || !root.contains(active) || active === root) {
    e.preventDefault();
    (e.shiftKey ? last : first).focus();
  } else if (e.shiftKey && active === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && active === last) {
    e.preventDefault();
    first.focus();
  }
}

export const Modal: React.FC<{
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: React.ElementType;
  size?: keyof typeof modalSizes;
  footer?: React.ReactNode;
  children: React.ReactNode;
  /** While true the dialog cannot be dismissed (an operation is running). */
  busy?: boolean;
  testId?: string;
  /** Keep one height whatever the content, so switching tabs inside does not resize the window. */
  fixedHeight?: boolean;
}> = ({ open, onClose, title, description, icon: Icon, size = "md", footer, children, busy, testId, fixedHeight }) => {
  const panel = useRef<HTMLDivElement>(null);
  const stackId = useRef(0);
  const titleId = useFieldId();
  const descriptionId = useFieldId();
  const close = useCallback(() => {
    if (!busy) onClose();
  }, [busy, onClose]);
  // What had focus when the dialog opened (the button that opened it). Read while rendering: by the
  // time effects run, React has already moved focus to an autoFocus field inside the dialog.
  const opener = useRef<HTMLElement | null>(null);
  const wasOpen = useRef(false);
  if (open && !wasOpen.current) {
    const active = typeof document === "undefined" ? null : document.activeElement;
    opener.current = active instanceof HTMLElement && active !== document.body ? active : null;
  }
  wasOpen.current = open;
  // Join the stack while open; on close, hand focus back to the opener, unless something else has
  // taken it since.
  useEffect(() => {
    if (!open) return;
    const id = ++modalSeq;
    stackId.current = id;
    modalStack.push(id);
    const before = opener.current;
    return () => {
      const i = modalStack.lastIndexOf(id);
      if (i >= 0) modalStack.splice(i, 1);
      stackId.current = 0;
      const now = document.activeElement;
      if (before && before.isConnected && (!now || now === document.body)) before.focus({ preventScroll: true });
    };
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (!isTopModal(stackId.current)) return;
      if (e.key === "Escape") {
        e.stopPropagation();
        close();
      } else if (e.key === "Tab" && panel.current) {
        trapTab(e, panel.current);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, close]);
  useEffect(() => {
    if (!open) return;
    const t = window.setTimeout(() => {
      const root = panel.current;
      if (!root || root.contains(document.activeElement)) return;
      // A field first; a dialog without one (a confirmation, the inspector) focuses itself, so
      // screen readers announce it and Tab starts inside it.
      const field = root.querySelector<HTMLElement>("[autofocus], input:not([type=hidden]):not([disabled]), textarea:not([disabled]), select:not([disabled])");
      (field ?? root).focus({ preventScroll: true });
    }, 30);
    return () => window.clearTimeout(t);
  }, [open]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim/40 p-4" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
        data-testid={testId}
        className={clsx("w-full bg-surface rounded-panel border border-line shadow-pop flex flex-col max-h-[90vh] outline-none", fixedHeight && "h-[min(760px,90vh)]", modalSizes[size])}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 px-6 pt-5 pb-4 border-b border-line">
          <div className="flex items-start gap-3 min-w-0">
            {Icon && (
              <span className="w-9 h-9 rounded-card border border-line bg-surface shadow-card flex items-center justify-center text-ink-2 shrink-0" aria-hidden>
                <Icon className="w-[18px] h-[18px]" />
              </span>
            )}
            <div className="min-w-0">
              <h3 id={titleId} className="text-[16px] font-semibold text-ink leading-6">
                {title}
              </h3>
              {description && (
                <p id={descriptionId} className="text-[13px] text-faint mt-0.5">
                  {description}
                </p>
              )}
            </div>
          </div>
          <IconButton icon={X} label="Close" onClick={close} disabled={busy} />
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
        {footer && <div className="px-6 py-4 border-t border-line bg-surface-2 rounded-b-panel flex justify-end gap-2">{footer}</div>}
      </div>
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* Toasts (app-wide)                                                           */
/* -------------------------------------------------------------------------- */

type ToastTone = "success" | "danger" | "info";
interface ToastItem {
  id: number;
  msg: React.ReactNode;
  tone: ToastTone;
  action?: { label: string; onClick: () => void };
}
interface ToastApi {
  success: (msg: React.ReactNode, action?: ToastItem["action"]) => void;
  error: (msg: React.ReactNode) => void;
  info: (msg: React.ReactNode) => void;
}

const ToastContext = createContext<ToastApi>({ success: () => {}, error: () => {}, info: () => {} });
export const useToast = () => useContext(ToastContext);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  // Each toast's dismissal timer. While the pointer or focus is on the toasts, the timers stop, so
  // a message (or its Undo) does not disappear while it is being read or reached for.
  const timers = useRef(new Map<number, { handle?: number; remaining: number; started: number }>());
  const paused = useRef(false);
  const dismiss = useCallback((id: number) => {
    const t = timers.current.get(id);
    if (t?.handle) window.clearTimeout(t.handle);
    timers.current.delete(id);
    setItems((list) => list.filter((x) => x.id !== id));
  }, []);
  const arm = useCallback(
    (id: number) => {
      const t = timers.current.get(id);
      if (!t || paused.current) return;
      t.started = Date.now();
      t.handle = window.setTimeout(() => dismiss(id), t.remaining);
    },
    [dismiss]
  );
  const pause = () => {
    if (paused.current) return;
    paused.current = true;
    for (const t of timers.current.values()) {
      if (t.handle) window.clearTimeout(t.handle);
      t.handle = undefined;
      t.remaining = Math.max(1500, t.remaining - (Date.now() - t.started));
    }
  };
  const resume = () => {
    if (!paused.current) return;
    paused.current = false;
    for (const id of timers.current.keys()) arm(id);
  };
  const push = useCallback(
    (msg: React.ReactNode, tone: ToastTone, action?: ToastItem["action"]) => {
      const id = ++seq.current;
      setItems((list) => {
        // Only the newest four are shown; the ones pushed out must not keep a timer.
        const kept = list.slice(-3);
        for (const old of list.slice(0, -3)) {
          const t = timers.current.get(old.id);
          if (t?.handle) window.clearTimeout(t.handle);
          timers.current.delete(old.id);
        }
        return [...kept, { id, msg, tone, action }];
      });
      timers.current.set(id, { remaining: tone === "danger" ? 9000 : 5000, started: Date.now() });
      arm(id);
    },
    [arm]
  );
  const api = useMemo<ToastApi>(
    () => ({
      success: (m, a) => push(m, "success", a),
      error: (m) => push(m, "danger"),
      info: (m) => push(m, "info"),
    }),
    [push]
  );
  return (
    <ToastContext.Provider value={api}>
      {children}
      {/* Above pages and the terminal (z-40), below dialogs (z-50): toasts sit bottom-right, exactly
          where a dialog's footer puts its primary button, and must never cover it. Dialogs that stay
          open after an action show the outcome inline instead. */}
      <div
        className="fixed bottom-5 right-5 z-[45] flex flex-col gap-2 w-[min(420px,calc(100vw-40px))]"
        // Not a live region itself: each toast is one (status, or alert for errors). A live region
        // around them made screen readers announce every toast twice.
        role="region"
        aria-label="Notifications"
        onMouseEnter={pause}
        onMouseLeave={resume}
        onFocus={pause}
        onBlur={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) resume();
        }}
      >
        {items.map((t) => (
          <div
            key={t.id}
            role={t.tone === "danger" ? "alert" : "status"}
            data-testid={`toast-${t.tone}`}
            className="flex items-start gap-2.5 bg-surface border border-line shadow-pop rounded-card px-4 py-3 text-[13px] text-ink select-text"
          >
            {t.tone === "success" ? (
              <CheckCircle2 className="w-4 h-4 mt-0.5 text-success shrink-0" />
            ) : t.tone === "danger" ? (
              <AlertCircle className="w-4 h-4 mt-0.5 text-danger shrink-0" />
            ) : (
              <Info className="w-4 h-4 mt-0.5 text-brand shrink-0" />
            )}
            <span className="flex-1 min-w-0 break-words">{t.msg}</span>
            {t.action && (
              <button
                type="button"
                className="text-[13px] font-semibold text-brand hover:underline cursor-pointer shrink-0"
                onClick={() => {
                  t.action!.onClick();
                  dismiss(t.id);
                }}
              >
                {t.action.label}
              </button>
            )}
            <button type="button" aria-label="Dismiss" className="text-faint hover:text-ink cursor-pointer" onClick={() => dismiss(t.id)}>
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

/* -------------------------------------------------------------------------- */
/* Confirm dialog (app-wide, promise based)                                    */
/* -------------------------------------------------------------------------- */

interface ConfirmOptions {
  title: string;
  message?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  /** Optional third choice, e.g. "Don't save". Resolves to "alternate". */
  alternateLabel?: string;
}
type ConfirmResult = boolean | "alternate";
const ConfirmContext = createContext<(o: ConfirmOptions) => Promise<ConfirmResult>>(async () => false);
export const useConfirm = () => useContext(ConfirmContext);

export const ConfirmProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [req, setReq] = useState<(ConfirmOptions & { resolve: (r: ConfirmResult) => void }) | null>(null);
  const confirm = useCallback((o: ConfirmOptions) => new Promise<ConfirmResult>((resolve) => setReq({ ...o, resolve })), []);
  const done = (r: ConfirmResult) => {
    req?.resolve(r);
    setReq(null);
  };
  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Modal
        open={req !== null}
        onClose={() => done(false)}
        size="sm"
        icon={req?.danger ? AlertCircle : Info}
        title={req?.title ?? ""}
        footer={
          <>
            {req?.alternateLabel && (
              <Button variant="danger" className="mr-auto" onClick={() => done("alternate")}>
                {req.alternateLabel}
              </Button>
            )}
            {/* A destructive choice is never the default: Enter on a danger confirmation cancels
                (resetting the vault, quitting without saving, overwriting a changed file). */}
            <Button onClick={() => done(false)} autoFocus={!!req?.danger} data-testid="confirm-cancel">
              {req?.cancelLabel ?? "Cancel"}
            </Button>
            <Button
              variant="primary"
              autoFocus={!req?.danger}
              data-testid="confirm-ok"
              // The text-safe danger red: white on the "-fill" red (meant for meters) is only 3.8:1.
              className={req?.danger ? "!bg-danger hover:!bg-danger/90 !border-danger" : undefined}
              onClick={() => done(true)}
            >
              {req?.confirmLabel ?? "Confirm"}
            </Button>
          </>
        }
      >
        <div className="text-[13px] text-muted leading-relaxed">{req?.message}</div>
      </Modal>
    </ConfirmContext.Provider>
  );
};

/* -------------------------------------------------------------------------- */
/* Form fields                                                                  */
/* -------------------------------------------------------------------------- */

let fieldSeq = 0;
const useFieldId = (id?: string) => {
  const ref = useRef<string>(id ?? `f-${++fieldSeq}`);
  return id ?? ref.current;
};

export const Field: React.FC<{
  label: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  htmlFor?: string;
  className?: string;
  children: React.ReactNode;
}> = ({ label, hint, error, htmlFor, className, children }) => (
  <div className={className}>
    <label className="label" htmlFor={htmlFor}>
      {label}
    </label>
    {children}
    {error ? <p className="text-[12px] text-danger mt-1">{error}</p> : hint ? <p className="text-[12px] text-faint mt-1">{hint}</p> : null}
  </div>
);

export const TextInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { label?: React.ReactNode; hint?: React.ReactNode; error?: React.ReactNode }> = ({
  label,
  hint,
  error,
  id,
  className,
  ...rest
}) => {
  const fid = useFieldId(id);
  const input = <input id={fid} {...rest} className={clsx("field", error && "!border-danger", className)} aria-invalid={!!error || undefined} />;
  return label ? (
    <Field label={label} hint={hint} error={error} htmlFor={fid}>
      {input}
    </Field>
  ) : (
    input
  );
};

export const TextArea: React.FC<React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label?: React.ReactNode; hint?: React.ReactNode; mono?: boolean }> = ({
  label,
  hint,
  id,
  className,
  mono,
  ...rest
}) => {
  const fid = useFieldId(id);
  const el = (
    <textarea
      id={fid}
      spellCheck={false}
      {...rest}
      className={clsx(
        "w-full p-3 rounded-control border border-line-strong bg-surface text-[13px] text-ink placeholder:text-subtle shadow-card focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand-soft select-text",
        mono && "font-mono text-[11.5px] leading-relaxed",
        className
      )}
    />
  );
  return label ? (
    <Field label={label} hint={hint} htmlFor={fid}>
      {el}
    </Field>
  ) : (
    el
  );
};

export const Select: React.FC<React.SelectHTMLAttributes<HTMLSelectElement> & { label?: React.ReactNode; hint?: React.ReactNode }> = ({
  label,
  hint,
  id,
  className,
  children,
  ...rest
}) => {
  const fid = useFieldId(id);
  const el = (
    <select id={fid} {...rest} className={clsx("field cursor-pointer", className)}>
      {children}
    </select>
  );
  return label ? (
    <Field label={label} hint={hint} htmlFor={fid}>
      {el}
    </Field>
  ) : (
    el
  );
};

export const Checkbox: React.FC<{
  checked: boolean;
  onChange: (v: boolean) => void;
  label: React.ReactNode;
  hint?: React.ReactNode;
  disabled?: boolean;
  id?: string;
  testId?: string;
}> = ({ checked, onChange, label, hint, disabled, id, testId }) => {
  const fid = useFieldId(id);
  return (
    <div className={clsx("flex items-start gap-2.5", disabled && "opacity-50")}>
      <input
        id={fid}
        type="checkbox"
        data-testid={testId}
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 w-4 h-4 rounded accent-[var(--color-brand)] cursor-pointer"
      />
      <label htmlFor={fid} className="text-[13px] text-ink-2 cursor-pointer select-none">
        {label}
        {hint && <span className="block text-[12px] text-faint">{hint}</span>}
      </label>
    </div>
  );
};

export const PasswordInput: React.FC<
  Omit<React.InputHTMLAttributes<HTMLInputElement>, "type" | "onChange" | "value"> & {
    value: string;
    onChange: (v: string) => void;
    label?: React.ReactNode;
    hint?: React.ReactNode;
    error?: React.ReactNode;
  }
> = ({ value, onChange, label, hint, error, id, ...rest }) => {
  const [show, setShow] = useState(false);
  const fid = useFieldId(id);
  const el = (
    <div className="relative">
      <input
        id={fid}
        type={show ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="off"
        spellCheck={false}
        {...rest}
        className={clsx("field !pr-9", error && "!border-danger")}
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        aria-label={show ? "Hide password" : "Show password"}
        title={show ? "Hide" : "Show"}
        tabIndex={-1}
        className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 rounded text-faint hover:text-ink cursor-pointer"
      >
        {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
      </button>
    </div>
  );
  return label ? (
    <Field label={label} hint={hint} error={error} htmlFor={fid}>
      {el}
    </Field>
  ) : (
    el
  );
};

/** Rough password strength (0–4) for hints; never a policy gate on its own. */
export const passwordStrength = (pw: string): { score: number; label: string } => {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 14) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  return { score, label: ["Very weak", "Weak", "Fair", "Good", "Strong"][score] };
};

export const Spinner: React.FC<{ className?: string }> = ({ className }) => <Loader2 className={clsx("w-4 h-4 animate-spin", className)} aria-hidden />;

/** A key or shortcut. Text such as "Ctrl+S" is shown the platform's way (⌘S on macOS). */
export const Kbd: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <kbd className="px-1.5 py-0.5 rounded-sm border border-line bg-surface-2 font-mono text-[11px] text-muted">{typeof children === "string" ? shortcutLabel(children) : children}</kbd>
);

/* -------------------------------------------------------------------------- */
/* Alerts, code, copy                                                           */
/* -------------------------------------------------------------------------- */

export const Alert: React.FC<{
  tone?: "info" | "success" | "warning" | "danger";
  title?: React.ReactNode;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
  /** Shows a close button at the end. The caller hides the alert, and decides how long it stays hidden. */
  onDismiss?: () => void;
  testId?: string;
}> = ({ tone = "info", title, children, action, className, onDismiss, testId }) => {
  const styles = {
    info: "bg-brand-tint border-brand-soft text-brand-deeper",
    success: "bg-success-tint border-success/20 text-success",
    warning: "bg-warning-tint border-warning/25 text-warning",
    danger: "bg-danger-tint border-danger/20 text-danger",
  }[tone];
  const Icon = { info: Info, success: CheckCircle2, warning: AlertTriangle, danger: AlertCircle }[tone];
  return (
    <div role={tone === "danger" ? "alert" : undefined} data-testid={testId} className={clsx("flex items-start gap-2.5 rounded-control border px-3.5 py-3 text-[13px]", styles, className)}>
      <Icon className="w-4 h-4 mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0 select-text">
        {title && <div className="font-semibold">{title}</div>}
        {children && <div className={clsx(title && "mt-0.5", "text-ink-2 break-words")}>{children}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label={typeof title === "string" ? `Dismiss: ${title}` : "Dismiss"}
          title="Dismiss"
          data-testid={testId ? `${testId}-dismiss` : undefined}
          className="shrink-0 -my-1 -mr-1.5 w-7 h-7 rounded-control flex items-center justify-center opacity-70 hover:opacity-100 hover:bg-surface/60 transition cursor-pointer"
        >
          <X className="w-4 h-4" aria-hidden />
        </button>
      )}
    </div>
  );
};

export const CopyButton: React.FC<{ value: string; label?: string; className?: string }> = ({ value, label = "Copy", className }) => {
  const [copied, setCopied] = useState(false);
  const toast = useToast();
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={(e) => {
        e.stopPropagation();
        const done = () => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        };
        // The async Clipboard API can be refused (no permission, no secure context); fall back to
        // the selection-based copy instead of failing silently.
        const fallback = () => {
          const area = document.createElement("textarea");
          area.value = value;
          area.setAttribute("readonly", "");
          area.style.cssText = "position:fixed;top:0;left:0;opacity:0";
          document.body.appendChild(area);
          area.select();
          const ok = document.execCommand("copy");
          area.remove();
          if (ok) done();
          else toast.error("Could not copy to the clipboard.");
        };
        if (navigator.clipboard?.writeText) navigator.clipboard.writeText(value).then(done, fallback);
        else fallback();
      }}
      className={clsx("w-7 h-7 rounded-control inline-flex items-center justify-center text-faint hover:text-ink hover:bg-surface-3 cursor-pointer shrink-0", className)}
    >
      {copied ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
};

/**
 * A file path on one line. The folder part truncates and the file name always shows, so a deep
 * path reads "/Users/me/projects/…/prod-tls.p12" instead of wrapping over several lines. The full
 * path is in the tooltip and can be copied.
 */
export const PathText: React.FC<{ path: string; className?: string; copy?: boolean }> = ({ path, className, copy = true }) => {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  const dir = cut >= 0 ? path.slice(0, cut + 1) : "";
  const file = cut >= 0 ? path.slice(cut + 1) : path;
  return (
    <span className={clsx("inline-flex items-center gap-1 min-w-0 max-w-full align-middle font-mono text-[12px]", className)} title={path} data-testid="path-text">
      <span className="flex min-w-0 select-text">
        {dir && <span className="truncate">{dir}</span>}
        <span className="shrink-0 whitespace-nowrap">{file}</span>
      </span>
      {copy && <CopyButton value={path} label="Copy path" className="!w-6 !h-6" />}
    </span>
  );
};

export const CodeBlock: React.FC<{ label?: React.ReactNode; value: string; maxHeight?: number; actions?: React.ReactNode; wrap?: boolean; testId?: string }> = ({
  label,
  value,
  maxHeight = 260,
  actions,
  wrap,
  testId,
}) => (
  <div>
    {(label || actions) && (
      <div className="flex items-center justify-between mb-1.5 gap-2">
        <span className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-faint">{label}</span>
        <div className="flex items-center gap-1">
          {actions}
          <CopyButton value={value} label="Copy to clipboard" />
        </div>
      </div>
    )}
    <pre
      data-testid={testId}
      style={{ maxHeight }}
      className={clsx(
        "bg-term-bg text-term-fg p-3.5 rounded-control font-mono text-[11.5px] leading-relaxed overflow-auto select-text",
        wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre"
      )}
    >
      {value}
    </pre>
  </div>
);

/* -------------------------------------------------------------------------- */
/* Dropdown menu                                                                */
/* -------------------------------------------------------------------------- */

export interface MenuItem {
  label: React.ReactNode;
  icon?: React.ElementType;
  onSelect: () => void;
  disabled?: boolean;
  hint?: React.ReactNode;
  danger?: boolean;
  divider?: boolean;
  testId?: string;
}

export const Menu: React.FC<{
  trigger: (props: { onClick: (e: React.MouseEvent) => void; "aria-expanded": boolean; "aria-haspopup": "menu" }) => React.ReactNode;
  items: MenuItem[];
  align?: "left" | "right";
  width?: number;
}> = ({ trigger, items, align = "right", width = 260 }) => {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; maxHeight: number } | null>(null);
  const anchor = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const focusTrigger = () => anchor.current?.querySelector<HTMLElement>("button, [tabindex]")?.focus({ preventScroll: true });

  // Rendered in a portal with fixed positioning so tables/cards with overflow never clip it;
  // opens upward when there is not enough room below the trigger.
  useLayoutEffect(() => {
    if (!open || !anchor.current) return;
    const place = () => {
      const r = anchor.current!.getBoundingClientRect();
      const h = panel.current?.offsetHeight ?? 0;
      const margin = 8;
      const below = window.innerHeight - r.bottom - margin;
      const above = r.top - margin;
      const up = h > below && above > below;
      const maxHeight = Math.max(160, (up ? above : below) - 6);
      const top = up ? Math.max(margin, r.top - 6 - Math.min(h, maxHeight)) : r.bottom + 6;
      const rawLeft = align === "right" ? r.right - width : r.left;
      const left = Math.min(Math.max(margin, rawLeft), window.innerWidth - width - margin);
      setPos({ top, left, maxHeight });
    };
    place();
    const raf = requestAnimationFrame(place);
    return () => cancelAnimationFrame(raf);
  }, [open, align, width, items.length]);

  // Once placed, focus moves into the menu so the arrow keys work straight away.
  const placed = !!pos;
  useEffect(() => {
    if (open && placed) panel.current?.querySelector<HTMLElement>('[role="menuitem"]:not([disabled])')?.focus({ preventScroll: true });
  }, [open, placed]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!anchor.current?.contains(t) && !panel.current?.contains(t)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        // The menu closes; a dialog it sits in stays open.
        e.stopPropagation();
        setOpen(false);
        focusTrigger();
      } else if (e.key === "Tab") {
        // Leave the menu from its trigger, so Tab continues from there.
        setOpen(false);
        focusTrigger();
      } else if (["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) {
        const items = [...(panel.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? [])];
        if (!items.length) return;
        e.preventDefault();
        const i = items.indexOf(document.activeElement as HTMLElement);
        const n = items.length;
        const next = e.key === "Home" ? 0 : e.key === "End" ? n - 1 : e.key === "ArrowDown" ? (i + 1) % n : i <= 0 ? n - 1 : i - 1;
        items[next].focus();
      }
    };
    const onScroll = (e: Event) => {
      if (!panel.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", onScroll);
    document.addEventListener("scroll", onScroll, true);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", onScroll);
      document.removeEventListener("scroll", onScroll, true);
    };
  }, [open]);

  return (
    <div ref={anchor} className="relative inline-block text-left" onClick={(e) => e.stopPropagation()}>
      {trigger({
        onClick: (e) => {
          e.stopPropagation();
          setPos(null);
          setOpen((o) => !o);
        },
        "aria-expanded": open,
        "aria-haspopup": "menu",
      })}
      {open &&
        createPortal(
          <div
            ref={panel}
            role="menu"
            aria-orientation="vertical"
            onClick={(e) => e.stopPropagation()}
            style={{ width, position: "fixed", top: pos?.top ?? -9999, left: pos?.left ?? -9999, maxHeight: pos?.maxHeight, visibility: pos ? "visible" : "hidden" }}
            className="z-[60] bg-surface rounded-card border border-line shadow-pop p-1.5 overflow-y-auto"
          >
            {items.map((item, i) => (
              <React.Fragment key={i}>
                {item.divider && i > 0 && <div className="my-1 border-t border-line" />}
                <button
                  type="button"
                  role="menuitem"
                  tabIndex={-1}
                  disabled={item.disabled}
                  data-testid={item.testId}
                  onClick={() => {
                    setOpen(false);
                    // Back to the trigger first: a dialog this opens returns focus there when it closes.
                    focusTrigger();
                    item.onSelect();
                  }}
                  className={clsx(
                    "w-full px-2.5 py-2 rounded-control text-left flex items-start gap-2.5 cursor-pointer outline-none disabled:opacity-45 disabled:cursor-not-allowed",
                    item.danger ? "hover:bg-danger-tint focus-visible:bg-danger-tint text-danger" : "hover:bg-surface-2 focus-visible:bg-surface-2 text-ink"
                  )}
                >
                  {item.icon && <item.icon className={clsx("w-4 h-4 mt-0.5 shrink-0", item.danger ? "text-danger" : "text-muted")} />}
                  <span className="min-w-0">
                    <span className="block text-[13px] font-medium">{item.label}</span>
                    {item.hint && <span className="block text-[12px] text-faint">{item.hint}</span>}
                  </span>
                </button>
              </React.Fragment>
            ))}
          </div>,
          document.body
        )}
    </div>
  );
};
