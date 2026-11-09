import React from "react";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, Clock, ClockAlert, FileBadge, KeyRound, KeySquare, Lock, LockOpen, Minus, XCircle, Infinity as InfinityIcon } from "lucide-react";
import { EntryType, KeystoreEntry } from "../types/crypto";
import { Badge, badgeTones, Meter, Tone } from "./ui";
import { daysUntilExpiry, expiryStatus, ExpiryStatus, formatDuration, isWeak, keyAgeDays, lifeUsed } from "../lib/metrics";
import { cnOf, ENTRY_TYPE_LABEL, entryTypeName, lockState, LockState } from "../lib/keystore";
import { useStore } from "../state/store";

/*
 * Display atoms for keystore entries, shared by every table that lists them.
 */

/*
 * Entry types are told apart by glyph and tile, never by status color:
 * key pair = round key on a brand tile, certificate = badged document on a white tile,
 * secret key = square key on a grey tile. A key pair also wears a lock badge, which is status
 * (locked needs action, unlocked is ready) and so uses the status colors.
 */
export const TYPE_ICON: Record<EntryType, React.ElementType> = {
  KeyPair: KeyRound,
  TrustedCertificate: FileBadge,
  SecretKey: KeySquare,
};

const TYPE_TILE: Record<EntryType, string> = {
  KeyPair: "bg-brand-tint border-brand-soft text-brand",
  TrustedCertificate: "bg-surface border-line-strong text-ink-2",
  SecretKey: "bg-surface-3 border-line text-ink-2",
};

export const entryTypeLabel = (t: EntryType) => ENTRY_TYPE_LABEL[t];

/**
 * Square glyph for an entry's type, plus a lock badge for keys when `locked` is given. Tables with a
 * Lock column leave `locked` out. `icon` and `label` refine a type, e.g. a CA among certificates.
 */
export const EntryIcon: React.FC<{ type: EntryType; locked?: boolean; size?: "sm" | "md"; icon?: React.ElementType; label?: string }> = ({
  type,
  locked,
  size = "md",
  icon,
  label,
}) => {
  const Icon = icon ?? TYPE_ICON[type];
  // Key pairs always show whether they are locked; other entries only when they are.
  const badge = locked ? Lock : type === "KeyPair" && locked === false ? LockOpen : null;
  const title = `${label ?? ENTRY_TYPE_LABEL[type]}${locked ? " — locked" : badge ? " — unlocked" : ""}`;
  const sm = size === "sm";
  return (
    <span
      title={title}
      data-entry-type={type}
      data-locked={locked ? "true" : undefined}
      className={clsx("relative rounded-control border flex items-center justify-center shrink-0", sm ? "w-6 h-6" : "w-8 h-8", TYPE_TILE[type])}
    >
      <Icon className={sm ? "w-3.5 h-3.5" : "w-4 h-4"} aria-hidden />
      <span className="sr-only">{title}</span>
      {badge &&
        React.createElement(badge, {
          "aria-hidden": true,
          className: clsx(
            "absolute rounded-full border border-surface p-[1.5px]",
            sm ? "-right-1 -bottom-1 w-3 h-3" : "-right-1.5 -bottom-1.5 w-[15px] h-[15px]",
            // Text-safe tones: the white glyph on the lighter "-fill" colours was under 3:1.
            locked ? "bg-warning text-on-accent" : "bg-success text-on-accent"
          ),
        })}
    </span>
  );
};

/**
 * Alias + subject CN, the primary cell of every entry table. Where a table has Type and Lock columns,
 * `icon="narrow"` draws the type tile (with its lock badge) only while those columns are hidden, below
 * the "md" width of the table. `tile` replaces the drawn tile. Long names truncate; the tooltip has them.
 */
export const EntryNameCell: React.FC<{ entry: KeystoreEntry; meta?: React.ReactNode; icon?: boolean | "narrow"; tile?: React.ReactNode }> = ({
  entry,
  meta,
  icon = true,
  tile,
}) => {
  const { isKeyLocked } = useStore();
  const locked = isKeyLocked(entry);
  const drawn = tile ?? <EntryIcon type={entry.entry_type} locked={entry.entry_type === "KeyPair" ? locked : entry.locked || undefined} />;
  const sub = meta ?? (entry.entry_type === "SecretKey" ? entry.subject : cnOf(entry.subject));
  return (
    <div className="flex items-center gap-3 min-w-0">
      {/* The DataTable wrapper is the @container; @2xl matches hideBelow "md". */}
      {icon === "narrow" ? <span className="inline-flex shrink-0 @2xl:hidden">{drawn}</span> : icon && drawn}
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="font-medium text-ink truncate" data-testid="entry-alias" title={entry.alias}>
            {entry.alias}
          </span>
        </div>
        <div className="text-[12px] text-faint truncate max-w-[340px]" title={typeof sub === "string" ? sub : undefined}>
          {sub}
        </div>
      </div>
    </div>
  );
};

/** For the name column of an entry table: it takes the room left and truncates, so the table never scrolls sideways. */
export const NAME_COLUMN_CLASS = "w-full max-w-0";

/** Type column: the entry's type as its icon alone, named in the tooltip and to screen readers. */
export const EntryTypeIconCell: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => <EntryIcon type={entry.entry_type} label={entryTypeName(entry)} />;

// Locked and unlocked differ in glyph as well as color; an entry without a key shows a dash.
const LOCK_VIEW: Record<LockState, { icon: React.ElementType; label: string; cls: string }> = {
  locked: { icon: Lock, label: "Locked: enter the key password to use it", cls: badgeTones.warning },
  "own-password": { icon: Lock, label: "Locked: the key has its own key password", cls: badgeTones.warning },
  unlocked: { icon: LockOpen, label: "Unlocked", cls: badgeTones.success },
  "no-key": { icon: Minus, label: "No private key: nothing to unlock", cls: "border-transparent text-faint" },
};

/** Lock column: one glyph. Locked keys use the warning color because they need action. */
export const LockIcon: React.FC<{ state: LockState }> = ({ state }) => {
  const v = LOCK_VIEW[state];
  return (
    <span role="img" aria-label={v.label} title={v.label} data-lock={state} className={clsx("inline-flex items-center justify-center w-6 h-6 rounded-full border", v.cls)}>
      <v.icon className="w-3.5 h-3.5" aria-hidden />
    </span>
  );
};

export const LockCell: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => {
  const { isKeyLocked } = useStore();
  return <LockIcon state={lockState(entry, isKeyLocked(entry))} />;
};

export const EntryTypeBadge: React.FC<{ type: EntryType }> = ({ type }) => <Badge tone="neutral">{ENTRY_TYPE_LABEL[type]}</Badge>;

export const AlgorithmCell: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => (
  <div className="min-w-0">
    <div className="flex items-center gap-1.5">
      <span className="text-ink font-medium">{entry.algorithm || "—"}</span>
      {entry.is_post_quantum && entry.entry_type !== "SecretKey" && <Badge tone="brand">PQC</Badge>}
    </div>
    <div className="text-[12px] text-faint tabular-nums">
      {entry.curve && entry.algorithm === "ECDSA" ? entry.curve : entry.key_size ? `${entry.key_size} bits` : ""}
    </div>
  </div>
);

const EXPIRY_TONE: Record<ExpiryStatus, Tone> = {
  expired: "danger",
  critical: "danger",
  warning: "warning",
  ok: "success",
  never: "neutral",
};

/** Expiry date, time remaining and a "life used" meter. */
export const ExpiryCell: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => {
  const days = daysUntilExpiry(entry);
  const status = expiryStatus(entry);
  if (days === null) {
    return (
      <span className="inline-flex items-center gap-1.5 text-faint">
        <InfinityIcon className="w-3.5 h-3.5" /> No expiry
      </span>
    );
  }
  const used = lifeUsed(entry);
  return (
    <div className="min-w-[120px]">
      <div className="flex items-baseline justify-between gap-2 whitespace-nowrap">
        <span className="text-ink tabular-nums">{entry.expiry_date}</span>
        <span className={clsx("text-[12px] font-medium tabular-nums", status === "ok" ? "text-faint" : status === "warning" ? "text-warning" : "text-danger")}>
          {days < 0 ? `${formatDuration(days)} ago` : formatDuration(days)}
        </span>
      </div>
      <Meter thin value={used} tone={EXPIRY_TONE[status]} className="mt-1.5" label={`${Math.round(used * 100)}% of validity used`} />
    </div>
  );
};

export const AgeCell: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => (
  <div>
    <div className="text-ink tabular-nums">{formatDuration(keyAgeDays(entry))}</div>
    <div className="text-[12px] text-faint tabular-nums">{entry.creation_date}</div>
  </div>
);

/** What the status of an entry is: a glyph, a word and a tone. Every status has its own glyph. */
export const healthView = (entry: KeystoreEntry): { key: string; label: string; detail: string; tone: Tone; icon: React.ElementType } => {
  const status = expiryStatus(entry);
  if (status === "expired") return { key: "expired", label: "Expired", detail: "Expired", tone: "danger", icon: XCircle };
  if (isWeak(entry)) return { key: "weak", label: "Weak", detail: entry.weak_reasons.length ? `Weak: ${entry.weak_reasons.join("; ")}` : "Weak", tone: "danger", icon: AlertTriangle };
  if (status === "critical") return { key: "critical", label: "Expires soon", detail: "Expires soon", tone: "danger", icon: ClockAlert };
  if (status === "warning") return { key: "renew", label: "Renew", detail: "Renew soon", tone: "warning", icon: Clock };
  return { key: "healthy", label: "Healthy", detail: "Healthy", tone: "success", icon: CheckCircle2 };
};

/** Status pill: icon + label so state never relies on color alone. */
export const HealthBadge: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => {
  const v = healthView(entry);
  return (
    <span title={v.key === "weak" ? entry.weak_reasons.join("\n") : undefined}>
      <Badge tone={v.tone} icon={v.icon}>
        {v.label}
      </Badge>
    </span>
  );
};

/** Status for a narrow column: the glyph alone, the word in the tooltip and for screen readers. */
export const HealthIcon: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => {
  const v = healthView(entry);
  return (
    <span role="img" aria-label={v.detail} title={v.detail} data-health={v.key} className={clsx("inline-flex items-center justify-center w-6 h-6 rounded-full border", badgeTones[v.tone])}>
      <v.icon className="w-3.5 h-3.5" aria-hidden />
    </span>
  );
};
