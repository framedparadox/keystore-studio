import React from "react";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, Clock, FileBadge, KeyRound, KeySquare, Lock, LockOpen, XCircle, Infinity as InfinityIcon } from "lucide-react";
import { EntryType, KeystoreEntry } from "../types/crypto";
import { Badge, Meter, Tone } from "./ui";
import { daysUntilExpiry, entryHealth, expiryStatus, ExpiryStatus, formatDuration, isWeak, keyAgeDays, lifeUsed } from "../lib/metrics";
import { cnOf, ENTRY_TYPE_LABEL, entryTypeName } from "../lib/keystore";
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

/** Square glyph in front of an alias: the entry's type, plus a lock badge for keys. */
export const EntryIcon: React.FC<{ type: EntryType; locked?: boolean; size?: "sm" | "md" }> = ({ type, locked, size = "md" }) => {
  const Icon = TYPE_ICON[type];
  // Key pairs always show whether they are locked; other entries only when they are.
  const badge = locked ? Lock : type === "KeyPair" && locked === false ? LockOpen : null;
  const title = `${ENTRY_TYPE_LABEL[type]}${locked ? " — locked" : badge ? " — unlocked" : ""}`;
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
            locked ? "bg-warning text-white" : "bg-success text-white"
          ),
        })}
    </span>
  );
};

/** Alias + subject CN, the primary cell of every entry table. */
export const EntryNameCell: React.FC<{ entry: KeystoreEntry; meta?: React.ReactNode }> = ({ entry, meta }) => {
  const { isKeyLocked } = useStore();
  const locked = isKeyLocked(entry);
  return (
    <div className="flex items-center gap-3 min-w-0">
      <EntryIcon type={entry.entry_type} locked={entry.entry_type === "KeyPair" ? locked : entry.locked || undefined} />
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="font-medium text-ink truncate" data-testid="entry-alias">
            {entry.alias}
          </span>
        </div>
        <div className="text-[12px] text-faint truncate max-w-[340px]">{meta ?? (entry.entry_type === "SecretKey" ? entry.subject : cnOf(entry.subject))}</div>
      </div>
    </div>
  );
};

/** Type column: what the entry is and, for keys, whether it can be used yet. */
export const EntryTypeCell: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => {
  const { isKeyLocked } = useStore();
  const locked = isKeyLocked(entry);
  const showLock = entry.entry_type === "KeyPair" || entry.locked;
  return (
    <div className="min-w-0">
      <div className="text-ink-2 font-medium">{entryTypeName(entry)}</div>
      {showLock ? (
        <div className={clsx("text-[12px] inline-flex items-center gap-1", locked ? "text-warning" : "text-success")}>
          {locked ? <Lock className="w-3 h-3" /> : <LockOpen className="w-3 h-3" />}
          {locked ? (entry.locked ? "Locked · own key password" : "Locked") : "Unlocked"}
        </div>
      ) : (
        <div className="text-[12px] text-faint">{entry.entry_type === "SecretKey" ? "Symmetric" : entry.certificate_chain[0]?.self_signed ? "Self-signed" : "Public"}</div>
      )}
    </div>
  );
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

/** Status pill: icon + label so state never relies on color alone. */
export const HealthBadge: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => {
  const status = expiryStatus(entry);
  if (status === "expired") return <Badge tone="danger" icon={XCircle}>Expired</Badge>;
  if (isWeak(entry))
    return (
      <span title={entry.weak_reasons.join("\n")}>
        <Badge tone="danger" icon={AlertTriangle}>
          Weak
        </Badge>
      </span>
    );
  if (status === "critical") return <Badge tone="danger" icon={Clock}>Expires soon</Badge>;
  if (status === "warning") return <Badge tone="warning" icon={Clock}>Renew</Badge>;
  return entryHealth(entry) === "healthy" ? (
    <Badge tone="success" icon={CheckCircle2}>
      Healthy
    </Badge>
  ) : null;
};

export const LabelList: React.FC<{ labels: string[]; max?: number }> = ({ labels, max = 2 }) =>
  labels.length === 0 ? (
    <span className="text-faint">—</span>
  ) : (
    <div className="flex items-center gap-1">
      {labels.slice(0, max).map((l) => (
        <Badge key={l}>{l}</Badge>
      ))}
      {labels.length > max && <span className="text-[11px] text-faint">+{labels.length - max}</span>}
    </div>
  );
