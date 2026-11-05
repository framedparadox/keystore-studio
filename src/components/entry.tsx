import React from "react";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, Clock, KeyRound, Lock, ShieldCheck, XCircle, Infinity as InfinityIcon } from "lucide-react";
import { EntryType, KeystoreEntry } from "../types/crypto";
import { Badge, Meter, Tone } from "./ui";
import { daysUntilExpiry, entryHealth, expiryStatus, ExpiryStatus, formatDuration, isWeak, keyAgeDays, lifeUsed } from "../lib/metrics";
import { cnOf, ENTRY_TYPE_LABEL } from "../lib/keystore";

/*
 * Display atoms for keystore entries, shared by every table that lists them.
 */

const TYPE_ICON: Record<EntryType, React.ElementType> = {
  KeyPair: KeyRound,
  TrustedCertificate: ShieldCheck,
  SecretKey: Lock,
};

export const entryTypeLabel = (t: EntryType) => ENTRY_TYPE_LABEL[t];

/** Square glyph in front of an alias. Neutral by design: type is identity, not status. */
export const EntryIcon: React.FC<{ type: EntryType }> = ({ type }) => {
  const Icon = TYPE_ICON[type];
  return (
    <span title={ENTRY_TYPE_LABEL[type]} className="w-8 h-8 rounded-control border border-line bg-surface-2 text-muted flex items-center justify-center shrink-0">
      <Icon className="w-4 h-4" />
    </span>
  );
};

/** Alias + subject CN, the primary cell of every entry table. */
export const EntryNameCell: React.FC<{ entry: KeystoreEntry; meta?: React.ReactNode }> = ({ entry, meta }) => (
  <div className="flex items-center gap-3 min-w-0">
    <EntryIcon type={entry.entry_type} />
    <div className="min-w-0">
      <div className="flex items-center gap-1.5">
        <span className="font-medium text-ink truncate" data-testid="entry-alias">
          {entry.alias}
        </span>
        {entry.locked && <Lock aria-label="Key locked by a separate password" className="w-3 h-3 text-warning shrink-0" />}
      </div>
      <div className="text-[12px] text-faint truncate max-w-[340px]">{meta ?? (entry.entry_type === "SecretKey" ? entry.subject : cnOf(entry.subject))}</div>
    </div>
  </div>
);

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
    <span className="text-subtle">—</span>
  ) : (
    <div className="flex items-center gap-1">
      {labels.slice(0, max).map((l) => (
        <Badge key={l}>{l}</Badge>
      ))}
      {labels.length > max && <span className="text-[11px] text-faint">+{labels.length - max}</span>}
    </div>
  );
