import { KeystoreEntry, KeystoreFile } from "../types/crypto";

/*
 * Derived inventory metrics shared by the dashboard, keystore table and security view.
 * Pure functions only — no React, no Tauri.
 */

const DAY = 86_400_000;

const parseDate = (value: string): Date | null => {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(value);
  if (!m) return null;
  return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
};

const todayUtc = () => {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
};

/** Days until the entry expires; `null` for entries that never expire (symmetric keys). */
export const daysUntilExpiry = (entry: KeystoreEntry): number | null => {
  const d = parseDate(entry.expiry_date);
  return d ? Math.round((d.getTime() - todayUtc()) / DAY) : null;
};

/** Days since the key was created; `null` if the creation date is unknown. */
export const keyAgeDays = (entry: KeystoreEntry): number | null => {
  const d = parseDate(entry.creation_date);
  return d ? Math.max(0, Math.round((todayUtc() - d.getTime()) / DAY)) : null;
};

/** Total validity period in days, used to draw the "life used" meter. */
export const lifetimeDays = (entry: KeystoreEntry): number | null => {
  const a = parseDate(entry.creation_date);
  const b = parseDate(entry.expiry_date);
  return a && b ? Math.max(1, Math.round((b.getTime() - a.getTime()) / DAY)) : null;
};

export type ExpiryStatus = "expired" | "critical" | "warning" | "ok" | "never";

export const expiryStatus = (entry: KeystoreEntry): ExpiryStatus => {
  const days = daysUntilExpiry(entry);
  if (days === null) return "never";
  if (entry.is_expired || days < 0) return "expired";
  if (days <= 30) return "critical";
  if (days <= 90) return "warning";
  return "ok";
};

export const isWeak = (entry: KeystoreEntry) =>
  entry.is_weak || (entry.algorithm === "RSA" && entry.entry_type !== "SecretKey" && entry.key_size < 2048);

export type Health = "healthy" | "attention" | "at-risk";

export const entryHealth = (entry: KeystoreEntry): Health => {
  const s = expiryStatus(entry);
  if (s === "expired" || isWeak(entry)) return "at-risk";
  if (s === "critical" || s === "warning") return "attention";
  return "healthy";
};

/** "3y 2m", "5 mo", "12 d" — compact human age. */
export const formatDuration = (days: number | null): string => {
  if (days === null) return "—";
  const abs = Math.abs(days);
  if (abs < 60) return `${abs} d`;
  if (abs < 365) return `${Math.round(abs / 30)} mo`;
  const y = Math.floor(abs / 365);
  const m = Math.round((abs - y * 365) / 30);
  return m ? `${y}y ${m}m` : `${y}y`;
};

export interface FlatEntry {
  entry: KeystoreEntry;
  keystore: KeystoreFile;
}

export const flattenEntries = (keystores: KeystoreFile[]): FlatEntry[] =>
  keystores.flatMap((keystore) => keystore.entries.map((entry) => ({ entry, keystore })));

export interface Bucket {
  key: string;
  label: string;
  count: number;
}

export const EXPIRY_BUCKETS: { key: ExpiryStatus; label: string }[] = [
  { key: "expired", label: "Expired" },
  { key: "critical", label: "≤ 30 days" },
  { key: "warning", label: "31–90 days" },
  { key: "ok", label: "> 90 days" },
  { key: "never", label: "No expiry" },
];

export const expiryBuckets = (entries: KeystoreEntry[]): Bucket[] =>
  EXPIRY_BUCKETS.map((b) => ({ ...b, count: entries.filter((e) => expiryStatus(e) === b.key).length }));

const AGE_BUCKETS: { key: string; label: string; max: number }[] = [
  { key: "lt90", label: "< 90 d", max: 90 },
  { key: "lt1y", label: "90 d – 1 y", max: 365 },
  { key: "lt2y", label: "1 – 2 y", max: 730 },
  { key: "lt5y", label: "2 – 5 y", max: 1825 },
  { key: "gte5y", label: "5 y +", max: Infinity },
];

export const ageBuckets = (entries: KeystoreEntry[]): Bucket[] => {
  const ages = entries.map(keyAgeDays).filter((a): a is number => a !== null);
  let floor = -1;
  return AGE_BUCKETS.map((b) => {
    const count = ages.filter((a) => a > floor && a <= b.max).length;
    floor = b.max;
    return { key: b.key, label: b.label, count };
  });
};

export const algorithmMix = (entries: KeystoreEntry[]): Bucket[] => {
  const map = new Map<string, number>();
  for (const e of entries) {
    const family = e.algorithm.startsWith("HMAC") ? "HMAC" : e.algorithm;
    map.set(family, (map.get(family) ?? 0) + 1);
  }
  return [...map.entries()]
    .map(([label, count]) => ({ key: label, label, count }))
    .sort((a, b) => b.count - a.count);
};

export interface InventorySummary {
  total: number;
  keyPairs: number;
  trusted: number;
  secrets: number;
  expired: number;
  expiring30: number;
  expiring90: number;
  weak: number;
  pqc: number;
  locked: number;
  medianAgeDays: number | null;
  oldestAgeDays: number | null;
  healthScore: number;
}

export const summarize = (entries: KeystoreEntry[]): InventorySummary => {
  const statuses = entries.map(expiryStatus);
  const ages = entries
    .map(keyAgeDays)
    .filter((a): a is number => a !== null)
    .sort((a, b) => a - b);
  const weak = entries.filter(isWeak).length;
  const expired = statuses.filter((s) => s === "expired").length;
  const expiring30 = statuses.filter((s) => s === "critical").length;
  const expiring90 = expiring30 + statuses.filter((s) => s === "warning").length;
  const atRisk = entries.filter((e) => entryHealth(e) === "at-risk").length;
  const attention = entries.filter((e) => entryHealth(e) === "attention").length;
  const healthScore = entries.length
    ? Math.round(100 * (1 - (atRisk + 0.5 * attention) / entries.length))
    : 100;

  return {
    total: entries.length,
    keyPairs: entries.filter((e) => e.entry_type === "KeyPair").length,
    trusted: entries.filter((e) => e.entry_type === "TrustedCertificate").length,
    secrets: entries.filter((e) => e.entry_type === "SecretKey").length,
    expired,
    expiring30,
    expiring90,
    weak,
    pqc: entries.filter((e) => e.is_post_quantum).length,
    locked: entries.filter((e) => e.locked).length,
    medianAgeDays: ages.length ? ages[Math.floor(ages.length / 2)] : null,
    oldestAgeDays: ages.length ? ages[ages.length - 1] : null,
    healthScore,
  };
};
