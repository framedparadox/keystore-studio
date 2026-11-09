import { KeystoreEntry, KeystoreFile } from "../types/crypto";

/*
 * Derived inventory metrics shared by the dashboard, keystore table and security view.
 * Pure functions only — no React, no Tauri.
 */

const DAY = 86_400_000;

/** Expiry thresholds (days), adjustable from Settings. */
export const thresholds = { critical: 30, warning: 90 };
export function setThresholds(critical: number, warning: number) {
  thresholds.critical = Math.max(1, critical);
  thresholds.warning = Math.max(thresholds.critical, warning);
}

const parseDate = (value: string): Date | null => {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(value ?? "");
  if (!m) return null;
  return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
};

const todayUtc = () => {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
};

/** Days until the entry expires; `null` for entries that never expire (symmetric keys). */
export const daysUntilExpiry = (entry: KeystoreEntry): number | null => {
  const notAfter = entry.certificate_chain[0]?.not_after;
  if (notAfter) return Math.floor((notAfter * 1000 - Date.now()) / DAY);
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
  const c = entry.certificate_chain[0];
  if (c) return Math.max(1, Math.round((c.not_after - c.not_before) / 86_400));
  const a = parseDate(entry.creation_date);
  const b = parseDate(entry.expiry_date);
  return a && b ? Math.max(1, Math.round((b.getTime() - a.getTime()) / DAY)) : null;
};

/** Fraction of the validity period already elapsed (0–1). */
export const lifeUsed = (entry: KeystoreEntry): number => {
  const c = entry.certificate_chain[0];
  if (!c) return 0;
  const total = Math.max(1, c.not_after - c.not_before);
  return Math.min(1, Math.max(0, (Date.now() / 1000 - c.not_before) / total));
};

export type ExpiryStatus = "expired" | "critical" | "warning" | "ok" | "never";

export const expiryStatus = (entry: KeystoreEntry): ExpiryStatus => {
  const days = daysUntilExpiry(entry);
  if (days === null) return "never";
  if (days < 0) return "expired";
  if (days <= thresholds.critical) return "critical";
  if (days <= thresholds.warning) return "warning";
  return "ok";
};

export const isWeak = (entry: KeystoreEntry) => entry.is_weak;

export type Health = "healthy" | "attention" | "at-risk";

export const entryHealth = (entry: KeystoreEntry): Health => {
  const s = expiryStatus(entry);
  if (s === "expired" || isWeak(entry)) return "at-risk";
  if (s === "critical" || s === "warning") return "attention";
  return "healthy";
};

/** "3y 2m", "5 mo", "12 d" — compact human duration. */
export const formatDuration = (days: number | null): string => {
  if (days === null) return "—";
  const abs = Math.abs(days);
  if (abs < 60) return `${abs} d`;
  if (abs < 365) return `${Math.round(abs / 30)} mo`;
  // Round to whole months first, then split into years: rounding the leftover days on their own
  // turned 729 days into "1y" (11.97 months rounded to 12, then dropped).
  const months = Math.round(abs / 30.4375);
  const y = Math.floor(months / 12);
  const m = months % 12;
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

export const expiryBucketDefs = (): { key: ExpiryStatus; label: string }[] => [
  { key: "expired", label: "Expired" },
  { key: "critical", label: `≤ ${thresholds.critical} days` },
  { key: "warning", label: `${thresholds.critical + 1}–${thresholds.warning} days` },
  { key: "ok", label: `> ${thresholds.warning} days` },
  { key: "never", label: "No expiry" },
];

export const expiryBuckets = (entries: KeystoreEntry[]): Bucket[] =>
  expiryBucketDefs().map((b) => ({ ...b, count: entries.filter((e) => expiryStatus(e) === b.key).length }));

// Short labels: each sits under one narrow column of the key-age chart.
const AGE_BUCKETS: { key: string; label: string; max: number }[] = [
  { key: "lt90", label: "< 90 d", max: 90 },
  { key: "lt1y", label: "3–12 mo", max: 365 },
  { key: "lt2y", label: "1–2 y", max: 730 },
  { key: "lt5y", label: "2–5 y", max: 1825 },
  { key: "gte5y", label: "5 y+", max: Infinity },
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
    const family = e.algorithm.startsWith("Hmac") ? "HMAC" : e.algorithm || "Unknown";
    map.set(family, (map.get(family) ?? 0) + 1);
  }
  return [...map.entries()].map(([label, count]) => ({ key: label, label, count })).sort((a, b) => b.count - a.count);
};

/** "1 key pair", "3 key pairs". */
export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "6 key pairs · 1 secret key": what an inventory holds, leaving out the types it has none of. */
export const entryMix = (s: Pick<InventorySummary, "keyPairs" | "trusted" | "secrets">): string => {
  const parts: string[] = [];
  if (s.keyPairs) parts.push(plural(s.keyPairs, "key pair"));
  if (s.trusted) parts.push(plural(s.trusted, "certificate"));
  if (s.secrets) parts.push(plural(s.secrets, "secret key"));
  return parts.length ? parts.join(" · ") : "No entries";
};

export interface InventorySummary {
  total: number;
  keyPairs: number;
  trusted: number;
  secrets: number;
  expired: number;
  expiringCritical: number;
  expiringWarning: number;
  weak: number;
  quantumSafe: number;
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
  const atRisk = entries.filter((e) => entryHealth(e) === "at-risk").length;
  const attention = entries.filter((e) => entryHealth(e) === "attention").length;
  const expiringCritical = statuses.filter((s) => s === "critical").length;
  return {
    total: entries.length,
    keyPairs: entries.filter((e) => e.entry_type === "KeyPair").length,
    trusted: entries.filter((e) => e.entry_type === "TrustedCertificate").length,
    secrets: entries.filter((e) => e.entry_type === "SecretKey").length,
    expired: statuses.filter((s) => s === "expired").length,
    expiringCritical,
    expiringWarning: expiringCritical + statuses.filter((s) => s === "warning").length,
    weak: entries.filter(isWeak).length,
    quantumSafe: entries.filter((e) => e.is_post_quantum).length,
    locked: entries.filter((e) => e.locked).length,
    medianAgeDays: ages.length ? ages[Math.floor(ages.length / 2)] : null,
    oldestAgeDays: ages.length ? ages[ages.length - 1] : null,
    healthScore: entries.length ? Math.round(100 * (1 - (atRisk + 0.5 * attention) / entries.length)) : 100,
  };
};

/** Whether two entries hold the same public key (SPKI hash when known, else the PEM). */
const sameKey = (a: KeystoreEntry, b: KeystoreEntry) => {
  const ha = a.certificate_chain[0]?.spki_sha256;
  const hb = b.certificate_chain[0]?.spki_sha256;
  if (ha && hb) return ha === hb;
  return !!a.public_key_pem && a.public_key_pem.replace(/\s+/g, "") === (b.public_key_pem ?? "").replace(/\s+/g, "");
};

/** Security findings for one entry, most severe first. */
export interface Finding {
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  detail: string;
}

export function findingsFor(entry: KeystoreEntry, ctx?: { format?: string; siblings?: KeystoreEntry[] }): Finding[] {
  const out: Finding[] = [];
  const days = daysUntilExpiry(entry);
  const status = expiryStatus(entry);
  if (status === "expired") out.push({ severity: "critical", title: "Expired", detail: `Expired ${formatDuration(days)} ago — clients reject it.` });
  else if (status === "critical") out.push({ severity: "high", title: "Expires soon", detail: `Expires in ${days} days.` });
  else if (status === "warning") out.push({ severity: "medium", title: "Renew soon", detail: `Expires in ${days} days.` });
  for (const r of entry.weak_reasons) out.push({ severity: "high", title: "Weak cryptography", detail: r });
  const leaf = entry.certificate_chain[0];
  if (entry.entry_type === "KeyPair" && leaf && leaf.self_signed && !leaf.is_ca && leaf.extended_key_usage.some((u) => u.includes("Server")))
    out.push({ severity: "low", title: "Self-signed server certificate", detail: "Browsers and clients will not trust it unless pinned." });
  if (entry.entry_type === "KeyPair" && leaf && !leaf.self_signed && entry.chain_length === 1)
    out.push({ severity: "low", title: "Incomplete chain", detail: "The issuing CA certificate is not stored with this key; some clients cannot build the chain." });
  if (entry.locked) out.push({ severity: "low", title: "Key locked", detail: "The private key uses a separate key password and is unavailable until unlocked." });
  // A property of the keystore, not of this entry: one "Save as PKCS#12" fixes every entry in it.
  // Low, so a JKS truststore of 150 CAs does not bury real problems; the audit page also raises it
  // once per keystore.
  if (ctx?.format === "JKS") out.push({ severity: "low", title: "JKS store", detail: "JKS integrity is SHA-1 and the key wrap is proprietary. Save as PKCS#12." });
  if (leaf && entry.entry_type !== "SecretKey" && leaf.extended_key_usage.some((u) => u.includes("Server")) && leaf.sans.length === 0)
    out.push({ severity: "medium", title: "No subject alternative name", detail: "TLS clients match the hostname against the SAN, not the common name." });
  if (leaf && leaf.extended_key_usage.some((u) => u.includes("Server"))) {
    const life = Math.round((leaf.not_after - leaf.not_before) / 86_400);
    if (life > 398) out.push({ severity: "low", title: "Long server lifetime", detail: `Valid for ${life} days. Public TLS certificates are capped at 398 days.` });
  }
  if (leaf?.is_ca && !leaf.self_signed && leaf.path_len == null)
    out.push({ severity: "low", title: "Subordinate CA without a path length", detail: "Set a path length so this CA cannot issue further CAs without a limit." });
  if (entry.entry_type === "TrustedCertificate" && leaf && !leaf.self_signed) {
    const issuerOpen = ctx?.siblings?.some((s) => s.id !== entry.id && s.subject === entry.issuer);
    if (!issuerOpen) out.push({ severity: "low", title: "Trust anchor not open", detail: "No open certificate has this issuer's subject." });
  }
  // The same key id on two different keys makes chain building ambiguous. The same certificate in
  // two keystores (a CA and its copy in a truststore), or a renewal that kept the key, is normal.
  const ski = leaf?.subject_key_id;
  if (ski && ctx?.siblings?.some((s) => s.id !== entry.id && s.certificate_chain[0]?.subject_key_id === ski && !sameKey(s, entry)))
    out.push({ severity: "medium", title: "Duplicate subject key id", detail: "Another open entry uses the same subject key identifier for a different key." });
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}
