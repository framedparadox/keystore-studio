import type { CertificateInfo, DetectionResult, FileProbe, KeystoreEntry, OpenCertificate } from "../types/crypto";
import { cnOf } from "./keystore";

/*
 * Certificates opened on their own (a .pem, .crt, .cer, .der or .p7b file), outside any keystore.
 * Pure helpers only: no React, no Tauri.
 */

const CERT_PREFIX = "cert::";

/**
 * Stable id of a certificate on the Certificates page: its SHA-256 fingerprint. The same
 * certificate opened from two files is one certificate, and a workspace that lists it finds it
 * again after a restart or when the file is opened again.
 */
export const certificateId = (sha256Fingerprint: string) => `${CERT_PREFIX}${sha256Fingerprint.replace(/:/g, "").toLowerCase()}`;

/** True for a workspace member that is a certificate rather than a keystore entry (`path::alias`). */
export const isCertificateId = (id: string) => id.startsWith(CERT_PREFIX);

/** Short fingerprint for a certificate that is not open, e.g. "3F:A2:…:9C". */
export const shortFingerprint = (id: string) => {
  const hex = id.slice(CERT_PREFIX.length).toUpperCase();
  const pairs = hex.match(/.{2}/g) ?? [];
  return pairs.length > 4 ? `${pairs.slice(0, 2).join(":")}:…:${pairs.slice(-2).join(":")}` : pairs.join(":");
};

/** The name a certificate is listed under: its subject CN, else the whole subject. */
export const certificateName = (subject: string) => cnOf(subject).trim() || subject.trim() || "certificate";

/** Alias for a certificate added to a keystore: its CN in lower case, with dashes for anything else. */
export const aliasForCertificate = (subject: string) =>
  cnOf(subject).toLowerCase().replace(/[^\w.-]+/g, "-").replace(/^-+|-+$/g, "") || "certificate";

/**
 * Turns engine entries (one TrustedCertificate per certificate in the file, leaf first) into
 * certificates for the page. Each is keyed by fingerprint and named after its subject.
 */
export function toOpenCertificates(entries: KeystoreEntry[], origin: { path: string; source: string; openedAt: string }): OpenCertificate[] {
  return entries.map((e) => {
    const id = certificateId(e.sha256_fingerprint);
    return {
      id,
      path: origin.path,
      source: origin.source,
      opened_at: origin.openedAt,
      entry: { ...e, id, alias: certificateName(e.subject), labels: [] },
    };
  });
}

/**
 * Adds `incoming` in front of `existing`, in their own order, skipping certificates that are
 * already listed (or repeated in the same file). Returns the new list and what was added or skipped.
 */
export function mergeCertificates(existing: OpenCertificate[], incoming: OpenCertificate[]) {
  const seen = new Set(existing.map((c) => c.id));
  const added: OpenCertificate[] = [];
  const duplicates: OpenCertificate[] = [];
  for (const c of incoming) {
    if (seen.has(c.id)) duplicates.push(existing.find((x) => x.id === c.id) ?? c);
    else {
      seen.add(c.id);
      added.push(c);
    }
  }
  return { list: [...added, ...existing], added, duplicates };
}

/** Probe kinds that are certificates and nothing else, so they open on the Certificates page. */
export const isCertificateProbe = (kind: FileProbe["kind"]) => kind === "certificate" || kind === "certificate_chain";

/**
 * A PKCS#7 file is either a certificate bundle (.p7b: certificates only) or CMS signed data
 * (.p7s/.p7m: a signature that happens to carry its signer's certificates). Only a bundle belongs
 * on the Certificates page; detect.rs gives a bundle this format, and a signature its encoding.
 */
export const PKCS7_BUNDLE_FORMAT = "PKCS#7 certificate bundle";
export const isCertificateBundle = (r: Pick<DetectionResult, "kind" | "format" | "certificates">) =>
  r.certificates.length > 0 && (r.kind === "certificate" || r.kind === "certificate_chain" || (r.kind === "pkcs7" && r.format === PKCS7_BUNDLE_FORMAT));

/** What is persisted for each certificate. The PEM is public, so it is kept in the app state. */
export interface PersistedCertificate {
  path: string;
  source: string;
  opened_at: string;
  pem: string;
}

export const persistCertificates = (list: OpenCertificate[]): PersistedCertificate[] =>
  list.map((c) => ({ path: c.path, source: c.source, opened_at: c.opened_at, pem: c.entry.certificate_chain[0]?.pem ?? "" })).filter((c) => c.pem);

/**
 * The file (or paste, or Examine capture) a certificate was opened from. Certificates opened
 * together share it, so the page can show a bundle as one group.
 */
export const certificateGroupKey = (c: Pick<OpenCertificate, "path" | "source" | "opened_at">) => `${c.path}\u0000${c.source}\u0000${c.opened_at}`;

const hexOnly = (s?: string | null) => (s ?? "").replace(/^keyid:/i, "").replace(/[^0-9a-f]/gi, "").toLowerCase();

/**
 * True when `issuer` plausibly issued `cert`: its subject is the certificate's issuer and, when
 * both carry key identifiers, the authority key ID matches the issuer's subject key ID. The
 * signature itself is checked by the engine (Verify), not here.
 */
export function isIssuerOf(issuer: CertificateInfo, cert: CertificateInfo): boolean {
  if (issuer.sha256_fingerprint === cert.sha256_fingerprint) return false;
  if (issuer.subject !== cert.issuer) return false;
  const aki = hexOnly(cert.authority_key_id);
  const ski = hexOnly(issuer.subject_key_id);
  return !aki || !ski || aki.startsWith(ski) || aki.includes(ski);
}

/**
 * The issuers of `leaf`, nearest first, found among `pool` (anything open): each step finds the
 * certificate that issued the one before, until a self-signed root or a missing issuer.
 */
export function issuerChain(leaf: CertificateInfo, pool: CertificateInfo[]): CertificateInfo[] {
  const chain: CertificateInfo[] = [];
  const seen = new Set([leaf.sha256_fingerprint]);
  let current = leaf;
  while (!current.self_signed) {
    const next = pool.find((c) => !seen.has(c.sha256_fingerprint) && isIssuerOf(c, current));
    if (!next) break;
    chain.push(next);
    seen.add(next.sha256_fingerprint);
    current = next;
  }
  return chain;
}

/** One row of the Certificates table drawn as a tree: the certificate, its depth and its group. */
export interface CertificateTreeRow {
  cert: OpenCertificate;
  group: string;
  /** Rows in the group: 1 for a certificate opened on its own. */
  groupSize: number;
  /** 0 for a root (or for anything whose issuer is not in the same file). */
  depth: number;
  /** The last child of its parent, so its connector ends here. */
  lastChild: boolean;
}

/**
 * Orders certificates as trees, one per file: within a file each root comes first with the
 * certificates it issued under it (root → intermediate → leaf). Files keep the order they are in.
 */
export function certificateTree(list: OpenCertificate[]): CertificateTreeRow[] {
  const groups = new Map<string, OpenCertificate[]>();
  for (const c of list) {
    const key = certificateGroupKey(c);
    const g = groups.get(key);
    if (g) g.push(c);
    else groups.set(key, [c]);
  }
  const rows: CertificateTreeRow[] = [];
  for (const [group, members] of groups) {
    const info = (c: OpenCertificate) => c.entry.certificate_chain[0];
    const parentOf = new Map<string, OpenCertificate | undefined>();
    for (const c of members) {
      const ci = info(c);
      parentOf.set(c.id, ci ? members.find((p) => p !== c && info(p) && isIssuerOf(info(p)!, ci)) : undefined);
    }
    const childrenOf = (parent: OpenCertificate | undefined) => members.filter((c) => parentOf.get(c.id) === parent);
    const placed = new Set<string>();
    const walk = (c: OpenCertificate, depth: number, lastChild: boolean) => {
      if (placed.has(c.id)) return;
      placed.add(c.id);
      rows.push({ cert: c, group, groupSize: members.length, depth, lastChild });
      const kids = childrenOf(c).filter((k) => !placed.has(k.id));
      kids.forEach((k, i) => walk(k, depth + 1, i === kids.length - 1));
    };
    // Roots: no issuer in the same file, in the file's own order.
    childrenOf(undefined).forEach((r) => walk(r, 0, true));
    // A cycle (cross-signed pair) leaves certificates unplaced; list them flat.
    for (const c of members) if (!placed.has(c.id)) walk(c, 0, true);
  }
  return rows;
}

/** Prefixes that start a new item in a comma-joined list of general names or access descriptions. */
const ITEM_START = /^(DNS|email|URI|IP|DirName|RID|othername|OCSP|CA Issuers|keyid|serial):?/;
export const LIST_OIDS = new Set(["2.5.29.15", "2.5.29.37", "2.5.29.32"]);
export const NAME_OIDS = new Set(["2.5.29.17", "2.5.29.18", "2.5.29.31", "1.3.6.1.5.5.7.1.1", "2.5.29.35"]);

/**
 * Splits an extension's value into its items. Lists of names are split only where a new name
 * starts, so a directory name's own commas stay inside it. Anything else is one item.
 */
export function extensionItems(oid: string, value: string): string[] {
  if (!value) return [];
  if (oid === "2.5.29.19") return value.split(/,\s*/).map((v) => v.replace("CA:TRUE", "CA").replace("CA:FALSE", "End entity").replace(/^pathlen:(\d+)/, "Path length $1"));
  if (LIST_OIDS.has(oid)) return value.split(/,\s*/).filter(Boolean);
  if (NAME_OIDS.has(oid)) {
    const out: string[] = [];
    for (const part of value.split(", ")) {
      if (!out.length || ITEM_START.test(part)) out.push(part);
      else out[out.length - 1] += `, ${part}`;
    }
    return out;
  }
  return [value];
}

