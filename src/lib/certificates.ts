import type { DetectionResult, FileProbe, KeystoreEntry, OpenCertificate } from "../types/crypto";
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
