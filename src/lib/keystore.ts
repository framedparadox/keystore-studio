import type { EntryType, KeystoreEntry, KeystoreFile, KeystoreFormat, OpenKeystore } from "../types/crypto";

/** Stable identity for an entry across sessions: keystore path (or in-memory id) + alias. */
export const entryKey = (ks: Pick<KeystoreFile, "id" | "path">, alias: string) => `${ks.path || ks.id}::${alias}`;

/** Re-keys every entry after load, rename or save-as. */
export function normalizeEntries(ks: OpenKeystore): OpenKeystore {
  return { ...ks, entries: ks.entries.map((e) => ({ ...e, id: entryKey(ks, e.alias) })) };
}

/**
 * Entry ids that changed between two snapshots of the open keystores, as `{ oldId: newId }`.
 * Undo and redo swap whole snapshots, so an undone rename brings back the old entry id while the
 * labels, workspace membership and unlocked state were already moved to the new one. An entry
 * counts as the same when it is in the same keystore with the same type and fingerprint, and the
 * match is unique on both sides.
 */
export function entryIdRemap(before: OpenKeystore[], after: OpenKeystore[]): Record<string, string> {
  const mapping: Record<string, string> = {};
  for (const ks of after) {
    const prev = before.find((k) => k.id === ks.id);
    if (!prev) continue;
    const nowIds = new Set(ks.entries.map((e) => e.id));
    const prevIds = new Set(prev.entries.map((e) => e.id));
    const sig = (e: KeystoreEntry) => (e.sha256_fingerprint ? `${e.entry_type}|${e.sha256_fingerprint}` : "");
    const group = (list: KeystoreEntry[]) => {
      const m = new Map<string, KeystoreEntry[]>();
      for (const e of list) {
        const s = sig(e);
        if (s) m.set(s, [...(m.get(s) ?? []), e]);
      }
      return m;
    };
    const gone = group(prev.entries.filter((e) => !nowIds.has(e.id)));
    const added = group(ks.entries.filter((e) => !prevIds.has(e.id)));
    for (const [s, from] of gone) {
      const to = added.get(s);
      if (from.length === 1 && to?.length === 1) mapping[from[0].id] = to[0].id;
    }
  }
  return mapping;
}

export const FORMAT_EXTENSION: Record<KeystoreFormat, string> = { PKCS12: "p12", JKS: "jks", JCEKS: "jceks", BKS: "bks", UBER: "uber", BCFKS: "bcfks" };

export interface FormatInfo {
  label: string;
  description: string;
  secretKeys: boolean;
  /** "Standard" formats every Java and OpenSSL reads, or "Bouncy Castle" ones that need its provider. */
  family: "Standard" | "Bouncy Castle";
  /**
   * Formats that protect a key the same way. A key still locked by its own password is the source
   * format's ciphertext, and only a format in the same group can carry it (mirrors
   * `Format::key_protection` in keystore.rs).
   */
  keyProtection: number;
}

export const FORMAT_INFO: Record<KeystoreFormat, FormatInfo> = {
  PKCS12: { label: "PKCS#12", description: "Industry standard (.p12/.pfx). Default for Java 9+, OpenSSL, Windows.", secretKeys: true, family: "Standard", keyProtection: 0 },
  JKS: { label: "JKS", description: "Legacy Java KeyStore. Key pairs and trusted certificates only.", secretKeys: false, family: "Standard", keyProtection: 1 },
  JCEKS: { label: "JCEKS", description: "Java Cryptography Extension KeyStore. Supports secret keys.", secretKeys: true, family: "Standard", keyProtection: 2 },
  BKS: { label: "BKS", description: "Bouncy Castle KeyStore (version 2), common on Android. Needs the Bouncy Castle provider in Java.", secretKeys: true, family: "Bouncy Castle", keyProtection: 3 },
  UBER: { label: "UBER", description: "Bouncy Castle UBER: BKS with the whole file encrypted (Twofish). Needs the Bouncy Castle provider.", secretKeys: true, family: "Bouncy Castle", keyProtection: 3 },
  BCFKS: { label: "BCFKS", description: "Bouncy Castle FIPS keystore (AES-256-CCM, PBKDF2-HMAC-SHA512), for FIPS-mode Java.", secretKeys: true, family: "Bouncy Castle", keyProtection: 4 },
};

/** The formats grouped as the pickers list them. */
export const FORMAT_GROUPS: { label: FormatInfo["family"]; formats: KeystoreFormat[] }[] = (["Standard", "Bouncy Castle"] as const).map((label) => ({
  label,
  formats: (Object.keys(FORMAT_INFO) as KeystoreFormat[]).filter((f) => FORMAT_INFO[f].family === label),
}));

export const canHoldSecretKeys = (format: KeystoreFormat) => FORMAT_INFO[format].secretKeys;

/** Returns `base`, or `base-2`, `base-3`… so the alias is unique (case-insensitive) in `ks`. */
export function uniqueAlias(ks: KeystoreFile, base: string, ignoreId?: string): string {
  const taken = new Set(ks.entries.filter((e) => e.id !== ignoreId).map((e) => e.alias.toLowerCase()));
  const clean = base.trim() || "entry";
  if (!taken.has(clean.toLowerCase())) return clean;
  for (let n = 2; ; n++) {
    const candidate = `${clean}-${n}`;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
}

export const aliasTaken = (ks: KeystoreFile, alias: string, ignoreId?: string) =>
  ks.entries.some((e) => e.id !== ignoreId && e.alias.toLowerCase() === alias.trim().toLowerCase());

export const ENTRY_TYPE_LABEL: Record<EntryType, string> = {
  KeyPair: "Key pair",
  TrustedCertificate: "Trusted certificate",
  SecretKey: "Secret key",
};

/**
 * A key pair whose certificate is a CA. A CA whose key has its own password still counts: it is open,
 * and its key is unlocked on use through ensureKeyAccess. Excluding it made the app say "not open".
 */
export const isCaEntry = (e: KeystoreEntry) => e.entry_type === "KeyPair" && !!e.certificate_chain[0]?.is_ca;

/** Type label for one entry: trusted certificates that are CAs read "CA certificate". */
export const entryTypeName = (e: Pick<KeystoreEntry, "entry_type" | "certificate_chain">) =>
  e.entry_type === "TrustedCertificate" && e.certificate_chain[0]?.is_ca ? "CA certificate" : ENTRY_TYPE_LABEL[e.entry_type];

/**
 * Whether an entry's key must be unlocked before it can be used.
 *
 * Entries the engine could not decrypt (`locked`: a separate key password) are always locked.
 * With `requireUnlock`, key pairs also open locked: their private key is not usable until the key
 * password is entered for this session. `unlocked` holds the ids unlocked so far.
 */
export function isKeyLocked(e: Pick<KeystoreEntry, "id" | "entry_type" | "locked">, unlocked: ReadonlySet<string>, requireUnlock: boolean): boolean {
  if (e.locked) return true;
  return requireUnlock && e.entry_type === "KeyPair" && !unlocked.has(e.id);
}

export type LockState = "locked" | "own-password" | "unlocked" | "no-key";

/**
 * What the Lock column shows: a certificate has no key to lock; a key is locked (its key password
 * is needed first, "own-password" when it differs from the keystore password) or unlocked.
 * `locked` is isKeyLocked for the entry.
 */
export const lockState = (e: Pick<KeystoreEntry, "entry_type" | "locked">, locked: boolean): LockState =>
  e.entry_type === "TrustedCertificate" ? "no-key" : locked ? (e.locked ? "own-password" : "locked") : "unlocked";

/**
 * Checks a key password for a key the engine already decrypted. Its key password is the keystore
 * password unless the key carries its own (`key_password`).
 */
export const keyPasswordMatches = (e: Pick<KeystoreEntry, "key_password">, password: string, storePassword: string | undefined) =>
  password.length > 0 && password === (e.key_password || storePassword);

/** Entries listed by type (key pairs, secret keys, certificates), then alias. */
export const ENTRY_TYPE_ORDER: Record<EntryType, number> = { KeyPair: 0, SecretKey: 1, TrustedCertificate: 2 };

export const byTypeThenAlias = (a: KeystoreEntry, b: KeystoreEntry) =>
  ENTRY_TYPE_ORDER[a.entry_type] - ENTRY_TYPE_ORDER[b.entry_type] || a.alias.localeCompare(b.alias, undefined, { sensitivity: "base", numeric: true });

/** Free-text match on alias, subject, issuer, algorithm, serial and SHA-256 fingerprint. */
export function entryMatches(e: KeystoreEntry, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    e.alias.toLowerCase().includes(q) ||
    e.subject.toLowerCase().includes(q) ||
    e.issuer.toLowerCase().includes(q) ||
    e.algorithm.toLowerCase().includes(q) ||
    e.serial_number.toLowerCase().includes(q) ||
    e.sha256_fingerprint.toLowerCase().replace(/:/g, "").includes(q.replace(/:/g, ""))
  );
}

export const cnOf = (dn: string) => /(?:^|,\s*)CN=((?:\\.|[^,])+)/.exec(dn)?.[1]?.replace(/\\(.)/g, "$1") ?? dn;

export interface ExportTarget {
  id: string;
  label: string;
  ext: string;
  group: "Certificate" | "Public key" | "Private key" | "Keystore" | "Secret key";
  needsPassword?: boolean;
  /** Takes a password to encrypt the file, but can be written without one. */
  optionalPassword?: boolean;
  sensitive?: boolean;
  appliesTo: EntryType[];
}

export const EXPORT_TARGETS: ExportTarget[] = [
  { id: "cert_pem", label: "Certificate (PEM)", ext: "pem", group: "Certificate", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "cert_der", label: "Certificate (DER .cer)", ext: "cer", group: "Certificate", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "chain_pem", label: "Full chain (PEM)", ext: "pem", group: "Certificate", appliesTo: ["KeyPair"] },
  { id: "pkcs7_pem", label: "PKCS#7 bundle (PEM .p7b)", ext: "p7b", group: "Certificate", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "pkcs7_der", label: "PKCS#7 bundle (DER .p7b)", ext: "p7b", group: "Certificate", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "pkipath", label: "PkiPath (.pkipath)", ext: "pkipath", group: "Certificate", appliesTo: ["KeyPair"] },
  { id: "public_pem", label: "Public key (PEM)", ext: "pub.pem", group: "Public key", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "public_openssh", label: "OpenSSH public key", ext: "pub", group: "Public key", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "public_ssh2", label: "SSH2 public key (RFC 4716)", ext: "pub", group: "Public key", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "public_jwk", label: "JWK (public)", ext: "jwk.json", group: "Public key", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "private_pkcs8_encrypted", label: "Private key, encrypted PKCS#8 (AES-256)", ext: "key", group: "Private key", needsPassword: true, sensitive: true, appliesTo: ["KeyPair"] },
  { id: "private_pkcs8_pem", label: "Private key, unencrypted PKCS#8", ext: "key", group: "Private key", sensitive: true, appliesTo: ["KeyPair"] },
  { id: "private_traditional", label: "Private key, PKCS#1 or SEC1", ext: "key", group: "Private key", sensitive: true, appliesTo: ["KeyPair"] },
  { id: "private_openssh", label: "Private key, OpenSSH (ssh-keygen format)", ext: "key", group: "Private key", optionalPassword: true, sensitive: true, appliesTo: ["KeyPair"] },
  { id: "private_jwk", label: "JWK (private)", ext: "jwk.json", group: "Private key", sensitive: true, appliesTo: ["KeyPair"] },
  { id: "pkcs12", label: "PKCS#12 with key and chain", ext: "p12", group: "Keystore", needsPassword: true, sensitive: true, appliesTo: ["KeyPair", "TrustedCertificate", "SecretKey"] },
  { id: "secret_hex", label: "Raw key (hex)", ext: "txt", group: "Secret key", sensitive: true, appliesTo: ["SecretKey"] },
  { id: "secret_jwk", label: "JWK (symmetric)", ext: "jwk.json", group: "Secret key", sensitive: true, appliesTo: ["SecretKey"] },
];

export const KEY_USAGES: { id: string; label: string }[] = [
  { id: "digitalSignature", label: "Digital signature" },
  { id: "nonRepudiation", label: "Non-repudiation" },
  { id: "keyEncipherment", label: "Key encipherment" },
  { id: "dataEncipherment", label: "Data encipherment" },
  { id: "keyAgreement", label: "Key agreement" },
  { id: "keyCertSign", label: "Certificate sign" },
  { id: "cRLSign", label: "CRL sign" },
];

export type CertProfileName = "server" | "client" | "codesign" | "ca";

/** Key usage for a profile. `keyEncipherment` is an RSA key-transport bit, so EC and Ed25519 omit it. */
export function profileUsages(profile: CertProfileName, algorithm: string): { isCa: boolean; ku: string[]; eku: string[] } {
  const encipher = algorithm === "RSA" ? ["keyEncipherment"] : [];
  switch (profile) {
    case "server":
      return { isCa: false, ku: ["digitalSignature", ...encipher], eku: ["serverAuth"] };
    case "client":
      return { isCa: false, ku: ["digitalSignature", ...encipher], eku: ["clientAuth"] };
    case "codesign":
      return { isCa: false, ku: ["digitalSignature"], eku: ["codeSigning"] };
    case "ca":
      return { isCa: true, ku: ["digitalSignature", "keyCertSign", "cRLSign"], eku: [] };
  }
}

/** Alias as it will be stored. Java lowercases JKS and JCEKS; PKCS#12 keeps the case OpenSSL uses. */
export function canonicalAlias(format: KeystoreFormat, alias: string): string {
  const trimmed = alias.trim();
  return format === "JKS" || format === "JCEKS" ? trimmed.toLowerCase() : trimmed;
}

/** Why a save into `target` would drop data. Empty means the save can proceed. */
export function saveProblems(entries: { entry_type: string; locked: boolean }[], source: KeystoreFormat, target: KeystoreFormat): string[] {
  const problems: string[] = [];
  const secrets = entries.filter((e) => e.entry_type === "SecretKey").length;
  if (!canHoldSecretKeys(target) && secrets) problems.push(`${FORMAT_INFO[target].label} cannot store secret keys; ${secrets} secret key(s) would be lost. Choose PKCS#12 or JCEKS.`);
  const locked = entries.filter((e) => e.locked).length;
  if (locked && FORMAT_INFO[target].keyProtection !== FORMAT_INFO[source].keyProtection) {
    problems.push(`${locked} entr${locked === 1 ? "y is" : "ies are"} locked by a separate key password and can only be saved as ${FORMAT_INFO[source].label}${source === "BKS" || source === "UBER" ? " or " + (source === "BKS" ? "UBER" : "BKS") : ""}. Unlock them first.`);
  }
  return problems;
}

/** Renewal length counted from today. Public TLS server certificates are capped at 398 days. */
export function renewalTerm(entry: KeystoreEntry): { days: number; cap: number | null; note: string } {
  const leaf = entry.certificate_chain[0];
  const lifetime = leaf ? Math.max(1, Math.round((leaf.not_after - leaf.not_before) / 86400)) : 365;
  const server = !!leaf?.extended_key_usage.some((u) => u.includes("Server") || u === "serverAuth");
  const cap = server ? 398 : null;
  const days = Math.min(lifetime, cap ?? 3650);
  const note = cap && lifetime > cap ? `Capped at ${cap} days for a TLS server certificate. Counted from today.` : "Counted from today, for the previous lifetime, and shortened if the CA expires sooner.";
  return { days, cap, note };
}

const keyId = (value?: string | null) => (value ?? "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();

/**
 * The open CA that issued `entry`. Matches authority key id to subject key id.
 * A subject-string match is used only when the leaf has no authority key id.
 */
export function findIssuingCa(entry: KeystoreEntry, pools: { entries: KeystoreEntry[] }[]): KeystoreEntry | null {
  const leaf = entry.certificate_chain[0];
  if (!leaf || leaf.self_signed) return null;
  const candidates = pools.flatMap((ks) => ks.entries).filter((e) => isCaEntry(e) && e.id !== entry.id);
  const aki = keyId(leaf.authority_key_id);
  if (aki) return candidates.find((e) => keyId(e.certificate_chain[0]?.subject_key_id) === aki) ?? null;
  return candidates.find((e) => e.subject === entry.issuer) ?? null;
}

export const EXTENDED_KEY_USAGES: { id: string; label: string }[] = [
  { id: "serverAuth", label: "TLS server" },
  { id: "clientAuth", label: "TLS client" },
  { id: "codeSigning", label: "Code signing" },
  { id: "emailProtection", label: "E-mail (S/MIME)" },
  { id: "timeStamping", label: "Time stamping" },
  { id: "OCSPSigning", label: "OCSP signing" },
];

export const splitList = (s: string) =>
  s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);

/**
 * Whether the "Create PKCS#12" dialog has everything it needs. The engine does the real
 * validation (it matches the key to the certificate); this only gates the submit button so the
 * user is not sent to a file dialog for a request that cannot succeed.
 */
export function pkcs12BuildReady(input: { hasCertificate: boolean; hasKey: boolean; passphrase: string; confirm: string }): boolean {
  return input.hasCertificate && input.hasKey && input.passphrase.length > 0 && input.passphrase === input.confirm;
}
