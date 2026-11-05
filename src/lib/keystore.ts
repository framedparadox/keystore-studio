import type { EntryType, KeystoreEntry, KeystoreFile, KeystoreFormat, OpenKeystore } from "../types/crypto";

/** Stable identity for an entry across sessions: keystore path (or in-memory id) + alias. */
export const entryKey = (ks: Pick<KeystoreFile, "id" | "path">, alias: string) => `${ks.path || ks.id}::${alias}`;

/** Re-keys every entry after load, rename or save-as. */
export function normalizeEntries(ks: OpenKeystore): OpenKeystore {
  return { ...ks, entries: ks.entries.map((e) => ({ ...e, id: entryKey(ks, e.alias) })) };
}

export const FORMAT_EXTENSION: Record<KeystoreFormat, string> = { PKCS12: "p12", JKS: "jks", JCEKS: "jceks" };

export const FORMAT_INFO: Record<KeystoreFormat, { label: string; description: string; secretKeys: boolean }> = {
  PKCS12: { label: "PKCS#12", description: "Industry standard (.p12/.pfx). Default for Java 9+, OpenSSL, Windows.", secretKeys: true },
  JKS: { label: "JKS", description: "Legacy Java KeyStore. Key pairs and trusted certificates only.", secretKeys: false },
  JCEKS: { label: "JCEKS", description: "Java Cryptography Extension KeyStore. Supports secret keys.", secretKeys: true },
};

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

export const isCaEntry = (e: KeystoreEntry) => e.entry_type === "KeyPair" && !e.locked && !!e.certificate_chain[0]?.is_ca;

export const cnOf = (dn: string) => /(?:^|,\s*)CN=((?:\\.|[^,])+)/.exec(dn)?.[1]?.replace(/\\(.)/g, "$1") ?? dn;

export interface ExportTarget {
  id: string;
  label: string;
  ext: string;
  group: "Certificate" | "Public key" | "Private key" | "Keystore" | "Secret key";
  needsPassword?: boolean;
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
  { id: "public_jwk", label: "JWK (public)", ext: "jwk.json", group: "Public key", appliesTo: ["KeyPair", "TrustedCertificate"] },
  { id: "private_pkcs8_encrypted", label: "Private key, encrypted PKCS#8 (AES-256)", ext: "key", group: "Private key", needsPassword: true, sensitive: true, appliesTo: ["KeyPair"] },
  { id: "private_pkcs8_pem", label: "Private key, unencrypted PKCS#8", ext: "key", group: "Private key", sensitive: true, appliesTo: ["KeyPair"] },
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
