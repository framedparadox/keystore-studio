/* Types mirrored from src-tauri/src/model.rs (snake_case over IPC). */

export type TabType =
  | "home"
  | "keystores"
  | "certificates"
  | "workspaces"
  | "examine"
  | "ca_signing"
  | "convert"
  | "scanner"
  | "vault"
  | "settings";

/** Formats Keystore Studio can open and save. */
export type KeystoreFormat = "PKCS12" | "JKS" | "JCEKS" | "BKS" | "UBER" | "BCFKS";
/** Every format, in the order the format pickers list them: the common three, then Bouncy Castle's. */
export const KEYSTORE_FORMATS: KeystoreFormat[] = ["PKCS12", "JKS", "JCEKS", "BKS", "UBER", "BCFKS"];
/** How a PKCS#12 file is protected: the default, PBMAC1 (RFC 9579), or the pre-PBES2 legacy profile. */
export type Pkcs12Profile = "pkcs12" | "pbmac1" | "legacy";

export type EntryType = "KeyPair" | "TrustedCertificate" | "SecretKey";

export interface X509ExtensionInfo {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
}

export interface CertificateInfo {
  version: number;
  serial_number: string;
  signature_algorithm: string;
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  not_before: number;
  not_after: number;
  days_remaining: number;
  is_ca: boolean;
  path_len?: number | null;
  self_signed: boolean;
  public_key_algorithm: string;
  key_size: number;
  curve?: string | null;
  sans: string[];
  key_usage: string[];
  extended_key_usage: string[];
  extensions: X509ExtensionInfo[];
  subject_key_id?: string | null;
  authority_key_id?: string | null;
  sha256_fingerprint: string;
  sha1_fingerprint: string;
  /** SHA-256 of the subjectPublicKeyInfo, for pinning. */
  spki_sha256?: string;
  crl_distribution_points?: string[];
  ocsp_urls?: string[];
  ca_issuer_urls?: string[];
  pem: string;
}

export interface KeystoreEntry {
  id: string;
  alias: string;
  entry_type: EntryType;
  algorithm: string;
  key_size: number;
  curve?: string | null;
  creation_date: string;
  expiry_date: string;
  subject: string;
  issuer: string;
  serial_number: string;
  sha256_fingerprint: string;
  sha1_fingerprint: string;
  chain_length: number;
  certificate_chain: CertificateInfo[];
  private_key_pem?: string | null;
  public_key_pem?: string | null;
  secret_key_hex?: string | null;
  /** Private key could not be decrypted with the store password (separate key password). */
  locked: boolean;
  protected_key?: string | null;
  /** Present when this key is re-wrapped with a password other than the store password. */
  key_password?: string | null;
  labels: string[];
  is_expired: boolean;
  is_weak: boolean;
  weak_reasons: string[];
  is_post_quantum: boolean;
}

export interface KeystoreFile {
  id: string;
  name: string;
  format: KeystoreFormat;
  /** Absolute path; empty until the keystore is saved for the first time. */
  path: string;
  description: string;
  password_protected: boolean;
  created_at: string;
  updated_at: string;
  /** File mtime in unix milliseconds, captured when the file was opened. */
  source_mtime_ms?: number | null;
  entries: KeystoreEntry[];
  /** What the engine found that the entry list does not show (entries it cannot model, weak integrity). */
  notes?: string[];
  /** Entries in the file the app could not represent. Saving over the file drops them. */
  omitted_entries?: number;
}

/** A keystore as held by the UI. */
export interface OpenKeystore extends KeystoreFile {
  /** Unsaved changes. */
  dirty: boolean;
  /** Known from the last session but not opened yet (password needed). */
  sealed: boolean;
}

/**
 * A certificate opened on its own (from a .pem/.crt/.cer/.der/.p7b file, pasted, or kept from
 * Examine), listed on the Certificates page. Not part of any keystore.
 */
export interface OpenCertificate {
  /** `cert::<sha256>`: see certificateId in lib/certificates. */
  id: string;
  /** The file it was read from; empty when it was pasted or kept from Examine. */
  path: string;
  /** Where it came from, for display: the file name, "Pasted" or a TLS endpoint. */
  source: string;
  opened_at: string;
  /** The certificate as a trusted-certificate entry, so the entry atoms and metrics apply. */
  entry: KeystoreEntry;
}

export interface Workspace {
  id: string;
  name: string;
  description: string;
  environment: "Production" | "Staging" | "Development" | "Compliance";
  created_at: string;
  updated_at: string;
  /** Entry keys: `${keystorePathOrId}::${alias}`, or `cert::<sha256>` for a certificate on the Certificates page. */
  entryIds: string[];
}

export interface GenerateKeyPairInput {
  alias: string;
  algorithm: "RSA" | "ECDSA" | "Ed25519";
  key_size: number;
  curve?: string | null;
  signature_hash?: string | null;
  subject_dn: string;
  common_name?: string;
  organization?: string;
  organizational_unit?: string;
  locality?: string;
  state?: string;
  country?: string;
  email?: string;
  validity_days: number;
  is_ca: boolean;
  path_len?: number | null;
  sans: string[];
  key_usage: string[];
  extended_key_usage: string[];
  labels: string[];
  not_before?: string;
  not_after?: string;
  crl_distribution_points?: string[];
  ocsp_urls?: string[];
  ca_issuer_urls?: string[];
}

export interface GenerateSecretKeyInput {
  alias: string;
  algorithm: string;
  key_size: number;
  custom_hex?: string | null;
  labels: string[];
}

export interface CsrOptions {
  subject_dn?: string | null;
  sans?: string[] | null;
  signature_hash?: string | null;
}

export interface CsrResult {
  alias: string;
  subject: string;
  algorithm: string;
  csr_pem: string;
  sha256_digest: string;
}

export interface CsrInfo {
  subject: string;
  public_key_algorithm: string;
  key_size: number;
  curve?: string | null;
  signature_algorithm: string;
  signature_valid: boolean;
  /** False when the signature uses an algorithm the engine cannot verify; signature_valid then says nothing. */
  signature_checked?: boolean;
  sans: string[];
  /** Builder ids requested by the CSR (`digitalSignature`, …). */
  key_usage: string[];
  /** Builder ids requested by the CSR (`serverAuth`, `codeSigning`, …). */
  extended_key_usage: string[];
  extensions: X509ExtensionInfo[];
  public_key_sha256: string;
  pem: string;
}

export interface SignCsrInput {
  csr_pem: string;
  subject_override?: string | null;
  validity_days: number;
  is_ca: boolean;
  path_len?: number | null;
  sans: string[];
  key_usage: string[];
  extended_key_usage: string[];
  copy_requested_sans?: boolean;
  /** When true (default), key usage comes from the CSR. When false, the lists above are written as given. */
  copy_requested_usages?: boolean;
  not_before?: string;
  not_after?: string;
  crl_distribution_points?: string[];
  ocsp_urls?: string[];
  ca_issuer_urls?: string[];
}

export interface SignedCertificateResult {
  certificate: CertificateInfo;
  chain_pem: string;
  /** Set when the requested lifetime was shortened to the CA certificate's expiry. */
  validity_note?: string | null;
}

/** Key pair from the engine, plus a note when the CA expiry shortened the lifetime. */
export type GeneratedKeyPair = KeystoreEntry & { validity_note?: string | null };

export interface RevokedCertEntry {
  serial_number: string;
  revocation_date: string;
  reason: string;
}

export interface CrlInfo {
  issuer: string;
  this_update: string;
  next_update: string;
  crl_number?: string | null;
  signature_algorithm: string;
  revoked_entries: RevokedCertEntry[];
  extensions: X509ExtensionInfo[];
  sha256_fingerprint: string;
  pem: string;
  signature_valid?: boolean | null;
}

/** An RFC 6960 OCSP revocation check for one certificate. */
export interface OcspInfo {
  /** "good", "revoked" or "unknown". */
  status: "good" | "revoked" | "unknown";
  responder: string;
  produced_at: string;
  this_update: string;
  next_update?: string | null;
  revocation_time?: string | null;
  revocation_reason?: string | null;
  signature_valid: boolean;
  signature_warning?: string | null;
  url: string;
}

/** An RFC 3161 trusted timestamp. */
export interface TimestampInfo {
  time: string;
  authority: string;
  serial_number: string;
  hash_algorithm: string;
  policy?: string | null;
  valid: boolean;
  error?: string | null;
  /** Set only when a TSA trust bundle was configured. */
  chain_trusted?: boolean | null;
}

export interface CmsSignResult {
  signer_alias: string;
  algorithm: string;
  detached: boolean;
  content_sha256: string;
  cms_pem: string;
  byte_length: number;
  signed_at: string;
  timestamp?: TimestampInfo | null;
}

export interface CmsSignerInfo {
  subject: string;
  issuer: string;
  serial_number: string;
  digest_algorithm: string;
  signature_algorithm: string;
  signing_time?: string | null;
  signature_valid: boolean;
  content_digest_valid?: boolean | null;
  timestamp?: TimestampInfo | null;
  error?: string | null;
}

export interface CmsVerifyResult {
  valid: boolean;
  detached: boolean;
  content_available: boolean;
  content_text?: string | null;
  content_sha256?: string | null;
  signers: CmsSignerInfo[];
  certificates: CertificateInfo[];
  message: string;
}

export interface JwtInfo {
  header_json: string;
  payload_json: string;
  algorithm: string;
  key_id?: string | null;
  issued_at?: string | null;
  not_before?: string | null;
  expires_at?: string | null;
  expired?: boolean | null;
  signature_b64url: string;
}

export interface JwtVerifyResult {
  valid: boolean;
  message: string;
  info: JwtInfo;
}

export interface DhParamsResult {
  bit_size: number;
  group: string;
  prime_hex: string;
  generator: number;
  pem: string;
  generated_at: string;
}

export interface TlsInspectionResult {
  host: string;
  port: number;
  address: string;
  protocol: string;
  cipher_suite: string;
  alpn?: string | null;
  trusted: boolean;
  verification_error?: string | null;
  hostname_matches: boolean;
  certificates: CertificateInfo[];
  handshake_ms: number;
  inspected_at: string;
}

/** One TCP connect attempt to one resolved address. */
export interface ConnectAttempt {
  address: string;
  succeeded: boolean;
  error?: string | null;
  elapsed_ms: number;
}

/** A TCP reachability test, the check `Test-NetConnection -Port` makes (src-tauri/src/netcheck.rs). */
export interface ConnectionTest {
  computer_name: string;
  remote_port: number;
  name_resolution: string[];
  resolve_ms: number;
  remote_address?: string | null;
  source_address?: string | null;
  interface_alias?: string | null;
  tcp_test_succeeded: boolean;
  tcp_ms?: number | null;
  attempts: ConnectAttempt[];
  failure?: "name-resolution" | "refused" | "timed-out" | "unreachable" | "error" | null;
  hint?: string | null;
  tested_at: string;
}

export interface KeyInfo {
  kind: "private" | "public" | "secret";
  algorithm: string;
  key_size: number;
  curve?: string | null;
  encrypted: boolean;
  format: string;
  public_key_sha256?: string | null;
  public_key_pem?: string | null;
}

export type DetectionKind =
  | "certificate"
  | "certificate_chain"
  | "csr"
  | "crl"
  | "private_key"
  | "public_key"
  | "jwt"
  | "pkcs7"
  | "keystore"
  | "dh_params"
  | "unknown";

export interface DetectionResult {
  kind: DetectionKind;
  title: string;
  format: string;
  summary: string;
  certificates: CertificateInfo[];
  csr?: CsrInfo | null;
  crl?: CrlInfo | null;
  key?: KeyInfo | null;
  jwt?: JwtInfo | null;
  keystore_format?: string | null;
  warnings: string[];
  sha256: string;
  byte_length: number;
}

export interface ExportResult {
  path: string;
  format: string;
  byte_length: number;
  text?: string | null;
}

export interface JarSignResult {
  output_path: string;
  signer_alias: string;
  signature_algorithm: string;
  digest_algorithm: string;
  entries_signed: number;
  manifest_preview: string;
  signature_file_name: string;
  signed_at: string;
  timestamp?: TimestampInfo | null;
}

/** Result of a conversion command (src-tauri/src/convert.rs). */
export interface ConvertResult {
  /** Where the output was written; null for a preview. */
  path: string | null;
  format: string;
  /** Suggested file extension, without the dot. */
  extension: string;
  byte_length: number;
  count: number;
  /** The output itself, for text that holds no private key material. */
  text: string | null;
  sensitive: boolean;
  notes: string[];
  sha256: string;
}

export interface PemBundleOptions {
  certificates: "chain" | "leaf" | "none";
  keys: "none" | "pkcs8" | "encrypted" | "traditional";
  password?: string | null;
  /** Precede each entry with an OpenSSL-style "Bag Attributes / friendlyName" header. */
  annotate: boolean;
}

export interface FileProbe {
  path: string;
  name: string;
  size: number;
  kind: DetectionKind | "jar" | "apk";
  keystore_format?: string | null;
}

export interface SaveResult {
  path: string;
  name: string;
  format: KeystoreFormat;
  byte_length: number;
  mtime_ms?: number | null;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  secret_count: number;
}

export interface SecretSummary {
  id: string;
  label: string;
  updated_at: string;
}

export interface AppInfo {
  version: string;
  data_dir: string;
  platform: string;
  home_dir: string;
  e2e: boolean;
}

export interface TerminalOutput {
  stdout: string;
  stderr: string;
  code: number;
  cwd: string;
  timed_out: boolean;
  truncated: boolean;
}

/** An external CLI tool Keystore Studio's workflows refer to (java, keytool, openssl), and whether it's on PATH. */
export interface ToolStatus {
  id: string;
  name: string;
  description: string;
  /** "java", "openssl" or "ssh": the family the Tools page groups it under. */
  group: string;
  /** What in Keystore Studio refers to the tool. */
  used_by: string[];
  available: boolean;
  version: string | null;
  path: string | null;
}

/** Input from a file path, pasted text or base64 bytes. */
export interface DataSource {
  path?: string;
  text?: string;
  base64?: string;
}
