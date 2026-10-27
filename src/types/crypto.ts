export type TabType =
  | "keystores"
  | "dashboard"
  | "ca_signing"
  | "examine"
  | "scanner"
  | "passwords"
  | "settings";

export type KeystoreFormat = "PKCS12" | "JKS" | "JCEKS" | "BKS" | "BCFKS" | "UBER";

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
  days_remaining: number;
  is_ca: boolean;
  public_key_algorithm: string;
  key_size: number;
  sans: string[];
  key_usage: string[];
  extended_key_usage: string[];
  extensions: X509ExtensionInfo[];
  sha256_fingerprint: string;
  sha1_fingerprint: string;
  md5_fingerprint: string;
  pem: string;
}

export interface KeystoreEntry {
  id: string;
  alias: string;
  entry_type: "KeyPair" | "TrustedCertificate" | "SecretKey";
  algorithm: string;
  key_size: number;
  curve?: string | null;
  creation_date: string;
  expiry_date: string;
  last_modified: string;
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
  locked: boolean;
  labels: string[];
  is_expired: boolean;
  is_weak: boolean;
  is_post_quantum: boolean;
}

export interface KeystoreFile {
  id: string;
  name: string;
  format: KeystoreFormat;
  path: string;
  description: string;
  password_protected: boolean;
  created_at: string;
  updated_at: string;
  entries: KeystoreEntry[];
}

export interface GenerateKeyPairInput {
  alias: string;
  algorithm: string;
  key_size: number;
  curve?: string | null;
  common_name: string;
  organization: string;
  organizational_unit: string;
  locality: string;
  state: string;
  country: string;
  email: string;
  validity_days: number;
  is_ca: boolean;
  sans: string[];
  key_usage: string[];
  extended_key_usage: string[];
  signer_alias?: string | null;
  labels: string[];
}

export interface GenerateSecretKeyInput {
  alias: string;
  algorithm: string;
  key_size: number;
  custom_hex?: string | null;
  labels: string[];
}

export interface CsrResult {
  alias: string;
  format: string;
  subject: string;
  algorithm: string;
  csr_pem: string;
  spkac_data: string;
  sha256_digest: string;
}

export interface SignCsrInput {
  csr_pem: string;
  ca_alias: string;
  subject_override?: string | null;
  validity_days: number;
  is_ca: boolean;
  sans: string[];
}

export interface RevokedCertEntry {
  serial_number: string;
  revocation_date: string;
  reason: string;
}

export interface CrlResult {
  issuer: string;
  this_update: string;
  next_update: string;
  crl_number: number;
  signature_algorithm: string;
  revoked_entries: RevokedCertEntry[];
  crl_pem: string;
  sha256_fingerprint: string;
}

export interface JarSignatureResult {
  jar_name: string;
  signer_alias: string;
  digest_algorithm: string;
  signature_algorithm: string;
  timestamp_authority?: string | null;
  signed_at: string;
  manifest_mf: string;
  signature_sf: string;
  signature_block_b64: string;
  verified: boolean;
  entry_digests: [string, string][];
}

export interface CmsSignResult {
  signer_alias: string;
  algorithm: string;
  detached: boolean;
  payload_sha256: string;
  signature_hex: string;
  cms_pem: string;
  signed_at: string;
  verified: boolean;
}

export interface DhParamsResult {
  bit_size: number;
  prime_p_hex: string;
  generator_g: number;
  pem: string;
  generated_at: string;
}

export interface SslInspectionResult {
  host: string;
  port: number;
  protocol: string;
  cipher_suite: string;
  peer_verified: boolean;
  server_certificates: CertificateInfo[];
  inspected_at: string;
}

export interface FileDetectionResult {
  detected_type: string;
  format: string;
  summary: string;
  details: Record<string, unknown>;
  raw_pem?: string | null;
}

export interface ExportPayloadResult {
  filename: string;
  format: string;
  mime_type: string;
  content: string;
  saved_path?: string | null;
  byte_length: number;
}
