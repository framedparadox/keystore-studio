export type TabType = "overview" | "keystores" | "certificates" | "trust_graph" | "scanner" | "cloud" | "jwt_ssh" | "settings";

export interface KeyPairResult {
  algorithm: string;
  key_size: number;
  curve?: string;
  public_key_pem: string;
  private_key_pem: string;
  fingerprint_sha256: string;
  is_post_quantum: boolean;
  cli_command: string;
}

export interface CertGenRequest {
  common_name: string;
  organization?: string;
  organizational_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
  sans: string[];
  validity_days: number;
  is_ca: boolean;
  algorithm: string;
  key_size: number;
}

export interface CertResult {
  certificate_pem: string;
  private_key_pem: string;
  csr_pem: string;
  serial_number: string;
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  fingerprint_sha256: string;
  fingerprint_sha1: string;
  sans: string[];
  is_ca: boolean;
  cli_command: string;
}

export interface JwtAnalysis {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  algorithm: string;
  is_expired: boolean;
  expires_at?: string;
  issued_at?: string;
  issuer?: string;
  subject?: string;
  signature_valid: boolean;
}

export interface SecurityIssue {
  severity: "CRITICAL" | "WARNING" | "INFO";
  title: string;
  description: string;
  recommendation: string;
  cli_fix: string;
}

export interface SecurityAuditReport {
  total_keys: number;
  health_score: number;
  weak_keys_count: number;
  deprecated_hashes_count: number;
  expiring_soon_count: number;
  post_quantum_ready_count: number;
  issues: SecurityIssue[];
}

export interface KeystoreEntry {
  alias: string;
  type: "PrivateKeyEntry" | "TrustedCertEntry";
  algorithm: string;
  keySize: number;
  creationDate: string;
  expiryDate: string;
  subject: string;
  issuer: string;
  sha256Fingerprint: string;
  chainLength: number;
  isExpired?: boolean;
  isWeak?: boolean;
}

export interface KeystoreFile {
  id: string;
  filename: string;
  format: "JKS" | "PKCS12" | "BCFKS" | "JCEKS";
  path: string;
  totalEntries: number;
  entries: KeystoreEntry[];
}
