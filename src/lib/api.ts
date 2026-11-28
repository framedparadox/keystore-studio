import { invoke } from "@tauri-apps/api/core";
import type {
  AppInfo,
  CertificateInfo,
  CmsSignResult,
  CmsVerifyResult,
  ConvertResult,
  CrlInfo,
  CsrInfo,
  CsrOptions,
  CsrResult,
  DataSource,
  DetectionResult,
  DhParamsResult,
  ExportResult,
  FileProbe,
  FolderScan,
  GeneratedKeyPair,
  GenerateKeyPairInput,
  GenerateSecretKeyInput,
  JarSignResult,
  JwtVerifyResult,
  KeystoreEntry,
  KeystoreFile,
  KeystoreFormat,
  OcspInfo,
  PemBundleOptions,
  Pkcs12Profile,
  RevokedCertEntry,
  SaveResult,
  SecretSummary,
  SignCsrInput,
  SignedCertificateResult,
  TerminalOutput,
  RevocationMethodResult,
  ToolStatus,
  ConnectionTest,
  TlsInspectionResult,
  VaultStatus,
} from "../types/crypto";

/** True inside the Tauri desktop shell (false in a plain browser preview). */
export const isDesktop = (): boolean => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** Normalises any rejection from a command into a readable message. */
const ERROR_KINDS = ["wrong-password", "unrecognized", "unrecognised", "unsupported", "invalid", "changed-on-disk", "apk"] as const;

/** Splits an engine error into a stable kind and a sentence for the dialog. */
export function classifyError(err: unknown): { kind: string; message: string } {
  const raw = typeof err === "string" ? err : err instanceof Error ? err.message : "";
  const match = new RegExp(`^(${ERROR_KINDS.join("|")}):\\s*`, "i").exec(raw);
  if (!match) return { kind: "other", message: errorMessage(err) };
  const rest = raw.slice(match[0].length);
  return { kind: match[1].toLowerCase().replace("unrecognised", "unrecognized"), message: rest ? rest.charAt(0).toUpperCase() + rest.slice(1) : errorMessage(err) };
}

export function errorMessage(err: unknown): string {
  const raw = typeof err === "string" ? err : err instanceof Error ? err.message : "";
  const match = new RegExp(`^(${ERROR_KINDS.join("|")}):\\s*`, "i").exec(raw);
  const text = match ? raw.slice(match[0].length) : raw;
  if (typeof err === "string" || err instanceof Error) return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Something went wrong.";
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isDesktop()) {
    throw new Error("This action needs the Keystore Studio desktop app (the browser preview has no native engine).");
  }
  return invoke<T>(cmd, args);
}

/** Strips UI-only fields before sending a keystore over IPC. */
const wire = (ks: KeystoreFile): KeystoreFile => ({
  id: ks.id,
  name: ks.name,
  format: ks.format,
  path: ks.path,
  description: ks.description,
  password_protected: ks.password_protected,
  created_at: ks.created_at,
  updated_at: ks.updated_at,
  source_mtime_ms: ks.source_mtime_ms ?? null,
  entries: ks.entries,
});

export const api = {
  appInfo: () => call<AppInfo>("app_info"),
  loadAppState: () => call<unknown>("load_app_state"),
  saveAppState: (state: unknown) => call<void>("save_app_state", { state }),

  probeFile: (path: string) => call<FileProbe>("probe_file", { path }),
  scanFolder: (path: string) => call<FolderScan>("scan_folder", { path }),
  openKeystore: (path: string, password: string, keyPasswords?: Record<string, string>) =>
    call<KeystoreFile>("open_keystore", { path, password, keyPasswords: keyPasswords ?? null }),
  saveKeystore: (ks: KeystoreFile, path: string, password: string, format: KeystoreFormat, mac?: Pkcs12Profile | null, force?: boolean) =>
    call<SaveResult>("save_keystore", { ks: wire(ks), path, password, format, mac: mac ?? null, force: force ?? false }),
  exportKeystoreCsv: (ks: KeystoreFile, path: string) => call<ExportResult>("export_keystore_csv", { ks: wire(ks), path }),

  generateKeyPair: (input: GenerateKeyPairInput, issuer?: KeystoreEntry | null) =>
    call<GeneratedKeyPair>("generate_key_pair", { input, issuer: issuer ?? null }),
  generateSecretKey: (input: GenerateSecretKeyInput) => call<KeystoreEntry>("generate_secret_key", { input }),
  importTrustedCertificates: (alias: string, data: DataSource, existingAliases: string[]) =>
    call<KeystoreEntry[]>("import_trusted_certificates", { alias, data, existingAliases }),
  importKeyPair: (alias: string, key: DataSource, keyPassword: string | null, certificates: DataSource | null) =>
    call<KeystoreEntry>("import_key_pair", { alias, key, keyPassword, certificates }),
  buildPkcs12: (args: { path: string; key: DataSource; certificate: DataSource | null; keyPassword: string | null; passphrase: string; alias: string | null; mac?: Pkcs12Profile | null }) =>
    call<ExportResult>("build_pkcs12", {
      path: args.path,
      key: args.key,
      certificate: args.certificate,
      keyPassword: args.keyPassword,
      passphrase: args.passphrase,
      alias: args.alias,
      mac: args.mac ?? null,
    }),
  generateCsr: (entry: KeystoreEntry, options: CsrOptions) => call<CsrResult>("generate_csr", { entry, options }),
  importCaReply: (entry: KeystoreEntry, reply: DataSource) => call<KeystoreEntry>("import_ca_reply", { entry, reply }),
  rotateKey: (entry: KeystoreEntry, algorithm: string, keySize: number, curve: string | null, issuer: KeystoreEntry | null) =>
    call<KeystoreEntry>("rotate_key", { entry, algorithm, keySize, curve, issuer }),
  exportEntry: (entry: KeystoreEntry, target: string, path: string, password?: string | null) =>
    call<ExportResult>("export_entry", { entry, target, path, password: password ?? null }),
  jwtAlgorithms: (entry: KeystoreEntry) => call<string[]>("jwt_algorithms", { entry }),

  // Conversions. Without `path` a conversion is a preview: nothing is written and only
  // non-sensitive text comes back.
  /** `chainPem` adds issuer certificates (roots, intermediates) to the input's own. */
  convertCertificates: (data: DataSource, target: string, order: boolean, path?: string | null, chainPem?: string) =>
    call<ConvertResult>("convert_certificates", { data, target, order, path: path ?? null, chainPem: chainPem ?? null }),
  convertPrivateKey: (data: DataSource, password: string | null, target: string, outPassword: string | null, path?: string | null, comment?: string) =>
    call<ConvertResult>("convert_private_key", { data, password, target, outPassword, comment: comment ?? null, path: path ?? null }),
  /** Every certificate in `data` as a trusted certificate entry of a new keystore in `format`. */
  convertTruststore: (data: DataSource, format: KeystoreFormat, password: string, alias: string, path?: string | null) =>
    call<ConvertResult>("convert_truststore", { data, format, password, alias, path: path ?? null }),
  convertPublicKey: (data: DataSource, password: string | null, target: string, comment: string, path?: string | null) =>
    call<ConvertResult>("convert_public_key", { data, password, target, comment, path: path ?? null }),
  convertEncoding: (data: DataSource, label: string | null, path?: string | null) => call<ConvertResult>("convert_encoding", { data, label, path: path ?? null }),
  entriesToPem: (entries: KeystoreEntry[], options: PemBundleOptions, path?: string | null) => call<ConvertResult>("entries_to_pem", { entries, options, path: path ?? null }),

  signCsr: (input: SignCsrInput, caEntry: KeystoreEntry) => call<SignedCertificateResult>("sign_csr", { input, caEntry }),
  inspectCsr: (data: DataSource) => call<CsrInfo>("inspect_csr", { data }),
  generateCrl: (caEntry: KeystoreEntry, nextUpdateDays: number, crlNumber: number, revokedEntries: RevokedCertEntry[]) =>
    call<CrlInfo>("generate_crl", { caEntry, nextUpdateDays, crlNumber, revokedEntries }),
  caNextCrlNumber: (caSki: string) => call<number>("ca_next_crl_number", { caSki }),
  readCrl: (data: DataSource) => call<CrlInfo>("read_crl", { data }),
  ledgerSearch: (query: string) => call<{ serial: string; subject: string; ski: string; not_after: string; profile: string; issuer_ski: string }[]>("ledger_search", { query }),
  ledgerDelete: (serial: string) => call<void>("ledger_delete", { serial }),
  /** Problems with the chain, none when it is trusted. `checkRevocation` asks OCSP responders / CRL servers online. */
  validateChain: (leafPem: string, intermediatesPem: string, anchorsPem: string, hostname?: string | null, checkRevocation = false) =>
    call<string[]>("validate_chain", { leafPem, intermediatesPem, anchorsPem, hostname: hostname ?? null, checkRevocation }),
  /** The OS trust store as PEM, for validateChain against the same roots examineTls trusts. */
  systemTrustAnchors: () => call<string>("system_trust_anchors"),
  /** Live revocation check (RFC 6960). `url` defaults to the subject certificate's own OCSP URL when omitted. */
  /** Every OCSP responder and CRL distribution point the certificate names, each asked on its own. */
  checkRevocation: (subjectPem: string, issuerPem: string, methods?: ("ocsp" | "crl")[]) =>
    call<RevocationMethodResult[]>("check_revocation", { subjectPem, issuerPem, methods: methods ?? null }),
  checkOcsp: (subjectPem: string, issuerPem: string, url?: string | null) => call<OcspInfo>("check_ocsp", { subjectPem, issuerPem, url: url ?? null }),
  cmsSign: (content: DataSource, signerEntry: KeystoreEntry, detached: boolean, tsaUrl?: string | null, tsaTrustPem?: string | null) =>
    call<CmsSignResult>("cms_sign", { content, signerEntry, detached, tsaUrl: tsaUrl || null, tsaTrustPem: tsaTrustPem || null }),
  cmsVerify: (signature: DataSource, content: DataSource | null, entry: KeystoreEntry | null, tsaTrustPem?: string | null) =>
    call<CmsVerifyResult>("cms_verify", { signature, content, entry, tsaTrustPem: tsaTrustPem || null }),
  jwtSign: (
    input: { issuer: string; subject: string; audience: string; validity_minutes: number; custom_claims_json: string; algorithm?: string | null },
    signerEntry: KeystoreEntry
  ) => call<string>("jwt_sign", { input, signerEntry }),
  jwtVerify: (token: string, entry: KeystoreEntry) => call<JwtVerifyResult>("jwt_verify", { token, entry }),
  dhParams: (bits: number, mode: "ffdhe" | "generate") => call<DhParamsResult>("dh_params", { bits, mode }),
  jarSign: (inputPath: string, outputPath: string, signerEntry: KeystoreEntry, tsaUrl?: string | null, tsaTrustPem?: string | null) =>
    call<JarSignResult>("jar_sign", { inputPath, outputPath, signerEntry, tsaUrl: tsaUrl || null, tsaTrustPem: tsaTrustPem || null }),

  examineTls: (host: string, port: number) => call<TlsInspectionResult>("examine_tls", { host, port }),
  /** Can this machine open a TCP connection to target:port? A port in `target` wins. */
  testConnection: (target: string, port: number, timeoutSecs = 5) => call<ConnectionTest>("test_connection", { target, port, timeoutSecs }),
  examineData: (data: DataSource, password?: string | null) => call<DetectionResult>("examine_data", { data, password: password ?? null }),

  writeTextFile: (path: string, content: string) => call<void>("write_text_file", { path, content }),
  readTextFile: (path: string) => call<string>("read_text_file", { path }),

  vaultStatus: () => call<VaultStatus>("vault_status"),
  vaultInit: (masterKey: string) => call<void>("vault_init", { masterKey }),
  vaultUnlock: (masterKey: string) => call<void>("vault_unlock", { masterKey }),
  vaultLock: () => call<void>("vault_lock"),
  vaultChangeMasterKey: (oldMasterKey: string, newMasterKey: string) => call<void>("vault_change_master_key", { oldMasterKey, newMasterKey }),
  vaultReset: () => call<void>("vault_reset"),
  vaultStoreSecret: (id: string, label: string, secret: string) => call<void>("vault_store_secret", { id, label, secret }),
  vaultGetSecret: (id: string) => call<string | null>("vault_get_secret", { id }),
  vaultDeleteSecret: (id: string) => call<void>("vault_delete_secret", { id }),
  vaultListSecrets: () => call<SecretSummary[]>("vault_list_secrets"),

  runTerminalCommand: (command: string, cwd: string | undefined, timeoutSecs: number) =>
    call<TerminalOutput>("run_terminal_command", { command, cwd: cwd ?? null, timeoutSecs }),

  /** `overrides` maps a tool id to the file or folder the user chose for it; omitted tools are detected. */
  toolStatus: (overrides: Record<string, string> = {}) => call<ToolStatus[]>("tool_status", { overrides }),
  /** The native unsaved-changes cue (macOS: the dot in the close button). */
  setDocumentEdited: (edited: boolean) => call<void>("set_document_edited", { edited }),
};

/** Shortest master key for a new vault or a master key change; mirrors vault.rs MIN_MASTER_KEY_LEN. */
export const MIN_MASTER_KEY_LEN = 12;

/** Vault id under which a keystore's password is remembered. */
export const passwordSecretId = (path: string) => `keystore:${path}`;

export type { CertificateInfo };
