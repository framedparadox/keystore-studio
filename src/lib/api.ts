import { invoke } from "@tauri-apps/api/core";
import type {
  AppInfo,
  CertificateInfo,
  CmsSignResult,
  CmsVerifyResult,
  CrlInfo,
  CsrInfo,
  CsrOptions,
  CsrResult,
  DataSource,
  DetectionResult,
  DhParamsResult,
  ExportResult,
  FileProbe,
  GenerateKeyPairInput,
  GenerateSecretKeyInput,
  JarSignResult,
  JwtVerifyResult,
  KeystoreEntry,
  KeystoreFile,
  KeystoreFormat,
  RevokedCertEntry,
  SaveResult,
  SecretSummary,
  SignCsrInput,
  SignedCertificateResult,
  TerminalOutput,
  TlsInspectionResult,
  VaultStatus,
} from "../types/crypto";

/** True inside the Tauri desktop shell (false in a plain browser preview). */
export const isDesktop = (): boolean => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** Normalises any rejection from a command into a readable message. */
export function errorMessage(err: unknown): string {
  if (typeof err === "string") return err.charAt(0).toUpperCase() + err.slice(1);
  if (err instanceof Error) return err.message;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isDesktop()) {
    throw new Error("This action needs the xkeystore desktop app (the browser preview has no native engine).");
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
  entries: ks.entries,
});

export const api = {
  appInfo: () => call<AppInfo>("app_info"),
  loadAppState: () => call<unknown>("load_app_state"),
  saveAppState: (state: unknown) => call<void>("save_app_state", { state }),

  probeFile: (path: string) => call<FileProbe>("probe_file", { path }),
  openKeystore: (path: string, password: string, keyPasswords?: Record<string, string>) =>
    call<KeystoreFile>("open_keystore", { path, password, keyPasswords: keyPasswords ?? null }),
  saveKeystore: (ks: KeystoreFile, path: string, password: string, format: KeystoreFormat) =>
    call<SaveResult>("save_keystore", { ks: wire(ks), path, password, format }),
  exportKeystoreCsv: (ks: KeystoreFile, path: string) => call<ExportResult>("export_keystore_csv", { ks: wire(ks), path }),

  generateKeyPair: (input: GenerateKeyPairInput, issuer?: KeystoreEntry | null) =>
    call<KeystoreEntry>("generate_key_pair", { input, issuer: issuer ?? null }),
  generateSecretKey: (input: GenerateSecretKeyInput) => call<KeystoreEntry>("generate_secret_key", { input }),
  importTrustedCertificates: (alias: string, data: DataSource, existingAliases: string[]) =>
    call<KeystoreEntry[]>("import_trusted_certificates", { alias, data, existingAliases }),
  importKeyPair: (alias: string, key: DataSource, keyPassword: string | null, certificates: DataSource | null) =>
    call<KeystoreEntry>("import_key_pair", { alias, key, keyPassword, certificates }),
  generateCsr: (entry: KeystoreEntry, options: CsrOptions) => call<CsrResult>("generate_csr", { entry, options }),
  importCaReply: (entry: KeystoreEntry, reply: DataSource) => call<KeystoreEntry>("import_ca_reply", { entry, reply }),
  rotateKey: (entry: KeystoreEntry, algorithm: string, keySize: number, curve: string | null, issuer: KeystoreEntry | null) =>
    call<KeystoreEntry>("rotate_key", { entry, algorithm, keySize, curve, issuer }),
  exportEntry: (entry: KeystoreEntry, target: string, path: string, password?: string | null) =>
    call<ExportResult>("export_entry", { entry, target, path, password: password ?? null }),
  jwtAlgorithms: (entry: KeystoreEntry) => call<string[]>("jwt_algorithms", { entry }),

  signCsr: (input: SignCsrInput, caEntry: KeystoreEntry) => call<SignedCertificateResult>("sign_csr", { input, caEntry }),
  inspectCsr: (data: DataSource) => call<CsrInfo>("inspect_csr", { data }),
  generateCrl: (caEntry: KeystoreEntry, nextUpdateDays: number, crlNumber: number, revokedEntries: RevokedCertEntry[]) =>
    call<CrlInfo>("generate_crl", { caEntry, nextUpdateDays, crlNumber, revokedEntries }),
  cmsSign: (content: DataSource, signerEntry: KeystoreEntry, detached: boolean, tsaUrl?: string | null) =>
    call<CmsSignResult>("cms_sign", { content, signerEntry, detached, tsaUrl: tsaUrl || null }),
  cmsVerify: (signature: DataSource, content: DataSource | null, entry: KeystoreEntry | null) =>
    call<CmsVerifyResult>("cms_verify", { signature, content, entry }),
  jwtSign: (
    input: { issuer: string; subject: string; audience: string; validity_minutes: number; custom_claims_json: string; algorithm?: string | null },
    signerEntry: KeystoreEntry
  ) => call<string>("jwt_sign", { input, signerEntry }),
  jwtVerify: (token: string, entry: KeystoreEntry) => call<JwtVerifyResult>("jwt_verify", { token, entry }),
  dhParams: (bits: number, mode: "ffdhe" | "generate") => call<DhParamsResult>("dh_params", { bits, mode }),
  jarSign: (inputPath: string, outputPath: string, signerEntry: KeystoreEntry, tsaUrl?: string | null) =>
    call<JarSignResult>("jar_sign", { inputPath, outputPath, signerEntry, tsaUrl: tsaUrl || null }),

  examineTls: (host: string, port: number) => call<TlsInspectionResult>("examine_tls", { host, port }),
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
};

/** Vault id under which a keystore's password is remembered. */
export const passwordSecretId = (path: string) => `keystore:${path}`;

export type { CertificateInfo };
