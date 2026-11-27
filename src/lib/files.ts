import { open, save } from "@tauri-apps/plugin-dialog";
import { isDesktop } from "./api";

export interface FileFilter {
  name: string;
  extensions: string[];
}

export const FILTERS = {
  keystores: { name: "Keystores", extensions: ["p12", "pfx", "jks", "jceks", "bks", "uber", "bcfks", "keystore", "ks", "truststore"] },
  certificates: { name: "Certificates", extensions: ["pem", "crt", "cer", "der", "p7b", "p7c", "pkipath", "txt"] },
  keys: { name: "Private keys", extensions: ["pem", "key", "der", "p8", "jwk", "json", "txt", "pub"] },
  csr: { name: "Certificate requests", extensions: ["csr", "pem", "req", "der", "txt"] },
  crl: { name: "CRLs", extensions: ["crl", "pem", "der"] },
  cms: { name: "Signatures", extensions: ["p7s", "p7m", "pem", "der", "sig"] },
  jar: { name: "Java archives", extensions: ["jar", "war", "ear", "apk", "zip"] },
  any: { name: "All files", extensions: ["*"] },
} satisfies Record<string, FileFilter>;

function requireDesktop() {
  if (!isDesktop()) throw new Error("File dialogs need the Keystore Studio desktop app.");
}

/*
 * End-to-end tests cannot drive native file dialogs. When the app is started with
 * KEYSTORE_STUDIO_E2E=1 the harness may queue answers in window.__xksStub = { open: [], save: [] }.
 */
let stubAllowed = false;
export const allowDialogStub = () => {
  stubAllowed = true;
};
type DialogStub = { open: (string | null)[]; save: (string | null)[] };
const dialogStub = (): DialogStub | undefined => (stubAllowed ? (window as unknown as { __xksStub?: DialogStub }).__xksStub : undefined);

/** Asks for one file to open. Resolves to null if the user cancels. */
export async function pickFile(title: string, filters: FileFilter[] = [FILTERS.any]): Promise<string | null> {
  requireDesktop();
  const stub = dialogStub();
  if (stub) return stub.open.shift() ?? null;
  const result = await open({ title, multiple: false, directory: false, filters: [...filters, FILTERS.any] });
  return typeof result === "string" ? result : null;
}

/** Asks for a folder. Resolves to null if the user cancels. */
export async function pickFolder(title: string): Promise<string | null> {
  requireDesktop();
  const stub = dialogStub();
  if (stub) return stub.open.shift() ?? null;
  const result = await open({ title, multiple: false, directory: true });
  return typeof result === "string" ? result : null;
}

export async function pickFiles(title: string, filters: FileFilter[] = [FILTERS.any]): Promise<string[]> {
  requireDesktop();
  const stub = dialogStub();
  if (stub) {
    const p = stub.open.shift();
    return p ? [p] : [];
  }
  const result = await open({ title, multiple: true, directory: false, filters: [...filters, FILTERS.any] });
  if (!result) return [];
  return Array.isArray(result) ? result : [result];
}

/** Asks where to save. Resolves to null if the user cancels. */
export async function pickSavePath(title: string, defaultPath: string, filters?: FileFilter[]): Promise<string | null> {
  requireDesktop();
  const stub = dialogStub();
  if (stub) return stub.save.shift() ?? null;
  const result = await save({ title, defaultPath, filters });
  return result ?? null;
}

export const baseName = (path: string) => path.split(/[\\/]/).pop() || path;

export const dirName = (path: string) => {
  const i = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return i > 0 ? path.slice(0, i) : "";
};

/** Replaces (or adds) the extension of a file name. */
export const withExtension = (name: string, ext: string) => {
  const stem = name.replace(/\.[^./\\]+$/, "");
  return `${stem || "keystore"}.${ext}`;
};

/** A filesystem-friendly version of an alias for default file names. */
export const safeFileStem = (s: string) => s.trim().replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "") || "export";
