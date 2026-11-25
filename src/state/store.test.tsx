// @vitest-environment jsdom
/*
 * StoreProvider behaviour that only shows up across async boundaries: a save that resolves after
 * an edit, files dropped while a password prompt is up, and the inactivity auto-lock. The engine
 * (lib/api) is mocked with promises each test resolves by hand.
 */
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { KeystoreEntry, KeystoreFile } from "../types/crypto";

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void };
const deferred = <T,>(): Deferred<T> => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const api = vi.hoisted(() => ({
  appInfo: vi.fn(),
  vaultStatus: vi.fn(),
  loadAppState: vi.fn(),
  saveAppState: vi.fn(),
  probeFile: vi.fn(),
  openKeystore: vi.fn(),
  saveKeystore: vi.fn(),
  vaultLock: vi.fn(),
  vaultGetSecret: vi.fn(),
  vaultStoreSecret: vi.fn(),
  importTrustedCertificates: vi.fn(),
  examineData: vi.fn(),
}));

vi.mock("../lib/api", async (importOriginal) => {
  const real = await importOriginal<typeof import("../lib/api")>();
  return { ...real, api, isDesktop: () => true };
});
// The window theme is applied through Tauri in the desktop app; nothing to do in a test.
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => ({ setTheme: async () => undefined, onCloseRequested: async () => () => undefined }) }));

import { StoreProvider, useStore } from "./store";
import { ConfirmProvider, ToastProvider } from "../components/ui";

type Store = ReturnType<typeof useStore>;
let store!: Store;
const Probe: React.FC = () => {
  store = useStore();
  return null;
};

let root: Root;
let container: HTMLDivElement;

const flush = async () => {
  await act(async () => {
    for (let i = 0; i < 5; i++) await Promise.resolve();
  });
};

const keyPair = (alias: string): KeystoreEntry =>
  ({
    id: alias,
    alias,
    entry_type: "KeyPair",
    algorithm: "ECDSA",
    key_size: 256,
    creation_date: "2026-01-01",
    expiry_date: "2027-01-01",
    subject: `CN=${alias}`,
    issuer: `CN=${alias}`,
    serial_number: "01",
    sha256_fingerprint: "",
    sha1_fingerprint: "",
    chain_length: 0,
    certificate_chain: [],
    locked: false,
    labels: [],
    is_expired: false,
    is_weak: false,
    weak_reasons: [],
    is_post_quantum: false,
    private_key_pem: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
  }) as KeystoreEntry;

const file = (path: string, entries: KeystoreEntry[] = []): KeystoreFile => ({
  id: `file-${path}`,
  name: path.split("/").pop()!,
  format: "PKCS12",
  path,
  description: "PKCS12 keystore",
  password_protected: true,
  created_at: "",
  updated_at: "",
  entries,
});

beforeEach(async () => {
  Object.values(api).forEach((f) => f.mockReset());
  api.appInfo.mockResolvedValue({ version: "test", data_dir: "/tmp", platform: "macos", home_dir: "/tmp", e2e: false });
  api.vaultStatus.mockResolvedValue({ exists: false, unlocked: false, secret_count: 0 });
  api.loadAppState.mockResolvedValue(null);
  api.saveAppState.mockResolvedValue(undefined);
  api.vaultLock.mockResolvedValue(undefined);
  api.probeFile.mockImplementation(async (path: string) => ({ path, name: path.split("/").pop(), size: 10, kind: "keystore", keystore_format: "PKCS12" }));
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  await mount();
});

/** Renders a fresh StoreProvider (again, after fake timers are on, so its interval uses them). */
async function mount() {
  if (root) await act(async () => root.unmount());
  container?.remove();
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(
      <ToastProvider>
        <ConfirmProvider>
          <StoreProvider>
            <Probe />
          </StoreProvider>
        </ConfirmProvider>
      </ToastProvider>
    );
  });
  await flush();
  expect(store.ready).toBe(true);
}

afterEach(async () => {
  await act(async () => root.unmount());
  root = undefined as unknown as Root;
  container.remove();
  vi.useRealTimers();
});

/** Opens `path` through the password prompt, as the user would. */
async function openWithPassword(path: string, entries: KeystoreEntry[] = []) {
  api.openKeystore.mockResolvedValueOnce(file(path, entries));
  await act(async () => void store.openFiles([path]));
  await flush();
  expect(store.pendingOpen?.path).toBe(path);
  await act(async () => void (await store.submitOpenPassword("pw", false)));
  await flush();
  return store.keystores.find((k) => k.path === path)!;
}

describe("store: save", () => {
  it("keeps an edit made while the save was still running", async () => {
    const ks = await openWithPassword("/tmp/a.p12");
    const saving = deferred<{ path: string; name: string; format: string; byte_length: number; mtime_ms: number }>();
    api.saveKeystore.mockReturnValueOnce(saving.promise);

    let done!: Promise<void>;
    await act(async () => {
      done = store.save(ks.id);
    });
    // The user adds an entry before the engine reports the save.
    await act(async () => void store.addEntries(ks.id, [keyPair("late")]));
    await act(async () => {
      saving.resolve({ path: "/tmp/a.p12", name: "a.p12", format: "PKCS12", byte_length: 100, mtime_ms: 1 });
      await done;
    });

    const after = store.keystores.find((k) => k.id === ks.id)!;
    expect(after.entries.map((e) => e.alias)).toEqual(["late"]);
    expect(after.dirty).toBe(true);
    expect(after.path).toBe("/tmp/a.p12");
  });

  it("marks the keystore saved when nothing changed during the save", async () => {
    const ks = await openWithPassword("/tmp/b.p12");
    api.saveKeystore.mockResolvedValueOnce({ path: "/tmp/b.p12", name: "b.p12", format: "PKCS12", byte_length: 100, mtime_ms: 1 });
    await act(async () => void store.addEntries(ks.id, [keyPair("x")]));
    expect(store.keystores[0].dirty).toBe(true);
    await act(async () => store.save(ks.id));
    expect(store.keystores[0].dirty).toBe(false);
    expect(store.keystores[0].entries.map((e) => e.alias)).toEqual(["x"]);
  });
});

describe("store: opening several files", () => {
  it("queues a file dropped while a password prompt is up instead of replacing the prompt", async () => {
    await act(async () => void store.openFiles(["/tmp/first.p12"]));
    await flush();
    expect(store.pendingOpen?.path).toBe("/tmp/first.p12");

    await act(async () => void store.openFiles(["/tmp/second.p12"]));
    await flush();
    expect(store.pendingOpen?.path).toBe("/tmp/first.p12");

    await act(async () => store.cancelOpen());
    await flush();
    expect(store.pendingOpen?.path).toBe("/tmp/second.p12");

    api.openKeystore.mockResolvedValueOnce(file("/tmp/second.p12"));
    await act(async () => void (await store.submitOpenPassword("pw", false)));
    await flush();
    expect(store.pendingOpen).toBeNull();
    expect(store.keystores.map((k) => k.path)).toEqual(["/tmp/second.p12"]);
  });
});

describe("store: inactivity auto-lock", () => {
  it("locks key pairs unlocked this session, not only the vault", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    await mount();
    await act(async () => {
      store.updateSettings({ autoLockMinutes: 5, requireKeyUnlock: true });
    });
    let ks!: ReturnType<Store["createKeystore"]>;
    await act(async () => {
      ks = store.createKeystore({ name: "new.p12", format: "PKCS12", password: "pw", remember: false, initialEntry: keyPair("signer") });
    });
    const signer = () => store.keystores.find((k) => k.id === ks.id)!.entries[0];
    // Made in this session, so usable right away.
    expect(store.isKeyLocked(signer())).toBe(false);

    await act(async () => {
      vi.advanceTimersByTime(4 * 60_000);
    });
    expect(store.isKeyLocked(signer())).toBe(false);

    await act(async () => {
      vi.advanceTimersByTime(2 * 60_000);
    });
    expect(store.isKeyLocked(signer())).toBe(true);
  });

  it("leaves keys alone when auto-lock is off", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    await mount();
    await act(async () => store.updateSettings({ autoLockMinutes: 0 }));
    let ks!: ReturnType<Store["createKeystore"]>;
    await act(async () => {
      ks = store.createKeystore({ name: "n.p12", format: "PKCS12", password: "pw", remember: false, initialEntry: keyPair("k") });
    });
    await act(async () => {
      vi.advanceTimersByTime(120 * 60_000);
    });
    expect(store.isKeyLocked(store.keystores.find((k) => k.id === ks.id)!.entries[0])).toBe(false);
  });
});
