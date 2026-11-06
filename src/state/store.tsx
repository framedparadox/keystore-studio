import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { api, errorMessage, isDesktop, passwordSecretId } from "../lib/api";
import { allowDialogStub, baseName, pickFile, FILTERS } from "../lib/files";
import { entryKey, normalizeEntries, uniqueAlias } from "../lib/keystore";
import { setThresholds } from "../lib/metrics";
import { useConfirm, useToast } from "../components/ui";
import type { AppInfo, KeystoreEntry, KeystoreFile, KeystoreFormat, OpenKeystore, TabType, VaultStatus, Workspace } from "../types/crypto";

export interface Settings {
  autoLockMinutes: number;
  criticalDays: number;
  warningDays: number;
  defaultFormat: KeystoreFormat;
  rememberPasswordsByDefault: boolean;
  terminalTimeoutSecs: number;
  restoreSession: boolean;
  /** Timestamp authority URL used when signing, empty to sign without a timestamp. */
  tsaUrl: string;
  timestampByDefault: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  autoLockMinutes: 15,
  criticalDays: 30,
  warningDays: 90,
  defaultFormat: "PKCS12",
  rememberPasswordsByDefault: false,
  terminalTimeoutSecs: 120,
  restoreSession: true,
  tsaUrl: "",
  timestampByDefault: false,
};

export interface RecentFile {
  path: string;
  name: string;
  format: string;
  openedAt: string;
}

interface PersistedState {
  version: 1;
  keystores: { id: string; path: string; name: string; format: KeystoreFormat }[];
  activeKeystoreId: string | null;
  recentFiles: RecentFile[];
  workspaces: Workspace[];
  activeWorkspaceId: string | null;
  labels: Record<string, string[]>;
  settings: Settings;
}

/** A file waiting for its password before it can be opened. */
export interface PendingOpen {
  path: string;
  name: string;
  format: string;
  /** Re-use this keystore id (restoring a sealed keystore from the last session). */
  sealedId?: string;
  error?: string;
}

export interface PendingSave {
  keystoreId: string;
  /** "save-as" always asks for a path; "first-save" is a Save of a never-saved keystore. */
  mode: "save-as" | "first-save";
  then?: () => void;
}

export interface NewKeystoreRequest {
  name: string;
  format: KeystoreFormat;
  password: string;
  remember: boolean;
  initialEntry?: KeystoreEntry | null;
}

interface Store {
  ready: boolean;
  desktop: boolean;
  appInfo: AppInfo | null;
  // navigation
  tab: TabType;
  setTab: (t: TabType) => void;
  examineRequest: { path?: string; text?: string; nonce: number } | null;
  examine: (input: { path?: string; text?: string }) => void;
  jarRequest: { path: string; nonce: number } | null;
  // keystores
  keystores: OpenKeystore[];
  activeKeystoreId: string | null;
  activeKeystore: OpenKeystore | null;
  selectKeystore: (id: string) => void;
  canUndo: boolean;
  canRedo: boolean;
  undo: () => void;
  redo: () => void;
  updateKeystore: (ks: OpenKeystore) => void;
  addEntries: (keystoreId: string, entries: KeystoreEntry[]) => KeystoreEntry[];
  replaceEntry: (keystoreId: string, entry: KeystoreEntry) => void;
  deleteEntries: (keystoreId: string, entryIds: string[]) => void;
  renameEntry: (keystoreId: string, entryId: string, alias: string) => void;
  setEntryLabels: (keystoreId: string, entryId: string, labels: string[]) => void;
  hasPassword: (keystoreId: string) => boolean;
  getPassword: (keystoreId: string) => string | undefined;
  setPassword: (keystoreId: string, password: string) => void;
  // file workflows
  openFiles: (paths?: string[]) => Promise<void>;
  pendingOpen: PendingOpen | null;
  submitOpenPassword: (password: string, remember: boolean) => Promise<boolean>;
  cancelOpen: () => void;
  unlockSealed: (keystoreId: string) => void;
  createKeystore: (req: NewKeystoreRequest) => OpenKeystore;
  newKeystoreOpen: boolean;
  setNewKeystoreOpen: (open: boolean) => void;
  save: (keystoreId: string, opts?: { saveAs?: boolean; then?: () => void }) => Promise<void>;
  pendingSave: PendingSave | null;
  completeSave: (args: { path: string; password: string; format: KeystoreFormat; remember: boolean }) => Promise<boolean>;
  cancelSave: () => void;
  closeKeystore: (keystoreId: string) => Promise<boolean>;
  recentFiles: RecentFile[];
  clearRecentFiles: () => void;
  // workspaces
  workspaces: Workspace[];
  activeWorkspaceId: string | null;
  setActiveWorkspaceId: (id: string | null) => void;
  saveWorkspace: (ws: Workspace) => void;
  deleteWorkspace: (id: string) => void;
  toggleWorkspaceEntry: (workspaceId: string, entryId: string) => void;
  // vault
  vault: VaultStatus;
  refreshVault: () => Promise<VaultStatus>;
  lockVault: () => Promise<void>;
  vaultPromptOpen: boolean;
  requestVaultUnlock: (after?: () => void) => void;
  closeVaultPrompt: () => void;
  onVaultUnlocked: () => Promise<void>;
  // settings
  settings: Settings;
  updateSettings: (patch: Partial<Settings>) => void;
  resetAppData: () => Promise<void>;
}

const StoreContext = createContext<Store | null>(null);

export const useStore = (): Store => {
  const s = useContext(StoreContext);
  if (!s) throw new Error("useStore outside StoreProvider");
  return s;
};

const now = () => new Date().toISOString();
export const uid = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
const HISTORY_LIMIT = 30;

export const StoreProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const toast = useToast();
  const confirm = useConfirm();
  const desktop = isDesktop();

  const [ready, setReady] = useState(false);
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [tab, setTab] = useState<TabType>("home");
  const [examineRequest, setExamineRequest] = useState<Store["examineRequest"]>(null);
  const [jarRequest, setJarRequest] = useState<Store["jarRequest"]>(null);

  // Keystores and their undo/redo history live in refs, which are the single source of truth;
  // every change goes through setAll(), synchronously, and bumps `version` to re-render. This
  // avoids React state updaters with side effects (which React may run lazily or twice) and
  // stale reads, either of which can silently drop an edit.
  const keystoresRef = useRef<OpenKeystore[]>([]);
  const historyRef = useRef<OpenKeystore[][]>([]);
  const redoRef = useRef<OpenKeystore[][]>([]);
  const [version, setVersion] = useState(0);
  const bump = useCallback(() => setVersion((v) => v + 1), []);
  const setAll = useCallback(
    (next: OpenKeystore[], history?: OpenKeystore[][], redo?: OpenKeystore[][]) => {
      keystoresRef.current = next;
      if (history) historyRef.current = history;
      if (redo) redoRef.current = redo;
      bump();
    },
    [bump]
  );
  const keystores = keystoresRef.current;
  const [activeKeystoreId, setActiveKeystoreId] = useState<string | null>(null);
  const passwords = useRef(new Map<string, string>());

  const [pendingOpen, setPendingOpen] = useState<PendingOpen | null>(null);
  const openQueue = useRef<string[]>([]);
  const [pendingSave, setPendingSave] = useState<PendingSave | null>(null);
  const [newKeystoreOpen, setNewKeystoreOpen] = useState(false);
  const [recentFiles, setRecentFiles] = useState<RecentFile[]>([]);

  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState<string | null>(null);
  const [labels, setLabels] = useState<Record<string, string[]>>({});
  const labelsRef = useRef(labels);
  labelsRef.current = labels;

  const [vault, setVault] = useState<VaultStatus>({ exists: false, unlocked: false, secret_count: 0 });
  const vaultRef = useRef(vault);
  vaultRef.current = vault;
  const [vaultPromptOpen, setVaultPromptOpen] = useState(false);
  const afterVaultUnlock = useRef<(() => void) | null>(null);

  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const settingsRef = useRef(settings);
  settingsRef.current = settings;

  useEffect(() => setThresholds(settings.criticalDays, settings.warningDays), [settings.criticalDays, settings.warningDays]);

  // ------------------------------------------------------------------ history
  const commit = useCallback(
    (next: OpenKeystore[]) => setAll(next, [...historyRef.current.slice(-(HISTORY_LIMIT - 1)), keystoresRef.current], []),
    [setAll]
  );

  const undo = useCallback(() => {
    const h = historyRef.current;
    if (!h.length) return;
    setAll(h[h.length - 1], h.slice(0, -1), [keystoresRef.current, ...redoRef.current]);
  }, [setAll]);

  const redo = useCallback(() => {
    const r = redoRef.current;
    if (!r.length) return;
    setAll(r[0], [...historyRef.current, keystoresRef.current], r.slice(1));
  }, [setAll]);

  // --------------------------------------------------------------- labels/ids
  const applyLabels = useCallback((ks: OpenKeystore): OpenKeystore => {
    const n = normalizeEntries(ks);
    return { ...n, entries: n.entries.map((e) => ({ ...e, labels: labelsRef.current[e.id] ?? e.labels ?? [] })) };
  }, []);

  /** Moves workspace membership and labels from old entry keys to new ones. */
  const migrateKeys = useCallback((mapping: Record<string, string>) => {
    if (!Object.keys(mapping).length) return;
    setWorkspaces((list) => list.map((w) => ({ ...w, entryIds: [...new Set(w.entryIds.map((id) => mapping[id] ?? id))] })));
    setLabels((l) => {
      const next = { ...l };
      for (const [from, to] of Object.entries(mapping)) {
        if (next[from]) {
          next[to] = next[from];
          delete next[from];
        }
      }
      return next;
    });
  }, []);

  // ---------------------------------------------------------------- mutations
  const updateKeystore = useCallback(
    (ks: OpenKeystore) => {
      commit(keystoresRef.current.map((k) => (k.id === ks.id ? { ...ks, dirty: true, updated_at: now() } : k)));
    },
    [commit]
  );

  const addEntries = useCallback(
    (keystoreId: string, entries: KeystoreEntry[]) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks) return [];
      let working: OpenKeystore = { ...ks, entries: [...ks.entries] };
      const added: KeystoreEntry[] = [];
      for (const e of entries) {
        const alias = uniqueAlias(working, e.alias);
        const entry = { ...e, alias, id: entryKey(working, alias), labels: e.labels ?? [] };
        working = { ...working, entries: [entry, ...working.entries] };
        added.push(entry);
      }
      updateKeystore(working);
      return added;
    },
    [updateKeystore]
  );

  const replaceEntry = useCallback(
    (keystoreId: string, entry: KeystoreEntry) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks) return;
      updateKeystore({ ...ks, entries: ks.entries.map((e) => (e.id === entry.id ? { ...entry, id: entryKey(ks, entry.alias) } : e)) });
    },
    [updateKeystore]
  );

  const deleteEntries = useCallback(
    (keystoreId: string, ids: string[]) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks) return;
      updateKeystore({ ...ks, entries: ks.entries.filter((e) => !ids.includes(e.id)) });
    },
    [updateKeystore]
  );

  const renameEntry = useCallback(
    (keystoreId: string, entryId: string, alias: string) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks) return;
      const newId = entryKey(ks, alias);
      updateKeystore({ ...ks, entries: ks.entries.map((e) => (e.id === entryId ? { ...e, alias, id: newId } : e)) });
      migrateKeys({ [entryId]: newId });
    },
    [updateKeystore, migrateKeys]
  );

  const setEntryLabels = useCallback((keystoreId: string, entryId: string, list: string[]) => {
    // Labels are xkeystore metadata (not stored in the keystore file): no dirty flag, no undo.
    setAll(keystoresRef.current.map((k) => (k.id === keystoreId ? { ...k, entries: k.entries.map((e) => (e.id === entryId ? { ...e, labels: list } : e)) } : k)));
    setLabels((l) => {
      const next = { ...l };
      if (list.length) next[entryId] = list;
      else delete next[entryId];
      return next;
    });
  }, [setAll]);

  // ------------------------------------------------------------------- vault
  const refreshVault = useCallback(async () => {
    if (!desktop) return vaultRef.current;
    try {
      const s = await api.vaultStatus();
      setVault(s);
      vaultRef.current = s;
      return s;
    } catch {
      return vaultRef.current;
    }
  }, [desktop]);

  const lockVault = useCallback(async () => {
    await api.vaultLock().catch(() => undefined);
    await refreshVault();
  }, [refreshVault]);

  const rememberPassword = useCallback(
    async (path: string, password: string) => {
      if (!path) return;
      try {
        await api.vaultStoreSecret(passwordSecretId(path), baseName(path), password);
        await refreshVault();
      } catch (err) {
        toast.error(`Could not store the password in the vault: ${errorMessage(err)}`);
      }
    },
    [refreshVault, toast]
  );

  /** After a save, refresh a remembered password if it changed. */
  const syncRememberedPassword = useCallback(async (path: string, password: string) => {
    if (!vaultRef.current.unlocked || !path) return;
    const existing = await api.vaultGetSecret(passwordSecretId(path)).catch(() => null);
    if (existing !== null && existing !== password) {
      await api.vaultStoreSecret(passwordSecretId(path), baseName(path), password).catch(() => undefined);
    }
  }, []);

  // ------------------------------------------------------------- recent files
  const addRecent = useCallback((path: string, format: string) => {
    setRecentFiles((r) => [{ path, name: baseName(path), format, openedAt: now() }, ...r.filter((x) => x.path !== path)].slice(0, 12));
  }, []);

  // --------------------------------------------------------------- open flow
  const installOpened = useCallback(
    (file: KeystoreFile, password: string, sealedId?: string) => {
      const existing = keystoresRef.current.find((k) => k.path === file.path);
      const id = sealedId ?? existing?.id ?? file.id;
      const opened = applyLabels({ ...file, id, dirty: false, sealed: false });
      passwords.current.set(id, password);
      setAll(keystoresRef.current.some((k) => k.id === id) ? keystoresRef.current.map((k) => (k.id === id ? opened : k)) : [...keystoresRef.current, opened]);
      setActiveKeystoreId(id);
      addRecent(file.path, file.format);
      return opened;
    },
    [applyLabels, addRecent, setAll]
  );

  const openPathRef = useRef<(path: string, sealedId?: string) => Promise<void>>(async () => undefined);
  const showNextQueued = useCallback(() => {
    const next = openQueue.current.shift();
    if (next) void openPathRef.current(next);
  }, []);

  const openPath = useCallback(
    async (path: string, sealedId?: string): Promise<void> => {
      try {
        const probe = await api.probeFile(path);
        if (probe.kind === "keystore") {
          const already = keystoresRef.current.find((k) => k.path === path && !k.sealed);
          if (already) {
            setActiveKeystoreId(already.id);
            setTab("keystores");
            toast.info(`${probe.name} is already open.`);
            showNextQueued();
            return;
          }
          // Try a password remembered in the vault first.
          if (vaultRef.current.unlocked) {
            const remembered = await api.vaultGetSecret(passwordSecretId(path)).catch(() => null);
            if (remembered) {
              try {
                const file = await api.openKeystore(path, remembered);
                installOpened(file, remembered, sealedId ?? keystoresRef.current.find((k) => k.path === path)?.id);
                setTab("keystores");
                toast.success(`Opened ${file.name} (${file.entries.length} entries) with the password from your vault.`);
                showNextQueued();
                return;
              } catch {
                /* stale password: fall through to prompting */
              }
            }
          }
          setPendingOpen({ path, name: probe.name, format: probe.keystore_format ?? "", sealedId: sealedId ?? keystoresRef.current.find((k) => k.path === path)?.id });
          return;
        }
        if (probe.kind === "unsupported_keystore") {
          toast.error(`${probe.name}: Bouncy Castle (BKS/UBER/BCFKS) keystores are not supported. Convert it to PKCS#12 with keytool -importkeystore.`);
        } else if (probe.kind === "jar") {
          setJarRequest({ path, nonce: Date.now() });
          setTab("ca_signing");
        } else if (probe.kind !== "unknown") {
          setExamineRequest({ path, nonce: Date.now() });
          setTab("examine");
        } else {
          toast.error(`${probe.name} is not a keystore, certificate, key, CSR, CRL or signature that xkeystore recognises.`);
        }
      } catch (err) {
        toast.error(errorMessage(err));
      }
      showNextQueued();
    },
    [installOpened, toast, showNextQueued]
  );
  openPathRef.current = openPath;

  const openFiles = useCallback(
    async (paths?: string[]) => {
      let list = paths;
      if (!list) {
        const picked = await pickFile("Open keystore or certificate file", [FILTERS.keystores, FILTERS.certificates]).catch((err) => {
          toast.error(errorMessage(err));
          return null;
        });
        if (!picked) return;
        list = [picked];
      }
      if (!list.length) return;
      openQueue.current.push(...list.slice(1));
      await openPath(list[0]);
    },
    [openPath, toast]
  );

  const submitOpenPassword = useCallback(
    async (password: string, remember: boolean) => {
      const p = pendingOpen;
      if (!p) return false;
      try {
        const file = await api.openKeystore(p.path, password);
        installOpened(file, password, p.sealedId);
        setPendingOpen(null);
        setTab("keystores");
        const locked = file.entries.filter((e) => e.locked).length;
        toast.success(`Opened ${file.name}: ${file.entries.length} ${file.entries.length === 1 ? "entry" : "entries"}${locked ? `, ${locked} key(s) need a separate key password` : ""}.`);
        if (remember && vaultRef.current.unlocked) await rememberPassword(p.path, password);
        showNextQueued();
        return true;
      } catch (err) {
        setPendingOpen({ ...p, error: errorMessage(err) });
        return false;
      }
    },
    [pendingOpen, installOpened, toast, rememberPassword, showNextQueued]
  );

  const cancelOpen = useCallback(() => {
    setPendingOpen(null);
    showNextQueued();
  }, [showNextQueued]);

  const unlockSealed = useCallback(
    (keystoreId: string) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (ks?.path) void openPath(ks.path, ks.id);
    },
    [openPath]
  );

  // ------------------------------------------------------------- create/save
  const createKeystore = useCallback(
    (req: NewKeystoreRequest) => {
      const id = `ks-${uid()}`;
      let ks: OpenKeystore = {
        id,
        name: req.name,
        format: req.format,
        path: "",
        description: `${req.format} keystore`,
        password_protected: true,
        created_at: now(),
        updated_at: now(),
        entries: [],
        dirty: true,
        sealed: false,
      };
      if (req.initialEntry) ks = { ...ks, entries: [{ ...req.initialEntry, id: entryKey(ks, req.initialEntry.alias) }] };
      passwords.current.set(id, req.password);
      commit([...keystoresRef.current, ks]);
      setActiveKeystoreId(id);
      setTab("keystores");
      return ks;
    },
    [commit]
  );

  const finishSaved = useCallback(
    (ks: OpenKeystore, path: string, format: KeystoreFormat, password: string) => {
      const name = baseName(path);
      const updated: OpenKeystore = applyLabels({ ...ks, path, name, format, dirty: false, updated_at: now() });
      const mapping: Record<string, string> = {};
      ks.entries.forEach((e, i) => {
        if (e.id !== updated.entries[i].id) mapping[e.id] = updated.entries[i].id;
      });
      migrateKeys(mapping);
      passwords.current.set(ks.id, password);
      // Any other snapshot of this keystore now differs from what is on disk.
      const markDirty = (snap: OpenKeystore[]) => snap.map((k) => (k.id === ks.id ? { ...k, dirty: true } : k));
      setAll(
        keystoresRef.current.map((k) => (k.id === ks.id ? updated : k)),
        historyRef.current.map(markDirty),
        redoRef.current.map(markDirty)
      );
      addRecent(path, format);
      return updated;
    },
    [applyLabels, migrateKeys, addRecent, setAll]
  );

  const save = useCallback(
    async (keystoreId: string, opts?: { saveAs?: boolean; then?: () => void }) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks || ks.sealed) return;
      const password = passwords.current.get(keystoreId);
      if (opts?.saveAs || !ks.path || !password) {
        setPendingSave({ keystoreId, mode: opts?.saveAs ? "save-as" : "first-save", then: opts?.then });
        return;
      }
      try {
        const res = await api.saveKeystore(ks, ks.path, password, ks.format);
        finishSaved(ks, res.path, res.format, password);
        void syncRememberedPassword(res.path, password);
        toast.success(`Saved ${res.name} (${res.byte_length.toLocaleString()} bytes).`);
        opts?.then?.();
      } catch (err) {
        toast.error(`Could not save ${ks.name}: ${errorMessage(err)}`);
      }
    },
    [finishSaved, toast, syncRememberedPassword]
  );

  const completeSave = useCallback(
    async ({ path, password, format, remember }: { path: string; password: string; format: KeystoreFormat; remember: boolean }) => {
      const req = pendingSave;
      const ks = req && keystoresRef.current.find((k) => k.id === req.keystoreId);
      if (!req || !ks) return false;
      const other = keystoresRef.current.find((k) => k.path === path && k.id !== ks.id && !k.sealed);
      if (other) {
        toast.error(`${baseName(path)} is open in another tab. Close it first or choose a different file.`);
        return false;
      }
      try {
        const res = await api.saveKeystore(ks, path, password, format);
        finishSaved(ks, res.path, res.format, password);
        setPendingSave(null);
        toast.success(`Saved ${res.name} as ${res.format} (${res.byte_length.toLocaleString()} bytes).`);
        if (remember && vaultRef.current.unlocked) await rememberPassword(res.path, password);
        else void syncRememberedPassword(res.path, password);
        req.then?.();
        return true;
      } catch (err) {
        toast.error(`Could not save: ${errorMessage(err)}`);
        return false;
      }
    },
    [pendingSave, finishSaved, toast, rememberPassword, syncRememberedPassword]
  );

  const closeKeystore = useCallback(
    async (keystoreId: string) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks) return true;
      const remove = () => {
        const next = keystoresRef.current.filter((k) => k.id !== keystoreId);
        const drop = (snap: OpenKeystore[]) => snap.filter((k) => k.id !== keystoreId);
        setAll(next, historyRef.current.map(drop), redoRef.current.map(drop));
        passwords.current.delete(keystoreId);
        setActiveKeystoreId((cur) => (cur === keystoreId ? next[0]?.id ?? null : cur));
      };
      if (ks.dirty) {
        const choice = await confirm({
          title: `Save changes to ${ks.name}?`,
          message: "Your changes will be lost if you close without saving.",
          confirmLabel: "Save",
          alternateLabel: "Don't save",
        });
        if (choice === false) return false;
        if (choice === true) {
          await save(keystoreId, { then: remove });
          return !keystoresRef.current.some((k) => k.id === keystoreId);
        }
      }
      remove();
      return true;
    },
    [confirm, save, setAll]
  );

  // --------------------------------------------------------------- workspaces
  const saveWorkspace = useCallback((ws: Workspace) => {
    setWorkspaces((list) => (list.some((w) => w.id === ws.id) ? list.map((w) => (w.id === ws.id ? ws : w)) : [ws, ...list]));
    setActiveWorkspaceId(ws.id);
  }, []);

  const deleteWorkspace = useCallback((id: string) => {
    setWorkspaces((list) => {
      const next = list.filter((w) => w.id !== id);
      setActiveWorkspaceId((cur) => (cur === id ? next[0]?.id ?? null : cur));
      return next;
    });
  }, []);

  const toggleWorkspaceEntry = useCallback((workspaceId: string, entryId: string) => {
    setWorkspaces((list) =>
      list.map((w) =>
        w.id !== workspaceId
          ? w
          : { ...w, updated_at: now(), entryIds: w.entryIds.includes(entryId) ? w.entryIds.filter((x) => x !== entryId) : [...w.entryIds, entryId] }
      )
    );
  }, []);

  // ------------------------------------------------------- vault integration
  const requestVaultUnlock = useCallback((after?: () => void) => {
    afterVaultUnlock.current = after ?? null;
    setVaultPromptOpen(true);
  }, []);

  const closeVaultPrompt = useCallback(() => {
    afterVaultUnlock.current = null;
    setVaultPromptOpen(false);
  }, []);

  const onVaultUnlocked = useCallback(async () => {
    setVaultPromptOpen(false);
    const status = await refreshVault();
    const cb = afterVaultUnlock.current;
    afterVaultUnlock.current = null;
    cb?.();
    if (!status.unlocked) return;
    // Open every sealed keystore whose password is remembered.
    let opened = 0;
    for (const ks of keystoresRef.current.filter((k) => k.sealed && k.path)) {
      const pw = await api.vaultGetSecret(passwordSecretId(ks.path)).catch(() => null);
      if (!pw) continue;
      try {
        installOpened(await api.openKeystore(ks.path, pw), pw, ks.id);
        opened++;
      } catch {
        /* leave sealed; the user can unlock manually */
      }
    }
    if (opened) toast.success(`Unlocked ${opened} keystore${opened === 1 ? "" : "s"} with passwords from your vault.`);
  }, [refreshVault, installOpened, toast]);

  // ---------------------------------------------------------- settings/reset
  const updateSettings = useCallback((patch: Partial<Settings>) => setSettings((s) => ({ ...s, ...patch })), []);

  const clearRecentFiles = useCallback(() => setRecentFiles([]), []);

  const resetAppData = useCallback(async () => {
    setWorkspaces([]);
    setActiveWorkspaceId(null);
    setLabels({});
    setRecentFiles([]);
    setSettings(DEFAULT_SETTINGS);
    await api.saveAppState(null).catch(() => undefined);
  }, []);

  // -------------------------------------------------------------- bootstrap
  useEffect(() => {
    if (!desktop) {
      setReady(true);
      return;
    }
    (async () => {
      try {
        const info = await api.appInfo();
        setAppInfo(info);
        if (info.e2e) allowDialogStub();
        await refreshVault();
        const raw = (await api.loadAppState()) as Partial<PersistedState> | null;
        if (raw && raw.version === 1) {
          const s = { ...DEFAULT_SETTINGS, ...(raw.settings ?? {}) };
          setSettings(s);
          setWorkspaces(raw.workspaces ?? []);
          setActiveWorkspaceId(raw.activeWorkspaceId ?? raw.workspaces?.[0]?.id ?? null);
          setLabels(raw.labels ?? {});
          labelsRef.current = raw.labels ?? {};
          setRecentFiles(raw.recentFiles ?? []);
          if (s.restoreSession && raw.keystores?.length) {
            const sealed: OpenKeystore[] = raw.keystores.map((k) => ({
              id: k.id,
              name: k.name,
              format: k.format,
              path: k.path,
              description: `${k.format} keystore`,
              password_protected: true,
              created_at: "",
              updated_at: "",
              entries: [],
              dirty: false,
              sealed: true,
            }));
            setAll(sealed);
            setActiveKeystoreId(raw.activeKeystoreId && sealed.some((k) => k.id === raw.activeKeystoreId) ? raw.activeKeystoreId : sealed[0].id);
          }
        }
      } catch (err) {
        toast.error(`Could not restore the previous session: ${errorMessage(err)}`);
      } finally {
        setReady(true);
      }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // -------------------------------------------------------------- persistence
  const persistTimer = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (!ready || !desktop) return;
    window.clearTimeout(persistTimer.current);
    persistTimer.current = window.setTimeout(() => {
      const state: PersistedState = {
        version: 1,
        keystores: keystores.filter((k) => k.path).map((k) => ({ id: k.id, path: k.path, name: k.name, format: k.format })),
        activeKeystoreId,
        recentFiles,
        workspaces,
        activeWorkspaceId,
        labels,
        settings,
      };
      api.saveAppState(state).catch(() => undefined);
    }, 400);
  }, [ready, desktop, version, activeKeystoreId, recentFiles, workspaces, activeWorkspaceId, labels, settings]); // eslint-disable-line react-hooks/exhaustive-deps

  // ------------------------------------------------------- vault auto-lock
  const lastActivity = useRef(Date.now());
  useEffect(() => {
    const bump = () => (lastActivity.current = Date.now());
    window.addEventListener("mousemove", bump);
    window.addEventListener("keydown", bump);
    const timer = window.setInterval(() => {
      const mins = settingsRef.current.autoLockMinutes;
      if (mins > 0 && vaultRef.current.unlocked && Date.now() - lastActivity.current > mins * 60_000) {
        void lockVault().then(() => toast.info("The vault was locked after a period of inactivity."));
      }
    }, 15_000);
    return () => {
      window.removeEventListener("mousemove", bump);
      window.removeEventListener("keydown", bump);
      window.clearInterval(timer);
    };
  }, [lockVault, toast]);

  // ------------------------------------------------- unsaved-changes guard
  useEffect(() => {
    if (!desktop) return;
    let unlisten: (() => void) | undefined;
    let closing = false;
    (async () => {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      const win = getCurrentWindow();
      unlisten = await win.onCloseRequested(async (event) => {
        if (closing) return;
        const dirty = keystoresRef.current.filter((k) => k.dirty);
        if (!dirty.length) return;
        event.preventDefault();
        const ok = await confirm({
          title: "Quit with unsaved changes?",
          message: `Unsaved changes in ${dirty.map((k) => k.name).join(", ")} will be lost.`,
          confirmLabel: "Quit without saving",
          danger: true,
        });
        if (ok === true) {
          closing = true;
          await win.destroy();
        }
      });
    })();
    return () => unlisten?.();
  }, [desktop, confirm]);

  const activeKeystore = keystores.find((k) => k.id === activeKeystoreId) ?? keystores[0] ?? null;

  const value: Store = {
    ready,
    desktop,
    appInfo,
    tab,
    setTab,
    examineRequest,
    examine: (input) => {
      setExamineRequest({ ...input, nonce: Date.now() });
      setTab("examine");
    },
    jarRequest,
    keystores,
    activeKeystoreId: activeKeystore?.id ?? null,
    activeKeystore,
    selectKeystore: setActiveKeystoreId,
    canUndo: historyRef.current.length > 0,
    canRedo: redoRef.current.length > 0,
    undo,
    redo,
    updateKeystore,
    addEntries,
    replaceEntry,
    deleteEntries,
    renameEntry,
    setEntryLabels,
    hasPassword: (id) => passwords.current.has(id),
    getPassword: (id) => passwords.current.get(id),
    setPassword: (id, pw) => {
      passwords.current.set(id, pw);
      const ks = keystoresRef.current.find((k) => k.id === id);
      if (ks) updateKeystore(ks);
    },
    openFiles,
    pendingOpen,
    submitOpenPassword,
    cancelOpen,
    unlockSealed,
    createKeystore,
    newKeystoreOpen,
    setNewKeystoreOpen,
    save,
    pendingSave,
    completeSave,
    cancelSave: () => setPendingSave(null),
    closeKeystore,
    recentFiles,
    clearRecentFiles,
    workspaces,
    activeWorkspaceId,
    setActiveWorkspaceId,
    saveWorkspace,
    deleteWorkspace,
    toggleWorkspaceEntry,
    vault,
    refreshVault,
    lockVault,
    vaultPromptOpen,
    requestVaultUnlock,
    closeVaultPrompt,
    onVaultUnlocked,
    settings,
    updateSettings,
    resetAppData,
  };

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
};
