import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { api, classifyError, errorMessage, isDesktop, passwordSecretId } from "../lib/api";
import { allowDialogStub, baseName, pickFile, FILTERS } from "../lib/files";
import { canonicalAlias, entryIdRemap, entryKey, isKeyLocked, keyPasswordMatches, normalizeEntries, uniqueAlias } from "../lib/keystore";
import type { ConverterId } from "../lib/convert";
import { setThresholds } from "../lib/metrics";
import { applyTheme, cachedThemePreference, isThemePreference, watchSystemTheme, type ThemePreference } from "../lib/theme";
import { isCertificateBundle, isCertificateProbe, mergeCertificates, persistCertificates, toOpenCertificates, type PersistedCertificate } from "../lib/certificates";
import { useConfirm, useToast } from "../components/ui";
import type { AppInfo, DataSource, KeystoreEntry, KeystoreFile, KeystoreFormat, OpenCertificate, OpenKeystore, Pkcs12Profile, TabType, VaultStatus, Workspace } from "../types/crypto";

export interface Settings {
  /** Light, dark (black) or follow the operating system. */
  theme: ThemePreference;
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
  /** PEM trust anchors used to decide whether a timestamp is trusted. Empty skips the check. */
  tsaTrustPem: string;
  /** Key pairs open locked; their key password must be entered before they can be used. */
  requireKeyUnlock: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  theme: "system",
  autoLockMinutes: 15,
  criticalDays: 30,
  warningDays: 90,
  defaultFormat: "PKCS12",
  rememberPasswordsByDefault: false,
  terminalTimeoutSecs: 120,
  restoreSession: true,
  tsaUrl: "",
  timestampByDefault: false,
  tsaTrustPem: "",
  requireKeyUnlock: true,
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
  /** The Certificates page. Optional: state saved before it existed has none. */
  certificates?: PersistedCertificate[];
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

/** A request to unlock one or more keys, raised by any view that needs a locked key. */
export interface PendingKeyUnlock {
  keystoreId: string;
  entryIds: string[];
  /** Runs once every requested key is unlocked. */
  then?: () => void;
}

export interface UnlockOutcome {
  unlocked: number;
  remaining: number;
  error?: string;
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
  convertMode: ConverterId | null;
  /** Opens the Convert page on one converter, or on the overview with null. */
  openConverter: (id: ConverterId | null) => void;
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
  /** True when "Remember the password" was ticked while creating this keystore, so its first save pre-selects it. */
  rememberRequested: (keystoreId: string) => boolean;
  // key access
  /** True while the entry's key cannot be used: see isKeyLocked in lib/keystore. */
  isKeyLocked: (entry: KeystoreEntry) => boolean;
  /** Runs `then` right away when every key is usable, otherwise asks for the key password first. */
  ensureKeyAccess: (keystoreId: string, entryIds: string[], then?: () => void) => void;
  pendingKeyUnlock: PendingKeyUnlock | null;
  cancelKeyUnlock: () => void;
  /** Unlocks the locked keys among `entryIds` that `password` opens. */
  unlockKeys: (keystoreId: string, entryIds: string[], password: string) => Promise<UnlockOutcome>;
  /**
   * The keystores as they are right now. A callback passed to `ensureKeyAccess` runs after the
   * unlock, but the entries it closed over were read before it, so it must look them up again here.
   */
  currentKeystores: () => OpenKeystore[];
  /** Locks key pairs again (all of the keystore's when `entryIds` is omitted). */
  lockKeys: (keystoreId: string, entryIds?: string[]) => void;
  // file workflows
  openFiles: (paths?: string[]) => Promise<void>;
  pendingOpen: PendingOpen | null;
  submitOpenPassword: (password: string, remember: boolean, keyPasswords?: Record<string, string>) => Promise<boolean>;
  cancelOpen: () => void;
  unlockSealed: (keystoreId: string) => void;
  createKeystore: (req: NewKeystoreRequest) => OpenKeystore;
  newKeystoreOpen: boolean;
  setNewKeystoreOpen: (open: boolean) => void;
  buildPkcs12Open: boolean;
  setBuildPkcs12Open: (open: boolean) => void;
  save: (keystoreId: string, opts?: { saveAs?: boolean; then?: () => void }) => Promise<void>;
  pendingSave: PendingSave | null;
  completeSave: (args: { path: string; password: string; format: KeystoreFormat; remember: boolean; mac?: Pkcs12Profile; force?: boolean }) => Promise<boolean>;
  cancelSave: () => void;
  closeKeystore: (keystoreId: string) => Promise<boolean>;
  recentFiles: RecentFile[];
  clearRecentFiles: () => void;
  // certificates
  certificates: OpenCertificate[];
  /**
   * Reads the certificates in a file or text and lists each on the Certificates page once.
   * Rejects when the data holds no certificate.
   */
  addCertificates: (data: DataSource, origin: { path?: string; source: string }) => Promise<{ added: OpenCertificate[]; duplicates: OpenCertificate[] }>;
  /** Takes certificates off the page (their files are never touched). Returns a function that puts them back. */
  removeCertificates: (ids: string[]) => () => void;
  /** The certificate to highlight on the Certificates page: the one opened last. */
  certificateFocus: string | null;
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
  const [convertMode, setConvertMode] = useState<ConverterId | null>(null);

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
  /**
   * Applies `fn` to one keystore in the current state and in every undo/redo snapshot, without
   * adding an undo step. For changes that are not edits (opening a file, unlocking a key), which
   * must survive undo: otherwise undoing an earlier edit restores a snapshot from before them.
   */
  const patchEverywhere = useCallback(
    (keystoreId: string, fn: (ks: OpenKeystore) => OpenKeystore) => {
      const patch = (snap: OpenKeystore[]) => snap.map((k) => (k.id === keystoreId ? fn(k) : k));
      setAll(patch(keystoresRef.current), historyRef.current.map(patch), redoRef.current.map(patch));
    },
    [setAll]
  );
  const [activeKeystoreId, setActiveKeystoreId] = useState<string | null>(null);
  const passwords = useRef(new Map<string, string>());
  // Keystores created with "Remember the password" ticked; their first save pre-selects it.
  const rememberOnSave = useRef(new Set<string>());
  // Key pairs unlocked this session, by entry id. Never persisted.
  const [unlockedKeys, setUnlockedKeys] = useState<ReadonlySet<string>>(() => new Set());
  const unlockedKeysRef = useRef(unlockedKeys);
  unlockedKeysRef.current = unlockedKeys;
  const [pendingKeyUnlock, setPendingKeyUnlock] = useState<PendingKeyUnlock | null>(null);
  const markUnlocked = useCallback((ids: string[]) => {
    if (ids.length) setUnlockedKeys((cur) => new Set([...cur, ...ids]));
  }, []);
  const forgetUnlocked = useCallback((ids: string[]) => {
    if (!ids.length) return;
    setUnlockedKeys((cur) => {
      if (!ids.some((id) => cur.has(id))) return cur;
      const next = new Set(cur);
      ids.forEach((id) => next.delete(id));
      return next;
    });
  }, []);

  const [pendingOpen, setPendingOpenState] = useState<PendingOpen | null>(null);
  // Read synchronously by openFiles: files dropped while a password prompt is up wait their turn
  // instead of replacing the prompt (which would lose the file it was asking about).
  const pendingOpenRef = useRef<PendingOpen | null>(null);
  const setPendingOpen = useCallback((p: PendingOpen | null) => {
    pendingOpenRef.current = p;
    setPendingOpenState(p);
  }, []);
  const openQueue = useRef<string[]>([]);
  const opening = useRef(false);
  const [pendingSave, setPendingSave] = useState<PendingSave | null>(null);
  const [newKeystoreOpen, setNewKeystoreOpen] = useState(false);
  const [buildPkcs12Open, setBuildPkcs12Open] = useState(false);
  const [recentFiles, setRecentFiles] = useState<RecentFile[]>([]);
  // Read and written synchronously through the ref, so two files dropped together both land.
  const [certificates, setCertificatesState] = useState<OpenCertificate[]>([]);
  const certificatesRef = useRef<OpenCertificate[]>([]);
  const setCertificates = useCallback((list: OpenCertificate[]) => {
    certificatesRef.current = list;
    setCertificatesState(list);
  }, []);
  const [certificateFocus, setCertificateFocus] = useState<string | null>(null);

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

  // The theme starts from the copy cached for the first paint, so it holds until saved settings load
  // (and in the browser preview, which has no saved settings).
  const [settings, setSettings] = useState<Settings>(() => ({ ...DEFAULT_SETTINGS, theme: cachedThemePreference() }));
  const settingsRef = useRef(settings);
  settingsRef.current = settings;

  useEffect(() => setThresholds(settings.criticalDays, settings.warningDays), [settings.criticalDays, settings.warningDays]);

  // Theme. Not before the saved settings are in: main.tsx already applied the cached choice, and
  // the defaults would switch a dark window to the system theme for a moment. The native window
  // (title bar, menus) follows too; null lets it follow the OS.
  useEffect(() => {
    if (!ready) return;
    const pref = settings.theme;
    applyTheme(pref);
    if (desktop) {
      void import("@tauri-apps/api/window")
        .then(({ getCurrentWindow }) => getCurrentWindow().setTheme(pref === "system" ? null : pref))
        .catch(() => undefined);
    }
    return pref === "system" ? watchSystemTheme(() => applyTheme("system")) : undefined;
  }, [ready, desktop, settings.theme]);

  // ------------------------------------------------------------------ history
  const commit = useCallback(
    (next: OpenKeystore[]) => setAll(next, [...historyRef.current.slice(-(HISTORY_LIMIT - 1)), keystoresRef.current], []),
    [setAll]
  );

  // --------------------------------------------------------------- labels/ids
  const applyLabels = useCallback((ks: OpenKeystore): OpenKeystore => {
    const n = normalizeEntries(ks);
    return { ...n, entries: n.entries.map((e) => ({ ...e, labels: labelsRef.current[e.id] ?? e.labels ?? [] })) };
  }, []);

  /** Moves workspace membership and labels from old entry keys to new ones. */
  const migrateKeys = useCallback((mapping: Record<string, string>) => {
    if (!Object.keys(mapping).length) return;
    setUnlockedKeys((cur) => (Object.keys(mapping).some((id) => cur.has(id)) ? new Set([...cur].map((id) => mapping[id] ?? id)) : cur));
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

  // Undo and redo swap whole snapshots. Entry metadata kept outside them (labels, workspaces,
  // unlocked keys) follows any entry whose id changed, e.g. when a rename is undone.
  const swapTo = useCallback(
    (next: OpenKeystore[], history: OpenKeystore[][], redoList: OpenKeystore[][]) => {
      const mapping = entryIdRemap(keystoresRef.current, next);
      setAll(next, history, redoList);
      migrateKeys(mapping);
    },
    [setAll, migrateKeys]
  );

  const undo = useCallback(() => {
    const h = historyRef.current;
    if (!h.length) return;
    swapTo(h[h.length - 1], h.slice(0, -1), [keystoresRef.current, ...redoRef.current]);
  }, [swapTo]);

  const redo = useCallback(() => {
    const r = redoRef.current;
    if (!r.length) return;
    swapTo(r[0], [...historyRef.current, keystoresRef.current], r.slice(1));
  }, [swapTo]);

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
        const alias = uniqueAlias(working, canonicalAlias(ks.format, e.alias));
        const entry = { ...e, alias, id: entryKey(working, alias), labels: e.labels ?? [] };
        working = { ...working, entries: [entry, ...working.entries] };
        added.push(entry);
      }
      updateKeystore(working);
      // The user just created, imported or pasted these, so their keys are usable.
      markUnlocked(added.map((e) => e.id));
      // Labels given when the entry was made (e.g. in "Generate key pair") are Keystore Studio metadata:
      // they live in the label map, which is what is persisted and survives a reopen.
      const labelled = added.filter((e) => e.labels.length);
      if (labelled.length) setLabels((l) => ({ ...l, ...Object.fromEntries(labelled.map((e) => [e.id, e.labels])) }));
      return added;
    },
    [updateKeystore, markUnlocked]
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
    // Labels are Keystore Studio metadata (not stored in the keystore file): no dirty flag, no undo.
    // Every snapshot gets them too, or undoing an earlier edit would bring back the old labels.
    patchEverywhere(keystoreId, (k) => ({ ...k, entries: k.entries.map((e) => (e.id === entryId ? { ...e, labels: list } : e)) }));
    setLabels((l) => {
      const next = { ...l };
      if (list.length) next[entryId] = list;
      else delete next[entryId];
      return next;
    });
  }, [patchEverywhere]);

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

  // ------------------------------------------------------------ certificates
  const addCertificates = useCallback(
    async (data: DataSource, origin: { path?: string; source: string }) => {
      // The engine reads PEM (one or many), DER or a PKCS#7 bundle, and orders a chain leaf first.
      const entries = await api.importTrustedCertificates("certificate", data, []);
      const incoming = toOpenCertificates(entries, { path: origin.path ?? "", source: origin.source, openedAt: now() });
      const { list, added, duplicates } = mergeCertificates(certificatesRef.current, incoming);
      if (added.length) setCertificates(list);
      setCertificateFocus(added[0]?.id ?? duplicates[0]?.id ?? null);
      return { added, duplicates };
    },
    [setCertificates]
  );

  const removeCertificates = useCallback(
    (ids: string[]) => {
      const before = certificatesRef.current;
      const removed = before.map((c, index) => ({ c, index })).filter(({ c }) => ids.includes(c.id));
      setCertificates(before.filter((c) => !ids.includes(c.id)));
      // Undo puts each one back where it was, unless it was opened again in the meantime.
      return () => {
        const next = [...certificatesRef.current];
        for (const { c, index } of removed) if (!next.some((x) => x.id === c.id)) next.splice(Math.min(index, next.length), 0, c);
        setCertificates(next);
      };
    },
    [setCertificates]
  );

  /** Lists a certificate file on the Certificates page. */
  const openCertificateFile = useCallback(
    async (path: string, name: string) => {
      const { added, duplicates } = await addCertificates({ path }, { path, source: name });
      setTab("certificates");
      const count = (n: number) => `${n} certificate${n === 1 ? "" : "s"}`;
      if (!added.length) toast.info(duplicates.length === 1 ? `${name} is already listed under Certificates.` : `The certificates in ${name} are already listed.`);
      else toast.success(`Opened ${name}: ${count(added.length)}${duplicates.length ? ` (${duplicates.length} already listed)` : ""}.`);
    },
    [addCertificates, toast]
  );

  // --------------------------------------------------------------- open flow
  const installOpened = useCallback(
    (file: KeystoreFile, password: string, sealedId?: string) => {
      const existing = keystoresRef.current.find((k) => k.path === file.path);
      const id = sealedId ?? existing?.id ?? file.id;
      const opened = applyLabels({ ...file, id, dirty: false, sealed: false });
      passwords.current.set(id, password);
      // A freshly read file starts with every key pair locked.
      forgetUnlocked(opened.entries.map((e) => e.id));
      // Opening a file is not an edit, so it is not an undo step. It is put into every undo/redo
      // snapshot as well: undoing an edit made before the open must not close the file again, or
      // bring back the locked placeholder of a keystore restored from the last session.
      const place = (snap: OpenKeystore[]) => (snap.some((k) => k.id === id) ? snap.map((k) => (k.id === id ? opened : k)) : [...snap, opened]);
      setAll(place(keystoresRef.current), historyRef.current.map(place), redoRef.current.map(place));
      setActiveKeystoreId(id);
      addRecent(file.path, file.format);
      // Entries the app cannot model are not silently dropped: say so once, when the file opens.
      if (file.omitted_entries) {
        toast.info(`${file.name}: ${file.omitted_entries} ${file.omitted_entries === 1 ? "entry is" : "entries are"} not shown. Saving over this file would drop ${file.omitted_entries === 1 ? "it" : "them"}; the Keystores page explains why.`);
      }
      return opened;
    },
    [applyLabels, addRecent, setAll, forgetUnlocked, toast]
  );

  const openPathRef = useRef<(path: string, sealedId?: string) => Promise<void>>(async () => undefined);
  const showNextQueued = useCallback(() => {
    opening.current = false;
    const next = openQueue.current.shift();
    if (next) void openPathRef.current(next);
  }, []);

  const openPath = useCallback(
    async (path: string, sealedId?: string): Promise<void> => {
      opening.current = true;
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
          opening.current = false;
          return;
        }
        if (probe.kind === "apk") {
          toast.error(`${probe.name} is an Android APK. APK Signature Scheme v2/v3 is not a JAR signature, so it is not opened for signing.`);
        } else if (probe.kind === "jar") {
          setJarRequest({ path, nonce: Date.now() });
          setTab("ca_signing");
        } else if (isCertificateProbe(probe.kind) || (probe.kind === "pkcs7" && (await api.examineData({ path }).then(isCertificateBundle, () => false)))) {
          // Certificates are listed on their own page; a PKCS#7 signature still goes to Examine.
          await openCertificateFile(path, probe.name);
        } else if (probe.kind !== "unknown") {
          setExamineRequest({ path, nonce: Date.now() });
          setTab("examine");
        } else {
          toast.error(`${probe.name} is not a keystore, certificate, key, CSR, CRL or signature that Keystore Studio recognises.`);
        }
      } catch (err) {
        toast.error(errorMessage(err));
      }
      showNextQueued();
    },
    [installOpened, toast, showNextQueued, openCertificateFile]
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
      if (pendingOpenRef.current || opening.current) {
        openQueue.current.push(...list);
        return;
      }
      openQueue.current.push(...list.slice(1));
      await openPath(list[0]);
    },
    [openPath, toast]
  );

  const submitOpenPassword = useCallback(
    async (password: string, remember: boolean, keyPasswords?: Record<string, string>) => {
      const p = pendingOpen;
      if (!p) return false;
      try {
        const file = await api.openKeystore(p.path, password, keyPasswords);
        installOpened(file, password, p.sealedId);
        setPendingOpen(null);
        setTab("keystores");
        const locked = file.entries.filter((e) => e.locked).length;
        toast.success(`Opened ${file.name}: ${file.entries.length} ${file.entries.length === 1 ? "entry" : "entries"}${locked ? `, ${locked} key(s) need a separate key password` : ""}.`);
        if (remember && vaultRef.current.unlocked) await rememberPassword(p.path, password);
        showNextQueued();
        return true;
      } catch (err) {
        const classified = classifyError(err);
        setPendingOpen({ ...p, error: classified.kind === "wrong-password" ? "That password does not open this keystore." : classified.message });
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
      if (!ks?.path) return;
      // Another file is being opened or waits for its password: this one follows it.
      if (pendingOpenRef.current || opening.current) openQueue.current.push(ks.path);
      else void openPath(ks.path, ks.id);
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
      if (req.initialEntry) {
        const alias = canonicalAlias(req.format, req.initialEntry.alias);
        ks = { ...ks, entries: [{ ...req.initialEntry, alias, id: entryKey(ks, alias) }] };
      }
      passwords.current.set(id, req.password);
      if (req.remember) rememberOnSave.current.add(id);
      commit([...keystoresRef.current, ks]);
      markUnlocked(ks.entries.map((e) => e.id));
      setActiveKeystoreId(id);
      setTab("keystores");
      return ks;
    },
    [commit, markUnlocked]
  );

  const finishSaved = useCallback(
    (ks: OpenKeystore, path: string, format: KeystoreFormat, password: string, mtimeMs?: number | null) => {
      const name = baseName(path);
      const updated: OpenKeystore = applyLabels({ ...ks, path, name, format, dirty: false, updated_at: now(), source_mtime_ms: mtimeMs ?? Date.now() });
      const mapping: Record<string, string> = {};
      ks.entries.forEach((e, i) => {
        if (e.id !== updated.entries[i].id) mapping[e.id] = updated.entries[i].id;
      });
      migrateKeys(mapping);
      passwords.current.set(ks.id, password);
      // Any other snapshot of this keystore now differs from what is on disk. It also takes the new
      // file, name and format: undoing an edit after "Save as" must not point the keystore back at
      // the old file, where the next Ctrl+S would write.
      const rebase = (snap: OpenKeystore[]) =>
        snap.map((k) => (k.id === ks.id ? normalizeEntries({ ...k, path, name, format, source_mtime_ms: updated.source_mtime_ms, dirty: true }) : k));
      // An edit made while the save was running is not in the file: keep it, still unsaved, rather
      // than replacing it with the snapshot that was written.
      const current = keystoresRef.current.find((k) => k.id === ks.id);
      const editedMeanwhile = !!current && current !== ks;
      setAll(
        editedMeanwhile ? rebase(keystoresRef.current) : keystoresRef.current.map((k) => (k.id === ks.id ? updated : k)),
        historyRef.current.map(rebase),
        redoRef.current.map(rebase)
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
        finishSaved(ks, res.path, res.format, password, res.mtime_ms);
        void syncRememberedPassword(res.path, password);
        toast.success(`Saved ${res.name} (${res.byte_length.toLocaleString()} bytes).`);
        opts?.then?.();
      } catch (err) {
        const classified = classifyError(err);
        if (classified.kind === "changed-on-disk") {
          const override = await confirm({
            title: `Replace ${ks.name} on disk?`,
            message: classified.message,
            confirmLabel: "Override",
            danger: true,
          });
          if (override) {
            try {
              const res = await api.saveKeystore(ks, ks.path, password, ks.format, null, true);
              finishSaved(ks, res.path, res.format, password, res.mtime_ms);
              void syncRememberedPassword(res.path, password);
              toast.success(`Saved ${res.name} (${res.byte_length.toLocaleString()} bytes).`);
              opts?.then?.();
            } catch (err2) {
              toast.error(`Could not save ${ks.name}: ${errorMessage(err2)}`);
            }
          }
          return;
        }
        toast.error(`Could not save ${ks.name}: ${errorMessage(err)}`);
      }
    },
    [finishSaved, toast, syncRememberedPassword, confirm]
  );

  const completeSave = useCallback(
    async ({ path, password, format, remember, mac, force }: { path: string; password: string; format: KeystoreFormat; remember: boolean; mac?: Pkcs12Profile; force?: boolean }) => {
      const req = pendingSave;
      const ks = req && keystoresRef.current.find((k) => k.id === req.keystoreId);
      if (!req || !ks) return false;
      const other = keystoresRef.current.find((k) => k.path === path && k.id !== ks.id && !k.sealed);
      if (other) {
        toast.error(`${baseName(path)} is open in another tab. Close it first or choose a different file.`);
        return false;
      }
      try {
        const res = await api.saveKeystore(ks, path, password, format, mac, force);
        finishSaved(ks, res.path, res.format, password, res.mtime_ms);
        rememberOnSave.current.delete(ks.id);
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
        forgetUnlocked(ks.entries.map((e) => e.id));
        setActiveKeystoreId((cur) => (cur === keystoreId ? next[0]?.id ?? null : cur));
        rememberOnSave.current.delete(keystoreId);
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
    [confirm, save, setAll, forgetUnlocked]
  );

  // --------------------------------------------------------------- key access
  const keyLocked = useCallback((e: KeystoreEntry) => isKeyLocked(e, unlockedKeys, settings.requireKeyUnlock), [unlockedKeys, settings.requireKeyUnlock]);

  const ensureKeyAccess = useCallback(
    (keystoreId: string, entryIds: string[], then?: () => void) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      const locked = (ks?.entries ?? []).filter((e) => entryIds.includes(e.id) && keyLocked(e));
      if (!locked.length) {
        then?.();
        return;
      }
      setPendingKeyUnlock({ keystoreId, entryIds: locked.map((e) => e.id), then });
    },
    [keyLocked]
  );

  const unlockKeys = useCallback(
    async (keystoreId: string, entryIds: string[], password: string): Promise<UnlockOutcome> => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks) return { unlocked: 0, remaining: entryIds.length, error: "The keystore is no longer open." };
      const storePw = passwords.current.get(keystoreId);
      const targets = ks.entries.filter((e) => entryIds.includes(e.id) && isKeyLocked(e, unlockedKeys, settingsRef.current.requireKeyUnlock));
      const done: string[] = [];
      // Keys the engine already decrypted: check the password against the one that protects them.
      for (const e of targets.filter((t) => !t.locked)) if (keyPasswordMatches(e, password, storePw)) done.push(e.id);
      // Keys with their own password: read the file again with it.
      const sealed = targets.filter((t) => t.locked);
      let error: string | undefined;
      if (sealed.length) {
        if (!ks.path || !storePw) {
          error = "Save the keystore first.";
        } else {
          try {
            const reread = await api.openKeystore(ks.path, storePw, Object.fromEntries(sealed.map((e) => [e.alias, password])));
            const fresh = new Map<string, KeystoreEntry>();
            for (const e of sealed) {
              const match = reread.entries.find((x) => x.alias.toLowerCase() === e.alias.toLowerCase());
              if (match && !match.locked) fresh.set(e.id, { ...match, id: e.id, alias: e.alias, labels: e.labels });
            }
            if (fresh.size && keystoresRef.current.some((k) => k.id === keystoreId)) {
              // Unlocking reads the key; it changes nothing that a save would write differently
              // (the key keeps its own password). So it is not an edit: no unsaved-changes mark and
              // no undo step. Every snapshot that still holds the locked copy gets the key too, so
              // undoing an earlier edit does not lock it again.
              patchEverywhere(keystoreId, (k) => ({
                ...k,
                entries: k.entries.map((e) => {
                  const f = e.locked ? fresh.get(e.id) : undefined;
                  return f ? { ...f, labels: e.labels } : e;
                }),
              }));
              done.push(...fresh.keys());
            }
          } catch (err) {
            error = classifyError(err).kind === "wrong-password" ? "The keystore password no longer opens this file." : errorMessage(err);
          }
        }
      }
      markUnlocked(done);
      const remaining = targets.length - done.length;
      if (!done.length && !error) error = targets.length === 1 ? "Incorrect key password." : "That password does not unlock any of these keys.";
      return { unlocked: done.length, remaining, error: done.length ? undefined : error };
    },
    [unlockedKeys, markUnlocked, patchEverywhere]
  );

  const lockKeys = useCallback(
    (keystoreId: string, entryIds?: string[]) => {
      const ks = keystoresRef.current.find((k) => k.id === keystoreId);
      if (!ks) return;
      forgetUnlocked(ks.entries.filter((e) => e.entry_type === "KeyPair" && (!entryIds || entryIds.includes(e.id))).map((e) => e.id));
    },
    [forgetUnlocked]
  );

  // --------------------------------------------------------------- workspaces
  const saveWorkspace = useCallback((ws: Workspace) => {
    setWorkspaces((list) => (list.some((w) => w.id === ws.id) ? list.map((w) => (w.id === ws.id ? ws : w)) : [ws, ...list]));
    setActiveWorkspaceId(ws.id);
  }, []);

  const workspacesRef = useRef(workspaces);
  workspacesRef.current = workspaces;
  const deleteWorkspace = useCallback((id: string) => {
    setWorkspaces((list) => list.filter((w) => w.id !== id));
    setActiveWorkspaceId((cur) => (cur === id ? workspacesRef.current.find((w) => w.id !== id)?.id ?? null : cur));
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
    setCertificates([]);
    setWorkspaces([]);
    setActiveWorkspaceId(null);
    setLabels({});
    setRecentFiles([]);
    setSettings(DEFAULT_SETTINGS);
    await api.saveAppState(null).catch(() => undefined);
  }, [setCertificates]);

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
          const s = { ...DEFAULT_SETTINGS, theme: cachedThemePreference(), ...(raw.settings ?? {}) };
          if (!isThemePreference(s.theme)) s.theme = DEFAULT_SETTINGS.theme;
          setSettings(s);
          setWorkspaces(raw.workspaces ?? []);
          setActiveWorkspaceId(raw.activeWorkspaceId ?? raw.workspaces?.[0]?.id ?? null);
          setLabels(raw.labels ?? {});
          labelsRef.current = raw.labels ?? {};
          setRecentFiles(raw.recentFiles ?? []);
          // Certificates are public, so they come back whatever restoreSession says, like workspaces.
          // Each is read again so its validity and findings are current.
          if (raw.certificates?.length) {
            const restored = await Promise.all(
              raw.certificates.map((c) =>
                api
                  .importTrustedCertificates("certificate", { text: c.pem }, [])
                  .then((entries) => toOpenCertificates(entries.slice(0, 1), { path: c.path, source: c.source, openedAt: c.opened_at }))
                  .catch(() => [] as OpenCertificate[])
              )
            );
            setCertificates(mergeCertificates([], restored.flat()).list);
          }
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
        certificates: persistCertificates(certificates),
      };
      api.saveAppState(state).catch(() => undefined);
    }, 400);
  }, [ready, desktop, version, activeKeystoreId, recentFiles, workspaces, activeWorkspaceId, labels, settings, certificates]); // eslint-disable-line react-hooks/exhaustive-deps

  // ------------------------------------------------- auto-lock on inactivity
  // One timer locks both the vault and the key pairs unlocked this session: a key unlocked hours
  // ago must not keep signing without its password just because the vault was never opened.
  const lastActivity = useRef(Date.now());
  useEffect(() => {
    const bump = () => (lastActivity.current = Date.now());
    const events = ["mousemove", "keydown", "pointerdown", "wheel"] as const;
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    const timer = window.setInterval(() => {
      const mins = settingsRef.current.autoLockMinutes;
      if (mins <= 0 || Date.now() - lastActivity.current <= mins * 60_000) return;
      const vaultOpen = vaultRef.current.unlocked;
      const keysOpen = settingsRef.current.requireKeyUnlock && unlockedKeysRef.current.size > 0;
      if (!vaultOpen && !keysOpen) return;
      if (keysOpen) {
        unlockedKeysRef.current = new Set();
        setUnlockedKeys(new Set());
        setPendingKeyUnlock(null);
      }
      const what = vaultOpen && keysOpen ? "The vault and unlocked keys were" : vaultOpen ? "The vault was" : "Unlocked keys were";
      const done = () => toast.info(`${what} locked after ${mins} minutes of inactivity.`);
      if (vaultOpen) void lockVault().then(done);
      else done();
    }, 15_000);
    return () => {
      events.forEach((e) => window.removeEventListener(e, bump));
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
    convertMode,
    openConverter: (id) => {
      setConvertMode(id);
      setTab("convert");
    },
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
    rememberRequested: (id) => rememberOnSave.current.has(id),
    isKeyLocked: keyLocked,
    ensureKeyAccess,
    pendingKeyUnlock,
    cancelKeyUnlock: () => setPendingKeyUnlock(null),
    unlockKeys,
    currentKeystores: () => keystoresRef.current,
    lockKeys,
    openFiles,
    pendingOpen,
    submitOpenPassword,
    cancelOpen,
    unlockSealed,
    createKeystore,
    newKeystoreOpen,
    setNewKeystoreOpen,
    buildPkcs12Open,
    setBuildPkcs12Open,
    save,
    pendingSave,
    completeSave,
    cancelSave: () => setPendingSave(null),
    closeKeystore,
    recentFiles,
    clearRecentFiles,
    certificates,
    addCertificates,
    removeCertificates,
    certificateFocus,
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
