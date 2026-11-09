import React, { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import {
  AlertTriangle,
  ArrowLeftRight,
  ChevronDown,
  ChevronRight,
  ChevronsDownUp,
  ClipboardPaste,
  Clock,
  Copy,
  Download,
  Edit3,
  Eye,
  FileKey2,
  FileOutput,
  FilePlus2,
  FileSignature,
  FileText,
  FolderArchive,
  FolderOpen,
  History,
  Import,
  KeyRound,
  KeySquare,
  Layers,
  Lock,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Reply,
  Save,
  Scissors,
  Search,
  Shapes,
  ShieldCheck,
  Tag,
  Trash2,
  Unlock,
  X,
} from "lucide-react";
import type { EntryType, KeystoreEntry, OpenKeystore } from "../types/crypto";
import { api, classifyError, errorMessage } from "../lib/api";
import { baseName, pickSavePath, safeFileStem, withExtension } from "../lib/files";
import { ENTRY_TYPE_LABEL, ENTRY_TYPE_ORDER, FORMAT_INFO, LockState, byTypeThenAlias, canHoldSecretKeys, entryMatches, entryTypeName, lockState } from "../lib/keystore";
import { diffEntries } from "../lib/diff";
import { daysUntilExpiry, entryHealth, entryMix, formatDuration, summarize } from "../lib/metrics";
import { useStore } from "../state/store";
import {
  Alert,
  Badge,
  Button,
  Card,
  Column,
  DataTable,
  EmptyState,
  IconButton,
  IconHeader,
  Menu,
  MenuItem,
  Modal,
  PageHeader,
  PasswordInput,
  PathText,
  SearchInput,
  Segmented,
  StatStrip,
  TextInput,
  useConfirm,
  useToast,
} from "../components/ui";
import { AlgorithmCell, EntryIcon, EntryNameCell, EntryTypeIconCell, ExpiryCell, HealthIcon, LockCell, NAME_COLUMN_CLASS, TYPE_ICON } from "../components/entry";
import { AssignWorkspaceDialog, CaReplyDialog, CsrDialog, EntryInspector, ExportDialog, LabelsDialog, RenameDialog } from "../components/EntryDialogs";
import { GenerateKeyPairDialog, GenerateSecretKeyDialog, ImportCertificateDialog, ImportFromKeystoreDialog, ImportKeyPairDialog } from "../components/AddEntryDialogs";
import { shortcutLabel } from "../lib/platform";

type TypeFilter = "ALL" | EntryType;
type Dialog =
  | null
  | { kind: "inspect" | "export" | "csr" | "reply" | "rename" | "labels" | "workspaces" | "keypw"; entry: KeystoreEntry }
  | { kind: "keypair" | "ca" | "secret" | "cert" | "importkp" | "merge" | "password" };

interface Clip {
  entries: KeystoreEntry[];
  mode: "copy" | "cut";
  from: string;
}
// Survives page switches for the whole session.
let clipboardMemory: Clip | null = null;

const HEALTH_RANK = { "at-risk": 0, attention: 1, healthy: 2 } as const;
// Keys that need their password first, then usable keys, then entries without a key.
const LOCK_RANK: Record<LockState, number> = { locked: 0, "own-password": 0, unlocked: 1, "no-key": 2 };
const NAV_HIDDEN_KEY = "xkeystore.keystoreNavHidden";
/** Entries listed under one keystore before "Show more". */
const TREE_PAGE = 100;

const ChangePasswordDialog: React.FC<{ keystore: OpenKeystore; onClose: () => void }> = ({ keystore, onClose }) => {
  const { setPassword } = useStore();
  const toast = useToast();
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const error = pw && pw.length < 6 ? "At least 6 characters" : pw2 && pw !== pw2 ? "Passwords do not match" : undefined;
  return (
    <Modal
      open
      onClose={onClose}
      icon={KeySquare}
      size="sm"
      title={`Change password of ${keystore.name}`}
      description="The new password applies when you next save."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!pw || pw !== pw2 || pw.length < 6}
            data-testid="change-password-submit"
            onClick={() => {
              setPassword(keystore.id, pw);
              toast.success("Password changed. Save the keystore to apply it.");
              onClose();
            }}
          >
            Change password
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <PasswordInput label="New password" value={pw} onChange={setPw} autoFocus />
        <PasswordInput label="Confirm" value={pw2} onChange={setPw2} error={error} />
      </div>
    </Modal>
  );
};

const ChangeKeyPasswordDialog: React.FC<{ entry: KeystoreEntry; format: OpenKeystore["format"]; onClose: () => void; onSave: (password: string) => void }> = ({ entry, format, onClose, onSave }) => {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const error = pw && pw.length < 6 ? "At least 6 characters" : pw2 && pw !== pw2 ? "Passwords do not match" : undefined;
  const ready = !!pw && pw === pw2 && !error;
  return (
    <Modal
      open
      onClose={onClose}
      icon={KeySquare}
      size="sm"
      title={`Key password for ${entry.alias}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="keypw-form" disabled={!ready} data-testid="keypw-submit">
            Save on next write
          </Button>
        </>
      }
    >
      <form
        id="keypw-form"
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) onSave(pw);
        }}
      >
        <PasswordInput label="New key password" value={pw} onChange={setPw} autoFocus data-testid="keypw-new" />
        <PasswordInput label="Confirm" value={pw2} onChange={setPw2} error={error} data-testid="keypw-confirm" />
        {format === "PKCS12" ? (
          <Alert tone="warning" title="Most tools expect one password in a PKCS#12">
            OpenSSL and Java&apos;s keytool open a PKCS#12 with a single password for the file and its keys; with a separate key password they fail to read this key. Use it
            only if every program that reads the file supports it, or save as JKS or JCEKS.
          </Alert>
        ) : (
          <p className="text-[12px] text-faint">The store password still opens the file. This password wraps only this key, the way keytool -keypasswd does.</p>
        )}
      </form>
    </Modal>
  );
};

/** Adds one label to several entries at once. (window.prompt does nothing in the desktop webview.) */
const BulkLabelDialog: React.FC<{ count: number; suggestions: string[]; onClose: () => void; onApply: (label: string) => void }> = ({ count, suggestions, onClose, onApply }) => {
  const [label, setLabel] = useState("");
  const submit = (value: string) => {
    const v = value.trim();
    if (!v) return;
    onApply(v);
    onClose();
  };
  return (
    <Modal
      open
      onClose={onClose}
      icon={Tag}
      size="sm"
      title={`Label ${count} ${count === 1 ? "entry" : "entries"}`}
      description="Labels are xkeystore metadata; they are not written into the keystore file."
      testId="bulk-label-dialog"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="bulk-label-form" disabled={!label.trim()} data-testid="bulk-label-submit">
            Add label
          </Button>
        </>
      }
    >
      <form
        id="bulk-label-form"
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          submit(label);
        }}
      >
        <TextInput label="Label" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. production, pci, rotate-q3" autoFocus data-testid="bulk-label-input" />
        {suggestions.length > 0 && (
          <div className="flex flex-wrap gap-1.5" aria-label="Labels in use">
            {suggestions.map((s) => (
              <button key={s} type="button" onClick={() => submit(s)} className="h-6 px-2 rounded-control border border-line text-[12px] text-muted hover:bg-surface-2 cursor-pointer">
                + {s}
              </button>
            ))}
          </div>
        )}
      </form>
    </Modal>
  );
};

/** Aliases only in the open keystore, only in the one it is compared with, and in both but different. */
type DiffResult = { against: string; onlyHere: string[]; onlyThere: string[]; changed: string[] };

const DiffDialog: React.FC<{
  keystore: OpenKeystore;
  others: OpenKeystore[];
  result: DiffResult | null;
  error: string | null;
  busy: boolean;
  onClose: () => void;
  onPick: (other: OpenKeystore | "disk") => void;
}> = ({ keystore, others, result, error, busy, onClose, onPick }) => {
  const rows: { label: string; items: string[]; tone: "success" | "danger" | "warning"; testId: string }[] = result
    ? [
        { label: `Only in ${keystore.name} (open here)`, items: result.onlyHere, tone: "success", testId: "diff-only-here" },
        { label: `Only in ${result.against}`, items: result.onlyThere, tone: "danger", testId: "diff-only-there" },
        { label: "In both, with a different certificate or key", items: result.changed, tone: "warning", testId: "diff-changed" },
      ]
    : [];
  const same = result && !result.onlyHere.length && !result.onlyThere.length && !result.changed.length;
  return (
    <Modal open onClose={onClose} icon={FileText} title={`Compare ${keystore.name}`} description="Entries are matched by alias; a match with a different SHA-256 fingerprint is reported as changed." size="md" busy={busy} testId="diff-dialog" footer={<Button onClick={onClose}>Close</Button>}>
      <div className="space-y-4">
        <div>
          <span className="label">Compare with</span>
          <div className="flex flex-wrap gap-2">
            {keystore.path && (
              <Button size="sm" icon={FolderOpen} onClick={() => onPick("disk")} disabled={busy} data-testid="diff-disk">
                The file on disk
              </Button>
            )}
            {others.map((o) => (
              <Button key={o.id} size="sm" icon={FolderArchive} onClick={() => onPick(o)} disabled={busy}>
                {o.name}
              </Button>
            ))}
            {!keystore.path && !others.length && <p className="text-[13px] text-faint">Save this keystore or open another one to compare against.</p>}
          </div>
        </div>
        {error && <Alert tone="danger">{error}</Alert>}
        {result && (
          <div className="space-y-2" data-testid="diff-result">
            {same ? (
              <Alert tone="success" title={`Same entries as ${result.against}`}>
                Every alias is in both, with the same fingerprint.
              </Alert>
            ) : (
              <dl className="rounded-card border border-line divide-y divide-line">
                {rows.map((r) => (
                  <div key={r.label} className="px-3.5 py-2.5 flex items-start justify-between gap-3" data-testid={r.testId}>
                    <dt className="text-[13px] text-muted">{r.label}</dt>
                    <dd className="flex flex-wrap justify-end gap-1 min-w-0">
                      {r.items.length ? (
                        r.items.map((a) => (
                          <Badge key={a} tone={r.tone}>
                            {a}
                          </Badge>
                        ))
                      ) : (
                        <span className="text-[13px] text-faint">None</span>
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
};

// ============================================================================ navigator

/** Tiny status mark for an entry in the tree; the label carries the meaning, not the color. */
const HealthMark: React.FC<{ entry: KeystoreEntry }> = ({ entry }) => {
  const h = entryHealth(entry);
  if (h === "healthy") return null;
  const label = h === "at-risk" ? "Needs action" : "Renew soon";
  const Icon = h === "at-risk" ? AlertTriangle : Clock;
  return (
    <span title={label} className={clsx("shrink-0", h === "at-risk" ? "text-danger" : "text-warning")}>
      <Icon className="w-3 h-3" aria-hidden />
      <span className="sr-only">{label}</span>
    </span>
  );
};

/**
 * The keystores of the session as a tree: each keystore, and under it its entries grouped by
 * type. Scales to many keystores: it scrolls, filters by keystore or entry, and shows recent
 * files that are not open.
 */
const KeystoreNavigator: React.FC<{
  activeId: string | null;
  focusEntryId: string | null;
  onSelectKeystore: (id: string) => void;
  onSelectEntry: (keystoreId: string, entry: KeystoreEntry) => void;
  onHide: () => void;
}> = ({ activeId, focusEntryId, onSelectKeystore, onSelectEntry, onHide }) => {
  const { keystores, openFiles, setNewKeystoreOpen, closeKeystore, unlockSealed, isKeyLocked, save, recentFiles } = useStore();
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set(activeId ? [activeId] : []));
  const [pages, setPages] = useState<Record<string, number>>({});
  useEffect(() => {
    // Keep the active keystore open, e.g. when it was just opened or picked elsewhere.
    if (activeId) setExpanded((cur) => (cur.has(activeId) ? cur : new Set([...cur, activeId])));
  }, [activeId]);

  const toggle = (id: string) =>
    setExpanded((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const q = query.trim().toLowerCase();
  const rows = useMemo(
    () =>
      keystores
        .map((k) => {
          const sorted = [...k.entries].sort(byTypeThenAlias);
          const nameHit = !q || k.name.toLowerCase().includes(q) || k.path.toLowerCase().includes(q);
          const matching = q ? sorted.filter((e) => entryMatches(e, q)) : sorted;
          return { k, nameHit, entries: q && matching.length ? matching : sorted, entryHits: q ? matching.length : 0 };
        })
        .filter((r) => !q || r.nameHit || r.entryHits > 0),
    [keystores, q]
  );
  const openPaths = new Set(keystores.map((k) => k.path).filter(Boolean));
  const recent = recentFiles.filter((f) => !openPaths.has(f.path) && (!q || f.name.toLowerCase().includes(q))).slice(0, 6);
  const totalEntries = keystores.reduce((n, k) => n + k.entries.length, 0);

  const ksMenu = (k: OpenKeystore): MenuItem[] =>
    k.sealed
      ? [
          { label: "Enter password…", icon: Unlock, onSelect: () => unlockSealed(k.id) },
          { label: "Remove from list", icon: X, onSelect: () => void closeKeystore(k.id), danger: true, divider: true },
        ]
      : [
          { label: "Save", icon: Save, onSelect: () => void save(k.id), disabled: !k.dirty && !!k.path },
          { label: "Save as…", icon: Save, onSelect: () => void save(k.id, { saveAs: true }) },
          ...(k.path ? [{ label: "Show in folder", icon: FolderOpen, onSelect: () => void revealItemInDir(k.path).catch(() => undefined) }] : []),
          { label: "Close", icon: X, onSelect: () => void closeKeystore(k.id), danger: true, divider: true, testId: `tree-close-${k.name}` },
        ];

  return (
    <aside className="w-[280px] shrink-0 h-full flex flex-col bg-surface border-r border-line" aria-label="Keystore navigator" data-testid="keystore-navigator">
      <div className="px-4 pt-4 pb-3 border-b border-line space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <h2 className="text-[13px] font-semibold text-ink">Keystores</h2>
            <p className="text-[11.5px] text-faint tabular-nums">
              {keystores.length} open · {totalEntries} {totalEntries === 1 ? "entry" : "entries"}
            </p>
          </div>
          <div className="flex items-center gap-0.5 shrink-0">
            <IconButton icon={FolderOpen} label={shortcutLabel("Open keystore… (Ctrl+O)")} onClick={() => openFiles()} data-testid="ks-open" />
            <IconButton icon={FilePlus2} label={shortcutLabel("New keystore… (Ctrl+N)")} onClick={() => setNewKeystoreOpen(true)} data-testid="ks-new" />
            <IconButton icon={ChevronsDownUp} label="Collapse all" onClick={() => setExpanded(new Set())} disabled={!expanded.size} />
            <IconButton icon={PanelLeftClose} label="Hide the keystore list" onClick={onHide} />
          </div>
        </div>
        <SearchInput value={query} onChange={setQuery} placeholder="Filter keystores and entries" />
      </div>

      <div role="tree" aria-label="Open keystores" className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-0.5">
        {keystores.length === 0 && (
          <div className="px-3 py-6 text-center">
            <FolderArchive className="w-5 h-5 text-subtle mx-auto" />
            <p className="text-[13px] text-faint mt-2">No keystores open.</p>
            <div className="mt-3 flex justify-center gap-1.5">
              <Button size="sm" icon={FolderOpen} onClick={() => openFiles()}>
                Open…
              </Button>
              <Button size="sm" icon={FilePlus2} onClick={() => setNewKeystoreOpen(true)}>
                New…
              </Button>
            </div>
          </div>
        )}
        {keystores.length > 0 && rows.length === 0 && <p className="px-3 py-6 text-center text-[13px] text-faint">Nothing matches “{query}”.</p>}
        {rows.map(({ k, entries, entryHits }) => {
          const active = k.id === activeId;
          const open = expanded.has(k.id) || entryHits > 0;
          const issues = k.entries.filter((e) => entryHealth(e) !== "healthy").length;
          const lockedKeys = k.entries.filter((e) => e.entry_type === "KeyPair" && isKeyLocked(e)).length;
          const limit = pages[k.id] ?? TREE_PAGE;
          let lastType: EntryType | null = null;
          return (
            <div key={k.id} role="treeitem" aria-level={1} aria-expanded={open} aria-selected={active} aria-label={k.name}>
              <div className={clsx("group flex items-center gap-0.5 rounded-control pr-1", active ? "bg-brand-tint" : "hover:bg-surface-2")}>
                <button
                  type="button"
                  onClick={() => toggle(k.id)}
                  aria-label={open ? `Collapse ${k.name}` : `Expand ${k.name}`}
                  className="w-6 h-10 shrink-0 flex items-center justify-center text-faint hover:text-ink cursor-pointer"
                >
                  {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => onSelectKeystore(k.id)}
                  onDoubleClick={() => toggle(k.id)}
                  aria-current={active ? "true" : undefined}
                  data-testid={`ks-tab-${k.name}`}
                  title={k.path || `${k.name} (not saved yet)`}
                  className="flex-1 min-w-0 h-10 flex items-center gap-2 text-left cursor-pointer"
                >
                  <span className={clsx("w-6 h-6 rounded-control flex items-center justify-center shrink-0", active ? "bg-surface text-brand" : "bg-surface-3 text-muted")}>
                    {k.sealed ? <Lock className="w-3.5 h-3.5" /> : <FolderArchive className="w-3.5 h-3.5" />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1.5">
                      <span className={clsx("text-[13px] truncate", active ? "font-semibold text-ink" : "font-medium text-ink-2")}>{k.name}</span>
                      {k.dirty && <span className="w-1.5 h-1.5 rounded-full bg-warning-fill shrink-0" title="Unsaved changes" aria-label="Unsaved changes" />}
                    </span>
                    <span className="block text-[11.5px] text-faint truncate">
                      {k.sealed
                        ? "Locked — enter the password"
                        : `${FORMAT_INFO[k.format].label} · ${k.entries.length} ${k.entries.length === 1 ? "entry" : "entries"}${lockedKeys ? ` · ${lockedKeys} locked` : ""}`}
                    </span>
                  </span>
                </button>
                {issues > 0 && (
                  <span title={`${issues} need attention`}>
                    <Badge tone="warning">{issues}</Badge>
                  </span>
                )}
                <Menu
                  items={ksMenu(k)}
                  width={220}
                  trigger={(p) => (
                    <IconButton icon={MoreHorizontal} label={`Actions for ${k.name}`} {...p} className="opacity-0 group-hover:opacity-100 focus:opacity-100 aria-expanded:opacity-100" />
                  )}
                />
              </div>
              {open && (
                <div role="group" className="ml-[11px] pl-2 border-l border-line mb-1">
                  {k.sealed ? (
                    <button type="button" onClick={() => unlockSealed(k.id)} className="w-full text-left px-2 py-1.5 text-[12px] text-brand font-medium hover:underline cursor-pointer">
                      Enter the password to see its entries…
                    </button>
                  ) : entries.length === 0 ? (
                    <div className="px-2 py-1.5 text-[12px] text-faint">No entries</div>
                  ) : (
                    entries.slice(0, limit).map((e) => {
                      const header = e.entry_type !== lastType;
                      lastType = e.entry_type;
                      const locked = isKeyLocked(e);
                      const focused = active && focusEntryId === e.id;
                      return (
                        <React.Fragment key={e.id}>
                          {header && (
                            <div className="px-2 pt-1.5 pb-0.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-faint">
                              {ENTRY_TYPE_LABEL[e.entry_type]}s · {k.entries.filter((x) => x.entry_type === e.entry_type).length}
                            </div>
                          )}
                          <button
                            type="button"
                            role="treeitem"
                            aria-level={2}
                            aria-selected={focused}
                            onClick={() => onSelectEntry(k.id, e)}
                            title={`${entryTypeName(e)}${locked ? " (locked)" : ""} — ${e.alias}`}
                            data-testid={`tree-entry-${e.alias}`}
                            className={clsx(
                              "w-full h-8 flex items-center gap-2 px-1.5 rounded-control text-left text-[13px] cursor-pointer",
                              focused ? "bg-surface-3 text-ink font-medium" : "text-ink-2 hover:bg-surface-2"
                            )}
                          >
                            <EntryIcon type={e.entry_type} size="sm" locked={e.entry_type === "KeyPair" ? locked : e.locked || undefined} />
                            <span className="truncate flex-1">{e.alias}</span>
                            <HealthMark entry={e} />
                          </button>
                        </React.Fragment>
                      );
                    })
                  )}
                  {!k.sealed && entries.length > limit && (
                    <button
                      type="button"
                      onClick={() => setPages((p) => ({ ...p, [k.id]: limit + TREE_PAGE * 2 }))}
                      className="w-full text-left px-2 py-1.5 text-[12px] text-brand font-medium hover:underline cursor-pointer"
                    >
                      Show {Math.min(entries.length - limit, TREE_PAGE * 2)} more of {entries.length}
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {recent.length > 0 && (
          <div className="pt-3">
            <div className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-[0.06em] text-faint flex items-center gap-1.5">
              <History className="w-3 h-3" /> Recent, not open
            </div>
            {recent.map((f) => (
              <button
                key={f.path}
                type="button"
                onClick={() => openFiles([f.path])}
                title={f.path}
                className="w-full h-8 flex items-center gap-2 px-2 rounded-control text-left text-[13px] text-muted hover:bg-surface-2 hover:text-ink cursor-pointer"
              >
                <FolderArchive className="w-3.5 h-3.5 text-subtle shrink-0" />
                <span className="truncate flex-1">{f.name}</span>
                <span className="text-[11px] text-faint shrink-0">{f.format}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Legend: the three entry types and the lock badge. */}
      <div className="px-4 py-2.5 border-t border-line flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[11.5px] text-faint" aria-label="Entry types">
        {(Object.keys(TYPE_ICON) as EntryType[])
          .sort((a, b) => ENTRY_TYPE_ORDER[a] - ENTRY_TYPE_ORDER[b])
          .map((t) => (
            <span key={t} className="inline-flex items-center gap-1.5">
              <EntryIcon type={t} size="sm" /> {t === "TrustedCertificate" ? "Certificate" : ENTRY_TYPE_LABEL[t]}
            </span>
          ))}
        <span className="inline-flex items-center gap-1.5">
          <Lock className="w-3 h-3 text-warning" /> locked
        </span>
      </div>
    </aside>
  );
};

// =============================================================================== view

export const KeystoresView: React.FC = () => {
  const store = useStore();
  const {
    keystores,
    activeKeystore: ks,
    selectKeystore,
    openFiles,
    setNewKeystoreOpen,
    save,
    closeKeystore,
    deleteEntries,
    addEntries,
    replaceEntry,
    setEntryLabels,
    getPassword,
    unlockSealed,
    workspaces,
    isKeyLocked,
    ensureKeyAccess,
    lockKeys,
    openConverter,
    settings,
  } = store;
  const toast = useToast();
  const confirm = useConfirm();

  const [navHidden, setNavHidden] = useState(() => {
    try {
      return localStorage.getItem(NAV_HIDDEN_KEY) === "true";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(NAV_HIDDEN_KEY, String(navHidden));
    } catch {
      /* private mode */
    }
  }, [navHidden]);

  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("ALL");
  const [labelFilter, setLabelFilter] = useState("");
  const [dialog, setDialog] = useState<Dialog>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [focusEntryId, setFocusEntryId] = useState<string | null>(null);
  const [diffOpen, setDiffOpen] = useState(false);
  const [diff, setDiff] = useState<{ result: DiffResult | null; error: string | null; busy: boolean }>({ result: null, error: null, busy: false });
  const [bulkLabelOpen, setBulkLabelOpen] = useState(false);
  const [clip, setClip] = useState<Clip | null>(clipboardMemory);
  useEffect(() => {
    clipboardMemory = clip;
  }, [clip]);
  useEffect(() => {
    setSearch("");
    setLabelFilter("");
    setTypeFilter("ALL");
    setSelected([]);
  }, [ks?.id]);

  const entries = ks?.entries ?? [];
  const allLabels = useMemo(() => [...new Set(entries.flatMap((e) => e.labels))].sort(), [entries]);
  const filtered = useMemo(
    () => entries.filter((e) => (typeFilter === "ALL" || e.entry_type === typeFilter) && (!labelFilter || e.labels.includes(labelFilter)) && entryMatches(e, search)),
    [entries, typeFilter, labelFilter, search]
  );
  // Bulk actions act on what is selected and visible. An entry the filter now hides drops out of
  // the selection, so "Delete 3" never removes entries that are no longer on screen.
  useEffect(() => {
    setSelected((cur) => {
      const visible = new Set(filtered.map((e) => e.id));
      const kept = cur.filter((id) => visible.has(id));
      return kept.length === cur.length ? cur : kept;
    });
  }, [filtered]);
  const sum = summarize(entries);
  const lockedKeyPairs = entries.filter((e) => e.entry_type === "KeyPair" && isKeyLocked(e));
  const lockedOther = entries.filter((e) => e.entry_type !== "KeyPair" && e.locked);
  const unlockedKeyPairs = entries.filter((e) => e.entry_type === "KeyPair" && !isKeyLocked(e));

  /** Opens the inspector, asking for the key password first when the key is locked. */
  const openEntry = (keystoreId: string, entry: KeystoreEntry) => {
    setFocusEntryId(entry.id);
    ensureKeyAccess(keystoreId, [entry.id], () => setDialog({ kind: "inspect", entry }));
  };

  // The navigator only earns its space with two or more keystores. With one or none it is hidden
  // along with its toggle. The saved preference is kept, so it applies again once a second one opens.
  const multiple = keystores.length > 1;
  const navOff = !multiple || navHidden;
  const navigator = navOff ? null : (
    <KeystoreNavigator
      activeId={ks?.id ?? null}
      focusEntryId={focusEntryId}
      onSelectKeystore={(id) => {
        selectKeystore(id);
        setFocusEntryId(null);
      }}
      onSelectEntry={(id, entry) => {
        selectKeystore(id);
        openEntry(id, entry);
      }}
      onHide={() => setNavHidden(true)}
    />
  );
  const showNav = multiple && navHidden ? (
    <IconButton icon={PanelLeftOpen} label="Show the keystore list" onClick={() => setNavHidden(false)} className="!w-9 !h-9 border border-line-strong bg-surface" data-testid="ks-nav-show" />
  ) : null;

  if (!ks) {
    return (
      <div className="flex-1 min-h-0 flex">
        {navigator}
        <div className="flex-1 min-w-0 overflow-y-auto">
          <div className="max-w-[1320px] mx-auto px-8 py-7">
            <PageHeader title="Keystores" leading={showNav} description="Open PKCS#12, JKS and JCEKS keystores, or create a new one." />
            <Card className="py-16">
              <EmptyState
                icon={FolderArchive}
                title="No keystores open"
                description="Open an existing keystore (you can also drag files onto the window) or create a new one. Open keystores are listed on the left with their keys and certificates."
                action={
                  <>
                    <Button variant="primary" icon={FolderOpen} onClick={() => openFiles()} data-testid="empty-open">
                      Open keystore…
                    </Button>
                    <Button icon={FilePlus2} onClick={() => setNewKeystoreOpen(true)} data-testid="empty-new">
                      New keystore
                    </Button>
                  </>
                }
              />
            </Card>
          </div>
        </div>
      </div>
    );
  }

  /** Resolves true when the entries were deleted, false when the user cancelled. */
  const deleteWithConfirm = async (list: KeystoreEntry[]): Promise<boolean> => {
    const names = list.slice(0, 5).map((e) => `'${e.alias}'`).join(", ") + (list.length > 5 ? ` and ${list.length - 5} more` : "");
    const ok = await confirm({
      title: list.length === 1 ? `Delete '${list[0].alias}'?` : `Delete ${list.length} entries?`,
      message: `${list.length === 1 ? "The entry" : names} will be removed from ${ks.name}. You can undo with ${shortcutLabel("Ctrl+Z")}; the file changes only when you save.`,
      confirmLabel: "Delete",
      danger: true,
    });
    if (ok !== true) return false;
    deleteEntries(ks.id, list.map((e) => e.id));
    setDialog(null);
    toast.success(`Deleted ${list.length === 1 ? `'${list[0].alias}'` : `${list.length} entries`}.`, { label: "Undo", onClick: store.undo });
    return true;
  };

  const copyEntries = (list: KeystoreEntry[], mode: "copy" | "cut") => {
    setClip({ entries: list, mode, from: ks.id });
    if (mode === "cut") deleteEntries(ks.id, list.map((e) => e.id));
    toast.info(`${mode === "cut" ? "Cut" : "Copied"} '${list[0].alias}'. Open another keystore and choose Paste.`);
  };

  const paste = () => {
    if (!clip) return;
    const blocked = clip.entries.filter((e) => e.entry_type === "SecretKey" && !canHoldSecretKeys(ks.format));
    if (blocked.length) {
      toast.error(`${FORMAT_INFO[ks.format].label} cannot store secret keys; ${blocked.map((e) => `'${e.alias}'`).join(", ")} ${blocked.length === 1 ? "stays" : "stay"} on the clipboard.`);
    }
    const added = addEntries(
      ks.id,
      clip.entries.filter((e) => !blocked.includes(e))
    );
    if (added.length) toast.success(`Pasted ${added.map((a) => `'${a.alias}'`).join(", ")} into ${ks.name}.`);
    // A cut is used up by pasting it, except what could not be pasted here: it was already removed
    // from its keystore, so dropping it from the clipboard would lose it.
    if (clip.mode === "cut") setClip(blocked.length ? { ...clip, entries: blocked } : null);
  };

  /** Runs `then` once the key is usable. */
  const withKey = (entry: KeystoreEntry, then: () => void) => ensureKeyAccess(ks.id, [entry.id], then);

  const exportCsv = async () => {
    try {
      const path = await pickSavePath("Export inventory", `${safeFileStem(ks.name.replace(/\.[^.]+$/, ""))}-inventory.csv`, [{ name: "CSV", extensions: ["csv"] }]);
      if (!path) return;
      const res = await api.exportKeystoreCsv(ks, path);
      toast.success(`Exported ${ks.entries.length} entries to ${res.path}`, { label: "Show in folder", onClick: () => void revealItemInDir(res.path).catch(() => undefined) });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const manageItems = (entry: KeystoreEntry): MenuItem[] => [
    { label: "Rename…", icon: Edit3, onSelect: () => setDialog({ kind: "rename", entry }), divider: true, testId: "menu-rename" },
    { label: "Labels…", icon: Tag, onSelect: () => setDialog({ kind: "labels", entry }) },
    { label: "Workspaces…", icon: Layers, onSelect: () => setDialog({ kind: "workspaces", entry }) },
  ];

  const rowMenu = (entry: KeystoreEntry): MenuItem[] => {
    const deleteItem: MenuItem = { label: "Delete", icon: Trash2, onSelect: () => deleteWithConfirm([entry]), danger: true, divider: true, testId: "menu-delete" };
    if (isKeyLocked(entry)) {
      return [
        {
          label: entry.entry_type === "KeyPair" ? "Unlock key pair…" : "Unlock key…",
          hint: "Enter the key password to inspect, export or use it",
          icon: Unlock,
          onSelect: () => withKey(entry, () => toast.success(`Unlocked '${entry.alias}'.`)),
          testId: "menu-unlock",
        },
        ...manageItems(entry),
        deleteItem,
      ];
    }
    return [
      { label: "Inspect", icon: Eye, onSelect: () => setDialog({ kind: "inspect", entry }) },
      { label: "Export…", icon: Download, onSelect: () => setDialog({ kind: "export", entry }), testId: "menu-export" },
      ...(entry.entry_type === "KeyPair"
        ? [
            { label: "Generate CSR…", icon: FileSignature, onSelect: () => setDialog({ kind: "csr", entry }), testId: "menu-csr" },
            { label: "Import CA reply…", icon: Reply, onSelect: () => setDialog({ kind: "reply", entry }), testId: "menu-reply" },
          ]
        : []),
      ...manageItems(entry),
      { label: "Clone", icon: Copy, onSelect: () => { addEntries(ks.id, [entry]); toast.success(`Cloned '${entry.alias}'.`); }, testId: "menu-clone" },
      { label: "Change key password…", icon: KeySquare, onSelect: () => setDialog({ kind: "keypw", entry }), testId: "menu-keypw", disabled: entry.entry_type === "TrustedCertificate" },
      { label: "Copy", icon: Copy, onSelect: () => copyEntries([entry], "copy"), divider: true, testId: "menu-copy" },
      { label: "Cut", icon: Scissors, onSelect: () => copyEntries([entry], "cut"), testId: "menu-cut" },
      ...(entry.entry_type === "KeyPair" && settings.requireKeyUnlock
        ? [{ label: "Lock key pair", hint: "Ask for the key password again", icon: Lock, onSelect: () => lockKeys(ks.id, [entry.id]), divider: true, testId: "menu-lock" }]
        : []),
      deleteItem,
    ];
  };

  const allVisibleSelected = filtered.length > 0 && filtered.every((e) => selected.includes(e.id));
  const someVisibleSelected = !allVisibleSelected && filtered.some((e) => selected.includes(e.id));
  const columns: Column<KeystoreEntry>[] = [
    {
      id: "pick",
      header: (
        <input
          type="checkbox"
          aria-label={allVisibleSelected ? "Deselect all entries" : "Select all entries shown"}
          title={allVisibleSelected ? "Deselect all" : "Select all shown"}
          checked={allVisibleSelected}
          disabled={!filtered.length}
          ref={(el) => {
            if (el) el.indeterminate = someVisibleSelected;
          }}
          onChange={() => setSelected(allVisibleSelected ? [] : filtered.map((e) => e.id))}
          className="cursor-pointer align-middle"
          data-testid="select-all"
        />
      ),
      width: "36px",
      cell: (e) => (
        <input
          type="checkbox"
          aria-label={`Select ${e.alias}`}
          checked={selected.includes(e.id)}
          onClick={(ev) => ev.stopPropagation()}
          onChange={() => setSelected((cur) => (cur.includes(e.id) ? cur.filter((id) => id !== e.id) : [...cur, e.id]))}
          className="cursor-pointer align-middle"
          data-testid={`select-${e.alias}`}
        />
      ),
    },
    // Type and lock are glyphs alone, named in the tooltip and to screen readers. Columns give way as the
    // table narrows (the navigator and the sidebar take room the window size does not show) so status and
    // the row actions always stay in view: Algorithm first; then Type and Lock, whose tile and lock badge
    // move into the alias cell; then Expires. The alias takes the room left and truncates.
    {
      id: "type",
      header: <IconHeader icon={Shapes} label="Type" />,
      width: "64px",
      align: "center",
      hideBelow: "md",
      sortValue: (e) => `${ENTRY_TYPE_ORDER[e.entry_type]}${e.alias.toLowerCase()}`,
      cell: (e) => <EntryTypeIconCell entry={e} />,
    },
    {
      id: "lock",
      header: <IconHeader icon={Lock} label="Lock status" />,
      width: "64px",
      align: "center",
      hideBelow: "md",
      sortValue: (e) => `${LOCK_RANK[lockState(e, isKeyLocked(e))]}${e.alias.toLowerCase()}`,
      cell: (e) => <LockCell entry={e} />,
    },
    { id: "alias", header: "Alias", className: NAME_COLUMN_CLASS, sortValue: (e) => e.alias.toLowerCase(), cell: (e) => <EntryNameCell entry={e} icon="narrow" /> },
    { id: "alg", header: "Algorithm", hideBelow: "lg", sortValue: (e) => e.algorithm, cell: (e) => <AlgorithmCell entry={e} /> },
    { id: "expiry", header: "Expires", width: "160px", hideBelow: "sm", sortValue: (e) => daysUntilExpiry(e), cell: (e) => <ExpiryCell entry={e} /> },
    { id: "status", header: "Status", width: "88px", align: "center", sortValue: (e) => HEALTH_RANK[entryHealth(e)], cell: (e) => <HealthIcon entry={e} /> },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "112px",
      cell: (entry) => (
        <div className="inline-flex items-center gap-0.5" onClick={(ev) => ev.stopPropagation()}>
          {isKeyLocked(entry) ? (
            <IconButton icon={Unlock} label={`Unlock ${entry.alias}`} onClick={() => withKey(entry, () => toast.success(`Unlocked '${entry.alias}'.`))} data-testid={`row-unlock-${entry.alias}`} />
          ) : (
            <IconButton icon={Download} label={`Export ${entry.alias}`} onClick={() => setDialog({ kind: "export", entry })} />
          )}
          <IconButton icon={Trash2} label={`Delete ${entry.alias}`} tone="danger" onClick={() => deleteWithConfirm([entry])} />
          <Menu items={rowMenu(entry)} trigger={(p) => <IconButton icon={MoreHorizontal} label={`More actions for ${entry.alias}`} {...p} data-testid={`row-menu-${entry.alias}`} />} />
        </div>
      ),
    },
  ];

  const addMenu: MenuItem[] = [
    { label: "Generate key pair…", hint: "RSA, ECDSA or Ed25519 with an X.509 certificate", icon: KeyRound, onSelect: () => setDialog({ kind: "keypair" }), testId: "add-keypair" },
    { label: "Generate CA key pair…", hint: "A root or intermediate certificate authority", icon: ShieldCheck, onSelect: () => setDialog({ kind: "ca" }), testId: "add-ca" },
    {
      label: "Generate secret key…",
      hint: canHoldSecretKeys(ks.format) ? "AES, HMAC or 3DES" : `${ks.format} cannot hold secret keys`,
      icon: KeySquare,
      onSelect: () => setDialog({ kind: "secret" }),
      disabled: !canHoldSecretKeys(ks.format),
      testId: "add-secret",
    },
    { label: "Import trusted certificates…", hint: "PEM, DER or PKCS#7 bundle", icon: ShieldCheck, onSelect: () => setDialog({ kind: "cert" }), divider: true, testId: "add-cert" },
    { label: "Import key pair…", hint: "Private key file plus certificate chain", icon: FileKey2, onSelect: () => setDialog({ kind: "importkp" }), testId: "add-importkp" },
    { label: "Import from another keystore…", hint: "Merge entries from a .p12/.jks/.jceks", icon: Import, onSelect: () => setDialog({ kind: "merge" }) },
    ...(clip ? [{ label: `Paste ${clip.entries.map((e) => `'${e.alias}'`).join(", ")}`, hint: "From the keystore clipboard", icon: ClipboardPaste, onSelect: paste, divider: true, testId: "add-paste" }] : []),
  ];

  const moreMenu: MenuItem[] = [
    { label: "Save as…", hint: "Different file, format or password", icon: Save, onSelect: () => save(ks.id, { saveAs: true }), testId: "ks-save-as" },
    {
      label: "Migrate to PKCS#12…",
      hint: "Write a new .p12 and leave this file in place",
      icon: Save,
      onSelect: async () => {
        const password = getPassword(ks.id);
        if (!password) return save(ks.id, { saveAs: true });
        const suggested = withExtension(baseName(ks.path || ks.name).replace(/\.[^.]+$/, ""), "p12");
        const path = await pickSavePath("Migrate to PKCS#12", suggested, [{ name: "PKCS#12", extensions: ["p12", "pfx"] }]).catch(() => null);
        if (!path) return;
        if (ks.path && path === ks.path) return toast.error("Choose a new file so the original stays in place.");
        try {
          const res = await api.saveKeystore(ks, path, password, "PKCS12", "pkcs12", false);
          toast.success(`Wrote ${res.name}. ${ks.name} was not modified.`);
        } catch (err) {
          toast.error(errorMessage(err));
        }
      },
    },
    { label: "Convert format…", hint: "PKCS#12, JKS or JCEKS, on the Convert page", icon: ArrowLeftRight, onSelect: () => openConverter("keystore"), testId: "ks-convert" },
    { label: "Export to PEM…", hint: "Certificates and keys in one PEM file", icon: FileOutput, onSelect: () => openConverter("extract"), testId: "ks-extract" },
    { label: "Compare…", hint: "Against another open keystore or the file on disk", icon: FileText, onSelect: () => setDiffOpen(true), divider: true, testId: "ks-compare" },
    { label: "Change password…", icon: KeySquare, onSelect: () => setDialog({ kind: "password" }) },
    { label: "Export inventory (CSV)…", icon: FileText, onSelect: exportCsv, testId: "ks-export-csv" },
    ...(lockedKeyPairs.length + lockedOther.length
      ? [{ label: "Unlock all keys…", icon: Unlock, onSelect: () => ensureKeyAccess(ks.id, [...lockedKeyPairs, ...lockedOther].map((e) => e.id)), divider: true, testId: "ks-unlock-all" }]
      : []),
    ...(settings.requireKeyUnlock && unlockedKeyPairs.length
      ? [{ label: "Lock all key pairs", icon: Lock, onSelect: () => lockKeys(ks.id), divider: !(lockedKeyPairs.length + lockedOther.length), testId: "ks-lock-all" }]
      : []),
    ...(ks.path ? [{ label: "Show in folder", icon: FolderOpen, onSelect: () => void revealItemInDir(ks.path).catch(() => undefined), divider: true }] : []),
    { label: "Close keystore", icon: X, onSelect: () => void closeKeystore(ks.id), danger: true, divider: true, testId: "ks-close" },
  ];

  const entryDialog = dialog && "entry" in dialog ? dialog : null;
  const current = entryDialog ? ks.entries.find((e) => e.id === entryDialog.entry.id) ?? entryDialog.entry : null;
  const selectedEntries = ks.entries.filter((e) => selected.includes(e.id));
  const selectedLocked = selectedEntries.filter((e) => isKeyLocked(e));
  const typeOption = (t: EntryType, label: string, count: number) => {
    const Icon = TYPE_ICON[t];
    return {
      value: t,
      label: (
        <>
          <Icon className="w-3.5 h-3.5" /> {label}
        </>
      ),
      count,
    };
  };

  return (
    <div className="flex-1 min-h-0 flex">
      {navigator}
      <div className="flex-1 min-w-0 overflow-y-auto" data-testid="keystore-detail">
        <div className="max-w-[1320px] mx-auto px-8 py-7">
          <PageHeader
            leading={showNav}
            eyebrow={
              <span className="inline-flex items-center gap-2">
                <Badge tone="brand">{FORMAT_INFO[ks.format].label}</Badge>
                {ks.dirty && <Badge tone="warning">Unsaved changes</Badge>}
                {!ks.path && !ks.sealed && <Badge>Not saved yet</Badge>}
              </span>
            }
            title={ks.name}
            description={ks.path ? <PathText path={ks.path} /> : "In memory — use Save to write it to disk"}
            actions={
              ks.sealed ? undefined : (
                <>
                  <Button variant={ks.dirty ? "primary" : "secondary"} icon={Save} onClick={() => save(ks.id)} data-testid="ks-save" title={shortcutLabel("Save (Ctrl+S)")}>
                    Save
                  </Button>
                  <Menu
                    items={addMenu}
                    width={300}
                    trigger={(p) => (
                      <Button variant="primary" icon={Plus} {...p} data-testid="ks-add-entry">
                        Add entry <ChevronDown className="w-3.5 h-3.5 -mr-1" />
                      </Button>
                    )}
                  />
                  <Menu items={moreMenu} width={290} trigger={(p) => <IconButton icon={MoreHorizontal} label="More keystore actions" {...p} data-testid="ks-more" className="!w-9 !h-9 border border-line-strong" />} />
                </>
              )
            }
          />

          {ks.sealed ? (
            <Card className="py-12">
              <EmptyState
                icon={Lock}
                title={`${ks.name} is locked`}
                description={<PathText path={ks.path} copy={false} />}
                action={
                  <>
                    <Button variant="primary" icon={Unlock} onClick={() => unlockSealed(ks.id)} data-testid="unlock-sealed">
                      Enter password…
                    </Button>
                    <Button variant="ghost" onClick={() => closeKeystore(ks.id)}>
                      Remove from list
                    </Button>
                  </>
                }
              />
            </Card>
          ) : (
            <>
              {lockedKeyPairs.length + lockedOther.length > 0 && (
                <Alert
                  tone="info"
                  className="mb-4"
                  title={
                    lockedKeyPairs.length
                      ? `${lockedKeyPairs.length} key pair${lockedKeyPairs.length === 1 ? " is" : "s are"} locked`
                      : `${lockedOther.length} secret key${lockedOther.length === 1 ? " is" : "s are"} locked`
                  }
                  action={
                    <Button size="sm" icon={Unlock} onClick={() => ensureKeyAccess(ks.id, [...lockedKeyPairs, ...lockedOther].map((e) => e.id))} data-testid="unlock-all">
                      Unlock all…
                    </Button>
                  }
                >
                  Enter the key password to inspect, export, copy or sign with {lockedKeyPairs.length + lockedOther.length === 1 ? "it" : "them"}. Locked keys are kept as they are when you save.
                </Alert>
              )}

              <Card padded={false} className="overflow-hidden flex flex-col">
                <div className="px-5 py-3 border-b border-line flex flex-wrap items-center gap-3">
                  <Segmented<TypeFilter>
                    label="Filter by entry type"
                    value={typeFilter}
                    onChange={setTypeFilter}
                    options={[
                      { value: "ALL", label: "All", count: entries.length },
                      typeOption("KeyPair", "Key pairs", sum.keyPairs),
                      typeOption("TrustedCertificate", "Certificates", sum.trusted),
                      typeOption("SecretKey", "Secret keys", sum.secrets),
                    ]}
                  />
                  {allLabels.length > 0 && (
                    <select aria-label="Filter by label" value={labelFilter} onChange={(e) => setLabelFilter(e.target.value)} className="field !w-auto !h-8 pr-8 cursor-pointer">
                      <option value="">All labels</option>
                      {allLabels.map((l) => (
                        <option key={l} value={l}>
                          {l}
                        </option>
                      ))}
                    </select>
                  )}
                  <div className="flex-1" />
                  {selected.length > 0 && (
                    <div className="flex items-center gap-2">
                      <span className="text-[12px] text-faint">{selected.length} selected</span>
                      {selectedLocked.length > 0 && (
                        <Button size="sm" icon={Unlock} onClick={() => ensureKeyAccess(ks.id, selectedLocked.map((e) => e.id))}>
                          Unlock
                        </Button>
                      )}
                      <Button size="sm" icon={Trash2} onClick={() => void deleteWithConfirm(selectedEntries).then((deleted) => deleted && setSelected([]))} data-testid="bulk-delete">
                        Delete
                      </Button>
                      <Button
                        size="sm"
                        icon={Download}
                        title="Certificates of the selected entries as one PEM file"
                        data-testid="bulk-export"
                        onClick={async () => {
                          // A CA shared by several entries is written once.
                          const seen = new Set<string>();
                          const certs = selectedEntries.flatMap((e) => e.certificate_chain).filter((c) => c.pem && !seen.has(c.sha256_fingerprint) && seen.add(c.sha256_fingerprint));
                          if (!certs.length) return toast.error("The selection has no certificates to export.");
                          try {
                            const path = await pickSavePath("Export certificates", "selection.pem", [{ name: "PEM", extensions: ["pem"] }]);
                            if (!path) return;
                            await api.writeTextFile(path, certs.map((c) => c.pem).join(""));
                            toast.success(`Wrote ${certs.length} certificate${certs.length === 1 ? "" : "s"} to ${baseName(path)}.`, {
                              label: "Show in folder",
                              onClick: () => void revealItemInDir(path).catch(() => undefined),
                            });
                          } catch (err) {
                            toast.error(errorMessage(err));
                          }
                        }}
                      >
                        Export
                      </Button>
                      <Button size="sm" icon={Tag} onClick={() => setBulkLabelOpen(true)} data-testid="bulk-label">
                        Label
                      </Button>
                    </div>
                  )}
                  <SearchInput value={search} onChange={setSearch} placeholder="Search entries…" label="Search by alias, subject, issuer, algorithm, serial or SHA-256 fingerprint" className="w-full sm:w-64" />
                </div>
                <DataTable<KeystoreEntry>
                  label={`Entries in ${ks.name}`}
                  columns={columns}
                  rows={filtered}
                  rowKey={(e) => e.id}
                  selectedKey={focusEntryId}
                  onRowClick={(entry) => openEntry(ks.id, entry)}
                  initialSort={{ id: "type", dir: "asc" }}
                  empty={
                    entries.length === 0 ? (
                      <EmptyState
                        icon={KeyRound}
                        title="This keystore is empty"
                        description="Generate a key pair, import certificates, or paste entries copied from another keystore."
                        action={
                          <>
                            <Button variant="primary" icon={KeyRound} onClick={() => setDialog({ kind: "keypair" })} data-testid="empty-generate">
                              Generate key pair
                            </Button>
                            <Button icon={ShieldCheck} onClick={() => setDialog({ kind: "cert" })}>
                              Import certificate
                            </Button>
                            {clip && (
                              <Button icon={ClipboardPaste} onClick={paste}>
                                Paste
                              </Button>
                            )}
                          </>
                        }
                      />
                    ) : (
                      <EmptyState
                        icon={Search}
                        title="No matching entries"
                        description="Try a different search or filter."
                        action={
                          <Button
                            onClick={() => {
                              setSearch("");
                              setTypeFilter("ALL");
                              setLabelFilter("");
                            }}
                          >
                            Clear filters
                          </Button>
                        }
                      />
                    )
                  }
                  footer={
                    <>
                      <span>
                        Showing <strong className="text-ink font-semibold">{filtered.length}</strong> of {entries.length} entries
                        {lockedKeyPairs.length > 0 && ` · ${lockedKeyPairs.length} key pair${lockedKeyPairs.length === 1 ? "" : "s"} locked`}
                      </span>
                      {clip ? (
                        <span className="inline-flex items-center gap-2">
                          Clipboard: <span className="font-medium text-ink">{clip.entries.map((e) => e.alias).join(", ")}</span>
                          <Button size="sm" icon={ClipboardPaste} onClick={paste} data-testid="footer-paste">
                            Paste here
                          </Button>
                        </span>
                      ) : (
                        <span>{workspaces.length ? `${workspaces.length} workspaces` : ""}</span>
                      )}
                    </>
                  }
                />
              </Card>
              <StatStrip
                className="mt-4"
                label="Keystore summary"
                items={[
                  { label: "Entries", value: sum.total, hint: entryMix(sum) },
                  {
                    label: "Expiring soon",
                    value: sum.expiringWarning,
                    hint: sum.expiringCritical ? `${sum.expiringCritical} within ${settings.criticalDays} days` : `None within ${settings.criticalDays} days`,
                    hintTone: sum.expiringCritical ? "warning" : "neutral",
                  },
                  { label: "Needs action", value: sum.expired + sum.weak, hint: `${sum.expired} expired · ${sum.weak} weak`, hintTone: sum.expired + sum.weak ? "danger" : "success" },
                  { label: "Median key age", value: formatDuration(sum.medianAgeDays), hint: `Oldest ${formatDuration(sum.oldestAgeDays)}` },
                ]}
              />
            </>
          )}
        </div>
      </div>

      {/* Dialogs */}
      {dialog?.kind === "inspect" && current && (
        <EntryInspector
          keystore={ks}
          entry={current}
          onClose={() => setDialog(null)}
          onAction={(action, entry) =>
            action === "delete"
              ? void deleteWithConfirm([entry])
              : action === "unlock"
                ? withKey(entry, () => setDialog({ kind: "inspect", entry }))
                : setDialog({ kind: action, entry })
          }
        />
      )}
      <ExportDialog entry={dialog?.kind === "export" ? current : null} keystoreId={ks.id} onClose={() => setDialog(null)} />
      <CsrDialog entry={dialog?.kind === "csr" ? current : null} onClose={() => setDialog(null)} />
      <CaReplyDialog keystore={ks} entry={dialog?.kind === "reply" ? current : null} onClose={() => setDialog(null)} />
      <RenameDialog keystore={ks} entry={dialog?.kind === "rename" ? current : null} onClose={() => setDialog(null)} />
      <LabelsDialog keystore={ks} entry={dialog?.kind === "labels" ? current : null} onClose={() => setDialog(null)} />
      <AssignWorkspaceDialog entry={dialog?.kind === "workspaces" ? current : null} onClose={() => setDialog(null)} />
      <GenerateKeyPairDialog keystore={ks} open={dialog?.kind === "keypair" || dialog?.kind === "ca"} presetCa={dialog?.kind === "ca"} onClose={() => setDialog(null)} />
      <GenerateSecretKeyDialog keystore={ks} open={dialog?.kind === "secret"} onClose={() => setDialog(null)} />
      <ImportCertificateDialog keystore={ks} open={dialog?.kind === "cert"} onClose={() => setDialog(null)} />
      <ImportKeyPairDialog keystore={ks} open={dialog?.kind === "importkp"} onClose={() => setDialog(null)} />
      <ImportFromKeystoreDialog keystore={ks} open={dialog?.kind === "merge"} onClose={() => setDialog(null)} />
      {dialog?.kind === "password" && <ChangePasswordDialog keystore={ks} onClose={() => setDialog(null)} />}
      {dialog?.kind === "keypw" && current && (
        <ChangeKeyPasswordDialog
          entry={current}
          format={ks.format}
          onClose={() => setDialog(null)}
          onSave={(password) => {
            replaceEntry(ks.id, { ...current, key_password: password });
            toast.success(`'${current.alias}' will be saved with its own key password.`);
            setDialog(null);
          }}
        />
      )}
      {diffOpen && (
        <DiffDialog
          keystore={ks}
          others={keystores.filter((k) => k.id !== ks.id && !k.sealed)}
          result={diff.result}
          error={diff.error}
          busy={diff.busy}
          onClose={() => {
            setDiffOpen(false);
            setDiff({ result: null, error: null, busy: false });
          }}
          onPick={async (other) => {
            setDiff({ result: null, error: null, busy: true });
            let right: { entries: KeystoreEntry[] };
            if (other === "disk") {
              try {
                right = await api.openKeystore(ks.path, getPassword(ks.id) ?? "");
              } catch (err) {
                const wrongPassword = classifyError(err).kind === "wrong-password";
                setDiff({
                  result: null,
                  busy: false,
                  error: wrongPassword ? "The file on disk does not open with this keystore's password. If you changed the password, save first or compare after saving." : errorMessage(err),
                });
                return;
              }
            } else {
              right = other;
            }
            // diffEntries(left, right): "added" is in right only, "removed" in left only.
            const d = diffEntries(
              ks.entries.map((e) => ({ alias: e.alias, fingerprint: e.sha256_fingerprint })),
              right.entries.map((e) => ({ alias: e.alias, fingerprint: e.sha256_fingerprint }))
            );
            setDiff({ result: { against: other === "disk" ? "the file on disk" : other.name, onlyHere: d.removed, onlyThere: d.added, changed: d.changed }, error: null, busy: false });
          }}
        />
      )}
      {bulkLabelOpen && (
        <BulkLabelDialog
          count={selectedEntries.length}
          suggestions={allLabels}
          onClose={() => setBulkLabelOpen(false)}
          onApply={(label) => {
            for (const entry of selectedEntries) setEntryLabels(ks.id, entry.id, [...new Set([...entry.labels, label])]);
            toast.success(`Added '${label}' to ${selectedEntries.length} ${selectedEntries.length === 1 ? "entry" : "entries"}.`);
          }}
        />
      )}
    </div>
  );
};

export default KeystoresView;
