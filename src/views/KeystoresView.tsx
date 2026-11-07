import React, { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import {
  ChevronDown,
  ClipboardPaste,
  Copy,
  Download,
  Edit3,
  Eye,
  FileKey2,
  FilePlus2,
  FileSignature,
  FileText,
  FolderArchive,
  FolderOpen,
  Import,
  KeyRound,
  Layers,
  Lock,
  MoreHorizontal,
  Plus,
  Reply,
  Save,
  Scissors,
  Search,
  ShieldCheck,
  Tag,
  Trash2,
  Unlock,
  X,
  KeySquare,
} from "lucide-react";
import type { KeystoreEntry, OpenKeystore } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { baseName, pickSavePath, safeFileStem, withExtension } from "../lib/files";
import { FORMAT_INFO, canHoldSecretKeys } from "../lib/keystore";
import { diffEntries } from "../lib/diff";
import { daysUntilExpiry, entryHealth, formatDuration, summarize } from "../lib/metrics";
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
  KpiCard,
  Menu,
  MenuItem,
  Modal,
  Page,
  PageHeader,
  PasswordInput,
  SearchInput,
  Segmented,
  useConfirm,
  useToast,
} from "../components/ui";
import { AlgorithmCell, EntryNameCell, ExpiryCell, HealthBadge, LabelList } from "../components/entry";
import { AssignWorkspaceDialog, CaReplyDialog, CsrDialog, EntryInspector, ExportDialog, LabelsDialog, RenameDialog } from "../components/EntryDialogs";
import { GenerateKeyPairDialog, GenerateSecretKeyDialog, ImportCertificateDialog, ImportFromKeystoreDialog, ImportKeyPairDialog } from "../components/AddEntryDialogs";
import { KeyPasswordDialog } from "../components/KeystoreDialogs";

type TypeFilter = "ALL" | "KeyPair" | "TrustedCertificate" | "SecretKey";
type Dialog =
  | null
  | { kind: "inspect" | "export" | "csr" | "reply" | "rename" | "labels" | "workspaces" | "unlock" | "keypw"; entry: KeystoreEntry }
  | { kind: "keypair" | "ca" | "secret" | "cert" | "importkp" | "merge" | "password" };

interface Clip {
  entries: KeystoreEntry[];
  mode: "copy" | "cut";
  from: string;
}
// Survives page switches for the whole session.
let clipboardMemory: Clip | null = null;

const HEALTH_RANK = { "at-risk": 0, attention: 1, healthy: 2 } as const;

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

const ChangeKeyPasswordDialog: React.FC<{ entry: KeystoreEntry; onClose: () => void; onSave: (password: string) => void }> = ({ entry, onClose, onSave }) => {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const error = pw && pw.length < 6 ? "At least 6 characters" : pw2 && pw !== pw2 ? "Passwords do not match" : undefined;
  return (
    <Modal open onClose={onClose} icon={KeySquare} size="sm" title={`Key password for ${entry.alias}`} footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!pw || !!error} onClick={() => onSave(pw)}>Save on next write</Button></>}>
      <div className="space-y-3">
        <PasswordInput label="New key password" value={pw} onChange={setPw} />
        <PasswordInput label="Confirm" value={pw2} onChange={setPw2} error={error} />
        <p className="text-[12px] text-faint">The store password still opens the file. This password wraps only this key, the way keytool -keypasswd does.</p>
      </div>
    </Modal>
  );
};

const DiffDialog: React.FC<{ keystore: OpenKeystore; others: OpenKeystore[]; text: string; onClose: () => void; onPick: (other: OpenKeystore | "disk") => void }> = ({ keystore, others, text, onClose, onPick }) => (
  <Modal open onClose={onClose} icon={FileText} title={`Compare ${keystore.name}`} size="md" footer={<Button onClick={onClose}>Close</Button>}>
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {keystore.path && <Button size="sm" onClick={() => onPick("disk")}>File on disk</Button>}
        {others.map((o) => <Button key={o.id} size="sm" onClick={() => onPick(o)}>{o.name}</Button>)}
      </div>
      {text && <pre className="text-[12.5px] whitespace-pre-wrap font-mono">{text}</pre>}
    </div>
  </Modal>
);

export const KeystoresView: React.FC = () => {
  const store = useStore();
  const { keystores, activeKeystore: ks, selectKeystore, openFiles, setNewKeystoreOpen, save, closeKeystore, deleteEntries, addEntries, replaceEntry, setEntryLabels, getPassword, unlockSealed, workspaces } = store;
  const toast = useToast();
  const confirm = useConfirm();

  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("ALL");
  const [labelFilter, setLabelFilter] = useState("");
  const [dialog, setDialog] = useState<Dialog>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [diffOpen, setDiffOpen] = useState(false);
  const [diffText, setDiffText] = useState("");
  const [clip, setClip] = useState<Clip | null>(clipboardMemory);
  useEffect(() => {
    clipboardMemory = clip;
  }, [clip]);
  useEffect(() => {
    setSearch("");
    setLabelFilter("");
  }, [ks?.id]);

  const entries = ks?.entries ?? [];
  const allLabels = useMemo(() => [...new Set(entries.flatMap((e) => e.labels))].sort(), [entries]);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter(
      (e) =>
        (typeFilter === "ALL" || e.entry_type === typeFilter) &&
        (!labelFilter || e.labels.includes(labelFilter)) &&
        (!q ||
          e.alias.toLowerCase().includes(q) ||
          e.subject.toLowerCase().includes(q) ||
          e.issuer.toLowerCase().includes(q) ||
          e.algorithm.toLowerCase().includes(q) ||
          e.serial_number.toLowerCase().includes(q) ||
          e.sha256_fingerprint.toLowerCase().replace(/:/g, "").includes(q.replace(/:/g, "")))
    );
  }, [entries, typeFilter, labelFilter, search]);
  const sum = summarize(entries);

  if (!ks) {
    return (
      <Page>
        <PageHeader title="Keystores" description="Open PKCS#12, JKS and JCEKS keystores, or create a new one." />
        <Card className="py-16">
          <EmptyState
            icon={FolderArchive}
            title="No keystores open"
            description="Open an existing keystore (you can also drag files onto the window) or create a new one."
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
      </Page>
    );
  }

  const deleteWithConfirm = async (list: KeystoreEntry[]) => {
    const ok = await confirm({
      title: list.length === 1 ? `Delete '${list[0].alias}'?` : `Delete ${list.length} entries?`,
      message: `${list.length === 1 ? "The entry" : "They"} will be removed from ${ks.name}. You can undo with Ctrl+Z; the file changes only when you save.`,
      confirmLabel: "Delete",
      danger: true,
    });
    if (ok !== true) return;
    deleteEntries(ks.id, list.map((e) => e.id));
    setDialog(null);
    toast.success(`Deleted ${list.length === 1 ? `'${list[0].alias}'` : `${list.length} entries`}.`, { label: "Undo", onClick: store.undo });
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
      toast.error(`${ks.format} cannot store secret keys; '${blocked[0].alias}' was not pasted.`);
    }
    const added = addEntries(
      ks.id,
      clip.entries.filter((e) => !blocked.includes(e))
    );
    if (added.length) toast.success(`Pasted ${added.map((a) => `'${a.alias}'`).join(", ")} into ${ks.name}.`);
    if (clip.mode === "cut") setClip(null);
  };

  const unlockKey = async (entry: KeystoreEntry, keyPassword: string): Promise<string | null> => {
    const storePw = getPassword(ks.id);
    if (!ks.path || !storePw) return "Save the keystore first.";
    try {
      const reread = await api.openKeystore(ks.path, storePw, { [entry.alias]: keyPassword });
      const fresh = reread.entries.find((e) => e.alias === entry.alias);
      if (!fresh || fresh.locked) return "Incorrect key password.";
      replaceEntry(ks.id, { ...fresh, id: entry.id, labels: entry.labels });
      toast.success(`Unlocked '${entry.alias}'. Saving keeps its key password separate from the store password.`);
      setDialog(null);
      return null;
    } catch (err) {
      return errorMessage(err);
    }
  };

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

  const rowMenu = (entry: KeystoreEntry): MenuItem[] => [
    { label: "Inspect", icon: Eye, onSelect: () => setDialog({ kind: "inspect", entry }) },
    { label: "Export…", icon: Download, onSelect: () => setDialog({ kind: "export", entry }), testId: "menu-export" },
    ...(entry.entry_type === "KeyPair" && !entry.locked
      ? [
          { label: "Generate CSR…", icon: FileSignature, onSelect: () => setDialog({ kind: "csr", entry }), testId: "menu-csr" },
          { label: "Import CA reply…", icon: Reply, onSelect: () => setDialog({ kind: "reply", entry }), testId: "menu-reply" },
        ]
      : []),
    ...(entry.locked ? [{ label: "Unlock key…", icon: Unlock, onSelect: () => setDialog({ kind: "unlock", entry }) }] : []),
    { label: "Rename…", icon: Edit3, onSelect: () => setDialog({ kind: "rename", entry }), divider: true, testId: "menu-rename" },
    { label: "Labels…", icon: Tag, onSelect: () => setDialog({ kind: "labels", entry }) },
    { label: "Workspaces…", icon: Layers, onSelect: () => setDialog({ kind: "workspaces", entry }) },
    { label: "Clone", icon: Copy, onSelect: () => { addEntries(ks.id, [entry]); toast.success(`Cloned '${entry.alias}'.`); } },
    { label: "Change key password…", icon: KeySquare, onSelect: () => setDialog({ kind: "keypw", entry }), disabled: entry.locked || entry.entry_type === "TrustedCertificate" },
    { label: "Copy", icon: Copy, onSelect: () => copyEntries([entry], "copy"), divider: true },
    { label: "Cut", icon: Scissors, onSelect: () => copyEntries([entry], "cut") },
    { label: "Delete", icon: Trash2, onSelect: () => deleteWithConfirm([entry]), danger: true, divider: true, testId: "menu-delete" },
  ];

  const columns: Column<KeystoreEntry>[] = [
    {
      id: "pick",
      header: "",
      width: "36px",
      cell: (e) => (
        <input
          type="checkbox"
          aria-label={`Select ${e.alias}`}
          checked={selected.includes(e.id)}
          onClick={(ev) => ev.stopPropagation()}
          onChange={() => setSelected((cur) => (cur.includes(e.id) ? cur.filter((id) => id !== e.id) : [...cur, e.id]))}
        />
      ),
    },
    { id: "alias", header: "Alias", width: "30%", sortValue: (e) => e.alias.toLowerCase(), cell: (e) => <EntryNameCell entry={e} /> },
    { id: "alg", header: "Algorithm", sortValue: (e) => e.algorithm, cell: (e) => <AlgorithmCell entry={e} /> },
    { id: "expiry", header: "Expires", width: "210px", sortValue: (e) => daysUntilExpiry(e), cell: (e) => <ExpiryCell entry={e} /> },
    { id: "status", header: "Status", sortValue: (e) => HEALTH_RANK[entryHealth(e)], cell: (e) => <HealthBadge entry={e} /> },
    { id: "labels", header: "Labels", hideBelow: "2xl", cell: (e) => <LabelList labels={e.labels} /> },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "112px",
      cell: (entry) => (
        <div className="inline-flex items-center gap-0.5" onClick={(ev) => ev.stopPropagation()}>
          <IconButton icon={Download} label={`Export ${entry.alias}`} onClick={() => setDialog({ kind: "export", entry })} />
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
      icon: Lock,
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
    { label: "Compare…", hint: "Against another open keystore or the file on disk", icon: FileText, onSelect: () => setDiffOpen(true) },
    { label: "Change password…", icon: KeySquare, onSelect: () => setDialog({ kind: "password" }) },
    { label: "Export inventory (CSV)…", icon: FileText, onSelect: exportCsv, testId: "ks-export-csv" },
    ...(ks.path ? [{ label: "Show in folder", icon: FolderOpen, onSelect: () => void revealItemInDir(ks.path).catch(() => undefined) }] : []),
    { label: "Close keystore", icon: X, onSelect: () => void closeKeystore(ks.id), danger: true, divider: true, testId: "ks-close" },
  ];

  const entryDialog = dialog && "entry" in dialog ? dialog : null;
  const current = entryDialog ? ks.entries.find((e) => e.id === entryDialog.entry.id) ?? entryDialog.entry : null;

  return (
    <Page>
      {/* Open keystores */}
      <div className="flex flex-wrap items-stretch gap-2 mb-5" role="tablist" aria-label="Open keystores">
        {keystores.map((k) => {
          const active = k.id === ks.id;
          const issues = k.entries.filter((e) => entryHealth(e) !== "healthy").length;
          return (
            <button
              key={k.id}
              role="tab"
              aria-selected={active}
              data-testid={`ks-tab-${k.name}`}
              onClick={() => selectKeystore(k.id)}
              className={clsx(
                "text-left rounded-card border bg-surface pl-3 pr-3.5 py-2.5 flex items-center gap-2.5 transition cursor-pointer min-w-[180px] max-w-[280px]",
                active ? "border-brand ring-4 ring-brand-soft/60" : "border-line shadow-card hover:border-line-strong"
              )}
            >
              <span className={clsx("w-8 h-8 rounded-control flex items-center justify-center shrink-0", active ? "bg-brand-tint text-brand" : "bg-surface-3 text-muted")}>
                {k.sealed ? <Lock className="w-4 h-4" /> : <FolderArchive className="w-4 h-4" />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="text-[13px] font-semibold text-ink truncate">{k.name}</span>
                  {k.dirty && <span className="w-2 h-2 rounded-full bg-warning-fill shrink-0" title="Unsaved changes" aria-label="Unsaved changes" />}
                </span>
                <span className="block text-[12px] text-faint">{k.sealed ? "Locked" : `${k.format} · ${k.entries.length} ${k.entries.length === 1 ? "entry" : "entries"}`}</span>
              </span>
              {issues > 0 && <Badge tone="warning">{issues}</Badge>}
            </button>
          );
        })}
        <div className="flex flex-col gap-1.5 justify-center">
          <Button size="sm" icon={FolderOpen} onClick={() => openFiles()} data-testid="ks-open">
            Open…
          </Button>
          <Button size="sm" icon={FilePlus2} onClick={() => setNewKeystoreOpen(true)} data-testid="ks-new">
            New…
          </Button>
        </div>
      </div>

      <PageHeader
        eyebrow={
          <span className="inline-flex items-center gap-2">
            <Badge tone="brand">{FORMAT_INFO[ks.format].label}</Badge>
            {ks.dirty && <Badge tone="warning">Unsaved changes</Badge>}
            {!ks.path && !ks.sealed && <Badge>Not saved yet</Badge>}
          </span>
        }
        title={ks.name}
        description={<span className="font-mono text-[12px] break-all">{ks.path || "In memory — use Save to write it to disk"}</span>}
        actions={
          ks.sealed ? undefined : (
            <>
              <Button variant={ks.dirty ? "primary" : "secondary"} icon={Save} onClick={() => save(ks.id)} data-testid="ks-save" title="Save (Ctrl+S)">
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
              <Menu items={moreMenu} trigger={(p) => <IconButton icon={MoreHorizontal} label="More keystore actions" {...p} data-testid="ks-more" className="!w-9 !h-9 border border-line-strong" />} />
            </>
          )
        }
      />

      {ks.sealed ? (
        <Card className="py-12">
          <EmptyState
            icon={Lock}
            title={`${ks.name} is locked`}
            description={<span className="font-mono text-[12px] break-all">{ks.path}</span>}
            action={
              <>
                <Button variant="primary" icon={Unlock} onClick={() => unlockSealed(ks.id)} data-testid="unlock-sealed">
                  Enter password…
                </Button>
                {store.vault.exists && !store.vault.unlocked && <Button onClick={() => store.requestVaultUnlock()}>Unlock vault</Button>}
                <Button variant="ghost" onClick={() => closeKeystore(ks.id)}>
                  Remove from list
                </Button>
              </>
            }
          />
        </Card>
      ) : (
        <>
          {entries.some((e) => e.locked) && (
            <Alert tone="warning" className="mb-4" title="Some private keys use a separate key password">
              They are kept as-is when you save to {ks.format}. Use “Unlock key…” from the entry menu to work with them.
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
                  { value: "KeyPair", label: "Key pairs", count: sum.keyPairs },
                  { value: "TrustedCertificate", label: "Certificates", count: sum.trusted },
                  { value: "SecretKey", label: "Secret keys", count: sum.secrets },
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
                  <Button size="sm" icon={Trash2} onClick={() => void deleteWithConfirm(ks.entries.filter((e) => selected.includes(e.id))).then(() => setSelected([]))}>
                    Delete
                  </Button>
                  <Button
                    size="sm"
                    icon={Download}
                    onClick={async () => {
                      const pem = ks.entries.filter((e) => selected.includes(e.id)).flatMap((e) => e.certificate_chain.map((c) => c.pem)).join("");
                      if (!pem) return toast.error("The selection has no certificates to export.");
                      const path = await pickSavePath("Export certificates", "selection.pem", [{ name: "PEM", extensions: ["pem"] }]).catch(() => null);
                      if (!path) return;
                      await api.writeTextFile(path, pem);
                      toast.success(`Wrote certificates to ${path}.`);
                    }}
                  >
                    Export
                  </Button>
                  <Button
                    size="sm"
                    icon={Tag}
                    onClick={() => {
                      const label = window.prompt("Label to add to the selected entries");
                      if (!label?.trim()) return;
                      for (const id of selected) {
                        const entry = ks.entries.find((e) => e.id === id);
                        if (entry) setEntryLabels(ks.id, id, [...new Set([...entry.labels, label.trim()])]);
                      }
                    }}
                  >
                    Label
                  </Button>
                </div>
              )}
              <SearchInput value={search} onChange={setSearch} placeholder="Search alias, subject, serial, fingerprint" className="w-full sm:w-80" />
            </div>
            <DataTable<KeystoreEntry>
              label={`Entries in ${ks.name}`}
              columns={columns}
              rows={filtered}
              rowKey={(e) => e.id}
              onRowClick={(entry) => setDialog({ kind: "inspect", entry })}
              initialSort={{ id: "alias", dir: "asc" }}
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

          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
            <KpiCard label="Entries" value={sum.total} hint={`${sum.keyPairs} key pairs · ${sum.trusted} certificates · ${sum.secrets} secret keys`} />
            <KpiCard
              label="Expiring soon"
              value={sum.expiringWarning}
              hint={sum.expiringCritical ? `${sum.expiringCritical} within ${store.settings.criticalDays} days` : `None within ${store.settings.criticalDays} days`}
              hintTone={sum.expiringCritical ? "warning" : "neutral"}
            />
            <KpiCard label="Needs action" value={sum.expired + sum.weak} hint={`${sum.expired} expired · ${sum.weak} weak`} hintTone={sum.expired + sum.weak ? "danger" : "success"} />
            <KpiCard label="Median key age" value={formatDuration(sum.medianAgeDays)} hint={`Oldest ${formatDuration(sum.oldestAgeDays)}`} />
          </div>
        </>
      )}

      {/* Dialogs */}
      {dialog?.kind === "inspect" && current && (
        <EntryInspector
          keystore={ks}
          entry={current}
          onClose={() => setDialog(null)}
          onAction={(action, entry) => (action === "delete" ? void deleteWithConfirm([entry]) : setDialog({ kind: action, entry }))}
        />
      )}
      <ExportDialog entry={dialog?.kind === "export" ? current : null} onClose={() => setDialog(null)} />
      <CsrDialog entry={dialog?.kind === "csr" ? current : null} onClose={() => setDialog(null)} />
      <CaReplyDialog keystore={ks} entry={dialog?.kind === "reply" ? current : null} onClose={() => setDialog(null)} />
      <RenameDialog keystore={ks} entry={dialog?.kind === "rename" ? current : null} onClose={() => setDialog(null)} />
      <LabelsDialog keystore={ks} entry={dialog?.kind === "labels" ? current : null} onClose={() => setDialog(null)} />
      <AssignWorkspaceDialog entry={dialog?.kind === "workspaces" ? current : null} onClose={() => setDialog(null)} />
      <KeyPasswordDialog open={dialog?.kind === "unlock"} alias={current?.alias ?? ""} onClose={() => setDialog(null)} onSubmit={(pw) => (current ? unlockKey(current, pw) : Promise.resolve(null))} />
      <GenerateKeyPairDialog keystore={ks} open={dialog?.kind === "keypair" || dialog?.kind === "ca"} presetCa={dialog?.kind === "ca"} onClose={() => setDialog(null)} />
      <GenerateSecretKeyDialog keystore={ks} open={dialog?.kind === "secret"} onClose={() => setDialog(null)} />
      <ImportCertificateDialog keystore={ks} open={dialog?.kind === "cert"} onClose={() => setDialog(null)} />
      <ImportKeyPairDialog keystore={ks} open={dialog?.kind === "importkp"} onClose={() => setDialog(null)} />
      <ImportFromKeystoreDialog keystore={ks} open={dialog?.kind === "merge"} onClose={() => setDialog(null)} />
      {dialog?.kind === "password" && <ChangePasswordDialog keystore={ks} onClose={() => setDialog(null)} />}
      {dialog?.kind === "keypw" && current && (
        <ChangeKeyPasswordDialog
          entry={current}
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
          text={diffText}
          onClose={() => { setDiffOpen(false); setDiffText(""); }}
          onPick={async (other) => {
            const right = other === "disk" ? await api.openKeystore(ks.path, getPassword(ks.id) ?? "").catch((err) => { setDiffText(errorMessage(err)); return null; }) : other;
            if (!right) return;
            const d = diffEntries(
              ks.entries.map((e) => ({ alias: e.alias, fingerprint: e.sha256_fingerprint })),
              right.entries.map((e) => ({ alias: e.alias, fingerprint: e.sha256_fingerprint })),
            );
            setDiffText([`Added: ${d.added.join(", ") || "—"}`, `Removed: ${d.removed.join(", ") || "—"}`, `Changed fingerprint: ${d.changed.join(", ") || "—"}`].join("\n"));
          }}
        />
      )}
    </Page>
  );
};

export default KeystoresView;
