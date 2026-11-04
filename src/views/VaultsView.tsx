import React, { useMemo, useState } from "react";
import { Check, Copy, Eye, EyeOff, FolderArchive, Lock, LockOpen, ShieldCheck, Unlock } from "lucide-react";
import { KeystoreEntry, KeystoreFile } from "../types/crypto";
import { Badge, Button, Card, Column, DataTable, KpiCard, Page, PageHeader, Segmented } from "../components/ui";
import { EntryNameCell, EntryTypeBadge } from "../components/entry";

const STORE_PASS = "changeit#2026";
const KEY_PASS = "unlocked-key-pass";

const CopyButton: React.FC<{ value: string; label: string }> = ({ value, label }) => {
  const [copied, setCopied] = useState(false);
  const copy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  };
  const Icon = copied ? Check : Copy;
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      title={label}
      className="w-7 h-7 rounded-control flex items-center justify-center text-subtle hover:text-ink hover:bg-surface-3 cursor-pointer"
    >
      <Icon className="w-3.5 h-3.5" />
    </button>
  );
};

interface VaultsViewProps {
  keystores: KeystoreFile[];
  onUpdateKeystore: (ks: KeystoreFile) => void;
}

type Row = { entry: KeystoreEntry; ks: KeystoreFile };

export const VaultsView: React.FC<VaultsViewProps> = ({ keystores, onUpdateKeystore }) => {
  const [reveal, setReveal] = useState(false);
  const [filter, setFilter] = useState<"all" | "locked" | "unlocked">("all");

  const rows = useMemo<Row[]>(() => keystores.flatMap((ks) => ks.entries.map((entry) => ({ entry, ks }))), [keystores]);
  const locked = rows.filter((r) => r.entry.locked).length;
  const protectedStores = keystores.filter((k) => k.password_protected).length;
  const visible = rows.filter((r) => (filter === "all" ? true : filter === "locked" ? r.entry.locked : !r.entry.locked));

  const toggle = ({ ks, entry }: Row) =>
    onUpdateKeystore({
      ...ks,
      entries: ks.entries.map((en) => (en.id === entry.id ? { ...en, locked: !en.locked } : en)),
    });

  const mask = (s: string) => (reveal ? s : "•".repeat(12));

  const columns: Column<Row>[] = [
    { id: "entry", header: "Entry", width: "34%", sortValue: (r) => r.entry.alias, cell: (r) => <EntryNameCell entry={r.entry} /> },
    { id: "ks", header: "Keystore", sortValue: (r) => r.ks.name, cell: (r) => <span className="text-muted">{r.ks.name}</span> },
    { id: "type", header: "Type", hideBelow: "xl", sortValue: (r) => r.entry.entry_type, cell: (r) => <EntryTypeBadge type={r.entry.entry_type} /> },
    {
      id: "pass",
      header: "Key passphrase",
      cell: () => (
        <span className="inline-flex items-center gap-1">
          <span className="font-mono text-[12px] text-muted select-text">{mask(KEY_PASS)}</span>
          <CopyButton value={KEY_PASS} label="Copy key passphrase" />
        </span>
      ),
    },
    {
      id: "state",
      header: "Lock / Unlock",
      sortValue: (r) => (r.entry.locked ? 0 : 1),
      cell: (r) => (
        <div className="inline-flex items-center gap-3">
          {r.entry.locked ? (
            <Badge tone="warning" icon={Lock}>
              Locked
            </Badge>
          ) : (
            <Badge tone="success" icon={Unlock}>
              Unlocked
            </Badge>
          )}
          <Button size="sm" icon={r.entry.locked ? LockOpen : Lock} onClick={() => toggle(r)}>
            {r.entry.locked ? "Unlock" : "Lock"}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <Page>
      <PageHeader
        title="Vaults"
        description="Store passphrases and per-entry lock state for every loaded keystore."
        actions={
          <Button icon={reveal ? EyeOff : Eye} onClick={() => setReveal(!reveal)}>
            {reveal ? "Mask passphrases" : "Reveal passphrases"}
          </Button>
        }
      />

      <Card padded={false} className="overflow-hidden">
        <div className="px-5 py-3 border-b border-line">
          <h3 className="text-[14px] font-semibold text-ink">Store passphrases</h3>
          <p className="text-[12px] text-faint">Passphrase required to open each loaded keystore.</p>
        </div>
        <div className="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {keystores.map((ks) => (
            <div key={ks.id} className="rounded-card border border-line bg-surface p-4">
              <div className="flex items-center gap-3">
                <span className="w-9 h-9 rounded-control bg-surface-3 text-muted flex items-center justify-center shrink-0">
                  <FolderArchive className="w-[18px] h-[18px]" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-semibold text-ink truncate">{ks.name}</div>
                  <div className="text-[12px] text-faint">
                    {ks.entries.filter((e) => e.locked).length} of {ks.entries.length} entries locked
                  </div>
                </div>
                <Badge tone="brand">{ks.format}</Badge>
              </div>
              <div className="mt-3 flex items-center justify-between gap-2 rounded-control bg-surface-2 border border-line pl-3 pr-1 h-9">
                <span className="text-[12px] text-faint">Store passphrase</span>
                <span className="flex items-center gap-1">
                  <span className="font-mono text-[12px] text-ink select-text">{mask(STORE_PASS)}</span>
                  <CopyButton value={STORE_PASS} label="Copy store passphrase" />
                </span>
              </div>
            </div>
          ))}
        </div>
        <div className="px-5 py-3 border-y border-line flex items-center justify-between gap-3">
          <div>
            <h3 className="text-[14px] font-semibold text-ink">Entries</h3>
            <p className="text-[12px] text-faint">Lock an entry to keep it out of exports and signing.</p>
          </div>
          <Segmented
            label="Lock filter"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: rows.length },
              { value: "locked", label: "Locked", count: locked },
              { value: "unlocked", label: "Unlocked", count: rows.length - locked },
            ]}
          />
        </div>
        <DataTable<Row>
          label="Vault entries"
          columns={columns}
          rows={visible}
          rowKey={(r) => r.entry.id}
          initialSort={{ id: "ks", dir: "asc" }}
          footer={<span>{visible.length} of {rows.length} entries</span>}
        />
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
        <KpiCard label="Password-protected stores" value={`${protectedStores}/${keystores.length}`} icon={ShieldCheck} tone="success" hint="Stores requiring a passphrase to open" />
        <KpiCard label="Locked entries" value={locked} icon={Lock} tone="warning" hint="Hidden from export and signing" />
        <KpiCard label="Unlocked entries" value={rows.length - locked} icon={Unlock} hint="Available to every operation" />
      </div>
    </Page>
  );
};
