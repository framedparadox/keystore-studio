import React, { useMemo, useState } from "react";
import { Eye, EyeOff, FolderArchive, Lock, LockOpen, ShieldCheck, Unlock } from "lucide-react";
import { KeystoreEntry, KeystoreFile } from "../types/crypto";
import { Badge, Button, Card, Column, DataTable, KpiCard, Page, PageHeader, Segmented } from "../components/ui";
import { EntryNameCell, EntryTypeBadge } from "../components/entry";

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
      cell: () => <span className="font-mono text-[12px] text-muted select-text">{mask("unlocked-key-pass")}</span>,
    },
    {
      id: "state",
      header: "State",
      sortValue: (r) => (r.entry.locked ? 0 : 1),
      cell: (r) =>
        r.entry.locked ? (
          <Badge tone="warning" icon={Lock}>
            Locked
          </Badge>
        ) : (
          <Badge tone="success" icon={Unlock}>
            Unlocked
          </Badge>
        ),
    },
    {
      id: "act",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "120px",
      cell: (r) => (
        <Button size="sm" icon={r.entry.locked ? LockOpen : Lock} onClick={() => toggle(r)}>
          {r.entry.locked ? "Unlock" : "Lock"}
        </Button>
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

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <KpiCard label="Password-protected stores" value={`${protectedStores}/${keystores.length}`} icon={ShieldCheck} tone="success" hint="Stores requiring a passphrase to open" />
        <KpiCard label="Locked entries" value={locked} icon={Lock} tone="warning" hint="Hidden from export and signing" />
        <KpiCard label="Unlocked entries" value={rows.length - locked} icon={Unlock} hint="Available to every operation" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mt-4">
        {keystores.map((ks) => (
          <Card key={ks.id} className="!p-4">
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
            <div className="mt-3 flex items-center justify-between rounded-control bg-surface-2 border border-line px-3 h-9">
              <span className="text-[12px] text-faint">Store passphrase</span>
              <span className="font-mono text-[12px] text-ink select-text">{mask("changeit#2026")}</span>
            </div>
          </Card>
        ))}
      </div>

      <Card padded={false} className="mt-4 overflow-hidden">
        <div className="px-5 py-3 border-b border-line flex items-center justify-between gap-3">
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
    </Page>
  );
};
