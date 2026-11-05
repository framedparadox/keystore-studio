import React, { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { AlertTriangle, CalendarClock, Check, Edit3, Eye, FolderPlus, KeyRound, Layers, Plus, Trash2, X } from "lucide-react";
import type { KeystoreEntry, OpenKeystore, Workspace } from "../types/crypto";
import { useStore, uid } from "../state/store";
import { baseName } from "../lib/files";
import { ENTRY_TYPE_LABEL, cnOf } from "../lib/keystore";
import { daysUntilExpiry, summarize } from "../lib/metrics";
import { Badge, Button, Card, Column, DataTable, EmptyState, IconButton, KpiCard, Modal, Page, PageHeader, SearchInput, Select, TextArea, TextInput, useConfirm, useToast } from "../components/ui";
import { AlgorithmCell, EntryNameCell, ExpiryCell, HealthBadge } from "../components/entry";
import { EntryInspector, ExportDialog } from "../components/EntryDialogs";

interface Member {
  id: string;
  entry: KeystoreEntry | null;
  ks: OpenKeystore | null;
  /** For entries whose keystore is not open. */
  alias: string;
  location: string;
}

const ENVIRONMENTS: Workspace["environment"][] = ["Production", "Staging", "Development", "Compliance"];

const WorkspaceDialog: React.FC<{ initial: Workspace | null; open: boolean; onClose: () => void }> = ({ initial, open, onClose }) => {
  const { saveWorkspace } = useStore();
  const toast = useToast();
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [env, setEnv] = useState<Workspace["environment"]>("Production");
  useEffect(() => {
    setName(initial?.name ?? "");
    setDesc(initial?.description ?? "");
    setEnv(initial?.environment ?? "Production");
  }, [initial, open]);
  if (!open) return null;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    const ts = new Date().toISOString();
    saveWorkspace({ id: initial?.id ?? `ws-${uid()}`, name: name.trim(), description: desc.trim(), environment: env, created_at: initial?.created_at ?? ts, updated_at: ts, entryIds: initial?.entryIds ?? [] });
    toast.success(initial ? `Updated workspace “${name.trim()}”.` : `Created workspace “${name.trim()}”.`);
    onClose();
  };
  return (
    <Modal
      open
      onClose={onClose}
      icon={Layers}
      size="sm"
      title={initial ? "Edit workspace" : "New workspace"}
      testId="workspace-dialog"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="ws-form" disabled={!name.trim()} data-testid="workspace-save">
            {initial ? "Save" : "Create"}
          </Button>
        </>
      }
    >
      <form id="ws-form" onSubmit={submit} className="space-y-4">
        <TextInput label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Payments mTLS" autoFocus data-testid="workspace-name" />
        <TextArea label="Description" rows={2} value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Which services or audit scope does it cover?" />
        <Select label="Environment" value={env} onChange={(e) => setEnv(e.target.value as Workspace["environment"])}>
          {ENVIRONMENTS.map((x) => (
            <option key={x}>{x}</option>
          ))}
        </Select>
      </form>
    </Modal>
  );
};

export const WorkspacesView: React.FC = () => {
  const { workspaces, activeWorkspaceId, setActiveWorkspaceId, deleteWorkspace, toggleWorkspaceEntry, keystores, setTab, selectKeystore } = useStore();
  const confirm = useConfirm();
  const toast = useToast();
  const [search, setSearch] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerSearch, setPickerSearch] = useState("");
  const [editing, setEditing] = useState<{ ws: Workspace | null } | null>(null);
  const [inspect, setInspect] = useState<{ entry: KeystoreEntry; ks: OpenKeystore } | null>(null);
  const [exporting, setExporting] = useState<KeystoreEntry | null>(null);

  const active = workspaces.find((w) => w.id === activeWorkspaceId) ?? workspaces[0] ?? null;
  const all = useMemo(() => keystores.flatMap((ks) => ks.entries.map((entry) => ({ entry, ks }))), [keystores]);
  const byId = useMemo(() => new Map(all.map((x) => [x.entry.id, x])), [all]);

  const members: Member[] = useMemo(() => {
    if (!active) return [];
    return active.entryIds.map((id) => {
      const hit = byId.get(id);
      const [location, alias] = [id.slice(0, id.lastIndexOf("::")), id.slice(id.lastIndexOf("::") + 2)];
      return { id, entry: hit?.entry ?? null, ks: hit?.ks ?? null, alias, location };
    });
  }, [active, byId]);
  const q = search.trim().toLowerCase();
  const visible = members.filter((m) => !q || m.alias.toLowerCase().includes(q) || (m.entry?.subject ?? "").toLowerCase().includes(q) || m.location.toLowerCase().includes(q));
  const loaded = members.filter((m) => m.entry).map((m) => m.entry!);
  const sum = summarize(loaded);
  const unavailable = members.length - loaded.length;

  const pickerRows = all.filter(({ entry, ks }) => {
    const s = pickerSearch.trim().toLowerCase();
    return !s || entry.alias.toLowerCase().includes(s) || entry.subject.toLowerCase().includes(s) || ks.name.toLowerCase().includes(s);
  });

  const columns: Column<Member>[] = [
    {
      id: "entry",
      header: "Entry",
      width: "30%",
      sortValue: (m) => m.alias,
      cell: (m) =>
        m.entry ? (
          <EntryNameCell entry={m.entry} meta={`${cnOf(m.entry.subject)} · ${m.ks?.name}`} />
        ) : (
          <div className="min-w-0">
            <div className="font-medium text-muted truncate">{m.alias}</div>
            <div className="text-[12px] text-faint truncate">{baseName(m.location)} — keystore not open</div>
          </div>
        ),
    },
    { id: "alg", header: "Algorithm", cell: (m) => (m.entry ? <AlgorithmCell entry={m.entry} /> : <span className="text-subtle">—</span>) },
    { id: "exp", header: "Expires", width: "210px", sortValue: (m) => (m.entry ? daysUntilExpiry(m.entry) : null), cell: (m) => (m.entry ? <ExpiryCell entry={m.entry} /> : <span className="text-subtle">—</span>) },
    { id: "status", header: "Status", hideBelow: "xl", cell: (m) => (m.entry ? <HealthBadge entry={m.entry} /> : <Badge>Unavailable</Badge>) },
    {
      id: "act",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "120px",
      cell: (m) => (
        <div className="inline-flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
          {m.entry && <IconButton icon={Eye} label="Inspect" onClick={() => setInspect({ entry: m.entry!, ks: m.ks! })} />}
          <IconButton
            icon={X}
            label="Remove from workspace"
            tone="danger"
            onClick={() => {
              toggleWorkspaceEntry(active!.id, m.id);
              toast.success(`Removed '${m.alias}' from ${active!.name}.`);
            }}
          />
        </div>
      ),
    },
  ];

  return (
    <Page>
      <PageHeader
        title="Workspaces"
        description="Group certificates and keys from several keystores by project, environment or audit scope. Workspaces never change keystore files."
        actions={
          <>
            {active && (
              <Button icon={FolderPlus} onClick={() => setPickerOpen(true)} data-testid="workspace-assign">
                Add entries
              </Button>
            )}
            <Button variant="primary" icon={Plus} onClick={() => setEditing({ ws: null })} data-testid="workspace-new">
              New workspace
            </Button>
          </>
        }
      />

      {workspaces.length === 0 ? (
        <Card className="py-14">
          <EmptyState
            icon={Layers}
            title="No workspaces yet"
            description="Create a workspace for a project, cluster or audit and add entries from any keystore."
            action={
              <Button variant="primary" icon={Plus} onClick={() => setEditing({ ws: null })}>
                New workspace
              </Button>
            }
          />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4" role="tablist" aria-label="Workspaces">
            {workspaces.map((ws) => {
              const selected = ws.id === active?.id;
              return (
                <div
                  key={ws.id}
                  role="tab"
                  tabIndex={0}
                  aria-selected={selected}
                  onClick={() => setActiveWorkspaceId(ws.id)}
                  onKeyDown={(e) => e.key === "Enter" && setActiveWorkspaceId(ws.id)}
                  className={clsx("rounded-card bg-surface border p-4 flex flex-col cursor-pointer transition", selected ? "border-brand ring-4 ring-brand-soft/60" : "border-line shadow-card hover:border-line-strong")}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className={clsx("w-8 h-8 rounded-control flex items-center justify-center shrink-0", selected ? "bg-brand-tint text-brand" : "bg-surface-3 text-muted")}>
                        <Layers className="w-4 h-4" />
                      </span>
                      <h3 className="text-[13.5px] font-semibold text-ink truncate">{ws.name}</h3>
                    </div>
                    <div className="flex items-center gap-0.5 shrink-0" onClick={(e) => e.stopPropagation()}>
                      <Badge tone={ws.environment === "Production" ? "brand" : "neutral"}>{ws.environment}</Badge>
                      <IconButton icon={Edit3} label={`Edit ${ws.name}`} onClick={() => setEditing({ ws })} />
                      <IconButton
                        icon={Trash2}
                        label={`Delete ${ws.name}`}
                        tone="danger"
                        onClick={async () => {
                          const ok = await confirm({ title: `Delete “${ws.name}”?`, message: "Only the grouping is removed; entries stay in their keystores.", confirmLabel: "Delete", danger: true });
                          if (ok === true) deleteWorkspace(ws.id);
                        }}
                      />
                    </div>
                  </div>
                  <p className="text-[12.5px] text-faint mt-2 line-clamp-2 min-h-[36px]">{ws.description || "No description"}</p>
                  <div className="flex items-center justify-between pt-3 mt-3 border-t border-line text-[12px] text-faint">
                    <span>
                      <strong className="text-ink font-semibold">{ws.entryIds.length}</strong> entries
                    </span>
                    <span>Updated {new Date(ws.updated_at).toLocaleDateString()}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {active && (
            <>
              <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
                <KpiCard label="Entries" value={members.length} icon={Layers} tone="brand" hint={unavailable ? `${unavailable} in keystores that are not open` : `From ${new Set(members.map((m) => m.location)).size} keystores`} />
                <KpiCard label="Key pairs / certificates" value={`${sum.keyPairs} / ${sum.trusted}`} icon={KeyRound} hint={`${sum.secrets} secret keys`} />
                <KpiCard label="Expiring soon" value={sum.expiringWarning} icon={CalendarClock} tone="warning" hint={`${sum.expiringCritical} critical`} hintTone={sum.expiringCritical ? "warning" : "neutral"} />
                <KpiCard label="Needs action" value={sum.expired + sum.weak} icon={AlertTriangle} tone="danger" hint={`${sum.expired} expired · ${sum.weak} weak`} hintTone={sum.expired + sum.weak ? "danger" : "success"} />
              </div>
              <Card padded={false} className="mt-4 overflow-hidden">
                <div className="px-5 py-3 border-b border-line flex flex-wrap items-center justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="text-[14px] font-semibold text-ink truncate">{active.name}</h3>
                    <p className="text-[12px] text-faint">Assigned certificates and keys</p>
                  </div>
                  <SearchInput value={search} onChange={setSearch} placeholder="Filter entries" className="w-64" />
                </div>
                <DataTable<Member>
                  label={`Entries in ${active.name}`}
                  columns={columns}
                  rows={visible}
                  rowKey={(m) => m.id}
                  onRowClick={(m) => m.entry && setInspect({ entry: m.entry, ks: m.ks! })}
                  initialSort={{ id: "exp", dir: "asc" }}
                  empty={
                    <EmptyState
                      icon={FolderPlus}
                      title={search ? "No matching entries" : `Nothing in “${active.name}” yet`}
                      description="Add entries from any open keystore."
                      action={
                        <>
                          <Button variant="primary" icon={Plus} onClick={() => setPickerOpen(true)}>
                            Add entries
                          </Button>
                          <Button onClick={() => setTab("keystores")}>Browse keystores</Button>
                        </>
                      }
                    />
                  }
                  footer={<span>{visible.length} of {members.length} entries</span>}
                />
              </Card>
            </>
          )}
        </>
      )}

      <WorkspaceDialog open={!!editing} initial={editing?.ws ?? null} onClose={() => setEditing(null)} />

      {pickerOpen && active && (
        <Modal
          open
          onClose={() => setPickerOpen(false)}
          icon={FolderPlus}
          size="lg"
          title={`Add entries to “${active.name}”`}
          description="Click entries from any open keystore to include or exclude them."
          footer={
            <Button variant="primary" onClick={() => setPickerOpen(false)}>
              Done
            </Button>
          }
        >
          <SearchInput value={pickerSearch} onChange={setPickerSearch} placeholder="Search alias, subject or keystore" className="mb-3" />
          {all.length === 0 ? (
            <EmptyState icon={KeyRound} title="No entries available" description="Open a keystore first." />
          ) : (
            <ul className="space-y-1.5">
              {pickerRows.map(({ entry, ks }) => {
                const on = active.entryIds.includes(entry.id);
                return (
                  <li key={entry.id}>
                    <button
                      onClick={() => toggleWorkspaceEntry(active.id, entry.id)}
                      aria-pressed={on}
                      className={clsx("w-full p-3 rounded-card flex items-center gap-3 cursor-pointer border text-left transition", on ? "bg-brand-tint/70 border-brand-soft-hover" : "hover:bg-surface-2 border-transparent")}
                    >
                      <span className={clsx("w-5 h-5 rounded-control flex items-center justify-center border shrink-0", on ? "bg-brand border-brand text-white" : "border-line-strong bg-surface")}>{on && <Check className="w-3.5 h-3.5" />}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-[13px] font-semibold text-ink truncate">{entry.alias}</span>
                        <span className="block text-[12px] text-faint truncate">
                          {ENTRY_TYPE_LABEL[entry.entry_type]} · {entry.entry_type === "SecretKey" ? entry.subject : cnOf(entry.subject)}
                        </span>
                      </span>
                      <Badge tone="brand">{ks.name}</Badge>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Modal>
      )}

      {inspect && (
        <EntryInspector
          keystore={inspect.ks}
          entry={inspect.entry}
          onClose={() => setInspect(null)}
          onAction={(action, entry) => {
            if (action === "export") {
              setExporting(entry);
              return;
            }
            // Other actions live on the Keystores page.
            selectKeystore(inspect.ks.id);
            setInspect(null);
            setTab("keystores");
          }}
        />
      )}
      <ExportDialog entry={exporting} onClose={() => setExporting(null)} />
    </Page>
  );
};
