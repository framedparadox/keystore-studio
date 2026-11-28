import React, { useLayoutEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { AlertTriangle, CalendarClock, Check, Edit3, Eye, FileBadge, FolderOpen, FolderPlus, KeyRound, Layers, Plus, Trash2, X } from "lucide-react";
import type { KeystoreEntry, OpenCertificate, OpenKeystore, Workspace } from "../types/crypto";
import { useStore, uid } from "../state/store";
import { baseName } from "../lib/files";
import { CERTIFICATE_ROLE_LABEL, ENTRY_TYPE_LABEL, certificateRole, cnOf } from "../lib/keystore";
import { isCertificateId, shortFingerprint } from "../lib/certificates";
import { daysUntilExpiry, plural, summarize } from "../lib/metrics";
import { Badge, Button, Card, Column, DataTable, EmptyState, IconButton, KpiCard, Modal, Page, PageHeader, SearchInput, Select, TextArea, TextInput, useConfirm, useToast } from "../components/ui";
import { AlgorithmCell, EntryNameCell, ExpiryCell, HealthBadge } from "../components/entry";
import { AssignWorkspaceDialog, EntryInspector, ExportDialog } from "../components/EntryDialogs";
import { FolderFiles } from "../components/FolderFiles";
import { CertificateInspector } from "../components/CertificateDialogs";

interface Member {
  id: string;
  /** A certificate from the Certificates page, or an entry of a keystore. */
  kind: "certificate" | "entry";
  entry: KeystoreEntry | null;
  ks: OpenKeystore | null;
  cert: OpenCertificate | null;
  /** For entries whose keystore is not open, and certificates that are not open. */
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
  useLayoutEffect(() => {
    setName(initial?.name ?? "");
    setDesc(initial?.description ?? "");
    setEnv(initial?.environment ?? "Production");
  }, [initial, open]);
  if (!open) return null;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    const ts = new Date().toISOString();
    saveWorkspace({ ...initial, id: initial?.id ?? `ws-${uid()}`, name: name.trim(), description: desc.trim(), environment: env, created_at: initial?.created_at ?? ts, updated_at: ts, entryIds: initial?.entryIds ?? [] });
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
  const { workspaces, activeWorkspaceId, setActiveWorkspaceId, deleteWorkspace, toggleWorkspaceEntry, keystores, certificates, setTab, selectKeystore, ensureKeyAccess, addFolderWorkspace, desktop } = useStore();
  const confirm = useConfirm();
  const toast = useToast();
  const [search, setSearch] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerSearch, setPickerSearch] = useState("");
  const [editing, setEditing] = useState<{ ws: Workspace | null } | null>(null);
  // The inspector holds ids, not the entry: an unlock replaces the entry, and a stored copy would still show it locked.
  const [inspect, setInspect] = useState<{ ksId: string; entryId: string } | null>(null);
  const inspectKs = inspect ? keystores.find((k) => k.id === inspect.ksId) : undefined;
  const inspectEntry = inspectKs?.entries.find((e) => e.id === inspect?.entryId);
  const [exporting, setExporting] = useState<{ entry: KeystoreEntry; keystoreId?: string } | null>(null);
  const [inspectCertId, setInspectCertId] = useState<string | null>(null);
  const [assigning, setAssigning] = useState<KeystoreEntry | null>(null);

  const active = workspaces.find((w) => w.id === activeWorkspaceId) ?? workspaces[0] ?? null;
  const all = useMemo(() => keystores.flatMap((ks) => ks.entries.map((entry) => ({ entry, ks }))), [keystores]);
  const byId = useMemo(() => new Map(all.map((x) => [x.entry.id, x])), [all]);
  const certById = useMemo(() => new Map(certificates.map((c) => [c.id, c])), [certificates]);
  const inspectCert = inspectCertId ? certById.get(inspectCertId) ?? null : null;

  const members: Member[] = useMemo(() => {
    if (!active) return [];
    return active.entryIds.map((id): Member => {
      if (isCertificateId(id)) {
        const cert = certById.get(id) ?? null;
        return { id, kind: "certificate", entry: cert?.entry ?? null, ks: null, cert, alias: cert?.entry.alias ?? shortFingerprint(id), location: cert?.source ?? "Certificates" };
      }
      const hit = byId.get(id);
      const [location, alias] = [id.slice(0, id.lastIndexOf("::")), id.slice(id.lastIndexOf("::") + 2)];
      return { id, kind: "entry", entry: hit?.entry ?? null, ks: hit?.ks ?? null, cert: null, alias, location };
    });
  }, [active, byId, certById]);
  const q = search.trim().toLowerCase();
  const visible = members.filter((m) => !q || m.alias.toLowerCase().includes(q) || (m.entry?.subject ?? "").toLowerCase().includes(q) || m.location.toLowerCase().includes(q));
  const loaded = members.filter((m) => m.entry).map((m) => m.entry!);
  const sum = summarize(loaded);
  const unavailable = members.length - loaded.length;
  const keystoreCount = new Set(members.filter((m) => m.kind === "entry").map((m) => m.location)).size;
  const certCount = members.filter((m) => m.kind === "certificate").length;

  /** Opens the inspector, asking for the key password first when the key is locked. Every way in goes through here. */
  const inspectMember = (m: Member) => {
    if (m.cert) {
      setInspectCertId(m.cert.id);
      return;
    }
    if (!m.entry || !m.ks) return;
    const ksId = m.ks.id;
    const entryId = m.entry.id;
    ensureKeyAccess(ksId, [entryId], () => setInspect({ ksId, entryId }));
  };

  const pickerQuery = pickerSearch.trim().toLowerCase();
  const pickerRows = all.filter(({ entry, ks }) => {
    const s = pickerQuery;
    return !s || entry.alias.toLowerCase().includes(s) || entry.subject.toLowerCase().includes(s) || ks.name.toLowerCase().includes(s);
  });
  const pickerCerts = certificates.filter((c) => !pickerQuery || c.entry.alias.toLowerCase().includes(pickerQuery) || c.entry.subject.toLowerCase().includes(pickerQuery) || c.source.toLowerCase().includes(pickerQuery) || "certificates".includes(pickerQuery));

  const columns: Column<Member>[] = [
    {
      id: "entry",
      header: "Entry",
      width: "30%",
      sortValue: (m) => m.alias,
      cell: (m) =>
        m.entry ? (
          <EntryNameCell entry={m.entry} meta={m.cert ? `Certificate · ${m.cert.source}` : `${cnOf(m.entry.subject)} · ${m.ks?.name}`} />
        ) : m.kind === "certificate" ? (
          <div className="min-w-0">
            <div className="font-medium text-muted truncate font-mono text-[12px]">SHA-256 {m.alias}</div>
            <div className="text-[12px] text-faint truncate">Certificate not open — open its file again to see it</div>
          </div>
        ) : (
          <div className="min-w-0">
            <div className="font-medium text-muted truncate">{m.alias}</div>
            <div className="text-[12px] text-faint truncate">{baseName(m.location)} — keystore not open</div>
          </div>
        ),
    },
    { id: "alg", header: "Algorithm", cell: (m) => (m.entry ? <AlgorithmCell entry={m.entry} /> : <span className="text-faint">—</span>) },
    { id: "exp", header: "Expires", width: "210px", sortValue: (m) => (m.entry ? daysUntilExpiry(m.entry) : null), cell: (m) => (m.entry ? <ExpiryCell entry={m.entry} /> : <span className="text-faint">—</span>) },
    { id: "status", header: "Status", hideBelow: "xl", cell: (m) => (m.entry ? <HealthBadge entry={m.entry} /> : <Badge>Unavailable</Badge>) },
    {
      id: "act",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "120px",
      cell: (m) => (
        <div className="inline-flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
          {m.entry && <IconButton icon={Eye} label="Inspect" onClick={() => inspectMember(m)} />}
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
        icon={Layers}
        title="Workspaces"
        description="Group keys and certificates from your keystores and the Certificates page by project, environment or audit scope. A workspace can also follow a folder. Workspaces never change keystore or certificate files."
        actions={
          <>
            {active && (
              <Button icon={FolderPlus} onClick={() => setPickerOpen(true)} data-testid="workspace-assign">
                Add entries
              </Button>
            )}
            {desktop && (
              <Button icon={FolderOpen} onClick={() => void addFolderWorkspace()} data-testid="workspace-folder">
                Add folder
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
            description="Create a workspace for a project, cluster or audit and add entries from any keystore, or certificates from the Certificates page. Or add a folder to gather the keystores and certificates in it."
            action={
              <>
                <Button variant="primary" icon={Plus} onClick={() => setEditing({ ws: null })}>
                  New workspace
                </Button>
                {desktop && (
                  <Button icon={FolderOpen} onClick={() => void addFolderWorkspace()}>
                    Add folder
                  </Button>
                )}
              </>
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
                        {ws.folder ? <FolderOpen className="w-4 h-4" /> : <Layers className="w-4 h-4" />}
                      </span>
                      <h3 className="text-[14px] font-semibold text-ink truncate">{ws.name}</h3>
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
                  <p className="text-[13px] text-faint mt-2 line-clamp-2 min-h-[36px]">{ws.description || "No description"}</p>
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
                <KpiCard
                  label="Entries"
                  value={members.length}
                  icon={Layers}
                  tone="brand"
                  hint={unavailable ? `${unavailable} not open` : [keystoreCount && `From ${plural(keystoreCount, "keystore")}`, certCount && plural(certCount, "certificate")].filter(Boolean).join(" · ") || "Nothing added yet"}
                />
                <KpiCard label="Key pairs / certificates" value={`${sum.keyPairs} / ${sum.trusted}`} icon={KeyRound} hint={plural(sum.secrets, "secret key")} />
                <KpiCard label="Expiring soon" value={sum.expiringWarning} icon={CalendarClock} tone="warning" hint={`${sum.expiringCritical} critical`} hintTone={sum.expiringCritical ? "warning" : "neutral"} />
                <KpiCard label="Needs action" value={sum.expired + sum.weak} icon={AlertTriangle} tone="danger" hint={`${sum.expired} expired · ${sum.weak} weak`} hintTone={sum.expired + sum.weak ? "danger" : "success"} />
              </div>
              {active.folder && <FolderFiles key={active.id} workspace={{ ...active, folder: active.folder }} />}
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
                  onRowClick={inspectMember}
                  initialSort={{ id: "exp", dir: "asc" }}
                  empty={
                    <EmptyState
                      icon={FolderPlus}
                      title={search ? "No matching entries" : `Nothing in “${active.name}” yet`}
                      description="Add entries from any open keystore, or certificates from the Certificates page."
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
          description="Click entries from any open keystore, or certificates from the Certificates page, to include or exclude them."
          footer={
            <Button variant="primary" onClick={() => setPickerOpen(false)}>
              Done
            </Button>
          }
        >
          <SearchInput value={pickerSearch} onChange={setPickerSearch} placeholder="Search alias, subject, keystore or file" className="mb-3" />
          {all.length === 0 && certificates.length === 0 ? (
            <EmptyState icon={KeyRound} title="Nothing to add yet" description="Open a keystore, or open certificate files on the Certificates page." />
          ) : (
            <ul className="space-y-1.5" aria-label="Entries and certificates">
              {pickerCerts.map((c) => {
                const on = active.entryIds.includes(c.id);
                return (
                  <li key={c.id}>
                    <button
                      onClick={() => toggleWorkspaceEntry(active.id, c.id)}
                      aria-pressed={on}
                      data-testid={`picker-cert-${c.entry.alias}`}
                      className={clsx("w-full p-3 rounded-card flex items-center gap-3 cursor-pointer border text-left transition", on ? "bg-brand-tint/70 border-brand-soft-hover" : "hover:bg-surface-2 border-transparent")}
                    >
                      <span className={clsx("w-5 h-5 rounded-control flex items-center justify-center border shrink-0", on ? "bg-brand border-brand text-on-accent" : "border-line-strong bg-surface")}>{on && <Check className="w-3.5 h-3.5" />}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-[13px] font-semibold text-ink truncate">{c.entry.alias}</span>
                        <span className="block text-[12px] text-faint truncate">
                          {CERTIFICATE_ROLE_LABEL[certificateRole(c.entry.certificate_chain[0])]} · {c.source}
                        </span>
                      </span>
                      <Badge icon={FileBadge}>Certificates</Badge>
                    </button>
                  </li>
                );
              })}
              {pickerRows.map(({ entry, ks }) => {
                const on = active.entryIds.includes(entry.id);
                return (
                  <li key={entry.id}>
                    <button
                      onClick={() => toggleWorkspaceEntry(active.id, entry.id)}
                      aria-pressed={on}
                      className={clsx("w-full p-3 rounded-card flex items-center gap-3 cursor-pointer border text-left transition", on ? "bg-brand-tint/70 border-brand-soft-hover" : "hover:bg-surface-2 border-transparent")}
                    >
                      <span className={clsx("w-5 h-5 rounded-control flex items-center justify-center border shrink-0", on ? "bg-brand border-brand text-on-accent" : "border-line-strong bg-surface")}>{on && <Check className="w-3.5 h-3.5" />}</span>
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

      {inspect && inspectKs && inspectEntry && (
        <EntryInspector
          keystore={inspectKs}
          entry={inspectEntry}
          onClose={() => setInspect(null)}
          onAction={(action, entry) => {
            if (action === "export") {
              setExporting({ entry, keystoreId: inspectKs.id });
              return;
            }
            if (action === "unlock") {
              ensureKeyAccess(inspectKs.id, [entry.id]);
              return;
            }
            // Other actions live on the Keystores page.
            selectKeystore(inspectKs.id);
            setInspect(null);
            setTab("keystores");
          }}
        />
      )}
      {inspectCert && (
        <CertificateInspector
          certificate={inspectCert}
          onClose={() => setInspectCertId(null)}
          onExport={() => setExporting({ entry: inspectCert.entry })}
          onWorkspaces={() => setAssigning(inspectCert.entry)}
        />
      )}
      <AssignWorkspaceDialog entry={assigning} onClose={() => setAssigning(null)} />
      <ExportDialog entry={exporting?.entry ?? null} keystoreId={exporting?.keystoreId} onClose={() => setExporting(null)} />
    </Page>
  );
};
