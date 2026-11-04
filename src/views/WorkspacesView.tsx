import React, { useState, useMemo } from "react";
import {
  Layers,
  Plus,
  Trash2,
  KeyRound,
  AlertTriangle,
  Search,
  Check,
  X,
  Eye,
  Download,
  Copy,
  FolderArchive,
  ArrowUpRight,
  CheckCircle2,
  FolderPlus,
  Filter,
  CalendarClock,
} from "lucide-react";
import clsx from "clsx";
import {
  Badge,
  Button,
  Card,
  Column,
  DataTable,
  EmptyState,
  IconButton,
  KpiCard,
  Modal,
  Page,
  PageHeader,
  SearchInput,
} from "../components/ui";
import { AlgorithmCell, EntryNameCell, ExpiryCell, HealthBadge } from "../components/entry";
import { daysUntilExpiry, summarize } from "../lib/metrics";
import { invoke } from "@tauri-apps/api/core";
import {
  Workspace,
  KeystoreFile,
  KeystoreEntry,
  TabType,
  ExportPayloadResult,
} from "../types/crypto";

interface WorkspacesViewProps {
  workspaces: Workspace[];
  activeWorkspaceId: string;
  onSelectWorkspace: (id: string) => void;
  onCreateWorkspace: (ws: Workspace) => void;
  onDeleteWorkspace: (id: string) => void;
  onToggleEntryInWorkspace: (workspaceId: string, entryId: string) => void;
  keystores: KeystoreFile[];
  onNavigateTab: (tab: TabType) => void;
  onSelectKeystore: (ksId: string) => void;
}

export const WorkspacesView: React.FC<WorkspacesViewProps> = ({
  workspaces,
  activeWorkspaceId,
  onSelectWorkspace,
  onCreateWorkspace,
  onDeleteWorkspace,
  onToggleEntryInWorkspace,
  keystores,
  onNavigateTab,
  onSelectKeystore,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [showAddCertsModal, setShowAddCertsModal] = useState(false);
  const [certPickerSearch, setCertPickerSearch] = useState("");
  const [certPickerStoreFilter, setCertPickerStoreFilter] = useState<string>("ALL");
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [pendingDeleteWs, setPendingDeleteWs] = useState<Workspace | null>(null);

  const [showNewWorkspaceModal, setShowNewWorkspaceModal] = useState(false);
  const [newWsName, setNewWsName] = useState("");
  const [newWsDesc, setNewWsDesc] = useState("");
  const [newWsEnv, setNewWsEnv] = useState<Workspace["environment"]>("Production");
  const [newWsColor, setNewWsColor] = useState<Workspace["color"]>("blue");

  const [inspectEntry, setInspectEntry] = useState<{
    entry: KeystoreEntry;
    keystore: KeystoreFile;
  } | null>(null);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 4000);
  };

  const activeWorkspace = useMemo(
    () =>
      workspaces.find((w) => w.id === activeWorkspaceId) || workspaces[0],
    [workspaces, activeWorkspaceId]
  );

  // Map all entries across all keystores with their parent keystore reference
  const allEntriesWithStore = useMemo(() => {
    const list: { entry: KeystoreEntry; keystore: KeystoreFile }[] = [];
    for (const ks of keystores) {
      for (const entry of ks.entries) {
        list.push({ entry, keystore: ks });
      }
    }
    return list;
  }, [keystores]);

  // Entries belonging to the active workspace
  const workspaceEntries = useMemo(() => {
    if (!activeWorkspace) return [];
    const idSet = new Set(activeWorkspace.entryIds);
    return allEntriesWithStore.filter(({ entry }) => {
      if (!idSet.has(entry.id)) return false;
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        entry.alias.toLowerCase().includes(q) ||
        entry.subject.toLowerCase().includes(q) ||
        entry.algorithm.toLowerCase().includes(q) ||
        entry.sha256_fingerprint.toLowerCase().includes(q)
      );
    });
  }, [activeWorkspace, allEntriesWithStore, searchQuery]);

  // Filtered entries inside the "Add Certificates to Workspace" modal
  const pickerEntries = useMemo(() => {
    return allEntriesWithStore.filter(({ entry, keystore }) => {
      if (certPickerStoreFilter !== "ALL" && keystore.id !== certPickerStoreFilter) {
        return false;
      }
      if (!certPickerSearch.trim()) return true;
      const q = certPickerSearch.toLowerCase();
      return (
        entry.alias.toLowerCase().includes(q) ||
        entry.subject.toLowerCase().includes(q) ||
        keystore.name.toLowerCase().includes(q) ||
        entry.algorithm.toLowerCase().includes(q)
      );
    });
  }, [allEntriesWithStore, certPickerStoreFilter, certPickerSearch]);

  // Workspace KPI stats
  const stats = useMemo(() => {
    const total = workspaceEntries.length;
    const keyPairs = workspaceEntries.filter(
      (x) => x.entry.entry_type === "KeyPair"
    ).length;
    const trustedCerts = workspaceEntries.filter(
      (x) => x.entry.entry_type === "TrustedCertificate"
    ).length;
    const pqcReady = workspaceEntries.filter((x) => x.entry.is_post_quantum).length;
    const warnings = workspaceEntries.filter(
      (x) => x.entry.is_expired || x.entry.is_weak
    ).length;
    return { total, keyPairs, trustedCerts, pqcReady, warnings };
  }, [workspaceEntries]);

  const handleCreateWorkspaceSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWsName.trim()) return;
    const now = new Date().toISOString().split("T")[0];
    const ws: Workspace = {
      id: `ws-${Date.now()}`,
      name: newWsName.trim(),
      description:
        newWsDesc.trim() ||
        "Custom logical certificate workspace across KeyStores",
      environment: newWsEnv,
      color: newWsColor,
      created_at: now,
      updated_at: "Just now",
      entryIds: [],
    };
    onCreateWorkspace(ws);
    onSelectWorkspace(ws.id);
    setNewWsName("");
    setNewWsDesc("");
    setShowNewWorkspaceModal(false);
    showToast(`Created workspace "${ws.name}"`);
  };

  const handleExportEntryToDisk = async (entry: KeystoreEntry) => {
    try {
      const res = await invoke<ExportPayloadResult>("export_entry", {
        entry,
        exportTarget: "PEM_CERT",
      });
      showToast(
        res.saved_path
          ? `Exported ${res.filename} to ${res.saved_path}`
          : `Exported ${res.filename}`
      );
    } catch (err) {
      showToast(`Export error: ${String(err)}`);
    }
  };

  const wsSummary = summarize(workspaceEntries.map((x) => x.entry));

  const columns: Column<{ entry: KeystoreEntry; keystore: KeystoreFile }>[] = [
    {
      id: "entry",
      header: "Entry",
      width: "30%",
      sortValue: (r) => r.entry.alias,
      cell: (r) => <EntryNameCell entry={r.entry} />,
    },
    {
      id: "ks",
      header: "Source keystore",
      sortValue: (r) => r.keystore.name,
      cell: ({ keystore }) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onSelectKeystore(keystore.id);
            onNavigateTab("keystores");
          }}
          className="inline-flex items-center gap-1.5 text-muted hover:text-brand cursor-pointer"
        >
          <FolderArchive className="w-3.5 h-3.5 text-subtle" />
          <span className="truncate max-w-[180px]">{keystore.name}</span>
          <ArrowUpRight className="w-3 h-3 text-subtle" />
        </button>
      ),
    },
    { id: "alg", header: "Algorithm", sortValue: (r) => r.entry.algorithm, cell: (r) => <AlgorithmCell entry={r.entry} /> },
    {
      id: "exp",
      header: "Expires",
      width: "210px",
      sortValue: (r) => daysUntilExpiry(r.entry),
      cell: (r) => <ExpiryCell entry={r.entry} />,
    },
    { id: "status", header: "Status", hideBelow: "xl", cell: (r) => <HealthBadge entry={r.entry} /> },
    {
      id: "act",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "130px",
      cell: ({ entry, keystore }) => (
        <div className="inline-flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
          <IconButton icon={Eye} label="Inspect" onClick={() => setInspectEntry({ entry, keystore })} />
          <IconButton icon={Download} label="Export PEM" onClick={() => handleExportEntryToDisk(entry)} />
          <IconButton
            icon={X}
            label="Remove from workspace"
            tone="danger"
            onClick={() => {
              onToggleEntryInWorkspace(activeWorkspace.id, entry.id);
              showToast(`Removed "${entry.alias}" from ${activeWorkspace.name}`);
            }}
          />
        </div>
      ),
    },
  ];

  return (
    <Page>
      {toastMsg && (
        <div
          role="status"
          className="fixed bottom-6 right-6 z-[60] max-w-md flex items-start gap-2.5 bg-surface border border-line shadow-pop rounded-card px-4 py-3 text-[13px] text-ink"
        >
          <CheckCircle2 className="w-4 h-4 mt-0.5 text-success shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      <PageHeader
        title="Workspaces"
        description="Group certificates, key pairs and CA roots from several keystores by project, environment or audit scope."
        actions={
          <>
            <Button icon={FolderPlus} onClick={() => setShowAddCertsModal(true)}>
              Assign entries
            </Button>
            <Button variant="primary" icon={Plus} onClick={() => setShowNewWorkspaceModal(true)}>
              New workspace
            </Button>
          </>
        }
      />

      {/* Workspace selector tiles */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4" role="tablist" aria-label="Workspaces">
        {workspaces.map((ws) => {
          const isSelected = ws.id === activeWorkspace?.id;
          return (
            <div
              key={ws.id}
              role="tab"
              tabIndex={0}
              aria-selected={isSelected}
              onClick={() => onSelectWorkspace(ws.id)}
              onKeyDown={(e) => e.key === "Enter" && onSelectWorkspace(ws.id)}
              className={clsx(
                "rounded-card bg-surface border p-4 flex flex-col cursor-pointer transition",
                isSelected ? "border-brand ring-4 ring-brand-soft/60" : "border-line shadow-card hover:border-line-strong"
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                  <span
                    className={clsx(
                      "w-8 h-8 rounded-control flex items-center justify-center shrink-0",
                      isSelected ? "bg-brand-tint text-brand" : "bg-surface-3 text-muted"
                    )}
                  >
                    <Layers className="w-4 h-4" />
                  </span>
                  <h3 className="text-[13.5px] font-semibold text-ink truncate">{ws.name}</h3>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <Badge tone={ws.environment === "Production" ? "brand" : "neutral"}>{ws.environment}</Badge>
                  {workspaces.length > 1 && (
                    <IconButton
                      icon={Trash2}
                      label={`Delete workspace ${ws.name}`}
                      tone="danger"
                      onClick={(e) => {
                        e.stopPropagation();
                        setPendingDeleteWs(ws);
                      }}
                    />
                  )}
                </div>
              </div>
              <p className="text-[12.5px] text-faint mt-2 line-clamp-2 min-h-[36px]">{ws.description}</p>
              <div className="flex items-center justify-between pt-3 mt-3 border-t border-line text-[12px] text-faint">
                <span>
                  <strong className="text-ink font-semibold">{ws.entryIds.length}</strong> entries
                </span>
                <span>Updated {ws.updated_at}</span>
              </div>
            </div>
          );
        })}
      </div>

      {activeWorkspace && (
        <>
          <Card padded={false} className="mt-4 overflow-hidden">
            <div className="px-5 py-3 border-b border-line flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-[14px] font-semibold text-ink truncate">{activeWorkspace.name}</h3>
                <p className="text-[12px] text-faint">Assigned certificates and keys</p>
              </div>
              <div className="flex items-center gap-2">
                <SearchInput value={searchQuery} onChange={setSearchQuery} placeholder="Filter entries" className="w-56" />
                <Button icon={Plus} onClick={() => setShowAddCertsModal(true)}>
                  Add / remove
                </Button>
              </div>
            </div>
            <DataTable
              label={`Entries in ${activeWorkspace.name}`}
              columns={columns}
              rows={workspaceEntries}
              rowKey={(r) => r.entry.id}
              onRowClick={(r) => setInspectEntry(r)}
              initialSort={{ id: "exp", dir: "asc" }}
              empty={
                <EmptyState
                  icon={FolderPlus}
                  title={searchQuery ? "No matching entries" : `Nothing assigned to “${activeWorkspace.name}” yet`}
                  description="Pick certificates, key pairs or trusted roots from any keystore and link them here."
                  action={
                    <>
                      <Button variant="primary" icon={Plus} onClick={() => setShowAddCertsModal(true)}>
                        Assign entries
                      </Button>
                      <Button onClick={() => onNavigateTab("keystores")}>Browse keystores</Button>
                    </>
                  }
                />
              }
              footer={<span>{workspaceEntries.length} of {activeWorkspace.entryIds.length} entries</span>}
            />
          </Card>

          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
            <KpiCard label="Assigned entries" value={wsSummary.total} icon={Layers} tone="brand" hint={`From ${new Set(workspaceEntries.map((x) => x.keystore.id)).size} keystores`} />
            <KpiCard
              label="Key pairs / trusted certs"
              value={
                <>
                  {stats.keyPairs}
                  <span className="text-subtle font-normal mx-1">/</span>
                  {stats.trustedCerts}
                </>
              }
              icon={KeyRound}
              hint={`${wsSummary.secrets} secret keys`}
            />
            <KpiCard
              label="Expiring in 90 days"
              value={wsSummary.expiring90}
              icon={CalendarClock}
              tone="warning"
              hint={wsSummary.expiring30 ? `${wsSummary.expiring30} within 30 days` : "None within 30 days"}
              hintTone={wsSummary.expiring30 ? "warning" : "neutral"}
            />
            <KpiCard
              label="Policy alerts"
              value={stats.warnings}
              icon={AlertTriangle}
              tone="danger"
              hint={stats.warnings ? "Weak or expired entries" : "No weak or expired entries"}
              hintTone={stats.warnings ? "danger" : "success"}
            />
          </div>
        </>
      )}

      <Modal
        open={pendingDeleteWs !== null}
        onClose={() => setPendingDeleteWs(null)}
        size="sm"
        icon={Trash2}
        title="Delete workspace?"
        description={pendingDeleteWs ? `“${pendingDeleteWs.name}” will be removed. Its entries stay in their keystores.` : undefined}
        footer={
          <>
            <Button onClick={() => setPendingDeleteWs(null)}>Cancel</Button>
            <Button
              variant="primary"
              className="!bg-danger-fill hover:!bg-danger"
              onClick={() => {
                if (pendingDeleteWs) {
                  onDeleteWorkspace(pendingDeleteWs.id);
                  showToast(`Deleted workspace "${pendingDeleteWs.name}"`);
                }
                setPendingDeleteWs(null);
              }}
            >
              Delete
            </Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">This only removes the grouping; no keys or certificates are deleted.</p>
      </Modal>

      {/* Modal: Add / Manage Certificates in Workspace */}
      {showAddCertsModal && activeWorkspace && (
        <div className="fixed inset-0 z-50 bg-ink/40 flex items-center justify-center p-4">
          <div className="bg-surface border border-line-strong rounded-panel max-w-3xl w-full overflow-hidden shadow-pop flex flex-col max-h-[85vh]">
            <div className="p-5 border-b border-line flex items-center justify-between">
              <div>
                <h3 className="text-[17px] font-semibold text-ink flex items-center space-x-2">
                  <FolderPlus className="w-5 h-5 text-brand" />
                  <span>Assign Certificates to "{activeWorkspace.name}"</span>
                </h3>
                <p className="text-[12.5px] text-faint mt-0.5">
                  Click any certificate, key pair, or secret key across your KeyStores to add or remove it from this workspace.
                </p>
              </div>
              <button
                onClick={() => setShowAddCertsModal(false)}
                className="p-1.5 rounded-control text-faint hover:text-ink cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Filter Bar */}
            <div className="p-4 bg-surface-2 border-b border-line flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-4 h-4 text-subtle absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={certPickerSearch}
                  onChange={(e) => setCertPickerSearch(e.target.value)}
                  placeholder="Search by alias, subject DN, KeyStore, or algorithm..."
                  className="field !pl-9"
                />
              </div>

              <div className="flex items-center space-x-1.5">
                <Filter className="w-4 h-4 text-faint" />
                <select
                  value={certPickerStoreFilter}
                  onChange={(e) => setCertPickerStoreFilter(e.target.value)}
                  className="bg-surface border border-line-strong rounded-control px-3.5 py-2 text-[12.5px] font-medium text-ink-2 focus:outline-none"
                >
                  <option value="ALL">All KeyStores ({keystores.length})</option>
                  {keystores.map((ks) => (
                    <option key={ks.id} value={ks.id}>
                      {ks.name} ({ks.format})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Certificate checklist */}
            <div className="flex-1 overflow-y-auto divide-y divide-surface-3 p-3 space-y-1.5">
              {pickerEntries.map(({ entry, keystore }) => {
                const isAssigned = activeWorkspace.entryIds.includes(entry.id);
                return (
                  <div
                    key={entry.id}
                    onClick={() =>
                      onToggleEntryInWorkspace(activeWorkspace.id, entry.id)
                    }
                    className={`p-3.5 rounded-card flex items-center justify-between gap-4 cursor-pointer transition-all border ${
                      isAssigned
                        ? "bg-brand-tint/70 border-brand-soft-hover"
                        : "hover:bg-surface-2 border-transparent"
                    }`}
                  >
                    <div className="flex items-center space-x-3 min-w-0">
                      <div
                        className={`w-5 h-5 rounded-control flex items-center justify-center border transition-all ${
                          isAssigned
                            ? "bg-brand border-brand text-white"
                            : "border-line-strong bg-surface"
                        }`}
                      >
                        {isAssigned && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center space-x-2">
                          <span className="text-[13.5px] font-semibold text-ink">
                            {entry.alias}
                          </span>
                          <span className="px-2 py-0.5 rounded-control text-[10.5px] font-semibold bg-surface-3 text-muted">
                            {entry.entry_type}
                          </span>
                          <span className="px-2 py-0.5 rounded-control text-[10.5px] font-semibold bg-brand-tint text-brand-deep">
                            {keystore.name}
                          </span>
                        </div>
                        <div className="text-[12px] text-faint truncate mt-0.5">
                          {entry.subject} • {entry.algorithm} ({entry.key_size}-bit)
                        </div>
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <span
                        className={`px-3 py-1 rounded-control text-[11.5px] font-semibold ${
                          isAssigned
                            ? "bg-success-tint text-success"
                            : "bg-surface-3 text-faint"
                        }`}
                      >
                        {isAssigned ? "✓ Assigned" : "+ Add to Workspace"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="p-4 border-t border-line bg-surface-2 flex items-center justify-between">
              <span className="text-[12.5px] text-muted">
                <strong className="text-ink">
                  {activeWorkspace.entryIds.length}
                </strong>{" "}
                certificates currently assigned to{" "}
                <strong className="text-brand">
                  {activeWorkspace.name}
                </strong>
              </span>
              <button
                onClick={() => setShowAddCertsModal(false)}
                className="px-5 py-2 rounded-control bg-brand hover:bg-brand-deep text-white font-semibold text-[12.5px] cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Create New Workspace */}
      {showNewWorkspaceModal && (
        <div className="fixed inset-0 z-50 bg-ink/40 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateWorkspaceSubmit}
            className="bg-surface border border-line-strong rounded-panel max-w-md w-full overflow-hidden shadow-pop"
          >
            <div className="p-5 border-b border-line flex items-center justify-between">
              <h3 className="text-[17px] font-semibold text-ink flex items-center space-x-2">
                <Layers className="w-5 h-5 text-brand" />
                <span>Create New Workspace</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowNewWorkspaceModal(false)}
                className="p-1 rounded-control text-faint hover:text-ink cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-4 text-[13px]">
              <div>
                <label className="block text-[12px] font-semibold text-muted mb-1">
                  Workspace Name
                </label>
                <input
                  type="text"
                  required
                  value={newWsName}
                  onChange={(e) => setNewWsName(e.target.value)}
                  placeholder="e.g., Payment Gateway mTLS Cluster"
                  className="field"
                />
              </div>

              <div>
                <label className="block text-[12px] font-semibold text-muted mb-1">
                  Description
                </label>
                <textarea
                  rows={2}
                  value={newWsDesc}
                  onChange={(e) => setNewWsDesc(e.target.value)}
                  placeholder="Describe the services or compliance scope..."
                  className="field"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[12px] font-semibold text-muted mb-1">
                    Environment
                  </label>
                  <select
                    value={newWsEnv}
                    onChange={(e) =>
                      setNewWsEnv(e.target.value as Workspace["environment"])
                    }
                    className="field !h-auto py-2"
                  >
                    <option value="Production">Production</option>
                    <option value="Staging">Staging</option>
                    <option value="Development">Development</option>
                    <option value="Compliance">Compliance</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[12px] font-semibold text-muted mb-1">
                    Accent Color
                  </label>
                  <select
                    value={newWsColor}
                    onChange={(e) =>
                      setNewWsColor(e.target.value as Workspace["color"])
                    }
                    className="field !h-auto py-2"
                  >
                    <option value="blue">Blue</option>
                    <option value="emerald">Emerald</option>
                    <option value="purple">Purple</option>
                    <option value="amber">Amber</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-line bg-surface-2 flex items-center justify-end space-x-2">
              <button
                type="button"
                onClick={() => setShowNewWorkspaceModal(false)}
                className="px-4 py-2 rounded-control bg-surface border border-line-strong text-muted text-[12.5px] font-semibold cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-5 py-2 rounded-control bg-brand hover:bg-brand-deep text-white text-[12.5px] font-semibold cursor-pointer"
              >
                Create Workspace
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Modal: Quick Certificate Inspector */}
      {inspectEntry && (
        <div className="fixed inset-0 z-50 bg-ink/40 flex items-center justify-center p-4">
          <div className="bg-surface border border-line-strong rounded-panel max-w-xl w-full overflow-hidden shadow-pop">
            <div className="p-5 border-b border-line flex items-center justify-between">
              <div>
                <h3 className="text-[16px] font-semibold text-ink">
                  {inspectEntry.entry.alias}
                </h3>
                <p className="text-[12px] text-faint">
                  Source KeyStore: {inspectEntry.keystore.name} ({inspectEntry.keystore.format})
                </p>
              </div>
              <button
                onClick={() => setInspectEntry(null)}
                className="p-1.5 rounded-control text-faint hover:text-ink cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-3 text-[12.5px] select-text">
              <div className="grid grid-cols-2 gap-3 bg-surface-2 p-4 rounded-card border border-line">
                <div>
                  <span className="text-faint block text-[11px]">Subject DN</span>
                  <span className="text-ink font-semibold">{inspectEntry.entry.subject}</span>
                </div>
                <div>
                  <span className="text-faint block text-[11px]">Issuer DN</span>
                  <span className="text-ink-2 font-medium">{inspectEntry.entry.issuer}</span>
                </div>
                <div>
                  <span className="text-faint block text-[11px]">Algorithm</span>
                  <span className="text-success font-semibold">
                    {inspectEntry.entry.algorithm} ({inspectEntry.entry.key_size}-bit)
                  </span>
                </div>
                <div>
                  <span className="text-faint block text-[11px]">SHA-256 Fingerprint</span>
                  <span className="text-brand-deep font-mono text-[11px] break-all">
                    {inspectEntry.entry.sha256_fingerprint}
                  </span>
                </div>
              </div>

              {inspectEntry.entry.certificate_chain?.[0]?.pem && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-muted font-semibold">X.509 Certificate PEM</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(
                          inspectEntry.entry.certificate_chain[0]?.pem || ""
                        );
                        showToast("Copied PEM to clipboard");
                      }}
                      className="text-[11.5px] text-brand hover:underline flex items-center space-x-1 cursor-pointer"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy PEM</span>
                    </button>
                  </div>
                  <pre className="bg-term-bg text-term-fg rounded-card p-3.5 text-[11px] font-mono max-h-44 overflow-y-auto">
                    {inspectEntry.entry.certificate_chain[0].pem}
                  </pre>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-line bg-surface-2 flex items-center justify-between">
              <button
                onClick={() => handleExportEntryToDisk(inspectEntry.entry)}
                className="px-4 py-2 rounded-control bg-brand-soft hover:bg-brand-soft-hover text-brand-deep text-[12px] font-semibold flex items-center space-x-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Save PEM to Disk</span>
              </button>
              <button
                onClick={() => setInspectEntry(null)}
                className="px-5 py-2 rounded-control bg-brand text-white text-[12px] font-semibold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </Page>
  );
};
