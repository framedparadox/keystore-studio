import React, { useState, useMemo } from "react";
import {
  Layers,
  Plus,
  Trash2,
  ShieldCheck,
  KeyRound,
  Lock,
  AlertTriangle,
  Search,
  Check,
  X,
  Eye,
  Download,
  Copy,
  FolderArchive,
  Sparkles,
  ArrowUpRight,
  CheckCircle2,
  FolderPlus,
  Filter,
} from "lucide-react";
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

const COLOR_MAP: Record<
  Workspace["color"],
  {
    badge: string;
    activeCard: string;
    dot: string;
  }
> = {
  blue: {
    badge: "bg-[#EFF6FF] text-[#1D4ED8] border-[#BFDBFE]",
    activeCard: "border-[#2563EB] bg-[#F8FAFC] ring-2 ring-[#BFDBFE]/60",
    dot: "bg-[#2563EB]",
  },
  emerald: {
    badge: "bg-[#ECFDF5] text-[#047857] border-[#A7F3D0]",
    activeCard: "border-[#059669] bg-[#F8FAFC] ring-2 ring-[#A7F3D0]/60",
    dot: "bg-[#059669]",
  },
  purple: {
    badge: "bg-[#FAF5FF] text-[#6D28D9] border-[#E9D5FF]",
    activeCard: "border-[#7C3AED] bg-[#F8FAFC] ring-2 ring-[#E9D5FF]/60",
    dot: "bg-[#7C3AED]",
  },
  amber: {
    badge: "bg-[#FFFBEB] text-[#B45309] border-[#FDE68A]",
    activeCard: "border-[#D97706] bg-[#F8FAFC] ring-2 ring-[#FDE68A]/60",
    dot: "bg-[#D97706]",
  },
};

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

  const activeTheme = activeWorkspace
    ? COLOR_MAP[activeWorkspace.color] || COLOR_MAP.blue
    : COLOR_MAP.blue;

  return (
    <div className="flex-1 overflow-y-auto px-8 py-6 bg-[#EEF2F7] select-none space-y-5 relative">
      {/* Floating Native Action Toast */}
      {toastMsg && (
        <div className="fixed bottom-6 right-8 z-50 flex items-center space-x-2.5 bg-[#0F172A] text-white px-4 py-3 rounded-2xl shadow-xl border border-[#334155] text-[13px]">
          <CheckCircle2 className="w-4 h-4 text-[#34D399] shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* Top Header & Action Buttons */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-2xl bg-[#C2E7FF] text-[#0A3464] flex items-center justify-center shadow-2xs">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-[24px] font-bold text-[#0F172A] tracking-tight">
                  Certificate Workspaces
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-white text-[#0A3464] border border-[#CBD5E1]">
                  {workspaces.length} Active Collections
                </span>
              </div>
              <p className="text-[13px] text-[#64748B]">
                Group certificates, TLS key pairs, and CA roots across multiple KeyStores into logical project or environment workspaces.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={() => setShowAddCertsModal(true)}
            className="px-4 py-2.5 rounded-full bg-[#C2E7FF] hover:bg-[#AEDBFF] text-[#0A3464] font-semibold text-[13px] flex items-center space-x-2 transition cursor-pointer shadow-2xs"
          >
            <FolderPlus className="w-4 h-4" />
            <span>Add Certificates to Workspace</span>
          </button>
          <button
            onClick={() => setShowNewWorkspaceModal(true)}
            className="px-4 py-2.5 rounded-full bg-[#0A3464] hover:bg-[#07274C] text-white font-semibold text-[13px] flex items-center space-x-1.5 transition cursor-pointer shadow-2xs"
          >
            <Plus className="w-4 h-4" />
            <span>New Workspace</span>
          </button>
        </div>
      </div>

      {/* Bento Workspace Selector Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {workspaces.map((ws) => {
          const isSelected = ws.id === activeWorkspace?.id;
          const theme = COLOR_MAP[ws.color] || COLOR_MAP.blue;
          return (
            <div
              key={ws.id}
              onClick={() => onSelectWorkspace(ws.id)}
              className={`rounded-[22px] bg-white border p-5 transition-all cursor-pointer flex flex-col justify-between ${
                isSelected
                  ? theme.activeCard
                  : "border-[#E2E8F0] hover:border-[#94A3B8] hover:shadow-xs"
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center space-x-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${theme.dot}`} />
                    <h3 className="text-[15.5px] font-bold text-[#0F172A]">
                      {ws.name}
                    </h3>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10.5px] font-bold border ${theme.badge}`}
                    >
                      {ws.environment}
                    </span>
                    {workspaces.length > 1 && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onDeleteWorkspace(ws.id);
                          showToast(`Deleted workspace "${ws.name}"`);
                        }}
                        title="Delete Workspace"
                        className="p-1 rounded-lg text-[#94A3B8] hover:text-[#DC2626] hover:bg-[#FEF2F2] transition cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                <p className="text-[12.5px] text-[#64748B] line-clamp-2">
                  {ws.description}
                </p>
              </div>

              <div className="flex items-center justify-between pt-3 mt-3 border-t border-[#F1F5F9] text-[11.5px]">
                <span className="font-semibold text-[#0A3464]">
                  {ws.entryIds.length} assigned certificates
                </span>
                <span className="text-[#94A3B8]">
                  Updated {ws.updated_at}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Active Workspace Bento KPI Cards */}
      {activeWorkspace && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white rounded-[20px] border border-[#E2E8F0] p-4">
            <div className="flex items-center justify-between text-[12px] text-[#64748B] font-medium mb-1">
              <span>Assigned Identities</span>
              <Layers className="w-4 h-4 text-[#2563EB]" />
            </div>
            <div className="text-[26px] font-bold text-[#0F172A]">
              {stats.total}
            </div>
            <div className="text-[11px] text-[#64748B]">
              Linked across {keystores.length} KeyStores
            </div>
          </div>

          <div className="bg-white rounded-[20px] border border-[#E2E8F0] p-4">
            <div className="flex items-center justify-between text-[12px] text-[#64748B] font-medium mb-1">
              <span>Key Pairs / Trusted CAs</span>
              <KeyRound className="w-4 h-4 text-[#059669]" />
            </div>
            <div className="text-[26px] font-bold text-[#0F172A]">
              {stats.keyPairs}{" "}
              <span className="text-[16px] text-[#94A3B8] font-normal">/</span>{" "}
              <span className="text-[#2563EB]">{stats.trustedCerts}</span>
            </div>
            <div className="text-[11px] text-[#64748B]">
              Private TLS Keys vs Root Anchors
            </div>
          </div>

          <div className="bg-white rounded-[20px] border border-[#E2E8F0] p-4">
            <div className="flex items-center justify-between text-[12px] text-[#64748B] font-medium mb-1">
              <span>Post-Quantum (PQC)</span>
              <Sparkles className="w-4 h-4 text-[#7C3AED]" />
            </div>
            <div className="text-[26px] font-bold text-[#6D28D9]">
              {stats.pqcReady}
            </div>
            <div className="text-[11px] text-[#64748B]">
              ML-DSA / ML-KEM / SLH-DSA entries
            </div>
          </div>

          <div className="bg-white rounded-[20px] border border-[#E2E8F0] p-4">
            <div className="flex items-center justify-between text-[12px] text-[#64748B] font-medium mb-1">
              <span>Policy / Expiry Alerts</span>
              <AlertTriangle className="w-4 h-4 text-[#D97706]" />
            </div>
            <div className="text-[26px] font-bold text-[#B45309]">
              {stats.warnings}
            </div>
            <div className="text-[11px] text-[#64748B]">
              Weak or expired certificates
            </div>
          </div>
        </div>
      )}

      {/* Active Workspace Certificate Table */}
      {activeWorkspace && (
        <div className="bg-white rounded-[22px] border border-[#E2E8F0] overflow-hidden shadow-2xs">
          <div className="px-6 py-4 border-b border-[#F1F5F9] flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center space-x-2.5">
              <span className={`w-2.5 h-2.5 rounded-full ${activeTheme.dot}`} />
              <h2 className="text-[16px] font-bold text-[#0F172A]">
                {activeWorkspace.name} — Assigned Certificates &amp; Keys
              </h2>
              <span
                className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${activeTheme.badge}`}
              >
                {activeWorkspace.environment}
              </span>
            </div>

            <div className="flex items-center space-x-2.5">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-[#94A3B8] absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter workspace certs..."
                  className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-full pl-9 pr-4 py-1.5 text-[12.5px] text-[#1E293B] placeholder-[#94A3B8] focus:outline-none focus:border-[#2563EB] w-60"
                />
              </div>

              <button
                onClick={() => setShowAddCertsModal(true)}
                className="px-3.5 py-1.5 rounded-full bg-[#EFF6FF] hover:bg-[#DBEAFE] text-[#1D4ED8] border border-[#BFDBFE] text-[12px] font-semibold flex items-center space-x-1.5 transition cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add / Remove Certs</span>
              </button>
            </div>
          </div>

          {workspaceEntries.length === 0 ? (
            <div className="p-12 text-center space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-[#EFF6FF] border border-[#BFDBFE] flex items-center justify-center text-[#2563EB] mx-auto">
                <FolderPlus className="w-6 h-6" />
              </div>
              <h3 className="text-[15px] font-bold text-[#0F172A]">
                No certificates assigned to "{activeWorkspace.name}" yet
              </h3>
              <p className="text-[12.5px] text-[#64748B] max-w-md mx-auto">
                Click below to select certificates, key pairs, or trusted roots from any of your KeyStores and link them to this workspace.
              </p>
              <div className="pt-2 flex items-center justify-center space-x-3">
                <button
                  onClick={() => setShowAddCertsModal(true)}
                  className="px-4 py-2 rounded-full bg-[#C2E7FF] hover:bg-[#AEDBFF] text-[#0A3464] font-semibold text-[12.5px] flex items-center space-x-1.5 transition cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  <span>Add Certificates to Workspace</span>
                </button>
                <button
                  onClick={() => onNavigateTab("keystores")}
                  className="px-4 py-2 rounded-full bg-[#F8FAFC] hover:bg-[#F1F5F9] text-[#334155] border border-[#CBD5E1] font-semibold text-[12.5px] transition cursor-pointer"
                >
                  Browse KeyStores
                </button>
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[#F1F5F9] text-[11.5px] font-semibold text-[#64748B] bg-[#F8FAFC]">
                    <th className="py-3 px-6">Type</th>
                    <th className="py-3 px-4">Alias &amp; Subject DN</th>
                    <th className="py-3 px-4">Source KeyStore</th>
                    <th className="py-3 px-4">Algorithm</th>
                    <th className="py-3 px-4">Valid Until</th>
                    <th className="py-3 px-6 text-right">Workspace Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#F1F5F9] text-[13px]">
                  {workspaceEntries.map(({ entry, keystore }) => (
                    <tr
                      key={entry.id}
                      className="hover:bg-[#F8FAFC] transition-colors"
                    >
                      <td className="py-3.5 px-6 whitespace-nowrap">
                        {entry.entry_type === "KeyPair" ? (
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-[#EFF6FF] text-[#2563EB] text-[11.5px] font-semibold">
                            <KeyRound className="w-3.5 h-3.5" />
                            <span>KeyPair</span>
                          </span>
                        ) : entry.entry_type === "TrustedCertificate" ? (
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-[#DCFCE7] text-[#15803D] text-[11.5px] font-semibold">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>TrustedCert</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-[#F3E8FF] text-[#7E22CE] text-[11.5px] font-semibold">
                            <Lock className="w-3.5 h-3.5" />
                            <span>SecretKey</span>
                          </span>
                        )}
                      </td>

                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-[#0F172A]">
                          {entry.alias}
                        </div>
                        <div className="text-[11.5px] text-[#64748B] truncate max-w-xs">
                          {entry.subject}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <button
                          onClick={() => {
                            onSelectKeystore(keystore.id);
                            onNavigateTab("keystores");
                          }}
                          className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-[#F8FAFC] hover:bg-[#EFF6FF] border border-[#E2E8F0] text-[#334155] hover:text-[#1D4ED8] text-[11.5px] font-medium transition cursor-pointer"
                        >
                          <FolderArchive className="w-3.5 h-3.5 text-[#2563EB]" />
                          <span>{keystore.name}</span>
                          <span className="text-[10px] font-bold text-[#64748B]">
                            ({keystore.format})
                          </span>
                          <ArrowUpRight className="w-3 h-3 text-[#94A3B8]" />
                        </button>
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="font-semibold text-[#1E293B]">
                          {entry.algorithm} ({entry.key_size}-bit)
                        </div>
                        {entry.is_post_quantum && (
                          <span className="text-[10px] font-bold text-[#6D28D9] bg-[#F3E8FF] px-1.5 py-0.2 rounded">
                            PQC Hybrid
                          </span>
                        )}
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap text-[12px] text-[#475569]">
                        {entry.expiry_date}
                      </td>

                      <td className="py-3.5 px-6 whitespace-nowrap text-right">
                        <div className="inline-flex items-center space-x-1.5">
                          <button
                            onClick={() => setInspectEntry({ entry, keystore })}
                            title="Inspect Certificate"
                            className="p-1.5 rounded-lg bg-[#F8FAFC] hover:bg-[#EFF6FF] text-[#475569] hover:text-[#2563EB] border border-[#E2E8F0] transition cursor-pointer"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleExportEntryToDisk(entry)}
                            title="Export PEM to Disk"
                            className="p-1.5 rounded-lg bg-[#F8FAFC] hover:bg-[#ECFDF5] text-[#475569] hover:text-[#059669] border border-[#E2E8F0] transition cursor-pointer"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => {
                              onToggleEntryInWorkspace(
                                activeWorkspace.id,
                                entry.id
                              );
                              showToast(
                                `Removed "${entry.alias}" from ${activeWorkspace.name}`
                              );
                            }}
                            title="Remove from Workspace"
                            className="px-2.5 py-1 rounded-lg bg-[#FEF2F2] hover:bg-[#FEE2E2] text-[#DC2626] border border-[#FECACA] text-[11px] font-semibold transition cursor-pointer"
                          >
                            Remove
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Modal: Add / Manage Certificates in Workspace */}
      {showAddCertsModal && activeWorkspace && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-[#CBD5E1] rounded-3xl max-w-3xl w-full overflow-hidden shadow-2xl flex flex-col max-h-[85vh]">
            <div className="p-5 border-b border-[#E2E8F0] flex items-center justify-between">
              <div>
                <h3 className="text-[17px] font-bold text-[#0F172A] flex items-center space-x-2">
                  <FolderPlus className="w-5 h-5 text-[#2563EB]" />
                  <span>Assign Certificates to "{activeWorkspace.name}"</span>
                </h3>
                <p className="text-[12.5px] text-[#64748B] mt-0.5">
                  Click any certificate, key pair, or secret key across your KeyStores to add or remove it from this workspace.
                </p>
              </div>
              <button
                onClick={() => setShowAddCertsModal(false)}
                className="p-1.5 rounded-lg text-[#64748B] hover:text-[#0F172A] cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Filter Bar */}
            <div className="p-4 bg-[#F8FAFC] border-b border-[#E2E8F0] flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-4 h-4 text-[#94A3B8] absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={certPickerSearch}
                  onChange={(e) => setCertPickerSearch(e.target.value)}
                  placeholder="Search by alias, subject DN, KeyStore, or algorithm..."
                  className="w-full bg-white border border-[#CBD5E1] rounded-full pl-9 pr-4 py-2 text-[13px] text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#2563EB]"
                />
              </div>

              <div className="flex items-center space-x-1.5">
                <Filter className="w-4 h-4 text-[#64748B]" />
                <select
                  value={certPickerStoreFilter}
                  onChange={(e) => setCertPickerStoreFilter(e.target.value)}
                  className="bg-white border border-[#CBD5E1] rounded-full px-3.5 py-2 text-[12.5px] font-medium text-[#1E293B] focus:outline-none"
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
            <div className="flex-1 overflow-y-auto divide-y divide-[#F1F5F9] p-3 space-y-1.5">
              {pickerEntries.map(({ entry, keystore }) => {
                const isAssigned = activeWorkspace.entryIds.includes(entry.id);
                return (
                  <div
                    key={entry.id}
                    onClick={() =>
                      onToggleEntryInWorkspace(activeWorkspace.id, entry.id)
                    }
                    className={`p-3.5 rounded-2xl flex items-center justify-between gap-4 cursor-pointer transition-all border ${
                      isAssigned
                        ? "bg-[#EFF6FF]/70 border-[#93C5FD]"
                        : "hover:bg-[#F8FAFC] border-transparent"
                    }`}
                  >
                    <div className="flex items-center space-x-3 min-w-0">
                      <div
                        className={`w-5 h-5 rounded-md flex items-center justify-center border transition-all ${
                          isAssigned
                            ? "bg-[#2563EB] border-[#2563EB] text-white"
                            : "border-[#CBD5E1] bg-white"
                        }`}
                      >
                        {isAssigned && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center space-x-2">
                          <span className="text-[13.5px] font-bold text-[#0F172A]">
                            {entry.alias}
                          </span>
                          <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-[#F1F5F9] text-[#475569]">
                            {entry.entry_type}
                          </span>
                          <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-[#E0F2FE] text-[#0369A1]">
                            {keystore.name}
                          </span>
                        </div>
                        <div className="text-[12px] text-[#64748B] truncate mt-0.5">
                          {entry.subject} • {entry.algorithm} ({entry.key_size}-bit)
                        </div>
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <span
                        className={`px-3 py-1 rounded-full text-[11.5px] font-semibold ${
                          isAssigned
                            ? "bg-[#DCFCE7] text-[#15803D]"
                            : "bg-[#F1F5F9] text-[#64748B]"
                        }`}
                      >
                        {isAssigned ? "✓ Assigned" : "+ Add to Workspace"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="p-4 border-t border-[#E2E8F0] bg-[#F8FAFC] flex items-center justify-between">
              <span className="text-[12.5px] text-[#475569]">
                <strong className="text-[#0F172A]">
                  {activeWorkspace.entryIds.length}
                </strong>{" "}
                certificates currently assigned to{" "}
                <strong className="text-[#2563EB]">
                  {activeWorkspace.name}
                </strong>
              </span>
              <button
                onClick={() => setShowAddCertsModal(false)}
                className="px-5 py-2 rounded-full bg-[#0A3464] hover:bg-[#07274C] text-white font-semibold text-[12.5px] cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Create New Workspace */}
      {showNewWorkspaceModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateWorkspaceSubmit}
            className="bg-white border border-[#CBD5E1] rounded-3xl max-w-md w-full overflow-hidden shadow-2xl"
          >
            <div className="p-5 border-b border-[#E2E8F0] flex items-center justify-between">
              <h3 className="text-[17px] font-bold text-[#0F172A] flex items-center space-x-2">
                <Layers className="w-5 h-5 text-[#2563EB]" />
                <span>Create New Workspace</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowNewWorkspaceModal(false)}
                className="p-1 rounded-lg text-[#64748B] hover:text-[#0F172A] cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-4 text-[13px]">
              <div>
                <label className="block text-[12px] font-semibold text-[#475569] mb-1">
                  Workspace Name
                </label>
                <input
                  type="text"
                  required
                  value={newWsName}
                  onChange={(e) => setNewWsName(e.target.value)}
                  placeholder="e.g., Payment Gateway mTLS Cluster"
                  className="w-full bg-[#F8FAFC] border border-[#CBD5E1] rounded-xl px-3.5 py-2 text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
                />
              </div>

              <div>
                <label className="block text-[12px] font-semibold text-[#475569] mb-1">
                  Description
                </label>
                <textarea
                  rows={2}
                  value={newWsDesc}
                  onChange={(e) => setNewWsDesc(e.target.value)}
                  placeholder="Describe the services or compliance scope..."
                  className="w-full bg-[#F8FAFC] border border-[#CBD5E1] rounded-xl px-3.5 py-2 text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[12px] font-semibold text-[#475569] mb-1">
                    Environment
                  </label>
                  <select
                    value={newWsEnv}
                    onChange={(e) =>
                      setNewWsEnv(e.target.value as Workspace["environment"])
                    }
                    className="w-full bg-[#F8FAFC] border border-[#CBD5E1] rounded-xl px-3 py-2 text-[#0F172A] focus:outline-none"
                  >
                    <option value="Production">Production</option>
                    <option value="Staging">Staging</option>
                    <option value="Development">Development</option>
                    <option value="Compliance">Compliance</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[12px] font-semibold text-[#475569] mb-1">
                    Accent Color
                  </label>
                  <select
                    value={newWsColor}
                    onChange={(e) =>
                      setNewWsColor(e.target.value as Workspace["color"])
                    }
                    className="w-full bg-[#F8FAFC] border border-[#CBD5E1] rounded-xl px-3 py-2 text-[#0F172A] focus:outline-none"
                  >
                    <option value="blue">Blue</option>
                    <option value="emerald">Emerald</option>
                    <option value="purple">Purple</option>
                    <option value="amber">Amber</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-[#E2E8F0] bg-[#F8FAFC] flex items-center justify-end space-x-2">
              <button
                type="button"
                onClick={() => setShowNewWorkspaceModal(false)}
                className="px-4 py-2 rounded-full bg-white border border-[#CBD5E1] text-[#475569] text-[12.5px] font-semibold cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-5 py-2 rounded-full bg-[#0A3464] hover:bg-[#07274C] text-white text-[12.5px] font-semibold cursor-pointer"
              >
                Create Workspace
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Modal: Quick Certificate Inspector */}
      {inspectEntry && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-[#CBD5E1] rounded-3xl max-w-xl w-full overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-[#E2E8F0] flex items-center justify-between">
              <div>
                <h3 className="text-[16px] font-bold text-[#0F172A]">
                  {inspectEntry.entry.alias}
                </h3>
                <p className="text-[12px] text-[#64748B]">
                  Source KeyStore: {inspectEntry.keystore.name} ({inspectEntry.keystore.format})
                </p>
              </div>
              <button
                onClick={() => setInspectEntry(null)}
                className="p-1.5 rounded-lg text-[#64748B] hover:text-[#0F172A] cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-3 text-[12.5px] select-text">
              <div className="grid grid-cols-2 gap-3 bg-[#F8FAFC] p-4 rounded-2xl border border-[#E2E8F0]">
                <div>
                  <span className="text-[#64748B] block text-[11px]">Subject DN</span>
                  <span className="text-[#0F172A] font-semibold">{inspectEntry.entry.subject}</span>
                </div>
                <div>
                  <span className="text-[#64748B] block text-[11px]">Issuer DN</span>
                  <span className="text-[#334155] font-medium">{inspectEntry.entry.issuer}</span>
                </div>
                <div>
                  <span className="text-[#64748B] block text-[11px]">Algorithm</span>
                  <span className="text-[#047857] font-semibold">
                    {inspectEntry.entry.algorithm} ({inspectEntry.entry.key_size}-bit)
                  </span>
                </div>
                <div>
                  <span className="text-[#64748B] block text-[11px]">SHA-256 Fingerprint</span>
                  <span className="text-[#1D4ED8] font-mono text-[11px] break-all">
                    {inspectEntry.entry.sha256_fingerprint}
                  </span>
                </div>
              </div>

              {inspectEntry.entry.certificate_chain?.[0]?.pem && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[#475569] font-semibold">X.509 Certificate PEM</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(
                          inspectEntry.entry.certificate_chain[0]?.pem || ""
                        );
                        showToast("Copied PEM to clipboard");
                      }}
                      className="text-[11.5px] text-[#2563EB] hover:underline flex items-center space-x-1 cursor-pointer"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy PEM</span>
                    </button>
                  </div>
                  <pre className="bg-[#0F172A] text-[#E2E8F0] rounded-2xl p-3.5 text-[11px] font-mono max-h-44 overflow-y-auto">
                    {inspectEntry.entry.certificate_chain[0].pem}
                  </pre>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-[#E2E8F0] bg-[#F8FAFC] flex items-center justify-between">
              <button
                onClick={() => handleExportEntryToDisk(inspectEntry.entry)}
                className="px-4 py-2 rounded-full bg-[#C2E7FF] hover:bg-[#AEDBFF] text-[#0A3464] text-[12px] font-semibold flex items-center space-x-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Save PEM to Disk</span>
              </button>
              <button
                onClick={() => setInspectEntry(null)}
                className="px-5 py-2 rounded-full bg-[#0A3464] text-white text-[12px] font-semibold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
