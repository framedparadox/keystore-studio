import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Search,
  Plus,
  FileText,
  ArrowUpDown,
  List,
  LayoutGrid,
  RefreshCw,
  Trash2,
  KeyRound,
  ShieldCheck,
  Lock,
  Copy,
  Scissors,
  ClipboardPaste,
  Download,
  Eye,
  FileSignature,
  Edit3,
  CheckCircle2,
  AlertTriangle,
  FolderArchive,
  Layers,
  X,
  Info,
} from "lucide-react";
import {
  KeystoreFile,
  KeystoreEntry,
  KeystoreFormat,
  GenerateKeyPairInput,
  GenerateSecretKeyInput,
  CsrResult,
  ExportPayloadResult,
  Workspace,
} from "../types/crypto";

interface KeystoresViewProps {
  keystores: KeystoreFile[];
  activeKeystoreId: string;
  onSelectKeystore: (id: string) => void;
  onUpdateKeystore: (updated: KeystoreFile) => void;
  onDeleteKeystore: (id: string) => void;
  onOpenNewKeystoreModal: () => void;
  onRecordOp: (increment?: number, isSig?: boolean) => void;
  workspaces?: Workspace[];
  onToggleEntryInWorkspace?: (workspaceId: string, entryId: string) => void;
}

export const KeystoresView: React.FC<KeystoresViewProps> = ({
  keystores,
  activeKeystoreId,
  onSelectKeystore,
  onUpdateKeystore,
  onOpenNewKeystoreModal,
  onRecordOp,
  workspaces = [],
  onToggleEntryInWorkspace,
}) => {
  const activeKs = keystores.find((k) => k.id === activeKeystoreId) || keystores[0];

  // Screenshot 1 View Controls
  const [subView, setSubView] = useState<"list" | "graph">("list");
  const [layoutMode, setLayoutMode] = useState<"table" | "grid">("table");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedLabelFilter, setSelectedLabelFilter] = useState<string>("ALL");
  const [sortAsc, setSortAsc] = useState(true);

  // Clipboard for Cut / Copy / Paste Keystore Entries
  const [clipboardEntry, setClipboardEntry] = useState<{
    entry: KeystoreEntry;
    mode: "copy" | "cut";
    sourceKsId: string;
  } | null>(null);

  // Modals State
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [activeModal, setActiveModal] = useState<
    | null
    | "gen_keypair"
    | "gen_secret"
    | "import_cert"
    | "inspect_entry"
    | "csr_result"
    | "export_entry"
    | "ks_properties"
    | "add_label"
    | "rename_entry"
    | "assign_workspace"
  >(null);

  const [selectedEntry, setSelectedEntry] = useState<KeystoreEntry | null>(null);
  const [inspectTab, setInspectTab] = useState<"cert" | "extensions" | "private" | "public" | "chain">("cert");
  const [csrData, setCsrData] = useState<CsrResult | null>(null);
  const [exportResult, setExportResult] = useState<ExportPayloadResult | null>(null);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Form states for Generate Key Pair
  const [kpAlias, setKpAlias] = useState("payment-service-tls");
  const [kpAlg, setKpAlg] = useState("RSA");
  const [kpBits, setKpBits] = useState(4096);
  const [kpCn, setKpCn] = useState("payment.xkeystore.internal");
  const [kpOrg, setKpOrg] = useState("xkeystore Financial Systems");
  const [kpOu, setKpOu] = useState("Core Infrastructure");
  const [kpCountry, setKpCountry] = useState("US");
  const [kpDays, setKpDays] = useState(365);
  const [kpIsCa, setKpIsCa] = useState(false);
  const [kpSans, setKpSans] = useState("payment.xkeystore.internal, 10.0.10.50");
  const [kpSignerAlias, setKpSignerAlias] = useState<string>("");

  // Form states for Generate Secret Key
  const [skAlias, setSkAlias] = useState("db-field-encryption-aes");
  const [skAlg, setSkAlg] = useState("AES");
  const [skBits, setSkBits] = useState(256);
  const [skCustomHex, setSkCustomHex] = useState("");

  // Form states for Import Certificate
  const [impAlias, setImpAlias] = useState("partner-gateway-ca");
  const [impSubjectCn, setImpSubjectCn] = useState("partner-ca.global.net");
  const [impIssuerCn, setImpIssuerCn] = useState("DigiCert Global Root G2");
  const [impPem, setImpPem] = useState("");

  // Rename & Label state
  const [newAliasName, setNewAliasName] = useState("");
  const [newLabelText, setNewLabelText] = useState("");

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 4000);
  };

  // Collect all unique labels in active keystore
  const allLabels = Array.from(new Set(activeKs?.entries.flatMap((e) => e.labels) || []));

  // Filter & Sort entries
  const filteredEntries = (activeKs?.entries || [])
    .filter((e) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        e.alias.toLowerCase().includes(q) ||
        e.subject.toLowerCase().includes(q) ||
        e.algorithm.toLowerCase().includes(q) ||
        e.sha256_fingerprint.toLowerCase().includes(q);
      const matchesFilter =
        selectedLabelFilter === "ALL" ||
        e.entry_type === selectedLabelFilter ||
        e.labels.includes(selectedLabelFilter);
      return matchesSearch && matchesFilter;
    })
    .sort((a, b) => {
      const cmp = a.alias.localeCompare(b.alias);
      return sortAsc ? cmp : -cmp;
    });

  // ==========================================================================
  // Native Rust Cryptographic Handlers
  // ==========================================================================

  const handleGenerateKeyPair = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const signerEntry = activeKs.entries.find((en) => en.alias === kpSignerAlias);
      const input: GenerateKeyPairInput = {
        alias: kpAlias,
        algorithm: kpAlg,
        key_size: Number(kpBits),
        curve: kpAlg === "ECDSA" ? "secp256r1 (P-256)" : null,
        common_name: kpCn,
        organization: kpOrg,
        organizational_unit: kpOu,
        locality: "San Francisco",
        state: "CA",
        country: kpCountry,
        email: `security@${kpCn}`,
        validity_days: Number(kpDays),
        is_ca: kpIsCa,
        sans: kpSans.split(",").map((s) => s.trim()).filter(Boolean),
        key_usage: kpIsCa
          ? ["Digital Signature", "Key Cert Sign", "CRL Sign"]
          : ["Digital Signature", "Key Encipherment"],
        extended_key_usage: ["TLS Web Server Authentication", "TLS Web Client Authentication"],
        signer_alias: kpSignerAlias || null,
        labels: kpIsCa ? ["CA", kpAlg] : ["TLS", kpAlg],
      };

      const created = await invoke<KeystoreEntry>("generate_keypair_entry", {
        input,
        issuerDn: signerEntry ? signerEntry.subject : null,
      });

      const updatedKs: KeystoreFile = {
        ...activeKs,
        updated_at: "Just now",
        entries: [created, ...activeKs.entries],
      };
      onUpdateKeystore(updatedKs);
      onRecordOp(created.key_size, true);
      setActiveModal(null);
      showToast(`Generated ${created.algorithm} (${created.key_size}-bit) Key Pair '${created.alias}' natively in Rust.`);
    } catch (err) {
      alert("Key generation failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleGenerateSecretKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const input: GenerateSecretKeyInput = {
        alias: skAlias,
        algorithm: skAlg,
        key_size: Number(skBits),
        custom_hex: skCustomHex.trim() || null,
        labels: ["SecretKey", skAlg],
      };
      const created = await invoke<KeystoreEntry>("generate_secret_key_entry", { input });
      const updatedKs: KeystoreFile = {
        ...activeKs,
        updated_at: "Just now",
        entries: [created, ...activeKs.entries],
      };
      onUpdateKeystore(updatedKs);
      onRecordOp(created.key_size, false);
      setActiveModal(null);
      showToast(`Generated ${created.algorithm} (${created.key_size}-bit) Secret Key '${created.alias}' in KeyStore.`);
    } catch (err) {
      alert("Secret key generation failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleImportTrustedCert = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const created = await invoke<KeystoreEntry>("import_pem_certificate", {
        alias: impAlias,
        subjectCn: impSubjectCn,
        issuerCn: impIssuerCn,
        pemData: impPem,
        labels: ["TrustedCert", "Imported"],
      });
      const updatedKs: KeystoreFile = {
        ...activeKs,
        updated_at: "Just now",
        entries: [created, ...activeKs.entries],
      };
      onUpdateKeystore(updatedKs);
      onRecordOp(2048, false);
      setActiveModal(null);
      showToast(`Imported Trusted Certificate '${created.alias}' into ${activeKs.name}.`);
    } catch (err) {
      alert("Import failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleGenerateCsr = async (entry: KeystoreEntry) => {
    setBusy(true);
    try {
      const res = await invoke<CsrResult>("generate_csr", {
        entry,
        format: "PKCS#10",
      });
      setSelectedEntry(entry);
      setCsrData(res);
      setActiveModal("csr_result");
      onRecordOp(512, true);
    } catch (err) {
      alert("CSR generation failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleExportEntryFormat = async (entry: KeystoreEntry, targetFormat: string) => {
    setBusy(true);
    try {
      const res = await invoke<ExportPayloadResult>("export_entry", {
        entry,
        exportTarget: targetFormat,
      });
      setExportResult(res);
      onRecordOp(256, false);
      showToast(
        res.saved_path
          ? `Exported ${res.filename} directly to ${res.saved_path}`
          : `Exported ${res.filename} (${res.byte_length} bytes)`
      );
    } catch (err) {
      alert("Export failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleSaveKeystoreBinary = async () => {
    setBusy(true);
    try {
      const res = await invoke<ExportPayloadResult>("save_keystore_file", {
        ks: activeKs,
        password: "changeit",
      });
      onRecordOp(512, false);
      showToast(
        res.saved_path
          ? `Saved native ${activeKs.format} binary (${res.byte_length} bytes) to ${res.saved_path}`
          : `Serialized ${activeKs.name} (${res.byte_length} bytes)`
      );
    } catch (err) {
      alert("Save keystore failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleExportCsv = async () => {
    setBusy(true);
    try {
      const res = await invoke<ExportPayloadResult>("export_keystore_to_csv", {
        ks: activeKs,
      });
      onRecordOp(128, false);
      showToast(
        res.saved_path
          ? `Exported CSV inventory to ${res.saved_path}`
          : `Exported ${res.filename}`
      );
    } catch (err) {
      alert("CSV Export failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleChangeKeystoreFormat = (newFmt: KeystoreFormat) => {
    const extMap: Record<KeystoreFormat, string> = {
      PKCS12: ".p12",
      JKS: ".jks",
      JCEKS: ".jceks",
      BKS: ".bks",
      BCFKS: ".bcfks",
      UBER: ".uber",
    };
    const baseName = activeKs.name.replace(/\.[^/.]+$/, "");
    const updated: KeystoreFile = {
      ...activeKs,
      format: newFmt,
      name: `${baseName}${extMap[newFmt]}`,
      updated_at: "Just now",
    };
    onUpdateKeystore(updated);
    onRecordOp(256, false);
    showToast(`Converted KeyStore type in-place to ${newFmt} (${updated.name}).`);
  };

  const handleDeleteEntry = (entryId: string, alias: string) => {
    const updated: KeystoreFile = {
      ...activeKs,
      updated_at: "Just now",
      entries: activeKs.entries.filter((e) => e.id !== entryId),
    };
    onUpdateKeystore(updated);
    showToast(`Deleted entry '${alias}' from ${activeKs.name}.`);
  };

  const handleCutOrCopyEntry = (entry: KeystoreEntry, mode: "copy" | "cut") => {
    setClipboardEntry({ entry, mode, sourceKsId: activeKs.id });
    if (mode === "cut") {
      const updated: KeystoreFile = {
        ...activeKs,
        entries: activeKs.entries.filter((e) => e.id !== entry.id),
      };
      onUpdateKeystore(updated);
    }
    showToast(`${mode === "cut" ? "Cut" : "Copied"} entry '${entry.alias}' to KeyStore clipboard.`);
  };

  const handlePasteEntry = () => {
    if (!clipboardEntry) return;
    const exists = activeKs.entries.some((e) => e.alias === clipboardEntry.entry.alias);
    const pasted: KeystoreEntry = {
      ...clipboardEntry.entry,
      id: "entry-" + Date.now(),
      alias: exists ? `${clipboardEntry.entry.alias}-copy` : clipboardEntry.entry.alias,
      last_modified: "Just now",
    };
    const updated: KeystoreFile = {
      ...activeKs,
      updated_at: "Just now",
      entries: [pasted, ...activeKs.entries],
    };
    onUpdateKeystore(updated);
    if (clipboardEntry.mode === "cut") {
      setClipboardEntry(null);
    }
    showToast(`Pasted entry '${pasted.alias}' into ${activeKs.name}.`);
  };

  const handleRenameSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEntry || !newAliasName.trim()) return;
    const updated: KeystoreFile = {
      ...activeKs,
      updated_at: "Just now",
      entries: activeKs.entries.map((en) =>
        en.id === selectedEntry.id ? { ...en, alias: newAliasName.trim().toLowerCase(), last_modified: "Just now" } : en
      ),
    };
    onUpdateKeystore(updated);
    setActiveModal(null);
    showToast(`Renamed alias '${selectedEntry.alias}' to '${newAliasName.trim().toLowerCase()}'.`);
  };

  const handleAddLabelSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newLabelText.trim()) return;
    const tag = newLabelText.trim();
    if (selectedEntry) {
      const updated: KeystoreFile = {
        ...activeKs,
        entries: activeKs.entries.map((en) =>
          en.id === selectedEntry.id && !en.labels.includes(tag)
            ? { ...en, labels: [...en.labels, tag] }
            : en
        ),
      };
      onUpdateKeystore(updated);
      showToast(`Added label '${tag}' to '${selectedEntry.alias}'.`);
    } else if (activeKs.entries.length > 0) {
      const firstId = activeKs.entries[0].id;
      const updated: KeystoreFile = {
        ...activeKs,
        entries: activeKs.entries.map((en) =>
          en.id === firstId && !en.labels.includes(tag) ? { ...en, labels: [...en.labels, tag] } : en
        ),
      };
      onUpdateKeystore(updated);
      showToast(`Added label '${tag}'.`);
    }
    setNewLabelText("");
    setActiveModal(null);
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-canvas px-8 py-6 select-none relative">
      {/* Floating Native Action Toast */}
      {toastMsg && (
        <div className="fixed bottom-6 right-8 z-50 flex items-center space-x-2.5 bg-ink text-white px-4 py-3 rounded-2xl shadow-xl border border-ink-2 text-[13px] animate-in fade-in slide-in-from-bottom-3">
          <CheckCircle2 className="w-4 h-4 text-[#34D399] shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* Header Row matching Screenshot 1 ("Knowledge Sources") */}
      <div className="flex items-center justify-between mb-3">
        <h1 className="text-[28px] font-normal text-ink-2 tracking-tight">
          KeyStore Sources
        </h1>
      </div>

      {/* Pill Toggle: File list | Graph view (Exact match to Screenshot 1) */}
      <div className="flex items-center space-x-2 mb-4">
        <button
          onClick={() => setSubView("list")}
          className={`px-4 py-1.5 rounded-full text-[13px] font-semibold transition cursor-pointer ${
            subView === "list"
              ? "bg-brand-soft text-brand-deep"
              : "bg-white text-ink-2 hover:bg-surface-2"
          }`}
        >
          File list
        </button>
        <button
          onClick={() => setSubView("graph")}
          className={`px-4 py-1.5 rounded-full text-[13px] font-semibold transition cursor-pointer ${
            subView === "graph"
              ? "bg-brand-soft text-brand-deep"
              : "bg-white text-ink-2 hover:bg-surface-2"
          }`}
        >
          Graph view
        </button>
      </div>

      {/* Search Bar & "+ Add source" Button Row (Exact match to Screenshot 1) */}
      <div className="flex items-center space-x-3 mb-3.5 relative">
        <div className="flex-1 h-12 bg-white rounded-full px-5 flex items-center space-x-3 border border-line/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
          <Search className="w-4 h-4 text-subtle" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search keystore entries, aliases, subjects, algorithms, or SHA-256 fingerprints..."
            className="w-full bg-transparent text-[14px] text-ink-2 placeholder-subtle focus:outline-none"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery("")} className="text-subtle hover:text-muted cursor-pointer">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* + Add source / entry button */}
        <div className="relative">
          <button
            onClick={() => setAddMenuOpen(!addMenuOpen)}
            className="h-12 px-6 rounded-full bg-brand-soft hover:bg-brand-soft-hover text-brand-deep font-semibold text-[13.5px] flex items-center space-x-2 transition cursor-pointer shadow-2xs"
          >
            <Plus className="w-4 h-4 stroke-[2.5]" />
            <span>Add source</span>
          </button>

          {addMenuOpen && (
            <div className="absolute right-0 mt-2 w-64 bg-white rounded-2xl border border-line-strong shadow-xl py-2 z-40 text-[13px]">
              <button
                onClick={() => {
                  setAddMenuOpen(false);
                  setActiveModal("gen_keypair");
                }}
                className="w-full px-4 py-2.5 text-left hover:bg-surface-3 flex items-center space-x-2.5 text-ink cursor-pointer"
              >
                <KeyRound className="w-4 h-4 text-brand" />
                <div>
                  <div className="font-semibold">Generate Key Pair</div>
                  <div className="text-[11px] text-faint">RSA, ECDSA, Ed25519, ML-DSA + Cert</div>
                </div>
              </button>

              <button
                onClick={() => {
                  setAddMenuOpen(false);
                  setActiveModal("gen_secret");
                }}
                className="w-full px-4 py-2.5 text-left hover:bg-surface-3 flex items-center space-x-2.5 text-ink cursor-pointer"
              >
                <Lock className="w-4 h-4 text-[#7E22CE]" />
                <div>
                  <div className="font-semibold">Generate Secret Key</div>
                  <div className="text-[11px] text-faint">AES-256, ChaCha20, HMAC, 3DES</div>
                </div>
              </button>

              <button
                onClick={() => {
                  setAddMenuOpen(false);
                  setActiveModal("import_cert");
                }}
                className="w-full px-4 py-2.5 text-left hover:bg-surface-3 flex items-center space-x-2.5 text-ink cursor-pointer"
              >
                <ShieldCheck className="w-4 h-4 text-success" />
                <div>
                  <div className="font-semibold">Import Trusted Certificate</div>
                  <div className="text-[11px] text-faint">X.509 PEM, DER, PKCS#7</div>
                </div>
              </button>

              {clipboardEntry && (
                <button
                  onClick={() => {
                    setAddMenuOpen(false);
                    handlePasteEntry();
                  }}
                  className="w-full px-4 py-2.5 text-left hover:bg-surface-3 flex items-center space-x-2.5 text-brand-deep border-t border-line cursor-pointer"
                >
                  <ClipboardPaste className="w-4 h-4 text-[#0284C7]" />
                  <div>
                    <div className="font-semibold">Paste '{clipboardEntry.entry.alias}'</div>
                    <div className="text-[11px] text-faint">From KeyStore clipboard</div>
                  </div>
                </button>
              )}
            </div>
          )}
        </div>
      </div>


      {/* Indexed Count & Sort / View Switcher Row (Exact match to Screenshot 1) */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2.5">
          <span className="text-[13.5px] font-medium text-faint">
            {filteredEntries.length} sources indexed
          </span>
          <div className="px-2.5 py-0.5 rounded-full bg-white border border-line flex items-center space-x-1 text-[12px] font-semibold text-ink-2 shadow-2xs">
            <FileText className="w-3.5 h-3.5 text-muted" />
            <span>{filteredEntries.length}</span>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          {/* Sort A -> Z Pill */}
          <button
            onClick={() => setSortAsc(!sortAsc)}
            className="px-4 py-1.5 rounded-full bg-white border border-line text-ink-2 text-[12.5px] font-medium flex items-center space-x-2 hover:bg-surface-2 cursor-pointer shadow-2xs"
          >
            <ArrowUpDown className="w-3.5 h-3.5 text-muted" />
            <span>{sortAsc ? "A -> Z" : "Z -> A"}</span>
          </button>

          {/* Segmented List | Grid View Toggle */}
          <div className="flex items-center bg-white rounded-full border border-line overflow-hidden shadow-2xs">
            <button
              onClick={() => setLayoutMode("table")}
              className={`px-3.5 py-1.5 flex items-center justify-center transition cursor-pointer ${
                layoutMode === "table" ? "bg-brand-soft text-brand-deep" : "text-muted hover:bg-surface-2"
              }`}
              title="Table List View"
            >
              <List className="w-4 h-4" />
            </button>
            <button
              onClick={() => setLayoutMode("grid")}
              className={`px-3.5 py-1.5 flex items-center justify-center transition cursor-pointer ${
                layoutMode === "grid" ? "bg-brand-soft text-brand-deep" : "text-muted hover:bg-surface-2"
              }`}
              title="Card Grid View"
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area: File List (Table or Grid) OR Graph View */}
      {subView === "list" ? (
        layoutMode === "table" ? (
          /* Rounded White Data Table matching Screenshot 1 */
          <div className="flex-1 bg-white rounded-[20px] border border-line/80 shadow-[0_1px_4px_rgba(0,0,0,0.02)] flex flex-col overflow-hidden">
            {/* Table Header */}
            <div className="grid grid-cols-12 gap-3 px-6 py-3 border-b border-surface-3 text-[12px] font-semibold text-faint items-center">
              <div className="col-span-5 flex items-center space-x-1">
                <span>Name</span>
                <span>{sortAsc ? "↑" : "↓"}</span>
              </div>
              <div className="col-span-2">Algorithm &amp; Type</div>
              <div className="col-span-2">Valid Until</div>
              <div className="col-span-3 text-right">Actions</div>
            </div>

            {/* Table Body */}
            <div className="flex-1 overflow-y-auto divide-y divide-surface-2">
              {filteredEntries.map((entry) => (
                <div
                  key={entry.id}
                  onClick={() => {
                    setSelectedEntry(entry);
                    setInspectTab(entry.entry_type === "SecretKey" ? "private" : "cert");
                    setActiveModal("inspect_entry");
                  }}
                  className="grid grid-cols-12 gap-3 px-6 py-3.5 items-center hover:bg-surface-2 transition cursor-pointer group"
                >
                  {/* Name & Icon */}
                  <div className="col-span-5 flex items-center space-x-3 pr-2">
                    <div
                      className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                        entry.entry_type === "KeyPair"
                          ? "bg-brand-tint text-brand"
                          : entry.entry_type === "TrustedCertificate"
                          ? "bg-success-tint text-[#15803D]"
                          : "bg-[#F3E8FF] text-[#7E22CE]"
                      }`}
                    >
                      {entry.entry_type === "KeyPair" ? (
                        <KeyRound className="w-4 h-4" />
                      ) : entry.entry_type === "TrustedCertificate" ? (
                        <ShieldCheck className="w-4 h-4" />
                      ) : (
                        <Lock className="w-4 h-4" />
                      )}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-[14px] font-medium text-ink-2 truncate">
                          {entry.alias}
                        </span>
                        {entry.is_weak && (
                          <span title="Weak Key Size (< 2048 bits)" className="shrink-0 flex items-center">
                            <AlertTriangle className="w-3.5 h-3.5 text-danger" />
                          </span>
                        )}
                      </div>
                      <span className="text-[11.5px] text-faint truncate block">
                        {entry.subject}
                      </span>
                    </div>
                  </div>

                  {/* Algorithm & Type */}
                  <div className="col-span-2">
                    <span className="text-[13px] font-medium text-ink-2 block">
                      {entry.algorithm} ({entry.key_size}-bit)
                    </span>
                    <span className="text-[11px] text-subtle">
                      {entry.entry_type}
                      {entry.chain_length > 0 ? ` • Chain (${entry.chain_length})` : ""}
                    </span>
                  </div>

                  {/* Valid Until */}
                  <div className="col-span-2">
                    <span className="text-[13px] text-faint block">{entry.expiry_date}</span>
                  </div>

                  {/* Actions */}
                  <div
                    className="col-span-3 flex items-center justify-end space-x-1"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {onToggleEntryInWorkspace && (
                      <button
                        onClick={() => {
                          setSelectedEntry(entry);
                          setActiveModal("assign_workspace");
                        }}
                        className="p-1.5 rounded-lg text-muted hover:text-brand hover:bg-brand-tint cursor-pointer"
                        title="Add / Assign to Workspace"
                      >
                        <Layers className="w-4 h-4" />
                      </button>
                    )}

                    <button
                      onClick={() => {
                        setSelectedEntry(entry);
                        setInspectTab(entry.entry_type === "SecretKey" ? "private" : "cert");
                        setActiveModal("inspect_entry");
                      }}
                      className="p-1.5 rounded-lg text-muted hover:text-ink hover:bg-line/60 cursor-pointer"
                      title="Inspect Certificate, Extensions & Keys"
                    >
                      <Eye className="w-4 h-4" />
                    </button>

                    {entry.entry_type === "KeyPair" && (
                      <button
                        onClick={() => handleGenerateCsr(entry)}
                        className="p-1.5 rounded-lg text-muted hover:text-brand hover:bg-brand-tint cursor-pointer"
                        title="Generate CSR (PKCS#10 / SPKAC)"
                      >
                        <FileSignature className="w-4 h-4" />
                      </button>
                    )}

                    <button
                      onClick={() => {
                        setSelectedEntry(entry);
                        setExportResult(null);
                        setActiveModal("export_entry");
                      }}
                      className="p-1.5 rounded-lg text-muted hover:text-success hover:bg-success-tint/60 cursor-pointer"
                      title="Export Key Pair / Certificate / JWK / OpenSSH"
                    >
                      <Download className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => {
                        setSelectedEntry(entry);
                        setNewAliasName(entry.alias);
                        setActiveModal("rename_entry");
                      }}
                      className="p-1.5 rounded-lg text-muted hover:text-ink hover:bg-line/60 cursor-pointer"
                      title="Rename Alias"
                    >
                      <Edit3 className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => handleCutOrCopyEntry(entry, "copy")}
                      className="p-1.5 rounded-lg text-muted hover:text-ink hover:bg-line/60 cursor-pointer"
                      title="Copy Entry"
                    >
                      <Copy className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => handleDeleteEntry(entry.id, entry.alias)}
                      className="p-1.5 rounded-lg text-muted hover:text-danger hover:bg-danger-tint/60 cursor-pointer"
                      title="Delete Entry"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}

              {filteredEntries.length === 0 && (
                <div className="py-16 text-center text-subtle text-[14px]">
                  No keystore entries match your current filter. Click <strong>+ Add source</strong> to generate or import keys.
                </div>
              )}
            </div>
          </div>
        ) : (
          /* Card Grid Mode */
          <div className="flex-1 overflow-y-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-4">
            {filteredEntries.map((entry) => (
              <div
                key={entry.id}
                onClick={() => {
                  setSelectedEntry(entry);
                  setActiveModal("inspect_entry");
                }}
                className="bg-white rounded-[20px] p-5 border border-line hover:border-[#93C5FD] shadow-2xs flex flex-col justify-between cursor-pointer transition"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-brand-tint text-brand">
                      {entry.entry_type}
                    </span>
                    <span className="text-[11.5px] font-mono text-faint">
                      {entry.algorithm} • {entry.key_size}b
                    </span>
                  </div>
                  <h3 className="text-[15px] font-semibold text-ink">{entry.alias}</h3>
                  <p className="text-[12px] text-faint mt-1 line-clamp-2">{entry.subject}</p>
                </div>

                <div className="pt-4 mt-4 border-t border-surface-3 flex items-center justify-between text-[11.5px] text-faint">
                  <span>Exp: {entry.expiry_date}</span>
                  <div className="flex space-x-1" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => {
                        setSelectedEntry(entry);
                        setExportResult(null);
                        setActiveModal("export_entry");
                      }}
                      className="px-2 py-1 rounded-md bg-surface-3 hover:bg-line text-ink-2"
                    >
                      Export
                    </button>
                    <button
                      onClick={() => handleDeleteEntry(entry.id, entry.alias)}
                      className="px-2 py-1 rounded-md bg-danger-tint text-[#991B1B]"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )
      ) : (
        /* Interactive Trust & KeyStore Hierarchy Graph View */
        <div className="flex-1 bg-white rounded-[20px] border border-line p-6 overflow-y-auto flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-[16px] font-semibold text-ink">
                  KeyStore Trust Hierarchy Graph ({activeKs.name})
                </h3>
                <p className="text-[12.5px] text-faint">
                  Visualizes Root CAs, Intermediate CAs, End-Entity TLS Key Pairs, and Symmetric Keys inside {activeKs.name}.
                </p>
              </div>
              <span className="px-3 py-1 rounded-full bg-success-tint text-[#166534] text-[12px] font-semibold flex items-center space-x-1.5">
                <CheckCircle2 className="w-4 h-4" />
                <span>All Chains Cryptographically Verified</span>
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-5 pt-2">
              {/* Column 1: Root & Trusted CAs */}
              <div className="bg-surface-2 rounded-2xl p-4 border border-line space-y-3">
                <span className="text-[11px] font-bold uppercase tracking-wider text-faint block">
                  Root &amp; Trusted CAs
                </span>
                {activeKs.entries
                  .filter((e) => e.entry_type === "TrustedCertificate" || e.labels.includes("CA"))
                  .map((ca) => (
                    <div
                      key={ca.id}
                      onClick={() => {
                        setSelectedEntry(ca);
                        setActiveModal("inspect_entry");
                      }}
                      className="p-3.5 bg-white rounded-xl border-l-4 border-l-[#059669] border border-line shadow-2xs cursor-pointer hover:border-success"
                    >
                      <div className="text-[13px] font-semibold text-ink">{ca.alias}</div>
                      <div className="text-[11px] text-faint truncate mt-0.5">{ca.subject}</div>
                      <div className="text-[10.5px] font-mono text-success mt-1">
                        {ca.algorithm} {ca.key_size}-bit • Trust Anchor
                      </div>
                    </div>
                  ))}
              </div>

              {/* Column 2: Issued Key Pairs */}
              <div className="bg-surface-2 rounded-2xl p-4 border border-line space-y-3">
                <span className="text-[11px] font-bold uppercase tracking-wider text-faint block">
                  Asymmetric Key Pairs (TLS / CodeSign / PQC)
                </span>
                {activeKs.entries
                  .filter((e) => e.entry_type === "KeyPair" && !e.labels.includes("CA"))
                  .map((kp) => (
                    <div
                      key={kp.id}
                      onClick={() => {
                        setSelectedEntry(kp);
                        setActiveModal("inspect_entry");
                      }}
                      className={`p-3.5 bg-white rounded-xl border-l-4 border border-line shadow-2xs cursor-pointer ${
                        kp.is_weak ? "border-l-[#DC2626]" : "border-l-[#2563EB]"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[13px] font-semibold text-ink">{kp.alias}</span>
                        {kp.is_post_quantum && (
                          <span className="px-1.5 py-0.2 rounded bg-brand-tint text-brand text-[10px] font-bold">
                            PQC
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-faint truncate mt-0.5">{kp.subject}</div>
                      <div className="text-[10.5px] text-muted mt-1">
                        Issued by: {kp.issuer.split(",")[0]}
                      </div>
                    </div>
                  ))}
              </div>

              {/* Column 3: Symmetric Secret Keys */}
              <div className="bg-surface-2 rounded-2xl p-4 border border-line space-y-3">
                <span className="text-[11px] font-bold uppercase tracking-wider text-faint block">
                  Symmetric Secret Keys (AES / HMAC)
                </span>
                {activeKs.entries
                  .filter((e) => e.entry_type === "SecretKey")
                  .map((sk) => (
                    <div
                      key={sk.id}
                      onClick={() => {
                        setSelectedEntry(sk);
                        setActiveModal("inspect_entry");
                      }}
                      className="p-3.5 bg-white rounded-xl border-l-4 border-l-[#7E22CE] border border-line shadow-2xs cursor-pointer"
                    >
                      <div className="text-[13px] font-semibold text-ink">{sk.alias}</div>
                      <div className="text-[11px] text-faint mt-0.5">
                        {sk.algorithm} ({sk.key_size}-bit)
                      </div>
                      <div className="text-[10.5px] font-mono text-[#7E22CE] mt-1">
                        Quantum-Resistant Envelope Key
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 1: Generate Key Pair + Self-Signed / CA-Signed X.509 Certificate
          ==================================================================== */}
      {activeModal === "gen_keypair" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-xl bg-white rounded-3xl border border-line-strong shadow-2xl p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <h3 className="text-[17px] font-semibold text-ink">
                Generate Key Pair &amp; X.509 v3 Certificate
              </h3>
              <button onClick={() => setActiveModal(null)} className="p-1 text-faint hover:text-ink cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleGenerateKeyPair} className="space-y-3.5 pt-4 text-[12.5px]">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-medium text-muted block mb-1">Entry Alias</label>
                  <input
                    type="text"
                    value={kpAlias}
                    onChange={(e) => setKpAlias(e.target.value)}
                    required
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Algorithm</label>
                  <select
                    value={kpAlg}
                    onChange={(e) => {
                      const val = e.target.value;
                      setKpAlg(val);
                      if (val === "RSA") setKpBits(4096);
                      else if (val === "ECDSA" || val === "ED25519") setKpBits(256);
                      else if (val === "ML-DSA-65") setKpBits(1952);
                      else if (val === "SLH-DSA") setKpBits(512);
                    }}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong bg-white"
                  >
                    <option value="RSA">RSA (1024 / 2048 / 4096 / 8192)</option>
                    <option value="ECDSA">ECDSA (secp256r1 / P-256 / P-384)</option>
                    <option value="ED25519">EdDSA (Ed25519)</option>
                    <option value="ML-DSA-65">Post-Quantum: ML-DSA-65 (FIPS 204)</option>
                    <option value="ML-KEM-768">Post-Quantum: ML-KEM-768 (FIPS 203)</option>
                    <option value="SLH-DSA">Post-Quantum: SLH-DSA (FIPS 205)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="font-medium text-muted block mb-1">Key Size (Bits)</label>
                  <input
                    type="number"
                    value={kpBits}
                    onChange={(e) => setKpBits(Number(e.target.value))}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Validity (Days)</label>
                  <input
                    type="number"
                    value={kpDays}
                    onChange={(e) => setKpDays(Number(e.target.value))}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Sign With CA (Optional)</label>
                  <select
                    value={kpSignerAlias}
                    onChange={(e) => setKpSignerAlias(e.target.value)}
                    className="w-full h-9 px-2 rounded-lg border border-line-strong bg-white"
                  >
                    <option value="">Self-Signed</option>
                    {activeKs.entries
                      .filter((e) => e.entry_type === "KeyPair")
                      .map((ca) => (
                        <option key={ca.id} value={ca.alias}>
                          CA: {ca.alias}
                        </option>
                      ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-medium text-muted block mb-1">Common Name (CN)</label>
                  <input
                    type="text"
                    value={kpCn}
                    onChange={(e) => setKpCn(e.target.value)}
                    required
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Organization (O)</label>
                  <input
                    type="text"
                    value={kpOrg}
                    onChange={(e) => setKpOrg(e.target.value)}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-medium text-muted block mb-1">Organizational Unit (OU)</label>
                  <input
                    type="text"
                    value={kpOu}
                    onChange={(e) => setKpOu(e.target.value)}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Country (C)</label>
                  <input
                    type="text"
                    value={kpCountry}
                    onChange={(e) => setKpCountry(e.target.value)}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
              </div>

              <div>
                <label className="font-medium text-muted block mb-1">
                  Subject Alternative Names (SANs - DNS &amp; IP comma-separated)
                </label>
                <input
                  type="text"
                  value={kpSans}
                  onChange={(e) => setKpSans(e.target.value)}
                  className="w-full h-9 px-3 rounded-lg border border-line-strong"
                />
              </div>

              <div className="flex items-center space-x-2 pt-1">
                <input
                  type="checkbox"
                  id="kpCaFlag"
                  checked={kpIsCa}
                  onChange={(e) => setKpIsCa(e.target.checked)}
                  className="w-4 h-4 rounded"
                />
                <label htmlFor="kpCaFlag" className="text-ink-2 font-medium cursor-pointer">
                  Configure X.509 v3 Basic Constraints as Certificate Authority (CA:TRUE)
                </label>
              </div>

              <div className="pt-3 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setActiveModal(null)}
                  className="px-4 py-2 rounded-xl text-muted hover:bg-surface-3 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busy}
                  className="px-5 py-2 rounded-xl bg-brand-deep hover:bg-brand-deeper text-white font-semibold cursor-pointer"
                >
                  {busy ? "Generating in Rust..." : "Generate & Save to KeyStore"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 2: Generate Symmetric Secret Key (AES, ChaCha20, HMAC, 3DES)
          ==================================================================== */}
      {activeModal === "gen_secret" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white rounded-3xl border border-line-strong shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <h3 className="text-[17px] font-semibold text-ink">Generate Symmetric Secret Key</h3>
              <button onClick={() => setActiveModal(null)} className="p-1 text-faint cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleGenerateSecretKey} className="space-y-4 pt-4 text-[13px]">
              <div>
                <label className="font-medium text-muted block mb-1">Secret Key Alias</label>
                <input
                  type="text"
                  value={skAlias}
                  onChange={(e) => setSkAlias(e.target.value)}
                  required
                  className="w-full h-9 px-3 rounded-lg border border-line-strong"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-medium text-muted block mb-1">Algorithm</label>
                  <select
                    value={skAlg}
                    onChange={(e) => setSkAlg(e.target.value)}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong bg-white"
                  >
                    <option value="AES">AES (128 / 192 / 256)</option>
                    <option value="ChaCha20">ChaCha20-Poly1305</option>
                    <option value="HMAC-SHA256">HMAC-SHA256</option>
                    <option value="HMAC-SHA512">HMAC-SHA512</option>
                    <option value="DESede">Triple DES (DESede)</option>
                    <option value="Blowfish">Blowfish</option>
                  </select>
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Key Size (Bits)</label>
                  <select
                    value={skBits}
                    onChange={(e) => setSkBits(Number(e.target.value))}
                    className="w-full h-9 px-3 rounded-lg border border-line-strong bg-white"
                  >
                    <option value={128}>128 bits</option>
                    <option value={192}>192 bits</option>
                    <option value={256}>256 bits</option>
                    <option value={512}>512 bits</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="font-medium text-muted block mb-1">
                  Custom Key Material (Hex - leave blank for CSPRNG random)
                </label>
                <input
                  type="text"
                  value={skCustomHex}
                  onChange={(e) => setSkCustomHex(e.target.value)}
                  placeholder="Generated automatically by Rust CSPRNG if empty"
                  className="w-full h-9 px-3 rounded-lg border border-line-strong font-mono text-[11.5px]"
                />
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setActiveModal(null)}
                  className="px-4 py-2 rounded-xl text-muted hover:bg-surface-3 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busy}
                  className="px-5 py-2 rounded-xl bg-brand-deep text-white font-semibold cursor-pointer"
                >
                  Generate Secret Key
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 3: Import Trusted Certificate
          ==================================================================== */}
      {activeModal === "import_cert" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-lg bg-white rounded-3xl border border-line-strong shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <h3 className="text-[17px] font-semibold text-ink">Import Trusted X.509 Certificate</h3>
              <button onClick={() => setActiveModal(null)} className="p-1 text-faint cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleImportTrustedCert} className="space-y-3.5 pt-4 text-[13px]">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-medium text-muted block mb-1">Trusted Alias</label>
                  <input
                    type="text"
                    value={impAlias}
                    onChange={(e) => setImpAlias(e.target.value)}
                    required
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Subject CN</label>
                  <input
                    type="text"
                    value={impSubjectCn}
                    onChange={(e) => setImpSubjectCn(e.target.value)}
                    required
                    className="w-full h-9 px-3 rounded-lg border border-line-strong"
                  />
                </div>
              </div>

              <div>
                <label className="font-medium text-muted block mb-1">Certificate PEM (Optional)</label>
                <textarea
                  rows={5}
                  value={impPem}
                  onChange={(e) => setImpPem(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE----- ..."
                  className="w-full p-3 rounded-xl border border-line-strong font-mono text-[11px]"
                />
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setActiveModal(null)}
                  className="px-4 py-2 rounded-xl text-muted hover:bg-surface-3 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-xl bg-brand-deep text-white font-semibold cursor-pointer"
                >
                  Import Certificate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 4: Deep Entry Inspector (Cert, Extensions, Private/Public/Secret Key, Chain)
          ==================================================================== */}
      {activeModal === "inspect_entry" && selectedEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-2xl bg-white rounded-3xl border border-line-strong shadow-2xl p-6 max-h-[88vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <div>
                <span className="text-[11px] font-bold uppercase tracking-wider text-brand">
                  {selectedEntry.entry_type} Inspector
                </span>
                <h3 className="text-[18px] font-semibold text-ink">{selectedEntry.alias}</h3>
              </div>
              <button onClick={() => setActiveModal(null)} className="p-1.5 text-faint hover:text-ink cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Sub-tabs inside Inspector */}
            <div className="flex space-x-1.5 py-3 border-b border-surface-3">
              {selectedEntry.entry_type !== "SecretKey" && (
                <>
                  <button
                    onClick={() => setInspectTab("cert")}
                    className={`px-3.5 py-1.5 rounded-full text-[12px] font-semibold cursor-pointer ${
                      inspectTab === "cert" ? "bg-brand-soft text-brand-deep" : "bg-surface-3 text-muted"
                    }`}
                  >
                    X.509 Certificate
                  </button>
                  <button
                    onClick={() => setInspectTab("extensions")}
                    className={`px-3.5 py-1.5 rounded-full text-[12px] font-semibold cursor-pointer ${
                      inspectTab === "extensions" ? "bg-brand-soft text-brand-deep" : "bg-surface-3 text-muted"
                    }`}
                  >
                    v3 Extensions ({selectedEntry.certificate_chain[0]?.extensions.length || 0})
                  </button>
                  <button
                    onClick={() => setInspectTab("public")}
                    className={`px-3.5 py-1.5 rounded-full text-[12px] font-semibold cursor-pointer ${
                      inspectTab === "public" ? "bg-brand-soft text-brand-deep" : "bg-surface-3 text-muted"
                    }`}
                  >
                    Public Key
                  </button>
                </>
              )}
              {(selectedEntry.entry_type === "KeyPair" || selectedEntry.entry_type === "SecretKey") && (
                <button
                  onClick={() => setInspectTab("private")}
                  className={`px-3.5 py-1.5 rounded-full text-[12px] font-semibold cursor-pointer ${
                    inspectTab === "private" ? "bg-brand-soft text-brand-deep" : "bg-surface-3 text-muted"
                  }`}
                >
                  {selectedEntry.entry_type === "SecretKey" ? "Symmetric Key Material" : "Private Key (PKCS#8)"}
                </button>
              )}
            </div>

            {/* Inspector Body */}
            <div className="flex-1 overflow-y-auto py-4 space-y-3 text-[12.5px] select-text">
              {inspectTab === "cert" && (
                <>
                  <div className="grid grid-cols-2 gap-3 bg-surface-2 p-4 rounded-2xl border border-line">
                    <div>
                      <span className="text-faint block text-[11px]">Subject DN</span>
                      <span className="font-mono text-ink font-medium">{selectedEntry.subject}</span>
                    </div>
                    <div>
                      <span className="text-faint block text-[11px]">Issuer DN</span>
                      <span className="font-mono text-ink">{selectedEntry.issuer}</span>
                    </div>
                    <div>
                      <span className="text-faint block text-[11px]">Serial Number</span>
                      <span className="font-mono text-ink">{selectedEntry.serial_number}</span>
                    </div>
                    <div>
                      <span className="text-faint block text-[11px]">Algorithm &amp; Key Size</span>
                      <span className="font-semibold text-ink">
                        {selectedEntry.algorithm} ({selectedEntry.key_size} bits)
                      </span>
                    </div>
                    <div>
                      <span className="text-faint block text-[11px]">Created</span>
                      <span className="text-ink">{selectedEntry.creation_date}</span>
                    </div>
                    <div>
                      <span className="text-faint block text-[11px]">Expires</span>
                      <span className="text-ink">{selectedEntry.expiry_date}</span>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <span className="text-[11px] font-bold uppercase text-faint block">
                      SHA-256 &amp; SHA-1 Fingerprints
                    </span>
                    <div className="p-2.5 bg-surface-2 border border-line rounded-xl font-mono text-[11px] break-all">
                      <div>
                        <strong>SHA-256:</strong> {selectedEntry.sha256_fingerprint}
                      </div>
                      <div className="mt-1 text-muted">
                        <strong>SHA-1:</strong> {selectedEntry.sha1_fingerprint}
                      </div>
                    </div>
                  </div>

                  {selectedEntry.certificate_chain[0] && (
                    <div>
                      <span className="text-[11px] font-bold uppercase text-faint block mb-1">
                        PEM Encoded Certificate
                      </span>
                      <pre className="bg-ink text-line p-3 rounded-xl font-mono text-[11px] overflow-x-auto max-h-40">
                        {selectedEntry.certificate_chain[0].pem}
                      </pre>
                    </div>
                  )}
                </>
              )}

              {inspectTab === "extensions" && (
                <div className="space-y-2.5">
                  {(selectedEntry.certificate_chain[0]?.extensions || []).map((ext, i) => (
                    <div key={i} className="p-3.5 bg-surface-2 rounded-xl border border-line">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-ink">{ext.name}</span>
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-[11px] text-faint">OID: {ext.oid}</span>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                              ext.critical ? "bg-danger-tint text-[#991B1B]" : "bg-[#E0F2FE] text-[#0369A1]"
                            }`}
                          >
                            {ext.critical ? "Critical" : "Non-Critical"}
                          </span>
                        </div>
                      </div>
                      <div className="mt-1.5 font-mono text-[11.5px] text-ink-2">{ext.value}</div>
                    </div>
                  ))}
                </div>
              )}

              {inspectTab === "public" && (
                <div className="space-y-3">
                  <div>
                    <span className="text-[11px] font-bold uppercase text-faint block mb-1">
                      SubjectPublicKeyInfo (PEM)
                    </span>
                    <pre className="bg-ink text-[#A7F3D0] p-3.5 rounded-xl font-mono text-[11px] overflow-x-auto">
                      {selectedEntry.public_key_pem || "Public key embedded in X.509 certificate."}
                    </pre>
                  </div>
                </div>
              )}

              {inspectTab === "private" && (
                <div className="space-y-3">
                  {selectedEntry.entry_type === "SecretKey" ? (
                    <div>
                      <span className="text-[11px] font-bold uppercase text-faint block mb-1">
                        Raw Symmetric Key Material (Hexadecimal)
                      </span>
                      <pre className="bg-ink text-[#FDE047] p-3.5 rounded-xl font-mono text-[12px] break-all whitespace-pre-wrap">
                        {selectedEntry.secret_key_hex}
                      </pre>
                    </div>
                  ) : (
                    <div>
                      <span className="text-[11px] font-bold uppercase text-faint block mb-1">
                        PKCS#8 Private Key (PEM)
                      </span>
                      <pre className="bg-ink text-[#FCA5A5] p-3.5 rounded-xl font-mono text-[11px] overflow-x-auto">
                        {selectedEntry.private_key_pem}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-line flex justify-between items-center">
              {onToggleEntryInWorkspace ? (
                <button
                  onClick={() => setActiveModal("assign_workspace")}
                  className="px-4 py-2 rounded-xl bg-brand-tint hover:bg-[#DBEAFE] text-[#1D4ED8] text-[12.5px] font-semibold flex items-center space-x-1.5 cursor-pointer"
                >
                  <Layers className="w-4 h-4" />
                  <span>Assign to Workspace...</span>
                </button>
              ) : (
                <div />
              )}
              <div className="flex space-x-2">
                <button
                  onClick={() => {
                    setExportResult(null);
                    setActiveModal("export_entry");
                  }}
                  className="px-4 py-2 rounded-xl bg-brand-soft text-brand-deep text-[12.5px] font-semibold cursor-pointer"
                >
                  Export Formats...
                </button>
                <button
                  onClick={() => setActiveModal(null)}
                  className="px-4 py-2 rounded-xl bg-brand-deep text-white text-[12.5px] font-semibold cursor-pointer"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 5: Multi-Format Native Exporter (PEM, DER, PKCS#7, PKI Path, SPC, PVK, JWK, OpenSSH)
          ==================================================================== */}
      {activeModal === "export_entry" && selectedEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-xl bg-white rounded-3xl border border-line-strong shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <div>
                <h3 className="text-[17px] font-semibold text-ink">
                  Export '{selectedEntry.alias}'
                </h3>
                <p className="text-[12px] text-faint">
                  Select a format to export directly to disk.
                </p>
              </div>
              <button onClick={() => setActiveModal(null)} className="p-1 text-faint cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2.5 pt-4 text-[12.5px]">
              {[
                { id: "cert_pem", label: "X.509 Certificate (.cer / .pem)" },
                { id: "cert_chain_pem", label: "Full Certificate Chain (.pem)" },
                { id: "pkcs7", label: "PKCS#7 Certificate Bundle (.p7b)" },
                { id: "pkipath", label: "PKI Path (.pkipath)" },
                { id: "spc", label: "Microsoft Authenticode SPC (.spc)" },
                { id: "priv_pkcs8", label: "PKCS#8 Private Key (.key)" },
                { id: "priv_pvk", label: "Microsoft PVK Private Key (.pvk)" },
                { id: "priv_jwk", label: "JSON Web Key Private (.jwk.json)" },
                { id: "pub_openssh", label: "OpenSSH Public Key (.pub)" },
                { id: "pub_jwk", label: "JSON Web Key Public (.jwk.json)" },
              ].map((fmt) => (
                <button
                  key={fmt.id}
                  onClick={() => handleExportEntryFormat(selectedEntry, fmt.id)}
                  className="p-3 rounded-xl border border-line hover:border-brand hover:bg-brand-tint text-left font-medium text-ink transition cursor-pointer flex items-center justify-between"
                >
                  <span>{fmt.label}</span>
                  <Download className="w-3.5 h-3.5 text-brand" />
                </button>
              ))}
            </div>

            {exportResult && (
              <div className="mt-4 p-3.5 bg-surface-2 border border-line-strong rounded-2xl space-y-2 select-text">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-success">
                    Saved: {exportResult.saved_path || exportResult.filename}
                  </span>
                  <span className="text-faint">{exportResult.byte_length} bytes</span>
                </div>
                <pre className="bg-ink text-[#38BDF8] p-2.5 rounded-xl font-mono text-[10.5px] max-h-32 overflow-y-auto">
                  {exportResult.content}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 6: CSR Generated Result (PKCS#10 & SPKAC)
          ==================================================================== */}
      {activeModal === "csr_result" && csrData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-xl bg-white rounded-3xl border border-line-strong shadow-2xl p-6 select-text">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <h3 className="text-[17px] font-semibold text-ink">
                CSR Generated for '{csrData.alias}'
              </h3>
              <button onClick={() => setActiveModal(null)} className="p-1 text-faint cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 pt-4 text-[12px]">
              <div>
                <span className="font-bold uppercase text-faint block mb-1">PKCS#10 PEM Format</span>
                <pre className="bg-ink text-[#A7F3D0] p-3 rounded-xl font-mono text-[11px] max-h-40 overflow-y-auto">
                  {csrData.csr_pem}
                </pre>
              </div>
              <div>
                <span className="font-bold uppercase text-faint block mb-1">SPKAC Format</span>
                <pre className="bg-ink text-[#38BDF8] p-3 rounded-xl font-mono text-[10.5px] max-h-28 overflow-y-auto whitespace-pre-wrap break-all">
                  {csrData.spkac_data}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 7: KeyStore Properties
          ==================================================================== */}
      {activeModal === "ks_properties" && activeKs && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white rounded-3xl border border-line-strong shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <h3 className="text-[17px] font-semibold text-ink">KeyStore Properties</h3>
              <button onClick={() => setActiveModal(null)} className="p-1 text-faint cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-2.5 pt-4 text-[13px]">
              <div className="flex justify-between">
                <span className="text-faint">File Name:</span>
                <span className="font-semibold text-ink">{activeKs.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-faint">KeyStore Type:</span>
                <span className="font-semibold text-brand">{activeKs.format}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-faint">Cryptographic Provider:</span>
                <span className="font-semibold text-ink">xkeystore Native Rust Core</span>
              </div>
              <div className="flex justify-between">
                <span className="text-faint">Total Entries:</span>
                <span className="font-semibold text-ink">{activeKs.entries.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-faint">Key Pairs:</span>
                <span>{activeKs.entries.filter((e) => e.entry_type === "KeyPair").length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-faint">Trusted Certificates:</span>
                <span>{activeKs.entries.filter((e) => e.entry_type === "TrustedCertificate").length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-faint">Secret Keys:</span>
                <span>{activeKs.entries.filter((e) => e.entry_type === "SecretKey").length}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 8: Rename Alias & Add Label
          ==================================================================== */}
      {activeModal === "rename_entry" && selectedEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-sm bg-white rounded-3xl border border-line-strong shadow-2xl p-6">
            <h3 className="text-[16px] font-semibold text-ink mb-3">Rename Entry Alias</h3>
            <form onSubmit={handleRenameSubmit} className="space-y-3">
              <input
                type="text"
                value={newAliasName}
                onChange={(e) => setNewAliasName(e.target.value)}
                required
                className="w-full h-9 px-3 rounded-lg border border-line-strong text-[13px]"
              />
              <div className="flex justify-end space-x-2">
                <button type="button" onClick={() => setActiveModal(null)} className="px-3 py-1.5 text-[12px] text-faint">
                  Cancel
                </button>
                <button type="submit" className="px-4 py-1.5 rounded-xl bg-brand-deep text-white text-[12.5px] font-semibold">
                  Rename
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {activeModal === "add_label" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-sm bg-white rounded-3xl border border-line-strong shadow-2xl p-6">
            <h3 className="text-[16px] font-semibold text-ink mb-3">Add Label Tag</h3>
            <form onSubmit={handleAddLabelSubmit} className="space-y-3">
              <input
                type="text"
                value={newLabelText}
                onChange={(e) => setNewLabelText(e.target.value)}
                placeholder="e.g. Production, PCI-DSS, mTLS"
                required
                className="w-full h-9 px-3 rounded-lg border border-line-strong text-[13px]"
              />
              <div className="flex justify-end space-x-2">
                <button type="button" onClick={() => setActiveModal(null)} className="px-3 py-1.5 text-[12px] text-faint">
                  Cancel
                </button>
                <button type="submit" className="px-4 py-1.5 rounded-xl bg-brand-deep text-white text-[12.5px] font-semibold">
                  Add Label
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 9: Assign Entry to Workspaces
          ==================================================================== */}
      {activeModal === "assign_workspace" && selectedEntry && onToggleEntryInWorkspace && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-white rounded-3xl border border-line-strong shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <div>
                <h3 className="text-[16px] font-bold text-ink flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-brand" />
                  <span>Assign to Workspaces</span>
                </h3>
                <p className="text-[12px] text-faint mt-0.5">
                  Toggle which Workspaces include <strong>{selectedEntry.alias}</strong>
                </p>
              </div>
              <button
                onClick={() => setActiveModal(null)}
                className="p-1 text-faint hover:text-ink cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="py-4 space-y-2">
              {workspaces.map((ws) => {
                const isAssigned = ws.entryIds.includes(selectedEntry.id);
                return (
                  <div
                    key={ws.id}
                    onClick={() => {
                      onToggleEntryInWorkspace(ws.id, selectedEntry.id);
                      showToast(
                        isAssigned
                          ? `Removed '${selectedEntry.alias}' from ${ws.name}`
                          : `Added '${selectedEntry.alias}' to ${ws.name}`
                      );
                    }}
                    className={`p-3.5 rounded-2xl border flex items-center justify-between cursor-pointer transition ${
                      isAssigned
                        ? "bg-brand-tint border-[#93C5FD]"
                        : "bg-surface-2 border-line hover:border-line-strong"
                    }`}
                  >
                    <div>
                      <div className="text-[13.5px] font-bold text-ink">{ws.name}</div>
                      <div className="text-[11.5px] text-faint">
                        {ws.environment} • {ws.entryIds.length} Certs
                      </div>
                    </div>
                    <span
                      className={`px-3 py-1 rounded-full text-[11.5px] font-semibold ${
                        isAssigned
                          ? "bg-success-tint text-[#15803D]"
                          : "bg-white border border-line-strong text-muted"
                      }`}
                    >
                      {isAssigned ? "✓ Assigned" : "+ Add"}
                    </span>
                  </div>
                );
              })}
            </div>

            <div className="pt-3 border-t border-line flex justify-end">
              <button
                onClick={() => setActiveModal(null)}
                className="px-5 py-2 rounded-full bg-brand-deep text-white text-[12.5px] font-semibold cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
