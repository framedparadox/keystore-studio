import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Search,
  Plus,
  FileText,
  List,
  Network,
  Save,
  ChevronDown,
  Trash2,
  KeyRound,
  ShieldCheck,
  Lock,
  Copy,
  ClipboardPaste,
  Download,
  FileSignature,
  Edit3,
  CheckCircle2,
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
import clsx from "clsx";
import {
  Badge,
  Button,
  Card,
  Column,
  DataTable,
  DescriptionList,
  EmptyState,
  IconButton,
  KpiCard,
  Modal,
  Page,
  PageHeader,
  SearchInput,
  Segmented,
} from "../components/ui";
import {
  AlgorithmCell,
  EntryNameCell,
  EntryTypeBadge,
  ExpiryCell,
  HealthBadge,
  LabelList,
} from "../components/entry";
import { daysUntilExpiry, entryHealth, formatDuration, summarize } from "../lib/metrics";

type TypeFilter = "ALL" | "KeyPair" | "TrustedCertificate" | "SecretKey";

const cnOf = (dn: string) => dn.match(/(?:^|,\s*)CN=([^,]+)/i)?.[1]?.trim() ?? "";

const CopyIcon: React.FC<{ value: string; label: string }> = ({ value, label }) => {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={() =>
        navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        })
      }
      className="w-6 h-6 rounded-control inline-flex items-center justify-center text-subtle hover:text-ink hover:bg-surface-3 cursor-pointer"
    >
      {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
};

const CodeBlock: React.FC<{ label: string; value: string; copyValue?: string; wrap?: boolean }> = ({
  label,
  value,
  copyValue,
  wrap,
}) => (
  <div>
    <div className="flex items-center justify-between mb-1">
      <span className="text-[11px] font-semibold uppercase text-faint">{label}</span>
      <CopyIcon value={copyValue ?? value} label={`Copy ${label}`} />
    </div>
    <pre
      className={clsx(
        "bg-term-bg text-term-fg p-3.5 rounded-control font-mono text-[11px]",
        wrap ? "break-all whitespace-pre-wrap" : "overflow-x-auto"
      )}
    >
      {value}
    </pre>
  </div>
);

const DetailTable: React.FC<{ rows: { label: string; value: string; mono?: boolean; copy?: string }[] }> = ({ rows }) => (
  <table className="w-full border border-line rounded-card overflow-hidden border-separate border-spacing-0 text-[12.5px]">
    <tbody>
      {rows.map((r) => (
        <tr key={r.label}>
          <th scope="row" className="w-[34%] align-top text-left font-medium text-faint bg-surface-2 border-b border-line px-3 py-2">
            {r.label}
          </th>
          <td className={clsx("align-top border-b border-line px-3 py-2 text-ink break-all", r.mono && "font-mono text-[11.5px]")}>
            <div className="flex items-start justify-between gap-2">
              <span>{r.value}</span>
              {r.copy !== undefined && r.copy !== "" && <CopyIcon value={r.copy} label={`Copy ${r.label}`} />}
            </div>
          </td>
        </tr>
      ))}
    </tbody>
  </table>
);

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

  // View controls
  const [subView, setSubView] = useState<"list" | "graph">("list");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedLabelFilter, setSelectedLabelFilter] = useState<string>("ALL");

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
  const [inspectTab, setInspectTab] = useState<"cert" | "pem" | "extensions" | "private" | "public" | "chain">("cert");
  const [csrData, setCsrData] = useState<CsrResult | null>(null);
  const [exportResult, setExportResult] = useState<ExportPayloadResult | null>(null);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<KeystoreEntry | null>(null);

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

  const typeCounts = {
    ALL: activeKs?.entries.length ?? 0,
    KeyPair: activeKs?.entries.filter((e) => e.entry_type === "KeyPair").length ?? 0,
    TrustedCertificate: activeKs?.entries.filter((e) => e.entry_type === "TrustedCertificate").length ?? 0,
    SecretKey: activeKs?.entries.filter((e) => e.entry_type === "SecretKey").length ?? 0,
  };
  const ksSummary = summarize(activeKs?.entries ?? []);
  const typeFilter = (["ALL", "KeyPair", "TrustedCertificate", "SecretKey"] as const).includes(
    selectedLabelFilter as "ALL"
  )
    ? (selectedLabelFilter as TypeFilter)
    : "ALL";

  const openInspector = (entry: KeystoreEntry) => {
    setSelectedEntry(entry);
    setInspectTab(entry.entry_type === "SecretKey" ? "private" : "cert");
    setActiveModal("inspect_entry");
  };

  const HEALTH_RANK = { "at-risk": 0, attention: 1, healthy: 2 } as const;

  const columns: Column<KeystoreEntry>[] = [
    {
      id: "alias",
      header: "Alias",
      width: "30%",
      sortValue: (e) => e.alias,
      cell: (e) => <EntryNameCell entry={e} />,
    },
    {
      id: "type",
      header: "Type",
      hideBelow: "2xl",
      sortValue: (e) => e.entry_type,
      cell: (e) => <EntryTypeBadge type={e.entry_type} />,
    },
    {
      id: "ext",
      header: "Extensions",
      sortValue: (e) => e.certificate_chain[0]?.extensions.length ?? 0,
      cell: (e) => {
        const exts = e.certificate_chain[0]?.extensions ?? [];
        return exts.length ? (
          <span className="text-ink-2" title={exts.map((x) => x.name).join(", ")}>
            {exts.length} {exts.length === 1 ? "extension" : "extensions"}
          </span>
        ) : (
          <span className="text-subtle">—</span>
        );
      },
    },
    {
      id: "alg",
      header: "Algorithm",
      sortValue: (e) => e.algorithm,
      cell: (e) => <AlgorithmCell entry={e} />,
    },
    {
      id: "expiry",
      header: "Expires",
      width: "210px",
      sortValue: (e) => daysUntilExpiry(e),
      cell: (e) => <ExpiryCell entry={e} />,
    },
    {
      id: "status",
      header: "Status",
      sortValue: (e) => HEALTH_RANK[entryHealth(e)],
      cell: (e) => <HealthBadge entry={e} />,
    },
    {
      id: "labels",
      header: "Labels",
      hideBelow: "2xl",
      cell: (e) => <LabelList labels={e.labels} />,
    },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "196px",
      cell: (entry) => (
        <div className="inline-flex items-center gap-0.5" onClick={(ev) => ev.stopPropagation()}>
          {onToggleEntryInWorkspace && (
            <IconButton
              icon={Layers}
              label="Assign to workspace"
              onClick={() => {
                setSelectedEntry(entry);
                setActiveModal("assign_workspace");
              }}
            />
          )}
          {entry.entry_type === "KeyPair" && (
            <IconButton icon={FileSignature} label="Generate CSR" onClick={() => handleGenerateCsr(entry)} />
          )}
          <IconButton
            icon={Download}
            label="Export"
            onClick={() => {
              setSelectedEntry(entry);
              setExportResult(null);
              setActiveModal("export_entry");
            }}
          />
          <IconButton
            icon={Edit3}
            label="Rename alias"
            onClick={() => {
              setSelectedEntry(entry);
              setNewAliasName(entry.alias);
              setActiveModal("rename_entry");
            }}
          />
          <IconButton icon={Copy} label="Copy entry" onClick={() => handleCutOrCopyEntry(entry, "copy")} />
          <IconButton icon={Trash2} label="Delete entry" tone="danger" onClick={() => setPendingDelete(entry)} />
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
        eyebrow="Keystores"
        title={activeKs.name}
        description={
          <span className="inline-flex items-center gap-2">
            <Badge tone="brand">{activeKs.format}</Badge>
            <span className="font-mono text-[12px] truncate">{activeKs.path}</span>
          </span>
        }
        actions={
          <>
            <Button icon={Info} onClick={() => setActiveModal("ks_properties")}>
              Properties
            </Button>
            <Button icon={FileText} onClick={handleExportCsv} disabled={busy}>
              Export CSV
            </Button>
            <Button icon={Save} onClick={handleSaveKeystoreBinary} disabled={busy}>
              Save
            </Button>
            <div className="relative">
              <Button variant="primary" icon={Plus} onClick={() => setAddMenuOpen(!addMenuOpen)} aria-expanded={addMenuOpen}>
                Add entry
                <ChevronDown className="w-3.5 h-3.5 -mr-1" />
              </Button>
              {addMenuOpen && (
                <>
                  <div className="fixed inset-0 z-30" onClick={() => setAddMenuOpen(false)} />
                  <div className="absolute right-0 mt-1.5 w-72 bg-surface rounded-card border border-line shadow-pop p-1.5 z-40" role="menu">
                    {[
                      { icon: KeyRound, title: "Generate key pair", sub: "RSA, ECDSA, Ed25519, ML-DSA + certificate", modal: "gen_keypair" as const },
                      { icon: Lock, title: "Generate secret key", sub: "AES-256, ChaCha20, HMAC, 3DES", modal: "gen_secret" as const },
                      { icon: ShieldCheck, title: "Import trusted certificate", sub: "X.509 PEM, DER, PKCS#7", modal: "import_cert" as const },
                    ].map((item) => (
                      <button
                        key={item.title}
                        role="menuitem"
                        onClick={() => {
                          setAddMenuOpen(false);
                          setActiveModal(item.modal);
                        }}
                        className="w-full px-2.5 py-2 rounded-control text-left hover:bg-surface-2 flex items-start gap-2.5 cursor-pointer"
                      >
                        <item.icon className="w-4 h-4 mt-0.5 text-muted shrink-0" />
                        <span>
                          <span className="block text-[13px] font-medium text-ink">{item.title}</span>
                          <span className="block text-[12px] text-faint">{item.sub}</span>
                        </span>
                      </button>
                    ))}
                    {clipboardEntry && (
                      <button
                        role="menuitem"
                        onClick={() => {
                          setAddMenuOpen(false);
                          handlePasteEntry();
                        }}
                        className="w-full mt-1 pt-2.5 px-2.5 pb-2 rounded-control border-t border-line text-left hover:bg-surface-2 flex items-start gap-2.5 cursor-pointer"
                      >
                        <ClipboardPaste className="w-4 h-4 mt-0.5 text-muted shrink-0" />
                        <span>
                          <span className="block text-[13px] font-medium text-ink">Paste “{clipboardEntry.entry.alias}”</span>
                          <span className="block text-[12px] text-faint">From the keystore clipboard</span>
                        </span>
                      </button>
                    )}
                  </div>
                </>
              )}
            </div>
          </>
        }
      />

      {/* Keystore switcher — one selectable tile per open file */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3" role="tablist" aria-label="Open keystores">
        {keystores.map((ks) => {
          const active = ks.id === activeKs.id;
          const issues = ks.entries.filter((e) => entryHealth(e) !== "healthy").length;
          return (
            <button
              key={ks.id}
              role="tab"
              aria-selected={active}
              onClick={() => onSelectKeystore(ks.id)}
              className={clsx(
                "text-left rounded-card border bg-surface px-4 py-3 flex items-center gap-3 transition cursor-pointer",
                active ? "border-brand ring-4 ring-brand-soft/60" : "border-line shadow-card hover:border-line-strong"
              )}
            >
              <span
                className={clsx(
                  "w-9 h-9 rounded-control flex items-center justify-center shrink-0",
                  active ? "bg-brand-tint text-brand" : "bg-surface-3 text-muted"
                )}
              >
                <FolderArchive className="w-[18px] h-[18px]" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] font-semibold text-ink truncate">{ks.name}</span>
                <span className="block text-[12px] text-faint">
                  {ks.format} · {ks.entries.length} {ks.entries.length === 1 ? "entry" : "entries"}
                </span>
              </span>
              {issues > 0 && <Badge tone="warning">{issues}</Badge>}
            </button>
          );
        })}
      </div>

      {/* Entries */}
      <Card padded={false} className="mt-4 overflow-hidden flex flex-col">
        <div className="px-5 py-3 border-b border-line flex flex-wrap items-center gap-3">
          <Segmented<TypeFilter>
            label="Filter by entry type"
            value={typeFilter}
            onChange={(v) => setSelectedLabelFilter(v)}
            options={[
              { value: "ALL", label: "All", count: typeCounts.ALL },
              { value: "KeyPair", label: "Key pairs", count: typeCounts.KeyPair },
              { value: "TrustedCertificate", label: "Certificates", count: typeCounts.TrustedCertificate },
              { value: "SecretKey", label: "Secret keys", count: typeCounts.SecretKey },
            ]}
          />
          {allLabels.length > 0 && (
            <select
              aria-label="Filter by label"
              value={typeFilter === "ALL" && selectedLabelFilter !== "ALL" ? selectedLabelFilter : ""}
              onChange={(e) => setSelectedLabelFilter(e.target.value || "ALL")}
              className="field !w-auto !h-8 pr-8 cursor-pointer"
            >
              <option value="">All labels</option>
              {allLabels.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          )}
          <div className="flex-1" />
          <SearchInput
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search entries"
            className="w-full sm:w-64"
          />
          <Segmented<"list" | "graph">
            label="View"
            value={subView}
            onChange={setSubView}
            options={[
              { value: "list", label: <><List className="w-3.5 h-3.5" /> Table</> },
              { value: "graph", label: <><Network className="w-3.5 h-3.5" /> Hierarchy</> },
            ]}
          />
        </div>

        {subView === "list" ? (
          <DataTable<KeystoreEntry>
            label={`Entries in ${activeKs.name}`}
            columns={columns}
            rows={filteredEntries}
            rowKey={(e) => e.id}
            onRowClick={openInspector}
            initialSort={{ id: "alias", dir: "asc" }}
            empty={
              <EmptyState
                icon={Search}
                title="No matching entries"
                description="Clear the filters or add a new entry to this keystore."
                action={
                  <Button
                    onClick={() => {
                      setSearchQuery("");
                      setSelectedLabelFilter("ALL");
                    }}
                  >
                    Clear filters
                  </Button>
                }
              />
            }
            footer={
              <>
                <span>
                  Showing <strong className="text-ink font-semibold">{filteredEntries.length}</strong> of {activeKs.entries.length} entries
                </span>
                {clipboardEntry ? (
                  <span className="inline-flex items-center gap-2">
                    Clipboard: <span className="font-medium text-ink">{clipboardEntry.entry.alias}</span>
                    <Button size="sm" icon={ClipboardPaste} onClick={handlePasteEntry}>
                      Paste
                    </Button>
                  </span>
                ) : (
                  <span>Updated {activeKs.updated_at}</span>
                )}
              </>
            }
          />
        ) : (
          <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-4">
            {(
              [
                {
                  title: "Root & trusted CAs",
                  items: activeKs.entries.filter((e) => e.entry_type === "TrustedCertificate" || e.labels.includes("CA")),
                },
                {
                  title: "Key pairs",
                  items: activeKs.entries.filter((e) => e.entry_type === "KeyPair" && !e.labels.includes("CA")),
                },
                { title: "Secret keys", items: activeKs.entries.filter((e) => e.entry_type === "SecretKey") },
              ] as const
            ).map((col) => (
              <section key={col.title} className="rounded-card border border-line bg-surface-2 p-3">
                <h4 className="px-1 pb-2 flex items-center justify-between text-[12px] font-semibold uppercase tracking-[0.05em] text-faint">
                  {col.title}
                  <span className="tabular-nums">{col.items.length}</span>
                </h4>
                <div className="space-y-2">
                  {col.items.map((e) => (
                    <button
                      key={e.id}
                      onClick={() => openInspector(e)}
                      className="w-full text-left rounded-control border border-line bg-surface p-3 shadow-card hover:border-line-strong cursor-pointer"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[13px] font-medium text-ink truncate">{e.alias}</span>
                        <HealthBadge entry={e} />
                      </div>
                      <div className="text-[12px] text-faint mt-1 truncate">
                        {e.algorithm} {e.key_size}-bit · issued by {e.issuer.split(",")[0].replace("CN=", "")}
                      </div>
                    </button>
                  ))}
                  {col.items.length === 0 && <p className="px-1 py-3 text-[12px] text-subtle">None</p>}
                </div>
              </section>
            ))}
          </div>
        )}
      </Card>

      {/* KPI strip for the active keystore */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
        <KpiCard label="Entries" value={ksSummary.total} hint={`${typeCounts.KeyPair} key pairs · ${typeCounts.TrustedCertificate} certs · ${typeCounts.SecretKey} secrets`} />
        <KpiCard
          label="Expiring in 90 days"
          value={ksSummary.expiring90}
          hint={ksSummary.expiring30 ? `${ksSummary.expiring30} within 30 days` : "None within 30 days"}
          hintTone={ksSummary.expiring30 ? "warning" : "neutral"}
        />
        <KpiCard
          label="Needs action"
          value={ksSummary.expired + ksSummary.weak}
          hint={`${ksSummary.expired} expired · ${ksSummary.weak} weak`}
          hintTone={ksSummary.expired + ksSummary.weak ? "danger" : "success"}
        />
        <KpiCard
          label="Median key age"
          value={formatDuration(ksSummary.medianAgeDays)}
          hint={`Oldest ${formatDuration(ksSummary.oldestAgeDays)}`}
        />
      </div>

      <Modal
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        icon={Trash2}
        size="sm"
        title="Delete entry?"
        description={pendingDelete ? `“${pendingDelete.alias}” will be removed from ${activeKs.name}. You can undo this from the top bar.` : undefined}
        footer={
          <>
            <Button onClick={() => setPendingDelete(null)}>Cancel</Button>
            <Button
              variant="primary"
              className="!bg-danger-fill hover:!bg-danger"
              onClick={() => {
                if (pendingDelete) handleDeleteEntry(pendingDelete.id, pendingDelete.alias);
                setPendingDelete(null);
              }}
            >
              Delete
            </Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">The underlying file changes only when you save the keystore.</p>
      </Modal>

      <Modal
        open={activeModal === "ks_properties"}
        onClose={() => setActiveModal(null)}
        icon={FolderArchive}
        title="Keystore properties"
        description={activeKs.path}
      >
        <DescriptionList
          items={[
            { label: "File name", value: activeKs.name },
            { label: "Provider", value: "xkeystore native Rust core" },
            { label: "Password protected", value: activeKs.password_protected ? "Yes" : "No" },
            { label: "Created", value: activeKs.created_at },
            { label: "Key pairs", value: typeCounts.KeyPair },
            { label: "Trusted certificates", value: typeCounts.TrustedCertificate },
            { label: "Secret keys", value: typeCounts.SecretKey },
            { label: "Last updated", value: activeKs.updated_at },
          ]}
        />
        <div className="mt-5 pt-5 border-t border-line">
          <label className="label" htmlFor="ks-format">
            Keystore type
          </label>
          <select
            id="ks-format"
            value={activeKs.format}
            onChange={(e) => handleChangeKeystoreFormat(e.target.value as KeystoreFormat)}
            className="field cursor-pointer"
          >
            {(["PKCS12", "JKS", "JCEKS", "BKS", "BCFKS", "UBER"] as KeystoreFormat[]).map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
          <p className="text-[12px] text-faint mt-1.5">Converting renames the file extension; save to write it to disk.</p>
        </div>
      </Modal>

      {/* ====================================================================
          MODAL 1: Generate Key Pair + Self-Signed / CA-Signed X.509 Certificate
          ==================================================================== */}
      {activeModal === "gen_keypair" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-xl bg-surface rounded-panel border border-line-strong shadow-pop p-6 max-h-[90vh] overflow-y-auto">
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
                    className="field"
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
                    className="field"
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
                    className="field"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Validity (Days)</label>
                  <input
                    type="number"
                    value={kpDays}
                    onChange={(e) => setKpDays(Number(e.target.value))}
                    className="field"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Sign With CA (Optional)</label>
                  <select
                    value={kpSignerAlias}
                    onChange={(e) => setKpSignerAlias(e.target.value)}
                    className="field"
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
                    className="field"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Organization (O)</label>
                  <input
                    type="text"
                    value={kpOrg}
                    onChange={(e) => setKpOrg(e.target.value)}
                    className="field"
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
                    className="field"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Country (C)</label>
                  <input
                    type="text"
                    value={kpCountry}
                    onChange={(e) => setKpCountry(e.target.value)}
                    className="field"
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
                  className="field"
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
                  className="px-4 py-2 rounded-control text-muted hover:bg-surface-3 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busy}
                  className="px-5 py-2 rounded-control bg-brand hover:bg-brand-deep text-white font-semibold cursor-pointer"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-md bg-surface rounded-panel border border-line-strong shadow-pop p-6">
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
                  className="field"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-medium text-muted block mb-1">Algorithm</label>
                  <select
                    value={skAlg}
                    onChange={(e) => setSkAlg(e.target.value)}
                    className="field"
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
                    className="field"
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
                  className="field font-mono !text-[12px]"
                />
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setActiveModal(null)}
                  className="px-4 py-2 rounded-control text-muted hover:bg-surface-3 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busy}
                  className="px-5 py-2 rounded-control bg-brand text-white font-semibold cursor-pointer"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-lg bg-surface rounded-panel border border-line-strong shadow-pop p-6">
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
                    className="field"
                  />
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">Subject CN</label>
                  <input
                    type="text"
                    value={impSubjectCn}
                    onChange={(e) => setImpSubjectCn(e.target.value)}
                    required
                    className="field"
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
                  className="w-full p-3 rounded-control border border-line-strong bg-surface shadow-card focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand-soft font-mono text-[11px]"
                />
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setActiveModal(null)}
                  className="px-4 py-2 rounded-control text-muted hover:bg-surface-3 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-control bg-brand text-white font-semibold cursor-pointer"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-[682px] bg-surface rounded-panel border border-line-strong shadow-pop p-6 max-h-[88vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-brand">
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
                    className={`px-3.5 py-1.5 rounded-control text-[12px] font-semibold cursor-pointer ${
                      inspectTab === "cert" ? "bg-brand-soft text-brand-deep" : "bg-surface-3 text-muted"
                    }`}
                  >
                    X.509 Certificate
                  </button>
                  <button
                    onClick={() => setInspectTab("pem")}
                    className={`px-3.5 py-1.5 rounded-control text-[12px] font-semibold cursor-pointer ${
                      inspectTab === "pem" ? "bg-brand-soft text-brand-deep" : "bg-surface-3 text-muted"
                    }`}
                  >
                    PEM
                  </button>
                  <button
                    onClick={() => setInspectTab("extensions")}
                    className={`px-3.5 py-1.5 rounded-control text-[12px] font-semibold cursor-pointer ${
                      inspectTab === "extensions" ? "bg-brand-soft text-brand-deep" : "bg-surface-3 text-muted"
                    }`}
                  >
                    v3 Extensions ({selectedEntry.certificate_chain[0]?.extensions.length || 0})
                  </button>
                  <button
                    onClick={() => setInspectTab("public")}
                    className={`px-3.5 py-1.5 rounded-control text-[12px] font-semibold cursor-pointer ${
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
                  className={`px-3.5 py-1.5 rounded-control text-[12px] font-semibold cursor-pointer ${
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
                  <DetailTable
                    rows={[
                      { label: "Subject CN", value: cnOf(selectedEntry.subject), mono: true, copy: cnOf(selectedEntry.subject) },
                      { label: "Subject DN", value: selectedEntry.subject, mono: true, copy: selectedEntry.subject },
                      { label: "Issuer CN", value: cnOf(selectedEntry.issuer), mono: true, copy: cnOf(selectedEntry.issuer) },
                      { label: "Issuer DN", value: selectedEntry.issuer, mono: true, copy: selectedEntry.issuer },
                      { label: "Serial Number", value: selectedEntry.serial_number, mono: true, copy: selectedEntry.serial_number },
                      { label: "Algorithm & Key Size", value: `${selectedEntry.algorithm} (${selectedEntry.key_size} bits)` },
                      { label: "Created", value: selectedEntry.creation_date },
                      { label: "Expires", value: selectedEntry.expiry_date },
                      { label: "SHA-256", value: selectedEntry.sha256_fingerprint, mono: true, copy: selectedEntry.sha256_fingerprint },
                      { label: "SHA-1", value: selectedEntry.sha1_fingerprint, mono: true, copy: selectedEntry.sha1_fingerprint },
                    ].filter((r) => r.value !== "")}
                  />
                </>
              )}

              {inspectTab === "pem" && selectedEntry.certificate_chain[0] && (
                <CodeBlock label="PEM Encoded Certificate" value={selectedEntry.certificate_chain[0].pem} />
              )}

              {inspectTab === "extensions" && (
                <div className="space-y-2.5">
                  {(selectedEntry.certificate_chain[0]?.extensions || []).map((ext, i) => (
                    <div key={i} className="p-3.5 bg-surface-2 rounded-control border border-line">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-ink">{ext.name}</span>
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-[11px] text-faint">OID: {ext.oid}</span>
                          <span
                            className={`px-2 py-0.5 rounded-control text-[10px] font-semibold ${
                              ext.critical ? "bg-danger-tint text-danger" : "bg-brand-tint text-brand-deep"
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
                  <CodeBlock
                    label="SubjectPublicKeyInfo (PEM)"
                    value={selectedEntry.public_key_pem || "Public key embedded in X.509 certificate."}
                    copyValue={selectedEntry.public_key_pem ?? undefined}
                  />
                </div>
              )}

              {inspectTab === "private" && (
                <div className="space-y-3">
                  {selectedEntry.entry_type === "SecretKey" ? (
                    <CodeBlock
                      label="Raw Symmetric Key Material (Hexadecimal)"
                      value={selectedEntry.secret_key_hex ?? ""}
                      wrap
                    />
                  ) : (
                    <CodeBlock label="PKCS#8 Private Key (PEM)" value={selectedEntry.private_key_pem ?? ""} />
                  )}
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-line flex justify-between items-center">
              {onToggleEntryInWorkspace ? (
                <button
                  onClick={() => setActiveModal("assign_workspace")}
                  className="w-9 h-9 rounded-control bg-brand-tint hover:bg-brand-soft text-brand-deep flex items-center justify-center cursor-pointer"
                  aria-label="Assign to workspace"
                  title="Assign to workspace"
                >
                  <Layers className="w-4 h-4" />
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
                  className="px-4 py-2 rounded-control bg-brand-soft text-brand-deep text-[12.5px] font-semibold cursor-pointer"
                >
                  Export Formats...
                </button>
                <button
                  onClick={() => setActiveModal(null)}
                  className="px-4 py-2 rounded-control bg-brand text-white text-[12.5px] font-semibold cursor-pointer"
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-xl bg-surface rounded-panel border border-line-strong shadow-pop p-6">
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
                  className="p-3 rounded-control border border-line hover:border-brand hover:bg-brand-tint text-left font-medium text-ink transition cursor-pointer flex items-center justify-between"
                >
                  <span>{fmt.label}</span>
                  <Download className="w-3.5 h-3.5 text-brand" />
                </button>
              ))}
            </div>

            {exportResult && (
              <div className="mt-4 p-3.5 bg-surface-2 border border-line-strong rounded-card space-y-2 select-text">
                <div className="flex items-center justify-between text-[12px]">
                  <span className="font-semibold text-success">
                    Saved: {exportResult.saved_path || exportResult.filename}
                  </span>
                  <span className="text-faint">{exportResult.byte_length} bytes</span>
                </div>
                <pre className="bg-term-bg text-term-fg p-2.5 rounded-control font-mono text-[10.5px] max-h-32 overflow-y-auto">
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-xl bg-surface rounded-panel border border-line-strong shadow-pop p-6 select-text">
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
                <span className="font-semibold uppercase text-faint block mb-1">PKCS#10 PEM Format</span>
                <pre className="bg-term-bg text-term-fg p-3 rounded-control font-mono text-[11px] max-h-40 overflow-y-auto">
                  {csrData.csr_pem}
                </pre>
              </div>
              <div>
                <span className="font-semibold uppercase text-faint block mb-1">SPKAC Format</span>
                <pre className="bg-term-bg text-term-fg p-3 rounded-control font-mono text-[10.5px] max-h-28 overflow-y-auto whitespace-pre-wrap break-all">
                  {csrData.spkac_data}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 8: Rename Alias & Add Label
          ==================================================================== */}
      {activeModal === "rename_entry" && selectedEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-sm bg-surface rounded-panel border border-line-strong shadow-pop p-6">
            <h3 className="text-[16px] font-semibold text-ink mb-3">Rename Entry Alias</h3>
            <form onSubmit={handleRenameSubmit} className="space-y-3">
              <input
                type="text"
                value={newAliasName}
                onChange={(e) => setNewAliasName(e.target.value)}
                required
                className="field"
              />
              <div className="flex justify-end space-x-2">
                <button type="button" onClick={() => setActiveModal(null)} className="px-3 py-1.5 text-[12px] text-faint">
                  Cancel
                </button>
                <button type="submit" className="px-4 py-1.5 rounded-control bg-brand text-white text-[12.5px] font-semibold">
                  Rename
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {activeModal === "add_label" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-sm bg-surface rounded-panel border border-line-strong shadow-pop p-6">
            <h3 className="text-[16px] font-semibold text-ink mb-3">Add Label Tag</h3>
            <form onSubmit={handleAddLabelSubmit} className="space-y-3">
              <input
                type="text"
                value={newLabelText}
                onChange={(e) => setNewLabelText(e.target.value)}
                placeholder="e.g. Production, PCI-DSS, mTLS"
                required
                className="field"
              />
              <div className="flex justify-end space-x-2">
                <button type="button" onClick={() => setActiveModal(null)} className="px-3 py-1.5 text-[12px] text-faint">
                  Cancel
                </button>
                <button type="submit" className="px-4 py-1.5 rounded-control bg-brand text-white text-[12.5px] font-semibold">
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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4">
          <div className="w-full max-w-md bg-surface rounded-panel border border-line-strong shadow-pop p-6">
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <div>
                <h3 className="text-[16px] font-semibold text-ink flex items-center space-x-2">
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
                    className={`p-3.5 rounded-card border flex items-center justify-between cursor-pointer transition ${
                      isAssigned
                        ? "bg-brand-tint border-brand-soft-hover"
                        : "bg-surface-2 border-line hover:border-line-strong"
                    }`}
                  >
                    <div>
                      <div className="text-[13.5px] font-semibold text-ink">{ws.name}</div>
                      <div className="text-[11.5px] text-faint">
                        {ws.environment} • {ws.entryIds.length} Certs
                      </div>
                    </div>
                    <span
                      className={`px-3 py-1 rounded-control text-[11.5px] font-semibold ${
                        isAssigned
                          ? "bg-success-tint text-success"
                          : "bg-surface border border-line-strong text-muted"
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
                className="px-5 py-2 rounded-control bg-brand text-white text-[12.5px] font-semibold cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </Page>
  );
};
