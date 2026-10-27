import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Header } from "./components/Header";
import { Sidebar } from "./components/Sidebar";
import { KeystoresView } from "./views/KeystoresView";
import { DashboardView } from "./views/DashboardView";
import { CaSigningView } from "./views/CaSigningView";
import { ExamineView } from "./views/ExamineView";
import { ScannerView } from "./views/ScannerView";
import { NewKeystoreModal } from "./components/NewKeystoreModal";
import { TabType, KeystoreFile, ExportPayloadResult } from "./types/crypto";
import { initialKeystores } from "./data/mockData";
import { KeyRound, ShieldCheck, CheckCircle2, Lock, Unlock, Eye, EyeOff } from "lucide-react";

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<TabType>("keystores");
  const [keystores, setKeystores] = useState<KeystoreFile[]>(initialKeystores);
  const [activeKeystoreId, setActiveKeystoreId] = useState<string>(initialKeystores[0].id);

  // Undo / Redo History Stack
  const [history, setHistory] = useState<KeystoreFile[][]>([]);
  const [redoStack, setRedoStack] = useState<KeystoreFile[][]>([]);

  // Telemetry & Operations Counter (for Stats Dashboard)
  const [opsCount, setOpsCount] = useState<number>(4113);
  const [signaturesCount, setSignaturesCount] = useState<number>(18);

  const [isNewKeystoreModalOpen, setIsNewKeystoreModalOpen] = useState(false);
  const [showPasswords, setShowPasswords] = useState(false);

  const pushState = (nextKeystores: KeystoreFile[]) => {
    setHistory((prev) => [...prev.slice(-19), keystores]);
    setRedoStack([]);
    setKeystores(nextKeystores);
  };

  const handleUndo = () => {
    if (history.length === 0) return;
    const prev = history[history.length - 1];
    setRedoStack((r) => [keystores, ...r]);
    setHistory((h) => h.slice(0, -1));
    setKeystores(prev);
  };

  const handleRedo = () => {
    if (redoStack.length === 0) return;
    const next = redoStack[0];
    setHistory((h) => [...h, keystores]);
    setRedoStack((r) => r.slice(1));
    setKeystores(next);
  };

  const handleUpdateKeystore = (updated: KeystoreFile) => {
    pushState(keystores.map((k) => (k.id === updated.id ? updated : k)));
  };

  const handleDeleteKeystore = (id: string) => {
    if (keystores.length <= 1) return;
    const next = keystores.filter((k) => k.id !== id);
    pushState(next);
    if (activeKeystoreId === id) {
      setActiveKeystoreId(next[0].id);
    }
  };

  const handleAddKeystore = (newKs: KeystoreFile) => {
    pushState([newKs, ...keystores]);
    setActiveKeystoreId(newKs.id);
    setOpsCount((c) => c + 1024);
    setCurrentTab("keystores");
  };

  const handleRecordOp = (increment = 256, isSig = false) => {
    setOpsCount((c) => c + increment);
    if (isSig) {
      setSignaturesCount((s) => s + 1);
    }
  };

  const handleExportAllCsv = async () => {
    const active = keystores.find((k) => k.id === activeKeystoreId) || keystores[0];
    if (!active) return;
    try {
      await invoke<ExportPayloadResult>("export_keystore_to_csv", { ks: active });
      handleRecordOp(128, false);
    } catch (e) {
      console.error(e);
    }
  };

  const handleLockAll = () => {
    pushState(
      keystores.map((ks) => ({
        ...ks,
        entries: ks.entries.map((e) => ({ ...e, locked: true })),
      }))
    );
  };

  const totalEntries = keystores.reduce((sum, k) => sum + k.entries.length, 0);

  return (
    <div className="h-screen w-screen flex flex-col bg-[#DDE5F0] select-none overflow-hidden font-sans">
      {/* Top Application Header */}
      <Header
        totalEntries={totalEntries}
        totalKeystores={keystores.length}
        opsCount={opsCount}
        canUndo={history.length > 0}
        canRedo={redoStack.length > 0}
        onUndo={handleUndo}
        onRedo={handleRedo}
        onOpenNewKeystoreModal={() => setIsNewKeystoreModalOpen(true)}
        onQuickExamineSsl={() => setCurrentTab("examine")}
      />

      {/* Main Container: Left Navigation Rail + Rounded Workspace Container */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          onLockAll={handleLockAll}
        />

        {/* Central Elevated Workspace Container */}
        <main className="flex-1 mr-4 mb-3 bg-[#EEF2F7] rounded-[24px] border border-[#CFD8E3] shadow-[0_2px_10px_rgba(0,0,0,0.03)] flex flex-col overflow-hidden relative">
          {currentTab === "keystores" && (
            <KeystoresView
              keystores={keystores}
              activeKeystoreId={activeKeystoreId}
              onSelectKeystore={setActiveKeystoreId}
              onUpdateKeystore={handleUpdateKeystore}
              onDeleteKeystore={handleDeleteKeystore}
              onOpenNewKeystoreModal={() => setIsNewKeystoreModalOpen(true)}
              onRecordOp={handleRecordOp}
            />
          )}

          {currentTab === "dashboard" && (
            <DashboardView
              keystores={keystores}
              opsCount={opsCount}
              signaturesCount={signaturesCount}
              onSelectTab={setCurrentTab}
              onExportAllCsv={handleExportAllCsv}
            />
          )}

          {currentTab === "ca_signing" && (
            <CaSigningView
              keystores={keystores}
              activeKeystoreId={activeKeystoreId}
              onUpdateKeystore={handleUpdateKeystore}
              onRecordOp={handleRecordOp}
            />
          )}

          {currentTab === "examine" && (
            <ExamineView
              keystores={keystores}
              activeKeystoreId={activeKeystoreId}
              onUpdateKeystore={handleUpdateKeystore}
              onRecordOp={handleRecordOp}
            />
          )}

          {currentTab === "scanner" && (
            <ScannerView
              keystores={keystores}
              onUpdateKeystore={handleUpdateKeystore}
              onRecordOp={handleRecordOp}
            />
          )}

          {currentTab === "passwords" && (
            <div className="flex-1 overflow-y-auto px-8 py-6 bg-[#EEF2F7]">
              <div className="flex items-center justify-between mb-5">
                <div>
                  <h1 className="text-[28px] font-normal text-[#1E293B] tracking-tight">
                    KeyStore &amp; Entry Password Manager
                  </h1>
                  <p className="text-[13px] text-[#64748B]">
                    Manage KeyStore passphrases and individual private/secret key entry protection in memory.
                  </p>
                </div>
                <button
                  onClick={() => setShowPasswords(!showPasswords)}
                  className="px-4 py-2 rounded-full bg-white border border-[#E2E8F0] text-[#0F172A] text-[12.5px] font-semibold flex items-center space-x-2 cursor-pointer"
                >
                  {showPasswords ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  <span>{showPasswords ? "Mask Passphrases" : "Reveal Passphrases"}</span>
                </button>
              </div>

              <div className="space-y-4">
                {keystores.map((ks) => (
                  <div key={ks.id} className="bg-white rounded-[22px] p-5 border border-[#E2E8F0] space-y-3">
                    <div className="flex items-center justify-between pb-2 border-b border-[#F1F5F9]">
                      <div className="flex items-center space-x-2.5">
                        <KeyRound className="w-4 h-4 text-[#2563EB]" />
                        <span className="text-[15px] font-semibold text-[#0F172A]">{ks.name}</span>
                        <span className="px-2 py-0.5 rounded-full bg-[#EFF6FF] text-[#2563EB] text-[11px] font-bold">
                          {ks.format}
                        </span>
                      </div>
                      <span className="font-mono text-[12.5px] text-[#475569]">
                        Store Passphrase: <strong>{showPasswords ? "changeit#2026" : "••••••••••••"}</strong>
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                      {ks.entries.map((entry) => (
                        <div
                          key={entry.id}
                          className="p-3 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] flex items-center justify-between text-[12.5px]"
                        >
                          <div>
                            <div className="font-semibold text-[#0F172A]">{entry.alias}</div>
                            <div className="text-[11px] text-[#64748B]">
                              {entry.entry_type} • {showPasswords ? "unlocked-key-pass" : "••••••••"}
                            </div>
                          </div>
                          <button
                            onClick={() => {
                              handleUpdateKeystore({
                                ...ks,
                                entries: ks.entries.map((en) =>
                                  en.id === entry.id ? { ...en, locked: !en.locked } : en
                                ),
                              });
                            }}
                            className={`px-3 py-1 rounded-full text-[11.5px] font-semibold flex items-center space-x-1 cursor-pointer ${
                              entry.locked
                                ? "bg-[#FEE2E2] text-[#991B1B]"
                                : "bg-[#DCFCE7] text-[#166534]"
                            }`}
                          >
                            {entry.locked ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                            <span>{entry.locked ? "Locked" : "Unlocked"}</span>
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {currentTab === "settings" && (
            <div className="flex-1 overflow-y-auto px-8 py-6 bg-[#EEF2F7]">
              <h1 className="text-[28px] font-normal text-[#1E293B] tracking-tight mb-5">
                Security Providers &amp; Preferences
              </h1>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-white rounded-[22px] p-6 border border-[#E2E8F0] space-y-3">
                  <div className="flex items-center space-x-2 text-[#0A3464] font-semibold text-[15px]">
                    <ShieldCheck className="w-5 h-5 text-[#2563EB]" />
                    <span>Built-in Native Rust Cryptographic Providers</span>
                  </div>
                  <p className="text-[13px] text-[#475569] leading-relaxed">
                    CertForge runs 100% self-contained in compiled Rust machine code. No external Java Runtime (JRE), `keytool`, `jarsigner`, or `openssl` binary is ever invoked.
                  </p>
                  <div className="space-y-1.5 pt-2 text-[12px]">
                    {[
                      "X.509 v3 Certificate & PKCS#10 CSR Engine (rcgen 0.13)",
                      "RSA PKCS#1 / PKCS#8 Asymmetric Engine (rsa 0.9)",
                      "NIST P-256 / secp256r1 Elliptic Curve Engine (p256 0.13)",
                      "Ed25519 / Curve25519 High-Speed Signatures (ed25519-dalek 2.2)",
                      "NIST FIPS 203 & FIPS 204 Post-Quantum Engine (ML-KEM / ML-DSA)",
                      "Java KeyStore (0xFEEDFEED) & PKCS#12 Binary Serializer",
                    ].map((prov, i) => (
                      <div key={i} className="flex items-center space-x-2 text-[#1E293B]">
                        <CheckCircle2 className="w-3.5 h-3.5 text-[#059669]" />
                        <span>{prov}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-white rounded-[22px] p-6 border border-[#E2E8F0] space-y-3">
                  <h3 className="text-[15px] font-semibold text-[#0F172A]">
                    Default KeyStore &amp; Export Location
                  </h3>
                  <p className="text-[13px] text-[#475569]">
                    All exported certificates, private keys, JWK bundles, CSV inventories, and binary `.jks` / `.p12` files are automatically written to:
                  </p>
                  <div className="p-3 rounded-xl bg-[#F8FAFC] border border-[#CBD5E1] font-mono text-[12px] text-[#0A3464]">
                    ~/Downloads/CertForge_Exports/
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* New KeyStore Modal */}
      <NewKeystoreModal
        isOpen={isNewKeystoreModalOpen}
        onClose={() => setIsNewKeystoreModalOpen(false)}
        onAddKeystore={handleAddKeystore}
      />
    </div>
  );
};

export default App;
