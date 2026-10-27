import React, { useState } from "react";
import {
  FilePlus2,
  FolderOpen,
  FolderKey,
  ShieldCheck,
  Search,
  HelpCircle,
  Layers,
  ArrowRight,
  Sparkles,
  CheckCircle2,
  Globe,
  KeyRound,
  BookOpen,
  X,
  FileSignature,
} from "lucide-react";
import { KeystoreFile, KeystoreFormat, TabType, Workspace } from "../types/crypto";

interface HomeViewProps {
  keystores: KeystoreFile[];
  workspaces: Workspace[];
  onSelectTab: (tab: TabType) => void;
  onSelectKeystoreAndOpen: (ksId: string) => void;
  onSelectWorkspaceAndOpen: (wsId: string) => void;
  onOpenNewKeystoreWithFormat: (format?: KeystoreFormat) => void;
}

export const HomeView: React.FC<HomeViewProps> = ({
  keystores,
  workspaces,
  onSelectTab,
  onSelectKeystoreAndOpen,
  onSelectWorkspaceAndOpen,
  onOpenNewKeystoreWithFormat,
}) => {
  const [helpModalOpen, setHelpModalOpen] = useState(false);
  const [activeHelpTopic, setActiveHelpTopic] = useState<"formats" | "pqc" | "workspaces" | "signing">("formats");

  const defaultKs = keystores.find((k) => k.id === "ks-default-user") || keystores[keystores.length - 1];
  const caCertsKs = keystores.find((k) => k.id === "ks-trust-jks") || keystores[0];

  return (
    <div className="flex-1 overflow-y-auto px-8 py-6 bg-[#EEF2F7] select-none">
      {/* Top Quick Start Hero Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between mb-6 gap-4">
        <div>
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-[#C2E7FF]/80 text-[#0A3464] text-[11.5px] font-bold mb-2">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Zero-Dependency Native Rust Engine</span>
          </div>
          <h1 className="text-[30px] font-bold text-[#0F172A] tracking-tight leading-tight">
            xkeystore <span className="font-normal text-[#2563EB]">Quick Start</span>
          </h1>
          <p className="text-[13.5px] text-[#475569] mt-1">
            Interactive cryptographic workstation for KeyStores, X.509 certificates, CA signing, and multi-environment Workspaces.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => onSelectTab("workspaces")}
            className="px-4 py-2 rounded-full bg-white border border-[#CBD5E1] hover:bg-[#F8FAFC] text-[#0F172A] text-[12.5px] font-semibold flex items-center space-x-1.5 cursor-pointer shadow-2xs transition"
          >
            <Layers className="w-3.5 h-3.5 text-[#2563EB]" />
            <span>Manage Workspaces ({workspaces.length})</span>
          </button>
          <button
            onClick={() => onSelectTab("keystores")}
            className="px-4 py-2 rounded-full bg-[#0A3464] hover:bg-[#07274C] text-white text-[12.5px] font-semibold flex items-center space-x-1.5 cursor-pointer shadow-xs transition"
          >
            <span>Open KeyStore Explorer</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* ====================================================================
          6 Interactive Quick Start Bento Cards (Modeled on KSE Quick Start)
          ==================================================================== */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-4">
        {/* Bento 1: Create a new KeyStore */}
        <div
          onClick={() => onOpenNewKeystoreWithFormat("PKCS12")}
          className="lg:col-span-4 bg-white rounded-[24px] p-6 border border-[#E2E8F0] hover:border-[#60A5FA] hover:shadow-md transition-all flex flex-col justify-between cursor-pointer group"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#EFF6FF] to-[#DBEAFE] border border-[#BFDBFE] text-[#1D4ED8] flex items-center justify-center shadow-2xs group-hover:scale-105 transition">
                <FilePlus2 className="w-6 h-6" />
              </div>
              <span className="px-2.5 py-1 rounded-full bg-[#F1F5F9] text-[#475569] text-[11px] font-semibold">
                6 Formats
              </span>
            </div>

            <h2 className="text-[17px] font-bold text-[#0F172A] group-hover:text-[#1D4ED8] transition">
              Create a new KeyStore
            </h2>
            <p className="text-[12.5px] text-[#64748B] mt-1 leading-relaxed">
              Initialize a new cryptographic store in PKCS#12, JKS, JCEKS, BKS, BCFKS, or UBER format with an initial root key pair.
            </p>

            {/* Interactive Format Pills */}
            <div
              className="flex flex-wrap gap-1.5 mt-4"
              onClick={(e) => e.stopPropagation()}
            >
              {(["PKCS12", "JKS", "JCEKS", "BKS", "BCFKS", "UBER"] as KeystoreFormat[]).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => onOpenNewKeystoreWithFormat(fmt)}
                  className="px-2.5 py-1 rounded-lg bg-[#F8FAFC] hover:bg-[#C2E7FF] border border-[#E2E8F0] hover:border-[#60A5FA] text-[#334155] hover:text-[#0A3464] text-[11px] font-bold transition cursor-pointer"
                >
                  + {fmt}
                </button>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-[#F1F5F9] flex items-center justify-between text-[12.5px] font-semibold text-[#2563EB]">
            <span>Launch KeyStore Wizard</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition" />
          </div>
        </div>

        {/* Bento 2: Open an existing KeyStore */}
        <div
          onClick={() => onSelectTab("keystores")}
          className="lg:col-span-4 bg-white rounded-[24px] p-6 border border-[#E2E8F0] hover:border-[#F59E0B] hover:shadow-md transition-all flex flex-col justify-between cursor-pointer group"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#FEF3C7] to-[#FDE68A] border border-[#FCD34D] text-[#B45309] flex items-center justify-center shadow-2xs group-hover:scale-105 transition">
                <FolderOpen className="w-6 h-6" />
              </div>
              <span className="px-2.5 py-1 rounded-full bg-[#FEF3C7] text-[#92400E] text-[11px] font-semibold">
                {keystores.length} Active Stores
              </span>
            </div>

            <h2 className="text-[17px] font-bold text-[#0F172A] group-hover:text-[#B45309] transition">
              Open an existing KeyStore
            </h2>
            <p className="text-[12.5px] text-[#64748B] mt-1 leading-relaxed">
              Browse and manage entries in your loaded KeyStores or switch between multi-format vaults.
            </p>

            {/* Interactive KeyStore Quick List */}
            <div className="space-y-1.5 mt-3.5" onClick={(e) => e.stopPropagation()}>
              {keystores.slice(0, 3).map((ks) => (
                <button
                  key={ks.id}
                  onClick={() => onSelectKeystoreAndOpen(ks.id)}
                  className="w-full px-3 py-1.5 rounded-xl bg-[#F8FAFC] hover:bg-[#FEF3C7]/60 border border-[#E2E8F0] flex items-center justify-between text-left transition cursor-pointer"
                >
                  <span className="text-[12px] font-semibold text-[#1E293B] truncate">{ks.name}</span>
                  <span className="text-[10.5px] font-bold text-[#64748B]">
                    {ks.format} • {ks.entries.length}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-[#F1F5F9] flex items-center justify-between text-[12.5px] font-semibold text-[#B45309]">
            <span>Browse All KeyStores</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition" />
          </div>
        </div>

        {/* Bento 3: Open the Default KeyStore */}
        <div
          onClick={() => defaultKs && onSelectKeystoreAndOpen(defaultKs.id)}
          className="lg:col-span-4 bg-white rounded-[24px] p-6 border border-[#E2E8F0] hover:border-[#0284C7] hover:shadow-md transition-all flex flex-col justify-between cursor-pointer group"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#E0F2FE] to-[#BAE6FD] border border-[#7DD3FC] text-[#0369A1] flex items-center justify-center shadow-2xs group-hover:scale-105 transition">
                <FolderKey className="w-6 h-6" />
              </div>
              <span className="px-2.5 py-1 rounded-full bg-[#E0F2FE] text-[#0369A1] text-[11px] font-semibold font-mono">
                ~/.keystore
              </span>
            </div>

            <h2 className="text-[17px] font-bold text-[#0F172A] group-hover:text-[#0369A1] transition">
              Open the Default KeyStore
            </h2>
            <p className="text-[12.5px] text-[#64748B] mt-1 leading-relaxed">
              Directly open your user profile default KeyStore containing personal signing keys and symmetric secrets.
            </p>

            {defaultKs && (
              <div className="mt-4 p-3 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] space-y-1 text-[11.5px]">
                <div className="flex justify-between">
                  <span className="text-[#64748B]">Store File:</span>
                  <span className="font-semibold text-[#0F172A]">{defaultKs.name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#64748B]">Format / Entries:</span>
                  <span className="font-mono font-semibold text-[#0369A1]">
                    {defaultKs.format} ({defaultKs.entries.length} entries)
                  </span>
                </div>
              </div>
            )}
          </div>

          <div className="pt-4 mt-4 border-t border-[#F1F5F9] flex items-center justify-between text-[12.5px] font-semibold text-[#0369A1]">
            <span>Open Default KeyStore</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition" />
          </div>
        </div>

        {/* Bento 4: Open the CA Certificates KeyStore */}
        <div
          onClick={() => caCertsKs && onSelectKeystoreAndOpen(caCertsKs.id)}
          className="lg:col-span-4 bg-white rounded-[24px] p-6 border border-[#E2E8F0] hover:border-[#059669] hover:shadow-md transition-all flex flex-col justify-between cursor-pointer group"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#DCFCE7] to-[#A7F3D0] border border-[#6EE7B7] text-[#047857] flex items-center justify-center shadow-2xs group-hover:scale-105 transition">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <span className="px-2.5 py-1 rounded-full bg-[#DCFCE7] text-[#166534] text-[11px] font-semibold">
                Trust Anchors
              </span>
            </div>

            <h2 className="text-[17px] font-bold text-[#0F172A] group-hover:text-[#047857] transition">
              Open the CA Certificates KeyStore
            </h2>
            <p className="text-[12.5px] text-[#64748B] mt-1 leading-relaxed">
              Manage system-wide and enterprise Root Certificate Authorities (`cacerts`) used for chain validation.
            </p>

            <div className="mt-3.5 flex flex-wrap gap-1.5">
              {["DigiCert Root G2", "ISRG Root X1", "xkeystore Root G3"].map((ca) => (
                <span
                  key={ca}
                  className="px-2.5 py-1 rounded-lg bg-[#F0FDF4] border border-[#BBF7D0] text-[#166534] text-[11px] font-medium"
                >
                  ✓ {ca}
                </span>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-[#F1F5F9] flex items-center justify-between text-[12.5px] font-semibold text-[#047857]">
            <span>Open CA TrustStore</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition" />
          </div>
        </div>

        {/* Bento 5: Examine a Certificate / Live SSL */}
        <div
          onClick={() => onSelectTab("examine")}
          className="lg:col-span-4 bg-white rounded-[24px] p-6 border border-[#E2E8F0] hover:border-[#7C3AED] hover:shadow-md transition-all flex flex-col justify-between cursor-pointer group"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#F3E8FF] to-[#E9D5FF] border border-[#D8B4FE] text-[#6D28D9] flex items-center justify-center shadow-2xs group-hover:scale-105 transition">
                <Search className="w-6 h-6" />
              </div>
              <span className="px-2.5 py-1 rounded-full bg-[#F3E8FF] text-[#6D28D9] text-[11px] font-semibold">
                SSL • PEM • CSR • CRL
              </span>
            </div>

            <h2 className="text-[17px] font-bold text-[#0F172A] group-hover:text-[#6D28D9] transition">
              Examine a Certificate
            </h2>
            <p className="text-[12.5px] text-[#64748B] mt-1 leading-relaxed">
              Connect to live TLS servers, auto-detect clipboard PEM/ASN.1 artifacts, or compare two certificates side-by-side.
            </p>

            <div className="mt-3.5 flex flex-wrap gap-1.5" onClick={(e) => e.stopPropagation()}>
              {["github.com:443", "google.com:443", "Paste Clipboard"].map((item) => (
                <button
                  key={item}
                  onClick={() => onSelectTab("examine")}
                  className="px-2.5 py-1 rounded-lg bg-[#FAF5FF] hover:bg-[#F3E8FF] border border-[#E9D5FF] text-[#6D28D9] text-[11px] font-semibold transition cursor-pointer"
                >
                  {item}
                </button>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-[#F1F5F9] flex items-center justify-between text-[12.5px] font-semibold text-[#6D28D9]">
            <span>Open Examine &amp; Diff Studio</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition" />
          </div>
        </div>

        {/* Bento 6: Show the Help Pages & Reference */}
        <div
          onClick={() => setHelpModalOpen(true)}
          className="lg:col-span-4 bg-white rounded-[24px] p-6 border border-[#E2E8F0] hover:border-[#2563EB] hover:shadow-md transition-all flex flex-col justify-between cursor-pointer group"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#DBEAFE] to-[#BFDBFE] border border-[#93C5FD] text-[#1E40AF] flex items-center justify-center shadow-2xs group-hover:scale-105 transition">
                <HelpCircle className="w-6 h-6" />
              </div>
              <span className="px-2.5 py-1 rounded-full bg-[#EFF6FF] text-[#1D4ED8] text-[11px] font-semibold">
                Built-in Guide
              </span>
            </div>

            <h2 className="text-[17px] font-bold text-[#0F172A] group-hover:text-[#1E40AF] transition">
              Show the Help Pages
            </h2>
            <p className="text-[12.5px] text-[#64748B] mt-1 leading-relaxed">
              Interactive cryptographic handbook covering KeyStore types, X.509 v3 extensions, Post-Quantum algorithms, and JAR signing.
            </p>

            <div className="mt-3.5 flex flex-wrap gap-1.5" onClick={(e) => e.stopPropagation()}>
              {[
                { id: "formats", label: "KeyStore Formats" },
                { id: "pqc", label: "Post-Quantum PQC" },
                { id: "workspaces", label: "Workspaces Guide" },
                { id: "signing", label: "CA & JAR Signing" },
              ].map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setActiveHelpTopic(t.id as typeof activeHelpTopic);
                    setHelpModalOpen(true);
                  }}
                  className="px-2.5 py-1 rounded-lg bg-[#F8FAFC] hover:bg-[#EFF6FF] border border-[#E2E8F0] text-[#334155] text-[11px] font-semibold cursor-pointer"
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-[#F1F5F9] flex items-center justify-between text-[12.5px] font-semibold text-[#1E40AF]">
            <span>Open Interactive Help Pages</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition" />
          </div>
        </div>
      </div>

      {/* ====================================================================
          Bottom Bento Section: Workspaces & CA Signing Shortcuts
          ==================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mt-4">
        {/* Workspaces Bento Card (8 cols) */}
        <div className="lg:col-span-8 bg-white rounded-[24px] p-6 border border-[#E2E8F0] flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2.5">
              <div className="w-9 h-9 rounded-xl bg-[#EFF6FF] text-[#2563EB] flex items-center justify-center">
                <Layers className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-[16px] font-bold text-[#0F172A]">Active Certificate Workspaces</h3>
                <p className="text-[12px] text-[#64748B]">
                  Group certificates and keys across multiple KeyStores by project, cluster, or compliance scope.
                </p>
              </div>
            </div>
            <button
              onClick={() => onSelectTab("workspaces")}
              className="px-3.5 py-1.5 rounded-full bg-[#C2E7FF] hover:bg-[#AEDBFF] text-[#0A3464] text-[12px] font-bold cursor-pointer transition"
            >
              Open Workspaces &rarr;
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {workspaces.map((ws) => (
              <div
                key={ws.id}
                onClick={() => onSelectWorkspaceAndOpen(ws.id)}
                className="p-4 rounded-2xl bg-[#F8FAFC] hover:bg-[#EFF6FF]/60 border border-[#E2E8F0] hover:border-[#93C5FD] transition cursor-pointer flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-white border border-[#CBD5E1] text-[#334155]">
                      {ws.environment}
                    </span>
                    <span className="text-[11px] font-semibold text-[#2563EB]">
                      {ws.entryIds.length} Certs
                    </span>
                  </div>
                  <h4 className="text-[14px] font-bold text-[#0F172A]">{ws.name}</h4>
                  <p className="text-[11.5px] text-[#64748B] mt-1 line-clamp-2">{ws.description}</p>
                </div>
                <div className="mt-3 pt-2 border-t border-[#E2E8F0]/70 text-[11px] font-semibold text-[#0A3464] flex items-center justify-between">
                  <span>Manage Certs</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* CA & Signing Quick Bento Card (4 cols) */}
        <div
          onClick={() => onSelectTab("ca_signing")}
          className="lg:col-span-4 bg-gradient-to-br from-[#0A3464] to-[#1E3A8A] text-white rounded-[24px] p-6 flex flex-col justify-between cursor-pointer hover:shadow-lg transition group"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="w-11 h-11 rounded-2xl bg-white/15 flex items-center justify-center">
                <FileSignature className="w-5 h-5 text-[#93C5FD]" />
              </div>
              <span className="px-2.5 py-1 rounded-full bg-white/15 text-[#E0F2FE] text-[11px] font-semibold">
                Zero CLI Needed
              </span>
            </div>
            <h3 className="text-[17px] font-bold">CA Authority &amp; JAR Signer</h3>
            <p className="text-[12.5px] text-[#BFDBFE] mt-1 leading-relaxed">
              Sign PKCS#10 CSRs, issue X.509 v2 CRLs, sign Java `.jar` archives, sign CMS/PKCS#7 payloads, and mint JWTs directly in Rust.
            </p>
          </div>

          <div className="pt-4 mt-4 border-t border-white/15 flex items-center justify-between text-[12.5px] font-semibold text-[#93C5FD]">
            <span>Launch Signing Studio</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition" />
          </div>
        </div>
      </div>

      {/* ====================================================================
          Interactive Help Pages Modal
          ==================================================================== */}
      {helpModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
          <div className="w-full max-w-2xl bg-white rounded-3xl border border-[#CBD5E1] shadow-2xl p-6 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-[#E2E8F0]">
              <div className="flex items-center space-x-2.5">
                <BookOpen className="w-5 h-5 text-[#2563EB]" />
                <h3 className="text-[18px] font-bold text-[#0F172A]">
                  xkeystore — Interactive Help &amp; Cryptographic Reference
                </h3>
              </div>
              <button
                onClick={() => setHelpModalOpen(false)}
                className="p-1.5 text-[#64748B] hover:text-[#0F172A] cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex space-x-2 py-3 border-b border-[#F1F5F9]">
              {[
                { id: "formats", label: "KeyStore Formats" },
                { id: "workspaces", label: "Workspaces" },
                { id: "pqc", label: "Post-Quantum (PQC)" },
                { id: "signing", label: "CA, JAR & CMS Signing" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveHelpTopic(tab.id as typeof activeHelpTopic)}
                  className={`px-3.5 py-1.5 rounded-full text-[12.5px] font-semibold cursor-pointer ${
                    activeHelpTopic === tab.id
                      ? "bg-[#C2E7FF] text-[#0A3464]"
                      : "bg-[#F1F5F9] text-[#475569]"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-y-auto py-4 space-y-3 text-[13px] text-[#334155] leading-relaxed select-text">
              {activeHelpTopic === "formats" && (
                <div className="space-y-3">
                  <div className="p-3.5 rounded-2xl bg-[#F8FAFC] border border-[#E2E8F0]">
                    <strong className="text-[#0F172A] block">PKCS#12 (.p12 / .pfx)</strong>
                    Industry-standard RFC 7292 archive format for storing private keys, X.509 certificate chains, and trusted root certificates.
                  </div>
                  <div className="p-3.5 rounded-2xl bg-[#F8FAFC] border border-[#E2E8F0]">
                    <strong className="text-[#0F172A] block">JKS (.jks — Java KeyStore 0xFEEDFEED)</strong>
                    Native binary format serialized directly by xkeystore's Rust engine without needing a local Java installation.
                  </div>
                  <div className="p-3.5 rounded-2xl bg-[#F8FAFC] border border-[#E2E8F0]">
                    <strong className="text-[#0F172A] block">BCFKS / BKS / UBER / JCEKS</strong>
                    FIPS 140-3 compliant and symmetric-capable KeyStore formats supporting AES-256, ChaCha20, and HMAC secret keys.
                  </div>
                </div>
              )}

              {activeHelpTopic === "workspaces" && (
                <div className="space-y-3">
                  <p>
                    <strong>Workspaces</strong> let you organize certificates and keys logically (for example, by Kubernetes cluster, microservice environment, or compliance audit) without duplicating or modifying the underlying KeyStore files.
                  </p>
                  <ul className="list-disc pl-5 space-y-1.5">
                    <li>Create custom Workspaces in the <strong>Workspaces</strong> tab.</li>
                    <li>Assign any Certificate or Key Pair to a Workspace from the <strong>Workspaces</strong> tab or directly from the <strong>KeyStores</strong> table.</li>
                    <li>Switch active Workspaces anytime using the top header selector.</li>
                  </ul>
                </div>
              )}

              {activeHelpTopic === "pqc" && (
                <div className="space-y-3">
                  <p>
                    <strong>xkeystore</strong> includes built-in support for NIST Post-Quantum Cryptography standards:
                  </p>
                  <ul className="list-disc pl-5 space-y-1.5">
                    <li><strong>ML-DSA-65 (FIPS 204 / Dilithium):</strong> Lattice-based digital signatures resistant to quantum Shor's algorithm.</li>
                    <li><strong>ML-KEM-768 (FIPS 203 / Kyber):</strong> Module-Lattice Key Encapsulation Mechanism for quantum-safe TLS handshakes.</li>
                    <li><strong>SLH-DSA (FIPS 205 / SPHINCS+):</strong> Stateless hash-based digital signature scheme.</li>
                  </ul>
                </div>
              )}

              {activeHelpTopic === "signing" && (
                <div className="space-y-3">
                  <p>
                    All signing workflows run 100% inside the embedded Rust engine:
                  </p>
                  <ul className="list-disc pl-5 space-y-1.5">
                    <li><strong>Sign CSR:</strong> Issue child X.509 v3 certificates signed by any KeyPair in your KeyStore.</li>
                    <li><strong>Issue CRL:</strong> Generate signed X.509 v2 Certificate Revocation Lists.</li>
                    <li><strong>Sign JAR:</strong> Generates <code>META-INF/MANIFEST.MF</code> and <code>.SF</code> signature files natively.</li>
                  </ul>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-[#E2E8F0] flex justify-end">
              <button
                onClick={() => setHelpModalOpen(false)}
                className="px-5 py-2 rounded-full bg-[#0A3464] text-white text-[12.5px] font-semibold cursor-pointer"
              >
                Close Help
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
