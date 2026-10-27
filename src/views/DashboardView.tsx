import React from "react";
import { KeyRound, FolderArchive, Sparkles, ShieldCheck, FileSignature, Globe, Download } from "lucide-react";
import { KeystoreFile, TabType } from "../types/crypto";

interface DashboardViewProps {
  keystores: KeystoreFile[];
  opsCount: number;
  signaturesCount: number;
  onSelectTab: (tab: TabType) => void;
  onExportAllCsv: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  keystores,
  opsCount,
  signaturesCount,
  onSelectTab,
  onExportAllCsv,
}) => {
  const allEntries = keystores.flatMap((k) => k.entries);
  const keyPairsCount = allEntries.filter((e) => e.entry_type === "KeyPair").length;
  const trustedCertsCount = allEntries.filter((e) => e.entry_type === "TrustedCertificate").length;
  const secretKeysCount = allEntries.filter((e) => e.entry_type === "SecretKey").length;
  const pqCount = allEntries.filter((e) => e.is_post_quantum).length;

  const totalKeyBits = allEntries.reduce((acc, e) => acc + (e.key_size || 0), 0) + opsCount;

  // Bar chart data modeled after Screenshot 2
  const maxVal = Math.max(totalKeyBits, 4115);
  const yTicks = [
    maxVal,
    Math.round(maxVal * 0.8),
    Math.round(maxVal * 0.6),
    Math.round(maxVal * 0.4),
    Math.round(maxVal * 0.2),
    0,
  ];

  const chartColumns = [
    { label: "RSA / DSA", value: allEntries.filter((e) => e.algorithm === "RSA").reduce((a, b) => a + b.key_size, 0) },
    { label: "ECDSA / Ed25519", value: allEntries.filter((e) => e.algorithm === "ECDSA" || e.algorithm === "Ed25519").reduce((a, b) => a + b.key_size * 4, 0) },
    { label: "AES / HMAC", value: allEntries.filter((e) => e.entry_type === "SecretKey").reduce((a, b) => a + b.key_size * 3, 0) },
    { label: "PQC (ML-DSA)", value: allEntries.filter((e) => e.is_post_quantum).reduce((a, b) => a + b.key_size, 0) },
    { label: "Total Managed", value: totalKeyBits },
  ];

  return (
    <div className="flex-1 overflow-y-auto px-8 py-6 bg-[#EEF2F7] select-none">
      {/* Page Title matching Screenshot 2 */}
      <h1 className="text-[28px] font-normal text-[#1E293B] tracking-tight mb-5">Stats</h1>

      {/* Top Hero Card: Left Blue KPI Box + Right Bar Chart */}
      <div className="bg-white rounded-[24px] p-6 border border-[#E2E8F0]/80 shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex flex-col lg:flex-row gap-8 items-stretch">
        {/* Left Blue Box */}
        <div className="w-full lg:w-[295px] shrink-0 bg-[#E6EFFC] rounded-[20px] p-6 flex flex-col justify-between min-h-[250px]">
          <span className="text-[14.5px] font-semibold text-[#1E293B]">
            Total Entropy &amp; Key Bits
          </span>

          <div className="my-4">
            <span className="text-[54px] font-medium tracking-tight text-[#1E293B] leading-none">
              {totalKeyBits.toLocaleString()}
            </span>
          </div>

          <span className="text-[12.5px] text-[#475569]">
            By running native Rust crypto on your device
          </span>
        </div>

        {/* Right Bar Chart */}
        <div className="flex-1 flex flex-col justify-between pt-1 pr-2">
          <h3 className="text-[14.5px] font-semibold text-[#1E293B] mb-4">
            Your cryptographic key &amp; operation distribution
          </h3>

          <div className="flex-1 flex flex-col justify-between relative min-h-[190px]">
            {/* Y-Axis & Horizontal Grid Lines */}
            <div className="flex-1 flex flex-col justify-between relative">
              {yTicks.map((tick, idx) => (
                <div key={idx} className="flex items-center w-full">
                  <span className="w-12 text-right pr-3 text-[11px] font-medium text-[#475569]">
                    {tick}
                  </span>
                  <div
                    className={`flex-1 border-b ${
                      idx === yTicks.length - 1 ? "border-[#64748B]" : "border-[#E2E8F0]"
                    }`}
                  />
                </div>
              ))}

              {/* Bars Overlay */}
              <div className="absolute inset-0 left-12 bottom-[7px] top-[7px] flex items-end justify-around px-6 pointer-events-none">
                {chartColumns.map((col, idx) => {
                  const heightPct = maxVal > 0 ? Math.max(2, Math.min(100, Math.round((col.value / maxVal) * 100))) : 0;
                  return (
                    <div key={idx} className="flex flex-col items-center justify-end h-full w-14 group">
                      <div
                        style={{ height: `${heightPct}%` }}
                        className={`w-11 rounded-t-[6px] transition-all duration-300 ${
                          idx === chartColumns.length - 1
                            ? "bg-[#65B8FF]"
                            : "bg-[#65B8FF]/75"
                        }`}
                      />
                    </div>
                  );
                })}
              </div>
            </div>

            {/* X-Axis Labels */}
            <div className="flex items-center justify-around pl-12 pt-2.5 px-6">
              {chartColumns.map((col, idx) => (
                <span key={idx} className="text-[11.5px] font-medium text-[#334155] text-center w-24 truncate">
                  {col.label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: 3 KPI Cards matching Screenshot 2 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
        {/* KPI 1: Purple circle icon */}
        <div
          onClick={() => onSelectTab("keystores")}
          className="bg-white rounded-[22px] p-5 border border-[#E2E8F0]/80 shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex items-center space-x-4 cursor-pointer hover:border-[#CBD5E1] transition"
        >
          <div className="w-12 h-12 rounded-full bg-[#F3E8FF] text-[#6B21A8] flex items-center justify-center shrink-0">
            <KeyRound className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[24px] font-normal text-[#0F172A] leading-tight">
              {keyPairsCount + secretKeysCount}
            </div>
            <div className="text-[13.5px] font-semibold text-[#1E293B]">
              Keys &amp; Key Pairs managed
            </div>
            <div className="text-[12px] text-[#64748B]">
              {keyPairsCount} Asymmetric • {secretKeysCount} Symmetric • {pqCount} PQC
            </div>
          </div>
        </div>

        {/* KPI 2: Light blue circle icon */}
        <div
          onClick={() => onSelectTab("keystores")}
          className="bg-white rounded-[22px] p-5 border border-[#E2E8F0]/80 shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex items-center space-x-4 cursor-pointer hover:border-[#CBD5E1] transition"
        >
          <div className="w-12 h-12 rounded-full bg-[#E0F2FE] text-[#0284C7] flex items-center justify-center shrink-0">
            <FolderArchive className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[24px] font-normal text-[#0F172A] leading-tight">
              {keystores.length}
            </div>
            <div className="text-[13.5px] font-semibold text-[#1E293B]">
              Keystore sources added
            </div>
            <div className="text-[12px] text-[#64748B]">
              Indexed across PKCS#12, JKS, BCFKS &amp; {trustedCertsCount} Root CAs
            </div>
          </div>
        </div>

        {/* KPI 3: Mint green circle icon */}
        <div
          onClick={() => onSelectTab("ca_signing")}
          className="bg-white rounded-[22px] p-5 border border-[#E2E8F0]/80 shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex items-center space-x-4 cursor-pointer hover:border-[#CBD5E1] transition"
        >
          <div className="w-12 h-12 rounded-full bg-[#E0F7F4] text-[#0F766E] flex items-center justify-center shrink-0">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[24px] font-normal text-[#0F172A] leading-tight">
              {signaturesCount}
            </div>
            <div className="text-[13.5px] font-semibold text-[#1E293B]">
              CA, JAR, CMS &amp; JWT operations
            </div>
            <div className="text-[12px] text-[#64748B]">
              Zero external Java or OpenSSL CLI calls
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Banner Card matching Screenshot 2 */}
      <div className="bg-white rounded-[24px] p-7 mt-4 border border-[#E2E8F0]/80 shadow-[0_1px_3px_rgba(0,0,0,0.02)] grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        <div className="lg:col-span-6 space-y-4">
          <h2 className="text-[22px] font-bold text-[#1E293B] leading-snug">
            CertForge is built with native Rust cryptography that processes your keystores locally on your device
          </h2>
          <p className="text-[13.5px] text-[#475569] leading-relaxed">
            Every KeyStore Explorer capability—generating RSA/ECDSA/Ed25519/Post-Quantum key pairs, converting JKS &amp; PKCS#12 binaries, signing CSRs, issuing CRLs, signing JAR archives, and inspecting live TLS servers—executes directly in memory without Java or OpenSSL.
          </p>
          <div className="flex flex-wrap gap-2.5 pt-1">
            <button
              onClick={() => onSelectTab("keystores")}
              className="px-4 py-2 rounded-full bg-[#C2E7FF] hover:bg-[#AEDBFF] text-[#0A3464] text-[12.5px] font-semibold transition cursor-pointer flex items-center space-x-1.5"
            >
              <FolderArchive className="w-3.5 h-3.5" />
              <span>Open KeyStore Table</span>
            </button>
            <button
              onClick={() => onSelectTab("ca_signing")}
              className="px-4 py-2 rounded-full bg-[#F1F5F9] hover:bg-[#E2E8F0] text-[#1E293B] text-[12.5px] font-medium transition cursor-pointer flex items-center space-x-1.5"
            >
              <FileSignature className="w-3.5 h-3.5 text-[#2563EB]" />
              <span>CA &amp; JAR Signer</span>
            </button>
            <button
              onClick={() => onSelectTab("examine")}
              className="px-4 py-2 rounded-full bg-[#F1F5F9] hover:bg-[#E2E8F0] text-[#1E293B] text-[12.5px] font-medium transition cursor-pointer flex items-center space-x-1.5"
            >
              <Globe className="w-3.5 h-3.5 text-[#0284C7]" />
              <span>Examine SSL Host</span>
            </button>
            <button
              onClick={onExportAllCsv}
              className="px-4 py-2 rounded-full bg-[#F1F5F9] hover:bg-[#E2E8F0] text-[#1E293B] text-[12.5px] font-medium transition cursor-pointer flex items-center space-x-1.5"
            >
              <Download className="w-3.5 h-3.5 text-[#059669]" />
              <span>Export Inventory CSV</span>
            </button>
          </div>
        </div>

        {/* Geometric Blueprint Graphic matching Screenshot 2 */}
        <div className="lg:col-span-6 bg-[#F1F5FB] rounded-[20px] p-6 flex items-center justify-center relative overflow-hidden min-h-[180px]">
          <svg
            width="160"
            height="160"
            viewBox="0 0 160 160"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            className="text-[#3B82F6]"
          >
            {/* Blueprint Grid Lines */}
            <line x1="80" y1="10" x2="80" y2="150" stroke="#93C5FD" strokeWidth="1" />
            <line x1="10" y1="80" x2="150" y2="80" stroke="#93C5FD" strokeWidth="1" />
            <line x1="52" y1="20" x2="52" y2="140" stroke="#BFDBFE" strokeWidth="1" />
            <line x1="108" y1="20" x2="108" y2="140" stroke="#BFDBFE" strokeWidth="1" />
            <line x1="20" y1="52" x2="140" y2="52" stroke="#BFDBFE" strokeWidth="1" />
            <line x1="20" y1="108" x2="140" y2="108" stroke="#BFDBFE" strokeWidth="1" />
            {/* Outer Circle */}
            <circle cx="80" cy="80" r="46" stroke="#93C5FD" strokeWidth="1.2" />
            {/* 4-Point Sparkle Curve */}
            <path
              d="M80 28 C80 58 102 80 132 80 C102 80 80 102 80 132 C80 102 58 80 28 80 C58 80 80 58 80 28 Z"
              stroke="#2563EB"
              strokeWidth="2"
              fill="#DBEAFE"
              fillOpacity="0.45"
            />
          </svg>
        </div>
      </div>
    </div>
  );
};
