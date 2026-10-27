import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Globe,
  FileSearch,
  GitCompare,
  CheckCircle2,
  Plus,
  Clipboard,
  Sparkles,
} from "lucide-react";
import {
  KeystoreFile,
  KeystoreEntry,
  CertificateInfo,
  SslInspectionResult,
  FileDetectionResult,
} from "../types/crypto";

interface ExamineViewProps {
  keystores: KeystoreFile[];
  activeKeystoreId: string;
  onUpdateKeystore: (updated: KeystoreFile) => void;
  onRecordOp: (increment?: number, isSig?: boolean) => void;
}

export const ExamineView: React.FC<ExamineViewProps> = ({
  keystores,
  activeKeystoreId,
  onUpdateKeystore,
  onRecordOp,
}) => {
  const activeKs = keystores.find((k) => k.id === activeKeystoreId) || keystores[0];
  const allCertEntries = keystores
    .flatMap((k) => k.entries)
    .filter((e) => e.certificate_chain.length > 0);

  const [mode, setMode] = useState<"ssl" | "clipboard" | "compare">("ssl");
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  // 1. Examine SSL State
  const [sslHost, setSslHost] = useState("github.com");
  const [sslPort, setSslPort] = useState(443);
  const [sslResult, setSslResult] = useState<SslInspectionResult | null>(null);

  // 2. Examine Clipboard / Detect Type State
  const [rawInput, setRawInput] = useState(
    "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJALb1234567890TANBgkqhkiG9w0BAQsFADBv...\n-----END CERTIFICATE-----"
  );
  const [detectResult, setDetectResult] = useState<FileDetectionResult | null>(null);

  // 3. Compare Certificates State
  const [leftEntryId, setLeftEntryId] = useState<string>(allCertEntries[0]?.id || "");
  const [rightEntryId, setRightEntryId] = useState<string>(
    allCertEntries[1]?.id || allCertEntries[0]?.id || ""
  );

  const leftEntry = allCertEntries.find((e) => e.id === leftEntryId) || allCertEntries[0];
  const rightEntry = allCertEntries.find((e) => e.id === rightEntryId) || allCertEntries[1] || allCertEntries[0];

  const handleExamineSsl = async (e?: React.FormEvent, presetHost?: string) => {
    if (e) e.preventDefault();
    const targetHost = presetHost || sslHost;
    if (presetHost) setSslHost(presetHost);
    setBusy(true);
    try {
      const res = await invoke<SslInspectionResult>("examine_ssl", {
        host: targetHost,
        port: Number(sslPort),
      });
      setSslResult(res);
      onRecordOp(512, false);
    } catch (err) {
      alert("SSL inspection failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleImportSslCert = (cert: CertificateInfo) => {
    if (!activeKs) return;
    const alias = `${sslResult?.host || "ssl"}-${cert.is_ca ? "ca" : "leaf"}-${Date.now().toString().slice(-3)}`;
    const newEntry: KeystoreEntry = {
      id: "entry-ssl-" + Date.now(),
      alias,
      entry_type: "TrustedCertificate",
      algorithm: cert.public_key_algorithm,
      key_size: cert.key_size,
      creation_date: new Date().toISOString().split("T")[0],
      expiry_date: cert.valid_to.split(" ")[0],
      last_modified: "Just now",
      subject: cert.subject,
      issuer: cert.issuer,
      serial_number: cert.serial_number,
      sha256_fingerprint: cert.sha256_fingerprint,
      sha1_fingerprint: cert.sha1_fingerprint,
      chain_length: 1,
      certificate_chain: [cert],
      locked: false,
      labels: ["SSL-Imported", sslResult?.host || "Remote"],
      is_expired: false,
      is_weak: false,
      is_post_quantum: false,
    };
    onUpdateKeystore({
      ...activeKs,
      updated_at: "Just now",
      entries: [newEntry, ...activeKs.entries],
    });
    setToast(`Imported '${alias}' into ${activeKs.name}!`);
    setTimeout(() => setToast(null), 3500);
  };

  const handleDetectAndExamine = async () => {
    setBusy(true);
    try {
      const res = await invoke<FileDetectionResult>("detect_and_examine", {
        rawInput,
      });
      setDetectResult(res);
      onRecordOp(256, false);
    } catch (err) {
      alert("Detection failed: " + err);
    } finally {
      setBusy(false);
    }
  };

  const handleReadSystemClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setRawInput(text);
        const res = await invoke<FileDetectionResult>("detect_and_examine", {
          rawInput: text,
        });
        setDetectResult(res);
      }
    } catch {
      handleDetectAndExamine();
    }
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#EEF2F7] px-8 py-6 select-none">
      {toast && (
        <div className="fixed bottom-6 right-8 z-50 bg-[#0F172A] text-white px-4 py-3 rounded-2xl shadow-xl flex items-center space-x-2 text-[13px]">
          <CheckCircle2 className="w-4 h-4 text-[#34D399]" />
          <span>{toast}</span>
        </div>
      )}

      <div className="mb-4">
        <h1 className="text-[28px] font-normal text-[#1E293B] tracking-tight">
          Examine SSL, Clipboard &amp; Compare Certificates
        </h1>
        <p className="text-[13px] text-[#64748B]">
          Connect to live TLS servers, auto-detect cryptographic file formats, and diff certificates side-by-side.
        </p>
      </div>

      {/* Mode Switcher Pills */}
      <div className="flex items-center space-x-2 mb-5">
        <button
          onClick={() => setMode("ssl")}
          className={`px-4 py-1.5 rounded-full text-[13px] font-semibold flex items-center space-x-2 cursor-pointer ${
            mode === "ssl" ? "bg-[#C2E7FF] text-[#0A3464]" : "bg-white text-[#334155]"
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>Examine SSL / TLS Host</span>
        </button>

        <button
          onClick={() => setMode("clipboard")}
          className={`px-4 py-1.5 rounded-full text-[13px] font-semibold flex items-center space-x-2 cursor-pointer ${
            mode === "clipboard" ? "bg-[#C2E7FF] text-[#0A3464]" : "bg-white text-[#334155]"
          }`}
        >
          <FileSearch className="w-3.5 h-3.5" />
          <span>Examine Clipboard &amp; Detect Type</span>
        </button>

        <button
          onClick={() => setMode("compare")}
          className={`px-4 py-1.5 rounded-full text-[13px] font-semibold flex items-center space-x-2 cursor-pointer ${
            mode === "compare" ? "bg-[#C2E7FF] text-[#0A3464]" : "bg-white text-[#334155]"
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>Compare Certificates</span>
        </button>
      </div>

      {/* Main Content Card */}
      <div className="flex-1 bg-white rounded-[24px] border border-[#E2E8F0] p-6 overflow-y-auto shadow-2xs">
        {mode === "ssl" && (
          <div className="space-y-5">
            <form onSubmit={(e) => handleExamineSsl(e)} className="flex flex-wrap items-center gap-3">
              <div className="flex-1 min-w-[240px] flex items-center bg-[#F8FAFC] border border-[#CBD5E1] rounded-full px-4 h-11">
                <Globe className="w-4 h-4 text-[#64748B] mr-2.5" />
                <input
                  type="text"
                  value={sslHost}
                  onChange={(e) => setSslHost(e.target.value)}
                  placeholder="Enter hostname (e.g. github.com, google.com, cloudflare.com)"
                  className="w-full bg-transparent text-[13.5px] focus:outline-none"
                />
              </div>
              <input
                type="number"
                value={sslPort}
                onChange={(e) => setSslPort(Number(e.target.value))}
                className="w-24 h-11 px-3 rounded-full bg-[#F8FAFC] border border-[#CBD5E1] text-[13.5px] text-center"
              />
              <button
                type="submit"
                disabled={busy}
                className="h-11 px-6 rounded-full bg-[#0A3464] hover:bg-[#07274C] text-white text-[13px] font-semibold cursor-pointer"
              >
                {busy ? "Handshaking..." : "Examine SSL"}
              </button>
            </form>

            {/* Quick Presets */}
            <div className="flex items-center space-x-2 text-[12px]">
              <span className="text-[#64748B]">Quick Inspect:</span>
              {["github.com", "google.com", "cloudflare.com", "letsencrypt.org"].map((h) => (
                <button
                  key={h}
                  onClick={() => handleExamineSsl(undefined, h)}
                  className="px-3 py-1 rounded-full bg-[#F1F5F9] hover:bg-[#E2E8F0] text-[#334155] font-medium cursor-pointer"
                >
                  {h}:443
                </button>
              ))}
            </div>

            {sslResult && (
              <div className="space-y-4 pt-2 select-text">
                <div className="p-4 rounded-2xl bg-[#F0F7FF] border border-[#BFDBFE] flex flex-wrap items-center justify-between gap-2 text-[12.5px]">
                  <div>
                    <span className="font-bold text-[#0A3464]">{sslResult.host}:{sslResult.port}</span>
                    <span className="mx-2 text-[#94A3B8]">•</span>
                    <span className="text-[#1E40AF] font-medium">{sslResult.protocol}</span>
                    <span className="mx-2 text-[#94A3B8]">•</span>
                    <span className="font-mono text-[#334155]">{sslResult.cipher_suite}</span>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#DCFCE7] text-[#166534] font-semibold text-[11.5px]">
                    Peer Chain Verified
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {sslResult.server_certificates.map((cert, i) => (
                    <div key={i} className="p-4 rounded-2xl border border-[#E2E8F0] bg-[#F8FAFC] space-y-2.5 text-[12px]">
                      <div className="flex items-center justify-between">
                        <span className="px-2.5 py-0.5 rounded-full bg-[#E0F2FE] text-[#0369A1] font-bold text-[11px]">
                          {cert.is_ca ? "Intermediate / Root CA" : "Server Leaf Certificate"}
                        </span>
                        <button
                          onClick={() => handleImportSslCert(cert)}
                          className="px-3 py-1 rounded-full bg-[#C2E7FF] hover:bg-[#AEDBFF] text-[#0A3464] font-semibold flex items-center space-x-1 cursor-pointer"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          <span>Import to {activeKs?.name}</span>
                        </button>
                      </div>
                      <div className="font-semibold text-[#0F172A]">{cert.subject}</div>
                      <div className="text-[#64748B]"><strong>Issuer:</strong> {cert.issuer}</div>
                      <div className="text-[#64748B]">
                        <strong>Algorithm:</strong> {cert.public_key_algorithm} ({cert.key_size} bits) • {cert.signature_algorithm}
                      </div>
                      <div className="font-mono text-[11px] text-[#334155] break-all">
                        <strong>SHA-256:</strong> {cert.sha256_fingerprint}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {mode === "clipboard" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-5 space-y-3 text-[12.5px]">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-[#0F172A]">
                  Paste Certificate, CSR, CRL, Key, or JWT
                </span>
                <button
                  onClick={handleReadSystemClipboard}
                  className="px-3 py-1 rounded-full bg-[#F1F5F9] hover:bg-[#E2E8F0] text-[#0F172A] font-medium flex items-center space-x-1 cursor-pointer"
                >
                  <Clipboard className="w-3.5 h-3.5" />
                  <span>Paste Clipboard</span>
                </button>
              </div>
              <textarea
                rows={8}
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                className="w-full p-3 rounded-2xl border border-[#CBD5E1] font-mono text-[11px]"
              />
              <button
                onClick={handleDetectAndExamine}
                className="w-full py-2.5 rounded-full bg-[#0A3464] text-white font-semibold cursor-pointer flex items-center justify-center space-x-2"
              >
                <Sparkles className="w-4 h-4" />
                <span>Detect File Type &amp; Inspect ASN.1</span>
              </button>
            </div>

            <div className="lg:col-span-7 bg-[#F8FAFC] rounded-2xl p-5 border border-[#E2E8F0] select-text">
              {detectResult ? (
                <div className="space-y-3 text-[12.5px]">
                  <div className="flex items-center justify-between">
                    <span className="text-[16px] font-bold text-[#0A3464]">
                      {detectResult.detected_type}
                    </span>
                    <span className="px-3 py-1 rounded-full bg-[#DCFCE7] text-[#166534] text-[11.5px] font-bold">
                      {detectResult.format}
                    </span>
                  </div>
                  <p className="text-[#475569]">{detectResult.summary}</p>
                  <pre className="bg-[#0F172A] text-[#38BDF8] p-4 rounded-xl font-mono text-[11.5px] overflow-x-auto">
                    {JSON.stringify(detectResult.details, null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-[#94A3B8] text-[13px]">
                  Paste any cryptographic artifact and click "Detect File Type &amp; Inspect ASN.1".
                </div>
              )}
            </div>
          </div>
        )}

        {mode === "compare" && leftEntry && rightEntry && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-[12px] font-semibold text-[#64748B] block mb-1">
                  Left Certificate Entry
                </label>
                <select
                  value={leftEntry.id}
                  onChange={(e) => setLeftEntryId(e.target.value)}
                  className="w-full h-10 px-3 rounded-xl border border-[#CBD5E1] bg-white text-[13px] font-semibold"
                >
                  {allCertEntries.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.alias} ({e.algorithm} {e.key_size}b)
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[12px] font-semibold text-[#64748B] block mb-1">
                  Right Certificate Entry
                </label>
                <select
                  value={rightEntry.id}
                  onChange={(e) => setRightEntryId(e.target.value)}
                  className="w-full h-10 px-3 rounded-xl border border-[#CBD5E1] bg-white text-[13px] font-semibold"
                >
                  {allCertEntries.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.alias} ({e.algorithm} {e.key_size}b)
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="border border-[#E2E8F0] rounded-2xl overflow-hidden text-[12.5px] select-text">
              {[
                { label: "Alias", l: leftEntry.alias, r: rightEntry.alias },
                { label: "Entry Type", l: leftEntry.entry_type, r: rightEntry.entry_type },
                { label: "Algorithm & Size", l: `${leftEntry.algorithm} (${leftEntry.key_size} bits)`, r: `${rightEntry.algorithm} (${rightEntry.key_size} bits)` },
                { label: "Subject DN", l: leftEntry.subject, r: rightEntry.subject },
                { label: "Issuer DN", l: leftEntry.issuer, r: rightEntry.issuer },
                { label: "Serial Number", l: leftEntry.serial_number, r: rightEntry.serial_number },
                { label: "Expiry Date", l: leftEntry.expiry_date, r: rightEntry.expiry_date },
                { label: "SHA-256 Fingerprint", l: leftEntry.sha256_fingerprint, r: rightEntry.sha256_fingerprint },
              ].map((row, idx) => {
                const diff = row.l !== row.r;
                return (
                  <div
                    key={idx}
                    className={`grid grid-cols-12 border-b border-[#F1F5F9] p-3 items-center ${
                      diff ? "bg-[#FEFCE8]/70" : "bg-white"
                    }`}
                  >
                    <div className="col-span-2 font-semibold text-[#475569]">{row.label}</div>
                    <div className="col-span-5 font-mono text-[11.5px] text-[#0F172A] pr-3 break-all">{row.l}</div>
                    <div className="col-span-5 font-mono text-[11.5px] text-[#0F172A] pl-3 border-l border-[#E2E8F0] break-all">
                      {row.r}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
