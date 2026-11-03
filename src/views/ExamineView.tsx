import { Page, PageHeader, Segmented } from "../components/ui";
import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { TerminalHint } from "../components/Terminal";
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
  /** Text handed over from another page (e.g. a file dropped on Home); opens in the detect tab. */
  initialInput?: string | null;
}

export const ExamineView: React.FC<ExamineViewProps> = ({
  keystores,
  activeKeystoreId,
  onUpdateKeystore,
  onRecordOp,
  initialInput,
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

  useEffect(() => {
    if (!initialInput) return;
    setMode("clipboard");
    setRawInput(initialInput);
    invoke<FileDetectionResult>("detect_and_examine", { rawInput: initialInput })
      .then(setDetectResult)
      .catch((err) => alert("Detection failed: " + err));
  }, [initialInput]);

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
    <Page>
      {toast && (
        <div role="status" className="fixed bottom-6 right-6 z-[60] max-w-md bg-surface border border-line text-ink px-4 py-3 rounded-card shadow-pop flex items-center gap-2.5 text-[13px]">
          <CheckCircle2 className="w-4 h-4 text-success" />
          <span>{toast}</span>
        </div>
      )}

      <PageHeader
        title="Examine"
        description="Inspect a live TLS server, detect and decode pasted PEM / CSR / CRL / JWT data, or compare two certificates."
      />

      <div className="mb-4">
        <Segmented
          label="Examine mode"
          value={mode}
          onChange={setMode}
          options={[
            { value: "ssl", label: <><Globe className="w-3.5 h-3.5" /> TLS host</> },
            { value: "clipboard", label: <><FileSearch className="w-3.5 h-3.5" /> Detect &amp; decode</> },
            { value: "compare", label: <><GitCompare className="w-3.5 h-3.5" /> Compare</> },
          ]}
        />
      </div>

      {/* Main Content Card */}
      <div className="bg-surface rounded-card border border-line p-6 shadow-card">
        {mode === "ssl" && (
          <div className="space-y-5">
            <form onSubmit={(e) => handleExamineSsl(e)} className="flex flex-wrap items-center gap-3">
              <div className="flex-1 min-w-[240px] flex items-center bg-surface border border-line-strong rounded-control shadow-card px-3 h-9 focus-within:border-brand focus-within:ring-4 focus-within:ring-brand-soft">
                <Globe className="w-4 h-4 text-faint mr-2.5" />
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
                className="field !w-24 text-center"
              />
              <button
                type="submit"
                disabled={busy}
                className="h-9 px-4 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold cursor-pointer"
              >
                {busy ? "Handshaking..." : "Examine SSL"}
              </button>
            </form>

            {/* Quick Presets */}
            <div className="flex items-center space-x-2 text-[12px]">
              <span className="text-faint">Quick Inspect:</span>
              {["github.com", "google.com", "cloudflare.com", "letsencrypt.org"].map((h) => (
                <button
                  key={h}
                  onClick={() => handleExamineSsl(undefined, h)}
                  className="px-3 py-1 rounded-control bg-surface-3 hover:bg-line text-ink-2 font-medium cursor-pointer"
                >
                  {h}:443
                </button>
              ))}
            </div>

            {sslResult && (
              <div className="space-y-4 pt-2 select-text">
                <div className="p-4 rounded-card bg-brand-tint border border-brand-soft flex flex-wrap items-center justify-between gap-2 text-[12.5px]">
                  <div>
                    <span className="font-semibold text-brand-deep">{sslResult.host}:{sslResult.port}</span>
                    <span className="mx-2 text-subtle">•</span>
                    <span className="text-brand-deeper font-medium">{sslResult.protocol}</span>
                    <span className="mx-2 text-subtle">•</span>
                    <span className="font-mono text-ink-2">{sslResult.cipher_suite}</span>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-control bg-success-tint text-success font-semibold text-[11.5px]">
                    Peer Chain Verified
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {sslResult.server_certificates.map((cert, i) => (
                    <div key={i} className="p-4 rounded-card border border-line bg-surface-2 space-y-2.5 text-[12px]">
                      <div className="flex items-center justify-between">
                        <span className="px-2.5 py-0.5 rounded-control bg-brand-tint text-brand-deep font-semibold text-[11px]">
                          {cert.is_ca ? "Intermediate / Root CA" : "Server Leaf Certificate"}
                        </span>
                        <button
                          onClick={() => handleImportSslCert(cert)}
                          className="px-3 py-1 rounded-control bg-brand-soft hover:bg-brand-soft-hover text-brand-deep font-semibold flex items-center space-x-1 cursor-pointer"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          <span>Import to {activeKs?.name}</span>
                        </button>
                      </div>
                      <div className="font-semibold text-ink">{cert.subject}</div>
                      <div className="text-faint"><strong>Issuer:</strong> {cert.issuer}</div>
                      <div className="text-faint">
                        <strong>Algorithm:</strong> {cert.public_key_algorithm} ({cert.key_size} bits) • {cert.signature_algorithm}
                      </div>
                      <div className="font-mono text-[11px] text-ink-2 break-all">
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
                <span className="font-semibold text-ink">
                  Paste Certificate, CSR, CRL, Key, or JWT
                </span>
                <button
                  onClick={handleReadSystemClipboard}
                  className="px-3 py-1 rounded-control bg-surface-3 hover:bg-line text-ink font-medium flex items-center space-x-1 cursor-pointer"
                >
                  <Clipboard className="w-3.5 h-3.5" />
                  <span>Paste Clipboard</span>
                </button>
              </div>
              <TerminalHint command="ls ~/Downloads/*.pem ~/Downloads/*.crt ~/Downloads/*.cer" label="Find files" />
              <textarea
                rows={8}
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                className="w-full p-3 rounded-control border border-line-strong bg-surface shadow-card focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand-soft font-mono text-[11px]"
              />
              <button
                onClick={handleDetectAndExamine}
                className="w-full h-9 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold shadow-card cursor-pointer disabled:opacity-50 flex items-center justify-center space-x-2"
              >
                <Sparkles className="w-4 h-4" />
                <span>Detect File Type &amp; Inspect ASN.1</span>
              </button>
            </div>

            <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line select-text">
              {detectResult ? (
                <div className="space-y-3 text-[12.5px]">
                  <div className="flex items-center justify-between">
                    <span className="text-[16px] font-semibold text-brand-deep">
                      {detectResult.detected_type}
                    </span>
                    <span className="px-3 py-1 rounded-control bg-success-tint text-success text-[11.5px] font-semibold">
                      {detectResult.format}
                    </span>
                  </div>
                  <p className="text-muted">{detectResult.summary}</p>
                  <pre className="bg-term-bg text-term-fg p-4 rounded-control font-mono text-[11.5px] overflow-x-auto">
                    {JSON.stringify(detectResult.details, null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-subtle text-[13px]">
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
                <label className="text-[12px] font-semibold text-faint block mb-1">
                  Left Certificate Entry
                </label>
                <select
                  value={leftEntry.id}
                  onChange={(e) => setLeftEntryId(e.target.value)}
                  className="field"
                >
                  {allCertEntries.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.alias} ({e.algorithm} {e.key_size}b)
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[12px] font-semibold text-faint block mb-1">
                  Right Certificate Entry
                </label>
                <select
                  value={rightEntry.id}
                  onChange={(e) => setRightEntryId(e.target.value)}
                  className="field"
                >
                  {allCertEntries.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.alias} ({e.algorithm} {e.key_size}b)
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="border border-line rounded-card overflow-hidden text-[12.5px] select-text">
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
                    className={`grid grid-cols-12 border-b border-surface-3 p-3 items-center ${
                      diff ? "bg-warning-tint" : "bg-surface"
                    }`}
                  >
                    <div className="col-span-2 font-semibold text-muted">{row.label}</div>
                    <div className="col-span-5 font-mono text-[11.5px] text-ink pr-3 break-all">{row.l}</div>
                    <div className="col-span-5 font-mono text-[11.5px] text-ink pl-3 border-l border-line break-all">
                      {row.r}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </Page>
  );
};
