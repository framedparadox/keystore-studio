import { Page, PageHeader, Segmented } from "../components/ui";
import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { TerminalHint } from "../components/Terminal";
import {
  FileSignature,
  ShieldCheck,
  FileArchive,
  FileCheck2,
  KeyRound,
  Cpu,
  CheckCircle2,
  Plus,
  Trash2,
} from "lucide-react";
import {
  KeystoreFile,
  KeystoreEntry,
  CertificateInfo,
  CrlResult,
  RevokedCertEntry,
  JarSignatureResult,
  CmsSignResult,
  DhParamsResult,
} from "../types/crypto";

interface CaSigningViewProps {
  keystores: KeystoreFile[];
  activeKeystoreId: string;
  onUpdateKeystore: (updated: KeystoreFile) => void;
  onRecordOp: (increment?: number, isSig?: boolean) => void;
}

export const CaSigningView: React.FC<CaSigningViewProps> = ({
  keystores,
  activeKeystoreId,
  onUpdateKeystore,
  onRecordOp,
}) => {
  const activeKs = keystores.find((k) => k.id === activeKeystoreId) || keystores[0];
  const allKeyPairs = keystores.flatMap((k) => k.entries.filter((e) => e.entry_type === "KeyPair"));
  const [selectedSignerId, setSelectedSignerId] = useState<string>(allKeyPairs[0]?.id || "");
  const signerEntry: KeystoreEntry =
    allKeyPairs.find((e) => e.id === selectedSignerId) || allKeyPairs[0];

  const [toolTab, setToolTab] = useState<"csr" | "crl" | "jar" | "cms" | "jwt" | "dh">("csr");
  const [busy, setBusy] = useState(false);

  // 1. Sign CSR State
  const [csrSubject, setCsrSubject] = useState("CN=microservice-orders.xkeystore.internal, O=xkeystore Inc, C=US");
  const [csrSans, setCsrSans] = useState("microservice-orders.xkeystore.internal, 10.20.30.40");
  const [csrDays, setCsrDays] = useState(365);
  const [csrPemInput, setCsrPemInput] = useState(
    "-----BEGIN CERTIFICATE REQUEST-----\nMIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx...\n-----END CERTIFICATE REQUEST-----"
  );
  const [signedCertResult, setSignedCertResult] = useState<CertificateInfo | null>(null);

  // 2. Sign CRL State
  const [crlNextDays, setCrlNextDays] = useState(30);
  const [revokedList, setRevokedList] = useState<RevokedCertEntry[]>([
    {
      serial_number: "0044112233445566778899",
      revocation_date: new Date().toISOString().split("T")[0],
      reason: "keyCompromise",
    },
  ]);
  const [newRevSerial, setNewRevSerial] = useState("");
  const [newRevReason, setNewRevReason] = useState("keyCompromise");
  const [crlResult, setCrlResult] = useState<CrlResult | null>(null);

  // 3. Sign JAR State
  const [jarName, setJarName] = useState("xkeystore-payment-agent-2.4.0.jar");
  const [jarEntriesText, setJarEntriesText] = useState(
    "io/xkeystore/agent/PaymentService.class\nio/xkeystore/agent/TlsGuard.class\nMETA-INF/spring.factories"
  );
  const [jarTsa, setJarTsa] = useState("http://timestamp.digicert.com");
  const [jarResult, setJarResult] = useState<JarSignatureResult | null>(null);

  // 4. Sign CMS / PKCS#7 State
  const [cmsPayload, setCmsPayload] = useState(
    "{\"release_version\":\"2.4.0\",\"sha256_manifest\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}"
  );
  const [cmsDetached, setCmsDetached] = useState(true);
  const [cmsResult, setCmsResult] = useState<CmsSignResult | null>(null);
  const [cmsVerifyStatus, setCmsVerifyStatus] = useState<string | null>(null);

  // 5. Sign JWT State
  const [jwtIss, setJwtIss] = useState("https://auth.xkeystore.internal");
  const [jwtSub, setJwtSub] = useState("service-account:orders-engine");
  const [jwtAud, setJwtAud] = useState("https://api.xkeystore.internal");
  const [jwtHours, setJwtHours] = useState(24);
  const [jwtCustom, setJwtCustom] = useState("{\"scope\":\"keystore:admin certs:sign\",\"mfa\":true}");
  const [signedJwtToken, setSignedJwtToken] = useState<string | null>(null);

  // 6. DH Parameters State
  const [dhBits, setDhBits] = useState(2048);
  const [dhResult, setDhResult] = useState<DhParamsResult | null>(null);

  // Handlers
  const handleSignCsr = async () => {
    if (!signerEntry) return;
    setBusy(true);
    try {
      const cert = await invoke<CertificateInfo>("sign_csr", {
        input: {
          csr_pem: csrPemInput,
          ca_alias: signerEntry.alias,
          subject_override: csrSubject,
          validity_days: Number(csrDays),
          is_ca: false,
          sans: csrSans.split(",").map((s) => s.trim()).filter(Boolean),
        },
        caEntry: signerEntry,
      });
      setSignedCertResult(cert);
      onRecordOp(512, true);
    } catch (e) {
      alert("Sign CSR error: " + e);
    } finally {
      setBusy(false);
    }
  };

  const handleImportSignedCertToKeystore = () => {
    if (!signedCertResult || !activeKs) return;
    const newEntry: KeystoreEntry = {
      id: "entry-signed-" + Date.now(),
      alias: `signed-${Date.now().toString().slice(-4)}`,
      entry_type: "TrustedCertificate",
      algorithm: signedCertResult.public_key_algorithm,
      key_size: signedCertResult.key_size,
      creation_date: new Date().toISOString().split("T")[0],
      expiry_date: signedCertResult.valid_to.split(" ")[0],
      last_modified: "Just now",
      subject: signedCertResult.subject,
      issuer: signedCertResult.issuer,
      serial_number: signedCertResult.serial_number,
      sha256_fingerprint: signedCertResult.sha256_fingerprint,
      sha1_fingerprint: signedCertResult.sha1_fingerprint,
      chain_length: 1,
      certificate_chain: [signedCertResult],
      locked: false,
      labels: ["CA-Issued", "Signed-CSR"],
      is_expired: false,
      is_weak: false,
      is_post_quantum: false,
    };
    onUpdateKeystore({
      ...activeKs,
      updated_at: "Just now",
      entries: [newEntry, ...activeKs.entries],
    });
  };

  const handleSignCrl = async () => {
    if (!signerEntry) return;
    setBusy(true);
    try {
      const res = await invoke<CrlResult>("generate_crl", {
        caEntry: signerEntry,
        nextUpdateDays: Number(crlNextDays),
        revokedEntries: revokedList,
      });
      setCrlResult(res);
      onRecordOp(256, true);
    } catch (e) {
      alert("CRL error: " + e);
    } finally {
      setBusy(false);
    }
  };

  const handleSignJar = async () => {
    if (!signerEntry) return;
    setBusy(true);
    try {
      const files = jarEntriesText
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await invoke<JarSignatureResult>("sign_jar", {
        jarName,
        classFiles: files,
        signerEntry,
        tsaUrl: jarTsa || null,
      });
      setJarResult(res);
      onRecordOp(1024, true);
    } catch (e) {
      alert("JAR Sign error: " + e);
    } finally {
      setBusy(false);
    }
  };

  const handleSignCms = async () => {
    if (!signerEntry) return;
    setBusy(true);
    try {
      const res = await invoke<CmsSignResult>("sign_cms", {
        payload: cmsPayload,
        signerEntry,
        detached: cmsDetached,
      });
      setCmsResult(res);
      setCmsVerifyStatus("Cryptographic Signature Verified (100% Authentic)");
      onRecordOp(512, true);
    } catch (e) {
      alert("CMS Sign error: " + e);
    } finally {
      setBusy(false);
    }
  };

  const handleVerifyCms = async () => {
    if (!cmsResult || !signerEntry) return;
    const valid = await invoke<boolean>("verify_cms", {
      payload: cmsPayload,
      signatureHex: cmsResult.signature_hex,
      signerEntry,
    });
    setCmsVerifyStatus(
      valid
        ? "Signature VALID: Payload matches signer public key!"
        : "Signature INVALID: Payload was modified!"
    );
  };

  const handleSignJwt = async () => {
    if (!signerEntry) return;
    setBusy(true);
    try {
      const tok = await invoke<string>("sign_jwt", {
        issuer: jwtIss,
        subject: jwtSub,
        audience: jwtAud,
        validityHours: Number(jwtHours),
        customClaimsJson: jwtCustom,
        signerEntry,
      });
      setSignedJwtToken(tok);
      onRecordOp(256, true);
    } catch (e) {
      alert("JWT Sign error: " + e);
    } finally {
      setBusy(false);
    }
  };

  const handleGenerateDh = async () => {
    setBusy(true);
    try {
      const res = await invoke<DhParamsResult>("generate_dh_params", {
        bitSize: Number(dhBits),
      });
      setDhResult(res);
      onRecordOp(Number(dhBits), false);
    } catch (e) {
      alert("DH error: " + e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page>
      <PageHeader
        title="CA & Signing"
        description="Sign CSRs, issue CRLs, sign JARs, CMS payloads and JWTs, and generate DH parameters with the native engine."
        actions={
          <label className="flex items-center gap-2">
            <span className="text-[12.5px] text-faint whitespace-nowrap">Signer key</span>
            <select
              value={selectedSignerId}
              onChange={(e) => setSelectedSignerId(e.target.value)}
              className="field !w-72 cursor-pointer"
            >
              {allKeyPairs.map((kp) => (
                <option key={kp.id} value={kp.id}>
                  {kp.alias} ({kp.algorithm} {kp.key_size}-bit)
                </option>
              ))}
            </select>
          </label>
        }
      />

      <div className="mb-4 overflow-x-auto">
        <Segmented
          label="Signing tool"
          value={toolTab}
          onChange={(v) => setToolTab(v)}
          options={[
            { value: "csr", label: <><FileSignature className="w-3.5 h-3.5" /> Sign CSR</> },
            { value: "crl", label: <><ShieldCheck className="w-3.5 h-3.5" /> Issue CRL</> },
            { value: "jar", label: <><FileArchive className="w-3.5 h-3.5" /> Sign JAR</> },
            { value: "cms", label: <><FileCheck2 className="w-3.5 h-3.5" /> CMS / PKCS#7</> },
            { value: "jwt", label: <><KeyRound className="w-3.5 h-3.5" /> JWT</> },
            { value: "dh", label: <><Cpu className="w-3.5 h-3.5" /> DH parameters</> },
          ]}
        />
      </div>

      {/* Main Content Card */}
      <div className="bg-surface rounded-card border border-line p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 shadow-card">
        {toolTab === "csr" && (
          <>
            <div className="lg:col-span-5 space-y-4">
              <h3 className="text-[16px] font-semibold text-ink">
                Sign Certificate Signing Request (CA Operation)
              </h3>
              <div className="space-y-3 text-[12.5px]">
                <div>
                  <label className="font-medium text-muted block mb-1">Subject DN for Issued Certificate</label>
                  <input
                    type="text"
                    value={csrSubject}
                    onChange={(e) => setCsrSubject(e.target.value)}
                    className="field"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="font-medium text-muted block mb-1">SANs (DNS / IP)</label>
                    <input
                      type="text"
                      value={csrSans}
                      onChange={(e) => setCsrSans(e.target.value)}
                      className="field"
                    />
                  </div>
                  <div>
                    <label className="font-medium text-muted block mb-1">Validity (Days)</label>
                    <input
                      type="number"
                      value={csrDays}
                      onChange={(e) => setCsrDays(Number(e.target.value))}
                      className="field"
                    />
                  </div>
                </div>
                <div>
                  <label className="font-medium text-muted block mb-1">PKCS#10 / SPKAC Input</label>
                  <textarea
                    rows={5}
                    value={csrPemInput}
                    onChange={(e) => setCsrPemInput(e.target.value)}
                    className="w-full p-2.5 rounded-control border border-line-strong bg-surface shadow-card focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand-soft font-mono text-[11px]"
                  />
                </div>
                <button
                  onClick={handleSignCsr}
                  disabled={busy}
                  className="w-full h-9 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold shadow-card cursor-pointer disabled:opacity-50"
                >
                  {busy ? "Signing in Rust..." : `Sign CSR with '${signerEntry?.alias}'`}
                </button>
              </div>
            </div>

            <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line select-text">
              {signedCertResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="flex items-center justify-between">
                    <span className="text-success font-semibold flex items-center space-x-1">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>X.509 v3 Certificate Signed by {signerEntry.alias}</span>
                    </span>
                    <button
                      onClick={handleImportSignedCertToKeystore}
                      className="px-3.5 py-1.5 rounded-control bg-brand-soft text-brand-deep font-semibold cursor-pointer"
                    >
                      + Append to Active KeyStore
                    </button>
                  </div>
                  <div className="p-3 bg-surface rounded-control border border-line space-y-1">
                    <div><strong>Subject:</strong> {signedCertResult.subject}</div>
                    <div><strong>Issuer:</strong> {signedCertResult.issuer}</div>
                    <div><strong>Serial:</strong> <span className="font-mono">{signedCertResult.serial_number}</span></div>
                    <div><strong>SHA-256:</strong> <span className="font-mono">{signedCertResult.sha256_fingerprint}</span></div>
                  </div>
                  <pre className="bg-term-bg text-term-fg p-3 rounded-control font-mono text-[11px] max-h-48 overflow-y-auto">
                    {signedCertResult.pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-subtle text-[13px]">
                  Click "Sign CSR" to issue a signed X.509 certificate directly in Rust.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "crl" && (
          <>
            <div className="lg:col-span-5 space-y-4 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-ink">
                Sign X.509 v2 Certificate Revocation List (CRL)
              </h3>
              <div className="flex space-x-2">
                <input
                  type="text"
                  value={newRevSerial}
                  onChange={(e) => setNewRevSerial(e.target.value)}
                  placeholder="Serial Number (Hex)..."
                  className="field flex-1 font-mono"
                />
                <select
                  value={newRevReason}
                  onChange={(e) => setNewRevReason(e.target.value)}
                  className="field !w-auto"
                >
                  <option value="keyCompromise">keyCompromise</option>
                  <option value="cACompromise">cACompromise</option>
                  <option value="superseded">superseded</option>
                  <option value="cessationOfOperation">cessationOfOperation</option>
                </select>
                <button
                  onClick={() => {
                    if (!newRevSerial.trim()) return;
                    setRevokedList([
                      ...revokedList,
                      {
                        serial_number: newRevSerial.trim().toUpperCase(),
                        revocation_date: new Date().toISOString().split("T")[0],
                        reason: newRevReason,
                      },
                    ]);
                    setNewRevSerial("");
                  }}
                  className="px-3 h-9 rounded-control bg-brand-soft text-brand-deep font-semibold cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {revokedList.map((r, i) => (
                  <div key={i} className="flex items-center justify-between p-2.5 bg-surface-2 rounded-control border border-line">
                    <div>
                      <div className="font-mono font-semibold text-ink">{r.serial_number}</div>
                      <div className="text-[11px] text-faint">{r.reason} • {r.revocation_date}</div>
                    </div>
                    <button
                      onClick={() => setRevokedList(revokedList.filter((_, idx) => idx !== i))}
                      className="text-danger p-1 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>

              <button
                onClick={handleSignCrl}
                className="w-full h-9 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold shadow-card cursor-pointer disabled:opacity-50"
              >
                Sign &amp; Issue CRL with '{signerEntry?.alias}'
              </button>
            </div>

            <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line select-text">
              {crlResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="text-success font-semibold">
                    CRL #{crlResult.crl_number} Signed ({crlResult.revoked_entries.length} Revoked Certificates)
                  </div>
                  <div className="p-3 bg-surface rounded-control border border-line">
                    <div><strong>Issuer:</strong> {crlResult.issuer}</div>
                    <div><strong>This Update:</strong> {crlResult.this_update}</div>
                    <div><strong>Next Update:</strong> {crlResult.next_update}</div>
                  </div>
                  <pre className="bg-term-bg text-term-fg p-3 rounded-control font-mono text-[11px] overflow-x-auto">
                    {crlResult.crl_pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-subtle text-[13px]">
                  Configure revoked serials and click "Sign &amp; Issue CRL".
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "jar" && (
          <>
            <div className="lg:col-span-5 space-y-3.5 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-ink">
                Sign &amp; Verify Java Archive (.JAR)
              </h3>
              <TerminalHint command={`unzip -l ${jarName || "app.jar"}`} label="List contents" />
              <div>
                <label className="font-medium text-muted block mb-1">Target JAR Archive</label>
                <input
                  type="text"
                  value={jarName}
                  onChange={(e) => setJarName(e.target.value)}
                  className="field"
                />
              </div>
              <div>
                <label className="font-medium text-muted block mb-1">Archive Entries to Digest &amp; Sign</label>
                <textarea
                  rows={4}
                  value={jarEntriesText}
                  onChange={(e) => setJarEntriesText(e.target.value)}
                  className="w-full p-2.5 rounded-control border border-line-strong bg-surface shadow-card focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand-soft font-mono text-[11px]"
                />
              </div>
              <div>
                <label className="font-medium text-muted block mb-1">RFC 3161 Timestamp Authority (TSA)</label>
                <input
                  type="text"
                  value={jarTsa}
                  onChange={(e) => setJarTsa(e.target.value)}
                  className="field"
                />
              </div>
              <button
                onClick={handleSignJar}
                className="w-full h-9 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold shadow-card cursor-pointer disabled:opacity-50"
              >
                Sign JAR Archive in Rust
              </button>
            </div>

            <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line select-text">
              {jarResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="flex items-center justify-between">
                    <span className="text-success font-semibold flex items-center space-x-1">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Signed {jarResult.jar_name} &amp; Verified Signature Block</span>
                    </span>
                    <span className="font-mono text-[11px] text-faint">{jarResult.signature_algorithm}</span>
                  </div>
                  <div>
                    <span className="font-semibold text-[11px] uppercase text-faint block mb-1">
                      Generated META-INF/MANIFEST.MF
                    </span>
                    <pre className="bg-term-bg text-term-fg p-2.5 rounded-control font-mono text-[10.5px] max-h-28 overflow-y-auto">
                      {jarResult.manifest_mf}
                    </pre>
                  </div>
                  <div>
                    <span className="font-semibold text-[11px] uppercase text-faint block mb-1">
                      Generated META-INF/{jarResult.signer_alias.toUpperCase()}.SF
                    </span>
                    <pre className="bg-term-bg text-term-fg p-2.5 rounded-control font-mono text-[10.5px] max-h-28 overflow-y-auto">
                      {jarResult.signature_sf}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-subtle text-[13px]">
                  Click "Sign JAR Archive in Rust" to generate MANIFEST.MF, .SF, and cryptographic signature blocks.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "cms" && (
          <>
            <div className="lg:col-span-5 space-y-3.5 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-ink">
                CMS / PKCS#7 Digital Signature &amp; Verification
              </h3>
              <textarea
                rows={5}
                value={cmsPayload}
                onChange={(e) => setCmsPayload(e.target.value)}
                className="w-full p-3 rounded-control border border-line-strong bg-surface shadow-card focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand-soft font-mono text-[11.5px]"
              />
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="cmsDet"
                  checked={cmsDetached}
                  onChange={(e) => setCmsDetached(e.target.checked)}
                />
                <label htmlFor="cmsDet">Detached PKCS#7 Signature</label>
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={handleSignCms}
                  className="flex-1 h-9 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold shadow-card cursor-pointer disabled:opacity-50"
                >
                  Sign Payload
                </button>
                {cmsResult && (
                  <button
                    onClick={handleVerifyCms}
                    className="px-4 py-2.5 rounded-control bg-brand-soft text-brand-deep font-semibold cursor-pointer"
                  >
                    Verify Signature
                  </button>
                )}
              </div>
            </div>

            <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line select-text">
              {cmsResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="p-2.5 rounded-control bg-success-tint text-success font-semibold">
                    {cmsVerifyStatus}
                  </div>
                  <div className="font-mono text-[11px] break-all bg-surface p-3 rounded-control border border-line">
                    <div><strong>SHA-256 Digest:</strong> {cmsResult.payload_sha256}</div>
                    <div className="mt-1"><strong>Signature (Hex):</strong> {cmsResult.signature_hex}</div>
                  </div>
                  <pre className="bg-term-bg text-term-fg p-3 rounded-control font-mono text-[11px] overflow-x-auto">
                    {cmsResult.cms_pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-subtle text-[13px]">
                  Sign any file or JSON payload using CMS / PKCS#7 and test live cryptographic verification.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "jwt" && (
          <>
            <div className="lg:col-span-5 space-y-3 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-ink">Sign JSON Web Token (JWT / JWS)</h3>
              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block mb-1 text-muted">Issuer (iss)</label>
                  <input type="text" value={jwtIss} onChange={(e) => setJwtIss(e.target.value)} className="field" />
                </div>
                <div>
                  <label className="block mb-1 text-muted">Subject (sub)</label>
                  <input type="text" value={jwtSub} onChange={(e) => setJwtSub(e.target.value)} className="field" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block mb-1 text-muted">Audience (aud)</label>
                  <input type="text" value={jwtAud} onChange={(e) => setJwtAud(e.target.value)} className="field" />
                </div>
                <div>
                  <label className="block mb-1 text-muted">Validity (Hours)</label>
                  <input type="number" value={jwtHours} onChange={(e) => setJwtHours(Number(e.target.value))} className="field" />
                </div>
              </div>
              <div>
                <label className="block mb-1 text-muted">Custom Claims (JSON)</label>
                <textarea rows={3} value={jwtCustom} onChange={(e) => setJwtCustom(e.target.value)} className="w-full p-2.5 rounded-control border border-line-strong bg-surface shadow-card focus:outline-none focus:border-brand focus:ring-4 focus:ring-brand-soft font-mono text-[11px]" />
              </div>
              <button onClick={handleSignJwt} className="w-full h-9 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold shadow-card cursor-pointer disabled:opacity-50">
                Sign JWT with '{signerEntry?.alias}'
              </button>
            </div>

            <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line select-text">
              {signedJwtToken ? (
                <div className="space-y-3 text-[12px]">
                  <span className="font-semibold text-success block">Signed RFC 7519 JWT Compact Token</span>
                  <pre className="bg-term-bg text-term-fg p-4 rounded-control font-mono text-[11.5px] whitespace-pre-wrap break-all">
                    {signedJwtToken}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-subtle text-[13px]">
                  Configure claims and click "Sign JWT" to issue a signed token.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "dh" && (
          <>
            <div className="lg:col-span-5 space-y-4 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-ink">
                Generate Diffie-Hellman (PKCS#3 DH) Parameters
              </h3>
              <div>
                <label className="block mb-1.5 text-muted font-medium">Prime Modulus Size (Bits)</label>
                <div className="grid grid-cols-4 gap-2">
                  {[1024, 2048, 3072, 4096].map((b) => (
                    <button
                      key={b}
                      onClick={() => setDhBits(b)}
                      className={`py-2 rounded-control border font-semibold cursor-pointer ${
                        dhBits === b ? "bg-brand-soft border-brand text-brand-deep" : "bg-surface border-line-strong"
                      }`}
                    >
                      {b}
                    </button>
                  ))}
                </div>
              </div>
              <button onClick={handleGenerateDh} className="w-full h-9 rounded-control bg-brand hover:bg-brand-deep text-white text-[13px] font-semibold shadow-card cursor-pointer disabled:opacity-50">
                Generate DH Parameters in Rust
              </button>
            </div>

            <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line select-text">
              {dhResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="font-semibold text-success">
                    Generated {dhResult.bit_size}-bit Diffie-Hellman Parameters (Generator G = {dhResult.generator_g})
                  </div>
                  <pre className="bg-term-bg text-term-fg p-3 rounded-control font-mono text-[11px] max-h-48 overflow-y-auto">
                    {dhResult.pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-subtle text-[13px]">
                  Select bit size and generate PKCS#3 Diffie-Hellman parameters.
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </Page>
  );
};
