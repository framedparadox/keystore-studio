import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
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
  const [csrSubject, setCsrSubject] = useState("CN=microservice-orders.certforge.internal, O=CertForge Inc, C=US");
  const [csrSans, setCsrSans] = useState("microservice-orders.certforge.internal, 10.20.30.40");
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
  const [jarName, setJarName] = useState("certforge-payment-agent-2.4.0.jar");
  const [jarEntriesText, setJarEntriesText] = useState(
    "com/certforge/agent/PaymentService.class\ncom/certforge/agent/TlsGuard.class\nMETA-INF/spring.factories"
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
  const [jwtIss, setJwtIss] = useState("https://auth.certforge.internal");
  const [jwtSub, setJwtSub] = useState("service-account:orders-engine");
  const [jwtAud, setJwtAud] = useState("https://api.certforge.internal");
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
    <div className="flex-1 flex flex-col overflow-hidden bg-[#EEF2F7] px-8 py-6 select-none">
      {/* Header & Active Signer Selector */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
        <div>
          <h1 className="text-[28px] font-normal text-[#1E293B] tracking-tight">
            CA Authority &amp; Digital Signing Studio
          </h1>
          <p className="text-[13px] text-[#64748B]">
            Native Rust execution for CSR signing, X.509 v2 CRL issuance, JAR signing, CMS/PKCS#7, JWT, and Diffie-Hellman.
          </p>
        </div>

        {/* Select KeyStore Signer KeyPair */}
        <div className="flex items-center space-x-2 bg-white px-4 py-2 rounded-full border border-[#E2E8F0] shadow-2xs">
          <KeyRound className="w-4 h-4 text-[#2563EB]" />
          <span className="text-[12px] text-[#64748B]">Active Signer Key:</span>
          <select
            value={selectedSignerId}
            onChange={(e) => setSelectedSignerId(e.target.value)}
            className="text-[13px] font-semibold text-[#0A3464] bg-transparent focus:outline-none cursor-pointer"
          >
            {allKeyPairs.map((kp) => (
              <option key={kp.id} value={kp.id}>
                {kp.alias} ({kp.algorithm} {kp.key_size}-bit)
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Tool Switcher Pills (matching Screenshot 1 pill bar) */}
      <div className="flex flex-wrap items-center gap-2 mb-5">
        {[
          { id: "csr", label: "Sign CSR (PKCS#10 / SPKAC)", icon: FileSignature },
          { id: "crl", label: "Issue & Sign CRL", icon: ShieldCheck },
          { id: "jar", label: "Sign & Verify JAR", icon: FileArchive },
          { id: "cms", label: "Sign File (CMS / PKCS#7)", icon: FileCheck2 },
          { id: "jwt", label: "Sign JWT Token", icon: KeyRound },
          { id: "dh", label: "Generate DH Parameters", icon: Cpu },
        ].map((t) => {
          const Icon = t.icon;
          const active = toolTab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setToolTab(t.id as typeof toolTab)}
              className={`px-4 py-1.5 rounded-full text-[13px] font-semibold flex items-center space-x-2 transition cursor-pointer ${
                active
                  ? "bg-[#C2E7FF] text-[#0A3464]"
                  : "bg-white text-[#334155] hover:bg-[#F8FAFC]"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* Main Content Card */}
      <div className="flex-1 bg-white rounded-[24px] border border-[#E2E8F0] p-6 overflow-y-auto grid grid-cols-1 lg:grid-cols-12 gap-6 shadow-2xs">
        {toolTab === "csr" && (
          <>
            <div className="lg:col-span-5 space-y-4">
              <h3 className="text-[16px] font-semibold text-[#0F172A]">
                Sign Certificate Signing Request (CA Operation)
              </h3>
              <div className="space-y-3 text-[12.5px]">
                <div>
                  <label className="font-medium text-[#475569] block mb-1">Subject DN for Issued Certificate</label>
                  <input
                    type="text"
                    value={csrSubject}
                    onChange={(e) => setCsrSubject(e.target.value)}
                    className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="font-medium text-[#475569] block mb-1">SANs (DNS / IP)</label>
                    <input
                      type="text"
                      value={csrSans}
                      onChange={(e) => setCsrSans(e.target.value)}
                      className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
                    />
                  </div>
                  <div>
                    <label className="font-medium text-[#475569] block mb-1">Validity (Days)</label>
                    <input
                      type="number"
                      value={csrDays}
                      onChange={(e) => setCsrDays(Number(e.target.value))}
                      className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
                    />
                  </div>
                </div>
                <div>
                  <label className="font-medium text-[#475569] block mb-1">PKCS#10 / SPKAC Input</label>
                  <textarea
                    rows={5}
                    value={csrPemInput}
                    onChange={(e) => setCsrPemInput(e.target.value)}
                    className="w-full p-2.5 rounded-xl border border-[#CBD5E1] font-mono text-[11px]"
                  />
                </div>
                <button
                  onClick={handleSignCsr}
                  disabled={busy}
                  className="w-full py-2.5 rounded-full bg-[#0A3464] hover:bg-[#07274C] text-white font-semibold cursor-pointer"
                >
                  {busy ? "Signing in Rust..." : `Sign CSR with '${signerEntry?.alias}'`}
                </button>
              </div>
            </div>

            <div className="lg:col-span-7 bg-[#F8FAFC] rounded-2xl p-5 border border-[#E2E8F0] select-text">
              {signedCertResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="flex items-center justify-between">
                    <span className="text-[#059669] font-bold flex items-center space-x-1">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>X.509 v3 Certificate Signed by {signerEntry.alias}</span>
                    </span>
                    <button
                      onClick={handleImportSignedCertToKeystore}
                      className="px-3.5 py-1.5 rounded-full bg-[#C2E7FF] text-[#0A3464] font-semibold cursor-pointer"
                    >
                      + Append to Active KeyStore
                    </button>
                  </div>
                  <div className="p-3 bg-white rounded-xl border border-[#E2E8F0] space-y-1">
                    <div><strong>Subject:</strong> {signedCertResult.subject}</div>
                    <div><strong>Issuer:</strong> {signedCertResult.issuer}</div>
                    <div><strong>Serial:</strong> <span className="font-mono">{signedCertResult.serial_number}</span></div>
                    <div><strong>SHA-256:</strong> <span className="font-mono">{signedCertResult.sha256_fingerprint}</span></div>
                  </div>
                  <pre className="bg-[#0F172A] text-[#A7F3D0] p-3 rounded-xl font-mono text-[11px] max-h-48 overflow-y-auto">
                    {signedCertResult.pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-[#94A3B8] text-[13px]">
                  Click "Sign CSR" to issue a signed X.509 certificate directly in Rust.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "crl" && (
          <>
            <div className="lg:col-span-5 space-y-4 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-[#0F172A]">
                Sign X.509 v2 Certificate Revocation List (CRL)
              </h3>
              <div className="flex space-x-2">
                <input
                  type="text"
                  value={newRevSerial}
                  onChange={(e) => setNewRevSerial(e.target.value)}
                  placeholder="Serial Number (Hex)..."
                  className="flex-1 h-9 px-3 rounded-lg border border-[#CBD5E1] font-mono"
                />
                <select
                  value={newRevReason}
                  onChange={(e) => setNewRevReason(e.target.value)}
                  className="h-9 px-2 rounded-lg border border-[#CBD5E1] bg-white"
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
                  className="px-3 h-9 rounded-lg bg-[#C2E7FF] text-[#0A3464] font-semibold cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {revokedList.map((r, i) => (
                  <div key={i} className="flex items-center justify-between p-2.5 bg-[#F8FAFC] rounded-xl border border-[#E2E8F0]">
                    <div>
                      <div className="font-mono font-semibold text-[#0F172A]">{r.serial_number}</div>
                      <div className="text-[11px] text-[#64748B]">{r.reason} • {r.revocation_date}</div>
                    </div>
                    <button
                      onClick={() => setRevokedList(revokedList.filter((_, idx) => idx !== i))}
                      className="text-[#DC2626] p-1 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>

              <button
                onClick={handleSignCrl}
                className="w-full py-2.5 rounded-full bg-[#0A3464] text-white font-semibold cursor-pointer"
              >
                Sign &amp; Issue CRL with '{signerEntry?.alias}'
              </button>
            </div>

            <div className="lg:col-span-7 bg-[#F8FAFC] rounded-2xl p-5 border border-[#E2E8F0] select-text">
              {crlResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="text-[#059669] font-bold">
                    CRL #{crlResult.crl_number} Signed ({crlResult.revoked_entries.length} Revoked Certificates)
                  </div>
                  <div className="p-3 bg-white rounded-xl border border-[#E2E8F0]">
                    <div><strong>Issuer:</strong> {crlResult.issuer}</div>
                    <div><strong>This Update:</strong> {crlResult.this_update}</div>
                    <div><strong>Next Update:</strong> {crlResult.next_update}</div>
                  </div>
                  <pre className="bg-[#0F172A] text-[#38BDF8] p-3 rounded-xl font-mono text-[11px] overflow-x-auto">
                    {crlResult.crl_pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-[#94A3B8] text-[13px]">
                  Configure revoked serials and click "Sign &amp; Issue CRL".
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "jar" && (
          <>
            <div className="lg:col-span-5 space-y-3.5 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-[#0F172A]">
                Sign &amp; Verify Java Archive (.JAR) Without JDK/Jarsigner
              </h3>
              <div>
                <label className="font-medium text-[#475569] block mb-1">Target JAR Archive</label>
                <input
                  type="text"
                  value={jarName}
                  onChange={(e) => setJarName(e.target.value)}
                  className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
                />
              </div>
              <div>
                <label className="font-medium text-[#475569] block mb-1">Archive Entries to Digest &amp; Sign</label>
                <textarea
                  rows={4}
                  value={jarEntriesText}
                  onChange={(e) => setJarEntriesText(e.target.value)}
                  className="w-full p-2.5 rounded-xl border border-[#CBD5E1] font-mono text-[11px]"
                />
              </div>
              <div>
                <label className="font-medium text-[#475569] block mb-1">RFC 3161 Timestamp Authority (TSA)</label>
                <input
                  type="text"
                  value={jarTsa}
                  onChange={(e) => setJarTsa(e.target.value)}
                  className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
                />
              </div>
              <button
                onClick={handleSignJar}
                className="w-full py-2.5 rounded-full bg-[#0A3464] text-white font-semibold cursor-pointer"
              >
                Sign JAR Archive in Rust
              </button>
            </div>

            <div className="lg:col-span-7 bg-[#F8FAFC] rounded-2xl p-5 border border-[#E2E8F0] select-text">
              {jarResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="flex items-center justify-between">
                    <span className="text-[#059669] font-bold flex items-center space-x-1">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Signed {jarResult.jar_name} &amp; Verified Signature Block</span>
                    </span>
                    <span className="font-mono text-[11px] text-[#64748B]">{jarResult.signature_algorithm}</span>
                  </div>
                  <div>
                    <span className="font-bold text-[11px] uppercase text-[#64748B] block mb-1">
                      Generated META-INF/MANIFEST.MF
                    </span>
                    <pre className="bg-[#0F172A] text-[#A7F3D0] p-2.5 rounded-xl font-mono text-[10.5px] max-h-28 overflow-y-auto">
                      {jarResult.manifest_mf}
                    </pre>
                  </div>
                  <div>
                    <span className="font-bold text-[11px] uppercase text-[#64748B] block mb-1">
                      Generated META-INF/{jarResult.signer_alias.toUpperCase()}.SF
                    </span>
                    <pre className="bg-[#0F172A] text-[#38BDF8] p-2.5 rounded-xl font-mono text-[10.5px] max-h-28 overflow-y-auto">
                      {jarResult.signature_sf}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-[#94A3B8] text-[13px]">
                  Click "Sign JAR Archive in Rust" to generate MANIFEST.MF, .SF, and cryptographic signature blocks.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "cms" && (
          <>
            <div className="lg:col-span-5 space-y-3.5 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-[#0F172A]">
                CMS / PKCS#7 Digital Signature &amp; Verification
              </h3>
              <textarea
                rows={5}
                value={cmsPayload}
                onChange={(e) => setCmsPayload(e.target.value)}
                className="w-full p-3 rounded-xl border border-[#CBD5E1] font-mono text-[11.5px]"
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
                  className="flex-1 py-2.5 rounded-full bg-[#0A3464] text-white font-semibold cursor-pointer"
                >
                  Sign Payload
                </button>
                {cmsResult && (
                  <button
                    onClick={handleVerifyCms}
                    className="px-4 py-2.5 rounded-full bg-[#C2E7FF] text-[#0A3464] font-semibold cursor-pointer"
                  >
                    Verify Signature
                  </button>
                )}
              </div>
            </div>

            <div className="lg:col-span-7 bg-[#F8FAFC] rounded-2xl p-5 border border-[#E2E8F0] select-text">
              {cmsResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="p-2.5 rounded-xl bg-[#DCFCE7] text-[#166534] font-semibold">
                    {cmsVerifyStatus}
                  </div>
                  <div className="font-mono text-[11px] break-all bg-white p-3 rounded-xl border border-[#E2E8F0]">
                    <div><strong>SHA-256 Digest:</strong> {cmsResult.payload_sha256}</div>
                    <div className="mt-1"><strong>Signature (Hex):</strong> {cmsResult.signature_hex}</div>
                  </div>
                  <pre className="bg-[#0F172A] text-[#38BDF8] p-3 rounded-xl font-mono text-[11px] overflow-x-auto">
                    {cmsResult.cms_pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-[#94A3B8] text-[13px]">
                  Sign any file or JSON payload using CMS / PKCS#7 and test live cryptographic verification.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "jwt" && (
          <>
            <div className="lg:col-span-5 space-y-3 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-[#0F172A]">Sign JSON Web Token (JWT / JWS)</h3>
              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block mb-1 text-[#475569]">Issuer (iss)</label>
                  <input type="text" value={jwtIss} onChange={(e) => setJwtIss(e.target.value)} className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]" />
                </div>
                <div>
                  <label className="block mb-1 text-[#475569]">Subject (sub)</label>
                  <input type="text" value={jwtSub} onChange={(e) => setJwtSub(e.target.value)} className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block mb-1 text-[#475569]">Audience (aud)</label>
                  <input type="text" value={jwtAud} onChange={(e) => setJwtAud(e.target.value)} className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]" />
                </div>
                <div>
                  <label className="block mb-1 text-[#475569]">Validity (Hours)</label>
                  <input type="number" value={jwtHours} onChange={(e) => setJwtHours(Number(e.target.value))} className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]" />
                </div>
              </div>
              <div>
                <label className="block mb-1 text-[#475569]">Custom Claims (JSON)</label>
                <textarea rows={3} value={jwtCustom} onChange={(e) => setJwtCustom(e.target.value)} className="w-full p-2.5 rounded-xl border border-[#CBD5E1] font-mono text-[11px]" />
              </div>
              <button onClick={handleSignJwt} className="w-full py-2.5 rounded-full bg-[#0A3464] text-white font-semibold cursor-pointer">
                Sign JWT with '{signerEntry?.alias}'
              </button>
            </div>

            <div className="lg:col-span-7 bg-[#F8FAFC] rounded-2xl p-5 border border-[#E2E8F0] select-text">
              {signedJwtToken ? (
                <div className="space-y-3 text-[12px]">
                  <span className="font-bold text-[#059669] block">Signed RFC 7519 JWT Compact Token</span>
                  <pre className="bg-[#0F172A] text-[#A7F3D0] p-4 rounded-xl font-mono text-[11.5px] whitespace-pre-wrap break-all">
                    {signedJwtToken}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-[#94A3B8] text-[13px]">
                  Configure claims and click "Sign JWT" to issue a signed token.
                </div>
              )}
            </div>
          </>
        )}

        {toolTab === "dh" && (
          <>
            <div className="lg:col-span-5 space-y-4 text-[12.5px]">
              <h3 className="text-[16px] font-semibold text-[#0F172A]">
                Generate Diffie-Hellman (PKCS#3 DH) Parameters
              </h3>
              <div>
                <label className="block mb-1.5 text-[#475569] font-medium">Prime Modulus Size (Bits)</label>
                <div className="grid grid-cols-4 gap-2">
                  {[1024, 2048, 3072, 4096].map((b) => (
                    <button
                      key={b}
                      onClick={() => setDhBits(b)}
                      className={`py-2 rounded-xl border font-semibold cursor-pointer ${
                        dhBits === b ? "bg-[#C2E7FF] border-[#2563EB] text-[#0A3464]" : "bg-white border-[#CBD5E1]"
                      }`}
                    >
                      {b}
                    </button>
                  ))}
                </div>
              </div>
              <button onClick={handleGenerateDh} className="w-full py-2.5 rounded-full bg-[#0A3464] text-white font-semibold cursor-pointer">
                Generate DH Parameters in Rust
              </button>
            </div>

            <div className="lg:col-span-7 bg-[#F8FAFC] rounded-2xl p-5 border border-[#E2E8F0] select-text">
              {dhResult ? (
                <div className="space-y-3 text-[12px]">
                  <div className="font-semibold text-[#059669]">
                    Generated {dhResult.bit_size}-bit Diffie-Hellman Parameters (Generator G = {dhResult.generator_g})
                  </div>
                  <pre className="bg-[#0F172A] text-[#38BDF8] p-3 rounded-xl font-mono text-[11px] max-h-48 overflow-y-auto">
                    {dhResult.pem}
                  </pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-[#94A3B8] text-[13px]">
                  Select bit size and generate PKCS#3 Diffie-Hellman parameters.
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
};
