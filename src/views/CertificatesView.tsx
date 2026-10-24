import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { KeyRound, ShieldCheck, Copy, Check, Sparkles, Terminal, FileCode, CheckCircle2 } from "lucide-react";
import { KeyPairResult, CertResult, CertGenRequest } from "../types/crypto";

export const CertificatesView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<"keypair" | "cert">("keypair");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  // Key Pair State
  const [algorithm, setAlgorithm] = useState("RSA");
  const [keySize, setKeySize] = useState(2048);
  const [keyResult, setKeyResult] = useState<KeyPairResult | null>(null);

  // Cert State
  const [commonName, setCommonName] = useState("api.certforge.internal");
  const [org, setOrg] = useState("CertForge Security Inc");
  const [country, setCountry] = useState("US");
  const [sans, setSans] = useState("api.certforge.internal, localhost, 127.0.0.1");
  const [validityDays, setValidityDays] = useState(365);
  const [isCa, setIsCa] = useState(false);
  const [certResult, setCertResult] = useState<CertResult | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleGenerateKeyPair = async () => {
    setLoading(true);
    try {
      const res = await invoke<KeyPairResult>("generate_key_pair", {
        algorithm,
        keySize: Number(keySize),
        curve: null,
      });
      setKeyResult(res);
    } catch (err) {
      console.error(err);
      alert("Error generating keypair: " + err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateCert = async () => {
    setLoading(true);
    try {
      const req: CertGenRequest = {
        common_name: commonName,
        organization: org,
        organizational_unit: "Platform Security",
        country,
        state: "California",
        locality: "San Francisco",
        sans: sans.split(",").map((s) => s.trim()).filter(Boolean),
        validity_days: Number(validityDays),
        is_ca: isCa,
        algorithm,
        key_size: Number(keySize),
      };
      const res = await invoke<CertResult>("generate_certificate", { request: req });
      setCertResult(res);
    } catch (err) {
      console.error(err);
      alert("Error generating certificate: " + err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 flex flex-col p-6 overflow-hidden">
      {/* View Header with Sub-tabs */}
      <div className="flex items-center justify-between pb-4 border-b border-[#E2E8F0]">
        <div>
          <h2 className="text-[20px] font-semibold text-[#1E293B]">Certificates & Cryptographic Keys</h2>
          <p className="text-[13px] text-[#64748B]">
            Generate RSA, ECC, Ed25519, and NIST Post-Quantum (ML-DSA / ML-KEM) key pairs and X.509 certificates.
          </p>
        </div>

        {/* Sub-tab Pill Switcher */}
        <div className="flex items-center space-x-1 p-1 bg-[#F1F5F9] rounded-xl border border-[#E2E8F0]">
          <button
            onClick={() => setActiveSubTab("keypair")}
            className={`px-3.5 py-1.5 text-[12.5px] font-medium rounded-lg transition cursor-pointer ${
              activeSubTab === "keypair"
                ? "bg-white text-[#0A3464] shadow-xs"
                : "text-[#64748B] hover:text-[#0F172A]"
            }`}
          >
            Key Pair Generator
          </button>
          <button
            onClick={() => setActiveSubTab("cert")}
            className={`px-3.5 py-1.5 text-[12.5px] font-medium rounded-lg transition cursor-pointer ${
              activeSubTab === "cert"
                ? "bg-white text-[#0A3464] shadow-xs"
                : "text-[#64748B] hover:text-[#0F172A]"
            }`}
          >
            X.509 & CSR Studio
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 grid grid-cols-12 gap-6 pt-5 overflow-hidden">
        {/* Left Form (5 cols) */}
        <div className="col-span-5 bg-white border border-[#E2E8F0] rounded-2xl p-5 flex flex-col justify-between overflow-y-auto shadow-xs">
          {activeSubTab === "keypair" ? (
            <div className="space-y-4">
              <h3 className="text-[15px] font-semibold text-[#0F172A]">Algorithm & Strength</h3>

              <div>
                <label className="text-[12px] font-medium text-[#475569] block mb-1.5">
                  Cryptographic Algorithm
                </label>
                <select
                  value={algorithm}
                  onChange={(e) => setAlgorithm(e.target.value)}
                  className="w-full h-10 px-3 rounded-lg border border-[#CBD5E1] bg-white text-[13px] text-[#0F172A] focus:outline-none focus:border-[#2563EB]"
                >
                  <option value="RSA">RSA (Rivest–Shamir–Adleman)</option>
                  <option value="ECDSA">ECDSA (P-256 Curve)</option>
                  <option value="ED25519">Ed25519 (Edwards Curve)</option>
                  <option value="ML-DSA-65">Post-Quantum: ML-DSA-65 (NIST FIPS 204 Dilithium)</option>
                  <option value="ML-KEM-768">Post-Quantum: ML-KEM-768 (NIST FIPS 203 Kyber)</option>
                </select>
              </div>

              {algorithm === "RSA" && (
                <div>
                  <label className="text-[12px] font-medium text-[#475569] block mb-1.5">
                    RSA Modulus Size (Bits)
                  </label>
                  <div className="grid grid-cols-4 gap-2">
                    {[1024, 2048, 4096, 8192].map((size) => (
                      <button
                        key={size}
                        type="button"
                        onClick={() => setKeySize(size)}
                        className={`py-2 text-[12px] font-medium rounded-lg border transition cursor-pointer ${
                          keySize === size
                            ? "bg-[#EFF6FF] border-[#2563EB] text-[#1D4ED8]"
                            : "bg-white border-[#CBD5E1] text-[#475569] hover:bg-[#F8FAFC]"
                        }`}
                      >
                        {size}
                      </button>
                    ))}
                  </div>
                  {keySize < 2048 && (
                    <p className="mt-1 text-[11px] text-[#DC2626]">
                      * Warning: 1024-bit RSA is considered cryptographically insecure.
                    </p>
                  )}
                </div>
              )}

              <div className="p-3.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl text-[12px] text-[#475569] space-y-1">
                <div className="flex items-center space-x-1.5 font-medium text-[#0A3464]">
                  <Sparkles className="w-3.5 h-3.5 text-[#2563EB]" />
                  <span>Hardware & OS Security</span>
                </div>
                <p className="text-[11.5px] leading-relaxed">
                  Keys are generated using the native Rust cryptographic entropy pool. Zero cloud transmission.
                </p>
              </div>

              <button
                onClick={handleGenerateKeyPair}
                disabled={loading}
                className="w-full py-2.5 rounded-xl bg-[#0A3464] hover:bg-[#08284D] active:scale-[0.99] text-white text-[13px] font-medium shadow-xs transition flex items-center justify-center space-x-2 cursor-pointer"
              >
                {loading ? (
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <KeyRound className="w-4 h-4" />
                    <span>Generate Cryptographic Keypair</span>
                  </>
                )}
              </button>
            </div>
          ) : (
            <div className="space-y-3.5">
              <h3 className="text-[15px] font-semibold text-[#0F172A]">X.509 Subject & SANs</h3>

              <div>
                <label className="text-[11.5px] font-medium text-[#475569] block mb-1">
                  Common Name (CN)
                </label>
                <input
                  type="text"
                  value={commonName}
                  onChange={(e) => setCommonName(e.target.value)}
                  className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[12.5px] focus:outline-none focus:border-[#2563EB]"
                />
              </div>

              <div>
                <label className="text-[11.5px] font-medium text-[#475569] block mb-1">
                  Organization (O)
                </label>
                <input
                  type="text"
                  value={org}
                  onChange={(e) => setOrg(e.target.value)}
                  className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[12.5px] focus:outline-none focus:border-[#2563EB]"
                />
              </div>

              <div>
                <label className="text-[11.5px] font-medium text-[#475569] block mb-1">
                  Subject Alternative Names (Comma Separated)
                </label>
                <input
                  type="text"
                  value={sans}
                  onChange={(e) => setSans(e.target.value)}
                  className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[12.5px] focus:outline-none focus:border-[#2563EB]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11.5px] font-medium text-[#475569] block mb-1">
                    Validity (Days)
                  </label>
                  <input
                    type="number"
                    value={validityDays}
                    onChange={(e) => setValidityDays(Number(e.target.value))}
                    className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[12.5px] focus:outline-none focus:border-[#2563EB]"
                  />
                </div>
                <div>
                  <label className="text-[11.5px] font-medium text-[#475569] block mb-1">
                    Country (C)
                  </label>
                  <input
                    type="text"
                    value={country}
                    onChange={(e) => setCountry(e.target.value)}
                    className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[12.5px] focus:outline-none focus:border-[#2563EB]"
                  />
                </div>
              </div>

              <div className="flex items-center space-x-2 pt-1">
                <input
                  type="checkbox"
                  id="caCheckbox"
                  checked={isCa}
                  onChange={(e) => setIsCa(e.target.checked)}
                  className="w-4 h-4 text-[#2563EB] rounded cursor-pointer"
                />
                <label htmlFor="caCheckbox" className="text-[12px] text-[#334155] cursor-pointer">
                  Act as Certificate Authority (Set Basic Constraints CA=True)
                </label>
              </div>

              <button
                onClick={handleGenerateCert}
                disabled={loading}
                className="w-full py-2.5 rounded-xl bg-[#0A3464] hover:bg-[#08284D] text-white text-[13px] font-medium shadow-xs transition flex items-center justify-center space-x-2 cursor-pointer mt-2"
              >
                {loading ? (
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    <span>Issue Self-Signed X.509 Certificate</span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>

        {/* Right Output & CLI Display (7 cols) */}
        <div className="col-span-7 bg-[#F8FAFC] border border-[#E2E8F0] rounded-2xl p-5 flex flex-col justify-between overflow-y-auto shadow-xs select-text">
          {activeSubTab === "keypair" ? (
            keyResult ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[11px] font-bold uppercase tracking-wider text-[#059669] flex items-center space-x-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Keypair Generated Successfully</span>
                    </span>
                    <h4 className="text-[16px] font-semibold text-[#0F172A] mt-0.5">
                      {keyResult.algorithm} ({keyResult.key_size} bits)
                    </h4>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => copyToClipboard(keyResult.public_key_pem, "pub")}
                      className="px-2.5 py-1 text-[11px] bg-white border border-[#CBD5E1] rounded-md hover:bg-[#F1F5F9] cursor-pointer"
                    >
                      {copied === "pub" ? "Copied Pub" : "Copy Public Key"}
                    </button>
                    <button
                      onClick={() => copyToClipboard(keyResult.private_key_pem, "priv")}
                      className="px-2.5 py-1 text-[11px] bg-white border border-[#CBD5E1] rounded-md hover:bg-[#F1F5F9] cursor-pointer"
                    >
                      {copied === "priv" ? "Copied Priv" : "Copy Private Key"}
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-[#64748B] block mb-1">Public Key (PEM)</span>
                  <div className="bg-[#0F172A] text-[#E2E8F0] font-mono text-[11px] p-3 rounded-xl max-h-36 overflow-y-auto">
                    <pre>{keyResult.public_key_pem}</pre>
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-[#64748B] block mb-1">SHA-256 Fingerprint</span>
                  <div className="bg-white border border-[#CBD5E1] font-mono text-[11px] text-[#334155] p-2 rounded-lg">
                    {keyResult.fingerprint_sha256}
                  </div>
                </div>

                {/* Show CLI Engine (FR 2.3) */}
                <div className="pt-2 border-t border-[#E2E8F0]">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center space-x-1.5 text-[#2563EB] text-[11.5px] font-bold uppercase">
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Equivalent CLI Command</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(keyResult.cli_command, "cli")}
                      className="text-[11px] text-[#2563EB] hover:underline cursor-pointer"
                    >
                      {copied === "cli" ? "Copied!" : "Copy Command"}
                    </button>
                  </div>
                  <div className="bg-[#0F172A] text-[#38BDF8] font-mono text-[11px] p-3 rounded-lg overflow-x-auto">
                    <code>{keyResult.cli_command}</code>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-[#94A3B8] text-center p-8">
                <KeyRound className="w-10 h-10 mb-2 stroke-[1.5] text-[#CBD5E1]" />
                <span className="text-[14px] font-medium text-[#64748B]">No Keypair Generated Yet</span>
                <p className="text-[12px] max-w-sm mt-1">
                  Select your desired cryptographic parameters on the left and click Generate to produce client-side keys and OpenSSL commands.
                </p>
              </div>
            )
          ) : certResult ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-[11px] font-bold uppercase tracking-wider text-[#059669] flex items-center space-x-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>X.509 Certificate Issued</span>
                  </span>
                  <h4 className="text-[15px] font-semibold text-[#0F172A] mt-0.5">
                    {certResult.subject}
                  </h4>
                </div>
                <button
                  onClick={() => copyToClipboard(certResult.certificate_pem, "cert")}
                  className="px-2.5 py-1 text-[11px] bg-white border border-[#CBD5E1] rounded-md hover:bg-[#F1F5F9] cursor-pointer"
                >
                  {copied === "cert" ? "Copied Cert" : "Copy Certificate PEM"}
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3 text-[11.5px]">
                <div className="p-2.5 bg-white border border-[#E2E8F0] rounded-lg">
                  <span className="text-[#64748B] block text-[10.5px]">Valid From</span>
                  <span className="font-mono text-[#0F172A]">{certResult.valid_from}</span>
                </div>
                <div className="p-2.5 bg-white border border-[#E2E8F0] rounded-lg">
                  <span className="text-[#64748B] block text-[10.5px]">Valid To</span>
                  <span className="font-mono text-[#0F172A]">{certResult.valid_to}</span>
                </div>
              </div>

              <div>
                <span className="text-[11px] text-[#64748B] block mb-1">Certificate PEM (Base64 X.509)</span>
                <div className="bg-[#0F172A] text-[#E2E8F0] font-mono text-[10.5px] p-3 rounded-xl max-h-32 overflow-y-auto">
                  <pre>{certResult.certificate_pem}</pre>
                </div>
              </div>

              {/* Show CLI Engine */}
              <div className="pt-2 border-t border-[#E2E8F0]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-bold uppercase text-[#2563EB]">
                    CLI Command
                  </span>
                  <button
                    onClick={() => copyToClipboard(certResult.cli_command, "certcli")}
                    className="text-[11px] text-[#2563EB] hover:underline cursor-pointer"
                  >
                    {copied === "certcli" ? "Copied" : "Copy"}
                  </button>
                </div>
                <div className="bg-[#0F172A] text-[#38BDF8] font-mono text-[10.5px] p-2.5 rounded-lg overflow-x-auto">
                  <code>{certResult.cli_command}</code>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-[#94A3B8] text-center p-8">
              <ShieldCheck className="w-10 h-10 mb-2 stroke-[1.5] text-[#CBD5E1]" />
              <span className="text-[14px] font-medium text-[#64748B]">No Certificate Generated Yet</span>
              <p className="text-[12px] max-w-sm mt-1">
                Configure your Subject DN, SANs, and validity period to issue a self-signed certificate or CSR.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
