import React, { useState } from "react";
import { Cloud, Lock, ShieldCheck, CheckCircle2, ArrowRight, RefreshCw, KeyRound, Globe } from "lucide-react";

export const CloudSyncView: React.FC = () => {
  const [selectedVault, setSelectedVault] = useState("aws");
  const [syncStatus, setSyncStatus] = useState<string | null>(null);
  const [acmeDomain, setAcmeDomain] = useState("api.example.com");
  const [acmeChallenge, setAcmeChallenge] = useState("dns-01");
  const [acmeStep, setAcmeStep] = useState<number>(0);

  const handleSync = (vaultName: string) => {
    setSyncStatus(`Syncing keys with ${vaultName}...`);
    setTimeout(() => {
      setSyncStatus(`Successfully synchronized 4 keys with ${vaultName}. TLS handshakes verified.`);
    }, 1200);
  };

  const handleRunAcme = () => {
    setAcmeStep(1);
    setTimeout(() => {
      setAcmeStep(2);
      setTimeout(() => {
        setAcmeStep(3);
      }, 1000);
    }, 1000);
  };

  return (
    <div className="flex-1 flex flex-col p-6 overflow-hidden">
      {/* View Header */}
      <div className="flex items-center justify-between pb-4 border-b border-[#E2E8F0]">
        <div>
          <h2 className="text-[20px] font-semibold text-[#1E293B]">Cloud Key Vaults & ACME Provisioning</h2>
          <p className="text-[13px] text-[#64748B]">
            Sync certificates with AWS KMS, Azure Key Vault, HashiCorp Vault, and issue automated Let's Encrypt certificates.
          </p>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-12 gap-6 pt-5 overflow-hidden">
        {/* Left Column: Cloud Vault Providers (6 cols) */}
        <div className="col-span-6 bg-white border border-[#E2E8F0] rounded-2xl p-5 flex flex-col justify-between shadow-xs overflow-y-auto">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[#64748B] block mb-3">
              Cloud Secret & Key Vault Sync (FR 3.1)
            </span>

            <div className="grid grid-cols-2 gap-3">
              {[
                { id: "aws", name: "AWS KMS / Secrets", region: "us-east-1", count: 4 },
                { id: "azure", name: "Azure Key Vault", region: "eastus2", count: 2 },
                { id: "hashi", name: "HashiCorp Vault", region: "vault.internal:8200", count: 6 },
                { id: "gcp", name: "Google Secret Manager", region: "global", count: 3 },
              ].map((v) => (
                <div
                  key={v.id}
                  onClick={() => setSelectedVault(v.id)}
                  className={`p-3.5 rounded-xl border transition cursor-pointer ${
                    selectedVault === v.id
                      ? "border-[#2563EB] bg-[#EFF6FF]"
                      : "border-[#E2E8F0] bg-white hover:bg-[#F8FAFC]"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <Cloud className="w-4 h-4 text-[#2563EB]" />
                    <span className="text-[11px] font-mono text-[#64748B]">{v.count} Keys</span>
                  </div>
                  <h4 className="text-[13.5px] font-semibold text-[#0F172A]">{v.name}</h4>
                  <span className="text-[11px] text-[#64748B]">{v.region}</span>
                </div>
              ))}
            </div>

            <div className="mt-4 p-3.5 bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl space-y-2">
              <span className="text-[12px] font-semibold text-[#1E293B] block">
                Synchronize Local Keystores to Remote Vault
              </span>
              <p className="text-[11.5px] text-[#64748B] leading-relaxed">
                Certificates and private keys are encrypted client-side using native OS Keychain and exported over TLS 1.3 to your target cloud vault.
              </p>
              <button
                onClick={() => handleSync(selectedVault.toUpperCase())}
                className="w-full py-2 bg-[#0A3464] hover:bg-[#07274C] text-white text-[12px] font-medium rounded-lg transition cursor-pointer"
              >
                Push Keys to {selectedVault.toUpperCase()}
              </button>
            </div>

            {syncStatus && (
              <div className="mt-3 p-2.5 bg-[#DCFCE7] border border-[#86EFAC] rounded-lg text-[11.5px] text-[#166534] flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{syncStatus}</span>
              </div>
            )}
          </div>

          <div className="pt-2 text-[11px] font-mono text-[#64748B]">
            Zero credentials logged or persisted locally.
          </div>
        </div>

        {/* Right Column: Automated ACME Provisioning (6 cols) */}
        <div className="col-span-6 bg-white border border-[#E2E8F0] rounded-2xl p-5 flex flex-col justify-between shadow-xs overflow-y-auto">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[#64748B] block mb-3">
              Automated ACME Client (Let's Encrypt / ZeroSSL) (FR 3.2)
            </span>

            <div className="space-y-3">
              <div>
                <label className="text-[11.5px] font-medium text-[#475569] block mb-1">
                  Domain Names (SANs)
                </label>
                <input
                  type="text"
                  value={acmeDomain}
                  onChange={(e) => setAcmeDomain(e.target.value)}
                  className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[12.5px] focus:outline-none focus:border-[#2563EB]"
                />
              </div>

              <div>
                <label className="text-[11.5px] font-medium text-[#475569] block mb-1">
                  Challenge Type
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {["dns-01", "http-01"].map((ch) => (
                    <button
                      key={ch}
                      type="button"
                      onClick={() => setAcmeChallenge(ch)}
                      className={`py-1.5 text-[12px] font-medium rounded-lg border transition cursor-pointer ${
                        acmeChallenge === ch
                          ? "bg-[#EFF6FF] border-[#2563EB] text-[#1D4ED8]"
                          : "bg-white border-[#CBD5E1] text-[#475569]"
                      }`}
                    >
                      {ch.toUpperCase()} Challenge
                    </button>
                  ))}
                </div>
              </div>

              <button
                onClick={handleRunAcme}
                className="w-full py-2 bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-[12.5px] font-medium rounded-lg transition cursor-pointer flex items-center justify-center space-x-1.5"
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Request Signed Certificate via ACME</span>
              </button>
            </div>

            {/* ACME Steps Pipeline */}
            <div className="mt-4 pt-3 border-t border-[#E2E8F0] space-y-2">
              <span className="text-[11.5px] font-bold uppercase tracking-wider text-[#475569] block">
                Provisioning Status
              </span>

              <div className="space-y-2 text-[12px]">
                <div className={`flex items-center space-x-2 ${acmeStep >= 1 ? "text-[#166534]" : "text-[#94A3B8]"}`}>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>1. Generate client-side RSA-4096 / Ed25519 CSR</span>
                </div>
                <div className={`flex items-center space-x-2 ${acmeStep >= 2 ? "text-[#166534]" : "text-[#94A3B8]"}`}>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>2. Publish {acmeChallenge.toUpperCase()} Challenge Token to Let's Encrypt</span>
                </div>
                <div className={`flex items-center space-x-2 ${acmeStep >= 3 ? "text-[#166534]" : "text-[#94A3B8]"}`}>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>3. Fetch Signed Production Certificate into CertForge Store</span>
                </div>
              </div>
            </div>
          </div>

          <div className="p-2.5 bg-[#0F172A] text-[#38BDF8] font-mono text-[10.5px] rounded-lg overflow-x-auto mt-4">
            <code>certbot certonly --standalone -d {acmeDomain} --preferred-challenges {acmeChallenge}</code>
          </div>
        </div>
      </div>
    </div>
  );
};
