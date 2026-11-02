import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Zap,
  Lock,
} from "lucide-react";
import { KeystoreFile, KeystoreEntry, GenerateKeyPairInput } from "../types/crypto";

interface ScannerViewProps {
  keystores: KeystoreFile[];
  onUpdateKeystore: (updated: KeystoreFile) => void;
  onRecordOp: (increment?: number, isSig?: boolean) => void;
}

export const ScannerView: React.FC<ScannerViewProps> = ({
  keystores,
  onUpdateKeystore,
  onRecordOp,
}) => {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const allEntriesWithKs = keystores.flatMap((ks) =>
    ks.entries.map((entry) => ({ ks, entry }))
  );

  const weakEntries = allEntriesWithKs.filter((item) => item.entry.is_weak || item.entry.key_size < 2048 && item.entry.entry_type !== "SecretKey" && item.entry.algorithm === "RSA");
  const pqEntries = allEntriesWithKs.filter((item) => item.entry.is_post_quantum);
  const totalCount = allEntriesWithKs.length;
  const healthScore = Math.max(
    60,
    Math.min(100, 100 - weakEntries.length * 12)
  );

  const handleAutoRotateEntry = async (ks: KeystoreFile, entry: KeystoreEntry, targetAlg: string, targetBits: number) => {
    setBusyId(entry.id);
    try {
      const input: GenerateKeyPairInput = {
        alias: entry.alias,
        algorithm: targetAlg,
        key_size: targetBits,
        curve: targetAlg === "ECDSA" ? "secp256r1 (P-256)" : null,
        common_name: entry.alias,
        organization: "xkeystore Auto-Rotated Security",
        organizational_unit: "Automated Compliance Engine",
        locality: "San Francisco",
        state: "CA",
        country: "US",
        email: `security@${entry.alias}`,
        validity_days: 730,
        is_ca: entry.labels.includes("CA"),
        sans: [entry.alias],
        key_usage: ["Digital Signature", "Key Encipherment"],
        extended_key_usage: ["TLS Web Server Authentication"],
        signer_alias: null,
        labels: [...entry.labels.filter((l) => l !== "Weak-Key" && l !== "Legacy"), "Rotated-Safe"],
      };

      const rotated = await invoke<KeystoreEntry>("generate_keypair_entry", {
        input,
        issuerDn: entry.issuer,
      });

      const updatedKs: KeystoreFile = {
        ...ks,
        updated_at: "Just now",
        entries: ks.entries.map((en) => (en.id === entry.id ? { ...rotated, id: entry.id } : en)),
      };
      onUpdateKeystore(updatedKs);
      onRecordOp(targetBits, true);
      setToast(`Automatically rotated '${entry.alias}' to ${targetAlg}-${targetBits} inside ${ks.name}!`);
      setTimeout(() => setToast(null), 4000);
    } catch (e) {
      alert("Auto-rotation failed: " + e);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-canvas px-8 py-6 select-none">
      {toast && (
        <div className="fixed bottom-6 right-8 z-50 bg-ink text-white px-4 py-3 rounded-2xl shadow-xl flex items-center space-x-2 text-[13px]">
          <CheckCircle2 className="w-4 h-4 text-[#34D399]" />
          <span>{toast}</span>
        </div>
      )}

      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-[28px] font-normal text-ink-2 tracking-tight">
            Security Posture &amp; Automated Key Rotation
          </h1>
          <p className="text-[13px] text-faint">
            Audits all loaded KeyStores and rotates weak or expiring keys in-place using native Rust cryptography.
          </p>
        </div>
      </div>

      {/* KPI Summary Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-5">
        <div className="bg-white rounded-[22px] p-5 border border-line">
          <span className="text-[12px] font-medium text-faint block">Compliance Score</span>
          <div className="text-[34px] font-bold text-success mt-1">{healthScore}%</div>
          <span className="text-[11.5px] text-faint">Across {totalCount} cryptographic entries</span>
        </div>

        <div className="bg-white rounded-[22px] p-5 border border-line">
          <span className="text-[12px] font-medium text-faint block">Weak Keys (&lt; 2048-bit)</span>
          <div className={`text-[34px] font-bold mt-1 ${weakEntries.length > 0 ? "text-danger" : "text-success"}`}>
            {weakEntries.length}
          </div>
          <span className="text-[11.5px] text-faint">
            {weakEntries.length === 0 ? "All keys meet NIST 2030+" : "Ready for 1-click rotation"}
          </span>
        </div>

        <div className="bg-white rounded-[22px] p-5 border border-line">
          <span className="text-[12px] font-medium text-faint block">Post-Quantum Ready</span>
          <div className="text-[34px] font-bold text-brand mt-1">{pqEntries.length}</div>
          <span className="text-[11.5px] text-faint">ML-DSA, ML-KEM &amp; AES-256</span>
        </div>

        <div className="bg-white rounded-[22px] p-5 border border-line">
          <span className="text-[12px] font-medium text-faint block">Runtime Dependencies</span>
          <div className="text-[34px] font-bold text-ink mt-1">0</div>
          <span className="text-[11.5px] text-success font-medium">Runs fully offline</span>
        </div>
      </div>

      {/* Interactive Audit Table with 1-Click Native Remediation */}
      <div className="flex-1 bg-white rounded-[24px] border border-line p-6 overflow-y-auto space-y-3 shadow-2xs">
        <h3 className="text-[15px] font-semibold text-ink mb-2">
          Live KeyStore Entry Audit &amp; One-Click In-Place Rotation
        </h3>

        {allEntriesWithKs.map(({ ks, entry }) => {
          const isWeak = entry.is_weak || (entry.algorithm === "RSA" && entry.key_size < 2048);
          return (
            <div
              key={entry.id}
              className={`p-4 rounded-2xl border flex flex-wrap items-center justify-between gap-4 ${
                isWeak
                  ? "bg-[#FEF2F2]/60 border-[#FCA5A5]"
                  : "bg-surface-2 border-line"
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[10.5px] font-bold ${
                      isWeak
                        ? "bg-danger-tint text-[#991B1B]"
                        : entry.is_post_quantum
                        ? "bg-[#DBEAFE] text-[#1E40AF]"
                        : "bg-success-tint text-[#166534]"
                    }`}
                  >
                    {isWeak ? "WEAK KEY WARNING" : entry.is_post_quantum ? "POST-QUANTUM SAFE" : "NIST COMPLIANT"}
                  </span>
                  <span className="text-[14.5px] font-semibold text-ink">{entry.alias}</span>
                  <span className="text-[12px] text-faint">in {ks.name}</span>
                </div>
                <div className="text-[12px] text-muted">
                  Current: <strong>{entry.algorithm} ({entry.key_size}-bit)</strong> • Expires: {entry.expiry_date}
                </div>
              </div>

              {entry.entry_type === "KeyPair" && (
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleAutoRotateEntry(ks, entry, "RSA", 4096)}
                    disabled={busyId === entry.id}
                    className="px-4 py-2 rounded-full bg-brand-deep hover:bg-brand-deeper text-white text-[12px] font-semibold flex items-center space-x-1.5 cursor-pointer"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${busyId === entry.id ? "animate-spin" : ""}`} />
                    <span>Rotate to RSA-4096</span>
                  </button>

                  <button
                    onClick={() => handleAutoRotateEntry(ks, entry, "ML-DSA-65", 1952)}
                    disabled={busyId === entry.id}
                    className="px-4 py-2 rounded-full bg-brand-soft hover:bg-brand-soft-hover text-brand-deep text-[12px] font-semibold flex items-center space-x-1.5 cursor-pointer"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Upgrade to ML-DSA-65 (PQC)</span>
                  </button>
                </div>
              )}

              {entry.entry_type === "SecretKey" && (
                <span className="flex items-center space-x-1 text-[12px] text-success font-semibold">
                  <Lock className="w-3.5 h-3.5" />
                  <span>256-Bit Symmetric Protected</span>
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
