import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { X, FolderPlus, Sparkles } from "lucide-react";
import { KeystoreFile, KeystoreFormat, KeystoreEntry, GenerateKeyPairInput } from "../types/crypto";

interface NewKeystoreModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddKeystore: (ks: KeystoreFile) => void;
  defaultFormat?: KeystoreFormat;
}

export const NewKeystoreModal: React.FC<NewKeystoreModalProps> = ({
  isOpen,
  onClose,
  onAddKeystore,
  defaultFormat = "PKCS12",
}) => {
  const [name, setName] = useState("custom-vault.p12");
  const [format, setFormat] = useState<KeystoreFormat>(defaultFormat);
  const [password, setPassword] = useState("changeit");
  const [initialAlias, setInitialAlias] = useState("default-root-key");
  const [alg, setAlg] = useState("RSA");
  const [busy, setBusy] = useState(false);

  const extMap: Record<KeystoreFormat, string> = {
    PKCS12: ".p12",
    JKS: ".jks",
    JCEKS: ".jceks",
    BKS: ".bks",
    BCFKS: ".bcfks",
    UBER: ".uber",
  };

  useEffect(() => {
    if (isOpen && defaultFormat) {
      setFormat(defaultFormat);
      setName((prev) => {
        const base = prev.replace(/\.[^/.]+$/, "");
        return `${base}${extMap[defaultFormat]}`;
      });
    }
  }, [isOpen, defaultFormat]);

  if (!isOpen) return null;

  const formats: { id: KeystoreFormat; ext: string; desc: string }[] = [
    { id: "PKCS12", ext: ".p12", desc: "RSA PKCS #12 Standard" },
    { id: "JKS", ext: ".jks", desc: "Java KeyStore (0xFEEDFEED)" },
    { id: "JCEKS", ext: ".jceks", desc: "Java Crypto Extension" },
    { id: "BKS", ext: ".bks", desc: "Bouncy Castle KeyStore" },
    { id: "BCFKS", ext: ".bcfks", desc: "Bouncy Castle FIPS 140" },
    { id: "UBER", ext: ".uber", desc: "Bouncy Castle UBER" },
  ];

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const input: GenerateKeyPairInput = {
        alias: initialAlias,
        algorithm: alg,
        key_size: alg === "RSA" ? 4096 : alg === "ML-DSA-65" ? 1952 : 256,
        curve: alg === "ECDSA" ? "secp256r1 (P-256)" : null,
        common_name: `${initialAlias}.xkeystore.internal`,
        organization: "xkeystore KeyStore",
        organizational_unit: "Security Operations",
        locality: "San Francisco",
        state: "CA",
        country: "US",
        email: `admin@xkeystore.internal`,
        validity_days: 1095,
        is_ca: true,
        sans: [`${initialAlias}.xkeystore.internal`],
        key_usage: ["Digital Signature", "Key Cert Sign", "CRL Sign"],
        extended_key_usage: ["TLS Web Server Authentication"],
        signer_alias: null,
        labels: ["Root", format],
      };

      const entry = await invoke<KeystoreEntry>("generate_keypair_entry", {
        input,
        issuerDn: null,
      });

      const newKs: KeystoreFile = {
        id: "ks-" + Date.now(),
        name,
        format,
        path: `/Users/local/vaults/${name}`,
        description: `${format} KeyStore created with native Rust cryptography`,
        password_protected: Boolean(password),
        created_at: new Date().toISOString().split("T")[0],
        updated_at: "Just now",
        entries: [entry],
      };

      onAddKeystore(newKs);
      onClose();
    } catch (err) {
      alert("Error creating keystore: " + err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
      <div className="w-full max-w-lg bg-white rounded-3xl border border-[#CBD5E1] shadow-2xl p-6 space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-[#E2E8F0]">
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-full bg-[#C2E7FF] text-[#0A3464] flex items-center justify-center">
              <FolderPlus className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-[17px] font-semibold text-[#0F172A]">Create New KeyStore</h3>
              <p className="text-[11.5px] text-[#64748B]">
                Supports all 6 KeyStore Explorer store formats natively in Rust
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 text-[#64748B] hover:text-[#0F172A] cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleCreate} className="space-y-4 text-[12.5px]">
          <div>
            <label className="font-medium text-[#475569] block mb-1.5">Select KeyStore Type</label>
            <div className="grid grid-cols-3 gap-2">
              {formats.map((f) => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => {
                    setFormat(f.id);
                    const base = name.replace(/\.[^/.]+$/, "");
                    setName(`${base}${f.ext}`);
                  }}
                  className={`p-2.5 rounded-xl border text-left transition cursor-pointer ${
                    format === f.id
                      ? "bg-[#EFF6FF] border-[#2563EB] text-[#0A3464]"
                      : "bg-white border-[#CBD5E1] text-[#475569] hover:bg-[#F8FAFC]"
                  }`}
                >
                  <div className="font-bold text-[12.5px]">{f.id}</div>
                  <div className="text-[10.5px] text-[#64748B] truncate">{f.desc}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="font-medium text-[#475569] block mb-1">KeyStore Filename</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
              />
            </div>
            <div>
              <label className="font-medium text-[#475569] block mb-1">Store Passphrase</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="font-medium text-[#475569] block mb-1">Initial Root Key Alias</label>
              <input
                type="text"
                value={initialAlias}
                onChange={(e) => setInitialAlias(e.target.value)}
                required
                className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1]"
              />
            </div>
            <div>
              <label className="font-medium text-[#475569] block mb-1">Initial Key Algorithm</label>
              <select
                value={alg}
                onChange={(e) => setAlg(e.target.value)}
                className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] bg-white"
              >
                <option value="RSA">RSA-4096</option>
                <option value="ECDSA">ECDSA P-256</option>
                <option value="ED25519">Ed25519</option>
                <option value="ML-DSA-65">Post-Quantum ML-DSA-65</option>
              </select>
            </div>
          </div>

          <div className="pt-2 flex justify-end space-x-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-[#475569] hover:bg-[#F1F5F9] rounded-xl cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="px-5 py-2 bg-[#0A3464] hover:bg-[#07274C] text-white font-semibold rounded-full shadow-xs cursor-pointer flex items-center space-x-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{busy ? "Initializing in Rust..." : "Create KeyStore"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
