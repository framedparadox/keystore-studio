import React, { useState } from "react";
import { X, FolderPlus, KeyRound, Sparkles, Check } from "lucide-react";
import { KeystoreFile } from "../types/crypto";

interface NewKeystoreModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddKeystore: (ks: KeystoreFile) => void;
}

export const NewKeystoreModal: React.FC<NewKeystoreModalProps> = ({
  isOpen,
  onClose,
  onAddKeystore,
}) => {
  const [filename, setFilename] = useState("app-vault.p12");
  const [format, setFormat] = useState<"PKCS12" | "JKS" | "BCFKS">("PKCS12");
  const [password, setPassword] = useState("");
  const [initialAlias, setInitialAlias] = useState("service-tls");

  if (!isOpen) return null;

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    const newKs: KeystoreFile = {
      id: "ks-" + Date.now(),
      filename,
      format,
      path: `/local/vaults/${filename}`,
      totalEntries: 1,
      entries: [
        {
          alias: initialAlias,
          type: "PrivateKeyEntry",
          algorithm: "RSA",
          keySize: 4096,
          creationDate: new Date().toISOString().split("T")[0],
          expiryDate: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString().split("T")[0],
          subject: `CN=${initialAlias}.internal, O=CertForge, C=US`,
          issuer: `CN=${initialAlias}.internal, O=CertForge, C=US`,
          sha256Fingerprint: "B8:10:99:AA:44:EE:31:00:88:21:44:90:55:12:DE:09",
          chainLength: 1,
        },
      ],
    };

    onAddKeystore(newKs);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-white rounded-2xl border border-[#CBD5E1] shadow-2xl p-6 flex flex-col space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-full bg-[#EFF6FF] text-[#2563EB] flex items-center justify-center">
              <FolderPlus className="w-4 h-4" />
            </div>
            <h3 className="text-[17px] font-semibold text-[#0F172A]">Create New Keystore</h3>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 rounded-full text-[#64748B] hover:text-[#0F172A] hover:bg-[#F1F5F9] flex items-center justify-center cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleCreate} className="space-y-3.5">
          <div>
            <label className="text-[12px] font-medium text-[#475569] block mb-1">
              Keystore Filename
            </label>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              required
              className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[13px] focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div>
            <label className="text-[12px] font-medium text-[#475569] block mb-1">
              Store Format
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(["PKCS12", "JKS", "BCFKS"] as const).map((fmt) => (
                <button
                  key={fmt}
                  type="button"
                  onClick={() => {
                    setFormat(fmt);
                    if (fmt === "JKS") setFilename(filename.replace(/\.[^/.]+$/, ".jks"));
                    if (fmt === "PKCS12") setFilename(filename.replace(/\.[^/.]+$/, ".p12"));
                    if (fmt === "BCFKS") setFilename(filename.replace(/\.[^/.]+$/, ".bcfks"));
                  }}
                  className={`py-1.5 text-[12px] font-medium rounded-lg border transition cursor-pointer ${
                    format === fmt
                      ? "bg-[#EFF6FF] border-[#2563EB] text-[#1D4ED8]"
                      : "bg-white border-[#CBD5E1] text-[#475569]"
                  }`}
                >
                  {fmt}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-[12px] font-medium text-[#475569] block mb-1">
              Primary Key Alias
            </label>
            <input
              type="text"
              value={initialAlias}
              onChange={(e) => setInitialAlias(e.target.value)}
              required
              className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[13px] focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div>
            <label className="text-[12px] font-medium text-[#475569] block mb-1">
              Keystore Password (Optional)
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Leave empty for unencrypted storage"
              className="w-full h-9 px-3 rounded-lg border border-[#CBD5E1] text-[13px] focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div className="pt-2 flex justify-end space-x-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-[12.5px] font-medium text-[#475569] hover:bg-[#F1F5F9] rounded-xl cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 text-[12.5px] font-medium bg-[#0A3464] hover:bg-[#07274C] text-white rounded-xl shadow-xs cursor-pointer flex items-center space-x-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Initialize Vault</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
