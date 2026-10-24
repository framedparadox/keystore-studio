import React, { useState } from "react";
import { 
  FolderArchive, 
  Key, 
  ShieldCheck, 
  AlertTriangle, 
  UploadCloud, 
  RefreshCw, 
  Copy, 
  Check, 
  ExternalLink 
} from "lucide-react";
import { KeystoreFile, KeystoreEntry } from "../types/crypto";

interface KeystoresViewProps {
  keystores: KeystoreFile[];
  onOpenConvertModal?: (source: KeystoreFile) => void;
}

export const KeystoresView: React.FC<KeystoresViewProps> = ({ keystores }) => {
  const [selectedKeystore, setSelectedKeystore] = useState<KeystoreFile>(keystores[0]);
  const [selectedEntry, setSelectedEntry] = useState<KeystoreEntry | null>(
    keystores[0]?.entries[0] || null
  );
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="flex-1 flex flex-col p-6 overflow-hidden">
      {/* View Header */}
      <div className="flex items-center justify-between pb-4 border-b border-[#E2E8F0]">
        <div>
          <h2 className="text-[20px] font-semibold text-[#1E293B]">Keystore Management</h2>
          <p className="text-[13px] text-[#64748B]">
            Create, inspect, and convert JKS, PKCS#12, BCFKS, and JCEKS vaults with zero local JRE dependencies.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => alert("Drag any .jks, .p12, .pem file into CertForge to inspect.")}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-[#CBD5E1] bg-white text-[#334155] text-[12.5px] font-medium hover:bg-[#F8FAFC] cursor-pointer"
          >
            <UploadCloud className="w-4 h-4 text-[#2563EB]" />
            <span>Import Keystore</span>
          </button>
        </div>
      </div>

      {/* Main Workspace Split: Left Keystores List, Center Entry Table, Right Entry Details */}
      <div className="flex-1 grid grid-cols-12 gap-5 pt-4 overflow-hidden">
        {/* Keystores list (3 cols) */}
        <div className="col-span-3 flex flex-col space-y-2.5 overflow-y-auto pr-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[#94A3B8] px-1">
            Active Keystores ({keystores.length})
          </span>
          {keystores.map((ks) => {
            const isSelected = selectedKeystore?.id === ks.id;
            return (
              <div
                key={ks.id}
                onClick={() => {
                  setSelectedKeystore(ks);
                  setSelectedEntry(ks.entries[0] || null);
                }}
                className={`p-3 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? "bg-[#EFF6FF] border-[#93C5FD] shadow-xs"
                    : "bg-white border-[#E2E8F0] hover:border-[#CBD5E1] hover:bg-[#F8FAFC]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <FolderArchive className={`w-4 h-4 ${isSelected ? "text-[#2563EB]" : "text-[#64748B]"}`} />
                    <span className="text-[13px] font-medium text-[#1E293B] truncate max-w-[140px]">
                      {ks.filename}
                    </span>
                  </div>
                  <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-[#E2E8F0] text-[#334155]">
                    {ks.format}
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between text-[11px] text-[#64748B]">
                  <span>{ks.totalEntries} entries</span>
                  <span className="font-mono text-[10px] text-[#94A3B8] truncate max-w-[120px]">
                    {ks.path}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Entries Table (5 cols) */}
        <div className="col-span-5 bg-white border border-[#E2E8F0] rounded-xl flex flex-col overflow-hidden shadow-xs">
          <div className="px-4 py-3 border-b border-[#E2E8F0] bg-[#F8FAFC] flex items-center justify-between">
            <span className="text-[12px] font-semibold text-[#334155]">
              Aliases in {selectedKeystore?.filename}
            </span>
            <span className="text-[11px] text-[#64748B]">
              Format: <strong className="text-[#0F172A]">{selectedKeystore?.format}</strong>
            </span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-[#F1F5F9]">
            {selectedKeystore?.entries.map((entry) => {
              const isSelected = selectedEntry?.alias === entry.alias;
              return (
                <div
                  key={entry.alias}
                  onClick={() => setSelectedEntry(entry)}
                  className={`p-3.5 transition cursor-pointer flex flex-col space-y-1 ${
                    isSelected ? "bg-[#F0F7FF]" : "hover:bg-[#F8FAFC]"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Key className="w-3.5 h-3.5 text-[#2563EB]" />
                      <span className="text-[13px] font-medium text-[#0F172A]">
                        {entry.alias}
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[10.5px] rounded-full font-medium ${
                        entry.type === "PrivateKeyEntry"
                          ? "bg-[#DCFCE7] text-[#166534]"
                          : "bg-[#E0E7FF] text-[#3730A3]"
                      }`}
                    >
                      {entry.type}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[11.5px] text-[#64748B]">
                    <span>
                      {entry.algorithm} • {entry.keySize} bits
                    </span>
                    <span>Expires: {entry.expiryDate}</span>
                  </div>

                  {entry.isWeak && (
                    <div className="mt-1 flex items-center space-x-1 text-[#DC2626] text-[11px]">
                      <AlertTriangle className="w-3 h-3" />
                      <span>Security Warning: Weak RSA-1024 key detected!</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Entry Inspector (4 cols) */}
        <div className="col-span-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl p-4 flex flex-col overflow-y-auto shadow-xs select-text">
          {selectedEntry ? (
            <div className="space-y-4">
              <div>
                <span className="text-[11px] font-bold uppercase tracking-wider text-[#64748B]">
                  Entry Metadata
                </span>
                <h3 className="text-[16px] font-semibold text-[#0F172A] mt-0.5">
                  {selectedEntry.alias}
                </h3>
              </div>

              <div className="space-y-2 text-[12px]">
                <div>
                  <span className="text-[#64748B] block text-[11px]">Subject Distinguished Name</span>
                  <span className="font-mono text-[#0F172A] text-[11px] break-all">
                    {selectedEntry.subject}
                  </span>
                </div>

                <div>
                  <span className="text-[#64748B] block text-[11px]">Issuer</span>
                  <span className="font-mono text-[#0F172A] text-[11px] break-all">
                    {selectedEntry.issuer}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div>
                    <span className="text-[#64748B] block text-[11px]">Algorithm</span>
                    <span className="font-medium text-[#0F172A]">{selectedEntry.algorithm}</span>
                  </div>
                  <div>
                    <span className="text-[#64748B] block text-[11px]">Key Size</span>
                    <span className="font-medium text-[#0F172A]">{selectedEntry.keySize} bits</span>
                  </div>
                  <div>
                    <span className="text-[#64748B] block text-[11px]">Created</span>
                    <span className="text-[#0F172A]">{selectedEntry.creationDate}</span>
                  </div>
                  <div>
                    <span className="text-[#64748B] block text-[11px]">Valid Until</span>
                    <span className="text-[#0F172A]">{selectedEntry.expiryDate}</span>
                  </div>
                </div>

                <div className="pt-2">
                  <span className="text-[#64748B] block text-[11px]">SHA-256 Fingerprint</span>
                  <div className="flex items-center justify-between bg-white border border-[#CBD5E1] p-1.5 rounded-md font-mono text-[10.5px] text-[#334155] mt-0.5">
                    <span className="truncate">{selectedEntry.sha256Fingerprint}</span>
                    <button
                      onClick={() => copyToClipboard(selectedEntry.sha256Fingerprint, "fp")}
                      className="ml-1 text-[#2563EB] hover:text-[#1D4ED8] cursor-pointer"
                    >
                      {copied === "fp" ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* CLI Command Generator Panel (FR 2.3) */}
              <div className="pt-3 border-t border-[#E2E8F0]">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-[#2563EB]">
                    Equivalent CLI Command
                  </span>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        `keytool -exportcert -alias ${selectedEntry.alias} -keystore ${selectedKeystore.filename} -file ${selectedEntry.alias}.crt`,
                        "cli"
                      )
                    }
                    className="text-[11px] text-[#2563EB] hover:underline cursor-pointer flex items-center space-x-1"
                  >
                    {copied === "cli" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>{copied === "cli" ? "Copied" : "Copy"}</span>
                  </button>
                </div>
                <div className="bg-[#0F172A] text-[#38BDF8] p-2 rounded-md font-mono text-[10.5px] overflow-x-auto">
                  <code>
                    keytool -exportcert -alias {selectedEntry.alias} -keystore {selectedKeystore.filename} -file {selectedEntry.alias}.crt
                  </code>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-[#94A3B8] text-[13px]">
              Select an alias to inspect details
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
