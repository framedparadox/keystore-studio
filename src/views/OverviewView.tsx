import React from "react";
import { KeyRound, ShieldAlert, GitFork, RefreshCw, Copy, Check, Terminal } from "lucide-react";
import { TabType } from "../types/crypto";

interface OverviewViewProps {
  onSelectTab: (tab: TabType) => void;
  onAsk: (prompt: string) => void;
  aiResponse?: {
    action: string;
    reply: string;
    cli: string;
    suggested_tab: string;
  } | null;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onSelectTab, onAsk, aiResponse }) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const samplePrompts = [
    { text: "Generate RSA 4096 Keypair", action: "Generate RSA-4096 keypair with OpenSSL" },
    { text: "Convert PKCS#12 (.p12) to JKS", action: "Convert server.p12 to keystore.jks format" },
    { text: "Inspect Broken Trust Chain", action: "Show trust graph with broken intermediate certificate" },
    { text: "Audit Keystore for Deprecated SHA-1", action: "Scan for weak RSA keys and SHA-1 signatures" },
    { text: "Verify JWT Bearer Token", action: "Inspect JWT claims and RS256 signature" },
  ];

  return (
    <div className="flex-1 flex flex-col items-center justify-center p-8 select-none overflow-y-auto">
      {/* Center Hero Text matching the screenshot */}
      <div className="max-w-2xl text-center flex flex-col items-center space-y-3">
        <h2 className="text-[28px] font-normal tracking-tight text-[#476082] leading-tight">
          Get answer from your personalized
          <br />
          cryptographic knowledge sources.
        </h2>
        <p className="text-[14px] text-[#64748B] max-w-lg">
          Zero-dependency native keystore management, visual trust graph verification, and dynamic CLI commands powered by client-side Rust.
        </p>
      </div>

      {/* Dynamic AI / CLI Assistant Card if a prompt was answered */}
      {aiResponse && (
        <div className="mt-6 w-full max-w-2xl bg-[#F8FAFC] border border-[#E2E8F0] rounded-2xl p-5 shadow-sm animate-in fade-in zoom-in-95 duration-200">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2 text-[#0A3464] font-medium text-[13px]">
              <Terminal className="w-4 h-4 text-[#2563EB]" />
              <span>CertForge CLI Assistant</span>
            </div>
            <button
              onClick={() => handleCopy(aiResponse.cli)}
              className="flex items-center space-x-1 px-2.5 py-1 text-[12px] bg-white border border-[#CBD5E1] rounded-md text-[#334155] hover:bg-[#F1F5F9] cursor-pointer transition"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied!" : "Copy CLI Command"}</span>
            </button>
          </div>
          <p className="text-[13px] text-[#334155] mb-3 leading-relaxed">{aiResponse.reply}</p>
          <div className="bg-[#0F172A] text-[#38BDF8] font-mono text-[12px] p-3 rounded-lg overflow-x-auto select-text">
            <code>{aiResponse.cli}</code>
          </div>
          <div className="mt-3 flex justify-end">
            <button
              onClick={() => onSelectTab(aiResponse.suggested_tab as TabType)}
              className="text-[12px] text-[#2563EB] hover:text-[#1D4ED8] font-medium hover:underline cursor-pointer"
            >
              Open in {aiResponse.suggested_tab.toUpperCase()} Tab &rarr;
            </button>
          </div>
        </div>
      )}

      {/* Suggested Quick Action Chips */}
      <div className="mt-8 flex flex-wrap items-center justify-center gap-2.5 max-w-xl">
        {samplePrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => onAsk(p.action)}
            className="px-3.5 py-1.5 rounded-full bg-white border border-[#E2E8F0] hover:border-[#93C5FD] hover:bg-[#F0F7FF] text-[#475569] hover:text-[#0A3464] text-[12.5px] font-medium transition cursor-pointer shadow-[0_1px_2px_rgba(0,0,0,0.02)] active:scale-95"
          >
            {p.text}
          </button>
        ))}
      </div>
    </div>
  );
};
