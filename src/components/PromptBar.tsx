import React, { useState } from "react";
import { ArrowUp, Terminal, Sparkles } from "lucide-react";

interface PromptBarProps {
  onAsk: (prompt: string) => void;
  isLoading?: boolean;
}

export const PromptBar: React.FC<PromptBarProps> = ({ onAsk, isLoading }) => {
  const [input, setInput] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    onAsk(input.trim());
    setInput("");
  };

  return (
    <div className="w-full px-8 pb-6 pt-2">
      <form onSubmit={handleSubmit} className="relative flex items-center space-x-3 w-full">
        {/* Left circular icon button (avatar/agent mode) */}
        <button
          type="button"
          className="w-9 h-9 rounded-full bg-[#E2E8F0] hover:bg-[#CBD5E1] text-[#475569] flex items-center justify-center shrink-0 transition shadow-inner cursor-pointer"
          title="CLI Engine & AI Prompt Mode"
        >
          <Terminal className="w-4 h-4" />
        </button>

        {/* Input box */}
        <div className="relative flex-1 flex items-center">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask CertForge about your keys, certificates, or CLI commands (e.g., 'Generate RSA 4096 CSR' or 'Convert to JKS')"
            className="w-full h-12 pl-5 pr-14 rounded-full border border-[#D5DEE8] bg-white text-[14px] text-[#1E293B] placeholder-[#94A3B8] shadow-[0_1px_3px_rgba(0,0,0,0.03)] focus:outline-none focus:border-[#3B82F6] focus:ring-2 focus:ring-[#BFDBFE]/50 transition"
          />

          {/* Right send button (light blue circle with dark blue up arrow) */}
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className={`absolute right-1.5 w-9 h-9 rounded-full flex items-center justify-center transition-all cursor-pointer ${
              input.trim() && !isLoading
                ? "bg-[#C2E7FF] text-[#0A3464] hover:bg-[#A8DBFF] active:scale-95 shadow-sm"
                : "bg-[#C2E7FF]/70 text-[#0A3464]/60 cursor-not-allowed"
            }`}
          >
            {isLoading ? (
              <div className="w-4 h-4 border-2 border-[#0A3464] border-t-transparent rounded-full animate-spin" />
            ) : (
              <ArrowUp className="w-4 h-4 stroke-[2.5]" />
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
