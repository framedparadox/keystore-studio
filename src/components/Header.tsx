import React from "react";
import { Sparkles, CheckCircle2, ShieldCheck, Plus } from "lucide-react";

interface HeaderProps {
  onOpenNewKeystoreModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenNewKeystoreModal }) => {
  return (
    <header className="h-14 px-4 flex items-center justify-between select-none border-b border-transparent">
      {/* Left side: macOS Traffic Lights + Brand Title + Status Pills */}
      <div className="flex items-center space-x-3.5">
        {/* macOS Traffic Lights */}
        <div className="flex items-center space-x-2 mr-1">
          <div className="w-3 h-3 rounded-full bg-[#FF5F56] border border-[#E0443E] hover:opacity-80 transition cursor-pointer" />
          <div className="w-3 h-3 rounded-full bg-[#FFBD2E] border border-[#DEA123] hover:opacity-80 transition cursor-pointer" />
          <div className="w-3 h-3 rounded-full bg-[#27C93F] border border-[#1AAB29] hover:opacity-80 transition cursor-pointer" />
        </div>

        {/* Brand Orb & Logo */}
        <div className="flex items-center space-x-2.5">
          <div className="relative w-7 h-7 rounded-full bg-gradient-to-tr from-[#00A86B] via-[#00C49F] to-[#26E5B4] shadow-sm flex items-center justify-center p-0.5">
            <div className="w-full h-full rounded-full bg-gradient-to-br from-[#00C49F] to-[#0D9488] opacity-90 flex items-center justify-center">
              <div className="w-2.5 h-2.5 rounded-full bg-white/70 blur-[0.5px]" />
            </div>
          </div>
          <span className="font-semibold text-[17px] tracking-tight text-[#1F2937]">
            CertForge <span className="text-[#4B5563] font-normal text-[15px]">Studio</span>
          </span>
        </div>

        {/* Pill 1: Powered by Rust Crypto Core */}
        <div className="hidden sm:flex items-center space-x-1.5 px-3 py-1 rounded-full bg-white border border-[#E2E8F0] shadow-[0_1px_2px_rgba(0,0,0,0.03)] text-[12px] text-[#475569]">
          <span className="text-[#64748B]">Powered by</span>
          <div className="flex items-center text-[#2563EB] font-medium space-x-1">
            <Sparkles className="w-3.5 h-3.5 text-[#3B82F6]" />
            <span>Rust Core 1.99</span>
          </div>
        </div>

        {/* Pill 2: Security Status & Zero Leaks */}
        <div className="hidden md:flex items-center space-x-1.5 px-3 py-1 rounded-full bg-white border border-[#E2E8F0] shadow-[0_1px_2px_rgba(0,0,0,0.03)] text-[12px] text-[#334155] font-medium">
          <span className="text-[#0F172A] font-semibold">100% Client-Side</span>
          <span className="text-[#64748B] font-normal">• Zero Leaks</span>
          <CheckCircle2 className="w-3.5 h-3.5 text-[#0284C7] ml-0.5" />
        </div>
      </div>

      {/* Right side: Action Button (matching the dark blue pill "+ Start transcribing") */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onOpenNewKeystoreModal}
          className="flex items-center space-x-2 px-4 py-2 rounded-full bg-[#0A3464] hover:bg-[#07274C] active:scale-[0.98] text-white text-[13px] font-medium shadow-sm transition-all duration-150 cursor-pointer"
        >
          <Sparkles className="w-4 h-4 text-white" />
          <span>New Keystore</span>
        </button>
      </div>
    </header>
  );
};
