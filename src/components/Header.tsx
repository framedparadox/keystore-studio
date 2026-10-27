import React from "react";
import { Sparkles, CheckCircle2, Undo2, Redo2, Globe, FolderPlus } from "lucide-react";

interface HeaderProps {
  totalEntries: number;
  totalKeystores: number;
  opsCount: number;
  canUndo: boolean;
  canRedo: boolean;
  onUndo: () => void;
  onRedo: () => void;
  onOpenNewKeystoreModal: () => void;
  onQuickExamineSsl: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  totalEntries,
  totalKeystores,
  opsCount,
  canUndo,
  canRedo,
  onUndo,
  onRedo,
  onOpenNewKeystoreModal,
  onQuickExamineSsl,
}) => {
  return (
    <header className="h-14 px-4 flex items-center justify-between select-none">
      {/* Left side: macOS Traffic Lights + Brand Title + Status Pills */}
      <div className="flex items-center space-x-3.5">
        {/* macOS Traffic Lights */}
        <div className="flex items-center space-x-2 mr-1">
          <div className="w-3 h-3 rounded-full bg-[#FF5F56] border border-[#E0443E]" />
          <div className="w-3 h-3 rounded-full bg-[#FFBD2E] border border-[#DEA123]" />
          <div className="w-3 h-3 rounded-full bg-[#27C93F] border border-[#1AAB29]" />
        </div>

        {/* Brand Orb & Logo */}
        <div className="flex items-center space-x-2.5">
          <div className="relative w-7 h-7 rounded-full bg-gradient-to-tr from-[#00A86B] via-[#00C49F] to-[#26E5B4] shadow-xs flex items-center justify-center p-0.5">
            <div className="w-full h-full rounded-full bg-gradient-to-br from-[#00C49F] to-[#0D9488] opacity-90 flex items-center justify-center">
              <div className="w-2.5 h-2.5 rounded-full bg-white/80 blur-[0.5px]" />
            </div>
          </div>
          <span className="font-semibold text-[17px] tracking-tight text-[#1F2937]">
            CertForge <span className="text-[#64748B] font-normal text-[15px]">KeyStore Explorer</span>
          </span>
        </div>

        {/* Pill 1: Native Rust Engine */}
        <div className="hidden sm:flex items-center space-x-1.5 px-3 py-1 rounded-full bg-white border border-[#E2E8F0] shadow-[0_1px_2px_rgba(0,0,0,0.03)] text-[12px] text-[#475569]">
          <span className="text-[#64748B]">Powered by</span>
          <div className="flex items-center text-[#2563EB] font-medium space-x-1">
            <Sparkles className="w-3.5 h-3.5 text-[#3B82F6]" />
            <span>Native Rust Crypto</span>
          </div>
        </div>

        {/* Pill 2: Live Assets & Operations Count */}
        <div className="hidden md:flex items-center space-x-1.5 px-3 py-1 rounded-full bg-white border border-[#E2E8F0] shadow-[0_1px_2px_rgba(0,0,0,0.03)] text-[12px] text-[#334155]">
          <span className="text-[#0F172A] font-semibold">{totalEntries} Assets</span>
          <span className="text-[#64748B]">• {totalKeystores} Keystores • {opsCount.toLocaleString()} Ops</span>
          <CheckCircle2 className="w-3.5 h-3.5 text-[#0284C7] ml-0.5" />
        </div>
      </div>

      {/* Right side: Undo/Redo + Quick SSL + New KeyStore Button */}
      <div className="flex items-center space-x-2">
        <div className="flex items-center bg-white border border-[#E2E8F0] rounded-full p-0.5 shadow-2xs">
          <button
            onClick={onUndo}
            disabled={!canUndo}
            title="Undo KeyStore Action"
            className={`p-1.5 rounded-full transition ${
              canUndo ? "text-[#334155] hover:bg-[#F1F5F9] cursor-pointer" : "text-[#CBD5E1] cursor-not-allowed"
            }`}
          >
            <Undo2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onRedo}
            disabled={!canRedo}
            title="Redo KeyStore Action"
            className={`p-1.5 rounded-full transition ${
              canRedo ? "text-[#334155] hover:bg-[#F1F5F9] cursor-pointer" : "text-[#CBD5E1] cursor-not-allowed"
            }`}
          >
            <Redo2 className="w-3.5 h-3.5" />
          </button>
        </div>

        <button
          onClick={onQuickExamineSsl}
          className="hidden lg:flex items-center space-x-1.5 px-3.5 py-1.5 rounded-full bg-white border border-[#E2E8F0] hover:bg-[#F8FAFC] text-[#0F172A] text-[12.5px] font-medium transition cursor-pointer shadow-2xs"
        >
          <Globe className="w-3.5 h-3.5 text-[#2563EB]" />
          <span>Examine SSL</span>
        </button>

        <button
          onClick={onOpenNewKeystoreModal}
          className="flex items-center space-x-2 px-4 py-2 rounded-full bg-[#0A3464] hover:bg-[#07274C] active:scale-[0.98] text-white text-[13px] font-medium shadow-xs transition-all duration-150 cursor-pointer"
        >
          <FolderPlus className="w-4 h-4 text-white" />
          <span>New KeyStore</span>
        </button>
      </div>
    </header>
  );
};
