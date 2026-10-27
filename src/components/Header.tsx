import React from "react";
import {
  Undo2,
  Redo2,
  FolderPlus,
  Layers,
} from "lucide-react";
import { Workspace, TabType } from "../types/crypto";

interface HeaderProps {
  workspaces: Workspace[];
  activeWorkspaceId: string;
  canUndo: boolean;
  canRedo: boolean;
  onUndo: () => void;
  onRedo: () => void;
  onSelectTab: (tab: TabType) => void;
  onSelectWorkspace: (wsId: string) => void;
  onOpenNewKeystoreModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  workspaces,
  activeWorkspaceId,
  canUndo,
  canRedo,
  onUndo,
  onRedo,
  onSelectTab,
  onSelectWorkspace,
  onOpenNewKeystoreModal,
}) => {
  return (
    <header className="h-14 px-6 flex items-center justify-between select-none shrink-0 bg-[#DDE5F0]">
      {/* Left: Brand + Active Workspace Selector */}
      <div className="flex items-center space-x-4">
        <button
          onClick={() => onSelectTab("home")}
          className="flex items-center space-x-2.5 group cursor-pointer focus:outline-none"
          title="xkeystore Home"
        >
          <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-[#0A3464] to-[#2563EB] flex items-center justify-center shadow-2xs">
            <div className="w-2.5 h-2.5 rounded-full bg-white" />
          </div>
          <span className="font-bold text-[17px] tracking-tight text-[#0F172A]">
            xkeystore
          </span>
        </button>

        <div className="h-4 w-[1px] bg-[#CBD5E1]" />

        {/* Essential Workspace Switcher */}
        <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-white/90 border border-[#CBD5E1] text-[12px]">
          <Layers className="w-3.5 h-3.5 text-[#2563EB] shrink-0" />
          <select
            value={activeWorkspaceId}
            onChange={(e) => {
              onSelectWorkspace(e.target.value);
              onSelectTab("workspaces");
            }}
            className="font-semibold text-[#0A3464] bg-transparent focus:outline-none cursor-pointer max-w-[180px] truncate"
            title="Switch Active Workspace"
          >
            {workspaces.map((ws) => (
              <option key={ws.id} value={ws.id}>
                {ws.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Right: Undo/Redo + New KeyStore */}
      <div className="flex items-center space-x-2.5">
        <div className="flex items-center bg-white/90 border border-[#CBD5E1] rounded-full p-0.5">
          <button
            onClick={onUndo}
            disabled={!canUndo}
            title="Undo"
            className={`p-1.5 rounded-full transition ${
              canUndo ? "text-[#334155] hover:bg-[#F1F5F9] cursor-pointer" : "text-[#CBD5E1] cursor-not-allowed"
            }`}
          >
            <Undo2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onRedo}
            disabled={!canRedo}
            title="Redo"
            className={`p-1.5 rounded-full transition ${
              canRedo ? "text-[#334155] hover:bg-[#F1F5F9] cursor-pointer" : "text-[#CBD5E1] cursor-not-allowed"
            }`}
          >
            <Redo2 className="w-3.5 h-3.5" />
          </button>
        </div>

        <button
          onClick={onOpenNewKeystoreModal}
          className="flex items-center space-x-1.5 px-4 py-1.5 rounded-full bg-[#0A3464] hover:bg-[#07274C] text-white text-[12.5px] font-semibold shadow-2xs transition cursor-pointer"
        >
          <FolderPlus className="w-3.5 h-3.5 text-white" />
          <span>New KeyStore</span>
        </button>
      </div>
    </header>
  );
};
