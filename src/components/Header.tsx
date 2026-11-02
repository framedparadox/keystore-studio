import React from "react";
import {
  Undo2,
  Redo2,
  FolderPlus,
  Layers,
  TerminalSquare,
} from "lucide-react";
import { Workspace, TabType } from "../types/crypto";
import { useTerminal } from "./Terminal";

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
  const { toggle: toggleTerminal } = useTerminal();

  return (
    <header className="h-14 px-6 flex items-center justify-between select-none shrink-0 bg-chrome">
      {/* Left: Brand + Active Workspace Selector */}
      <div className="flex items-center space-x-4">
        <button
          onClick={() => onSelectTab("home")}
          className="flex items-center space-x-2.5 group cursor-pointer focus:outline-none"
          title="xkeystore Home"
        >
          <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-brand-deep to-brand flex items-center justify-center shadow-2xs">
            <div className="w-2.5 h-2.5 rounded-full bg-white" />
          </div>
          <span className="font-bold text-[17px] tracking-tight text-ink">
            xkeystore
          </span>
        </button>

        <div className="h-4 w-[1px] bg-line-strong" />

        {/* Essential Workspace Switcher */}
        <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-white/90 border border-line-strong text-[12px]">
          <Layers className="w-3.5 h-3.5 text-brand shrink-0" />
          <select
            value={activeWorkspaceId}
            onChange={(e) => {
              onSelectWorkspace(e.target.value);
              onSelectTab("workspaces");
            }}
            className="font-semibold text-brand-deep bg-transparent focus:outline-none cursor-pointer max-w-[180px] truncate"
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
        <div className="flex items-center bg-white/90 border border-line-strong rounded-full p-0.5">
          <button
            onClick={onUndo}
            disabled={!canUndo}
            title="Undo"
            className={`p-1.5 rounded-full transition ${
              canUndo ? "text-ink-2 hover:bg-surface-3 cursor-pointer" : "text-line-strong cursor-not-allowed"
            }`}
          >
            <Undo2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onRedo}
            disabled={!canRedo}
            title="Redo"
            className={`p-1.5 rounded-full transition ${
              canRedo ? "text-ink-2 hover:bg-surface-3 cursor-pointer" : "text-line-strong cursor-not-allowed"
            }`}
          >
            <Redo2 className="w-3.5 h-3.5" />
          </button>
        </div>

        <button
          onClick={toggleTerminal}
          title="Toggle terminal (Ctrl+`)"
          aria-label="Toggle terminal"
          className="p-2 rounded-full bg-surface/90 border border-line-strong text-ink-2 hover:bg-surface-3 cursor-pointer"
        >
          <TerminalSquare className="w-3.5 h-3.5" />
        </button>

        <button
          onClick={onOpenNewKeystoreModal}
          className="flex items-center space-x-1.5 px-4 py-1.5 rounded-full bg-brand-deep hover:bg-brand-deeper text-white text-[12.5px] font-semibold shadow-2xs transition cursor-pointer"
        >
          <FolderPlus className="w-3.5 h-3.5 text-white" />
          <span>New KeyStore</span>
        </button>
      </div>
    </header>
  );
};
