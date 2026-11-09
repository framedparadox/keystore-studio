import React from "react";
import { ChevronRight, FilePlus2, FolderOpen, LockOpen, Redo2, Search, TerminalSquare, Undo2 } from "lucide-react";
import { useTerminal } from "./Terminal";
import { Button, IconButton, Kbd } from "./ui";
import { useStore } from "../state/store";
import { shortcutLabel } from "../lib/platform";

/**
 * Top bar: search in the middle, global actions on the right. Page titles live in each page's header.
 * While the sidebar is collapsed, `onExpandSidebar` puts a chevron at the start of the bar to expand it.
 */
export const Header: React.FC<{ onOpenPalette: () => void; onExpandSidebar?: () => void }> = ({ onOpenPalette, onExpandSidebar }) => {
  const { toggle: toggleTerminal } = useTerminal();
  const { canUndo, canRedo, undo, redo, openFiles, setNewKeystoreOpen, vault, lockVault } = useStore();
  return (
    <header className="h-14 px-6 grid grid-cols-[1fr_auto_1fr] items-center gap-4 shrink-0 bg-surface border-b border-line">
      {/* No page title here: each page names itself in its own header. */}
      <div className="flex items-center -ml-2">
        {onExpandSidebar && <IconButton icon={ChevronRight} label="Expand sidebar" onClick={onExpandSidebar} className="!w-9 !h-9" data-testid="sidebar-expand" />}
      </div>

      <button
        onClick={onOpenPalette}
        className="hidden md:inline-flex items-center gap-2 h-9 pl-3 pr-2 rounded-control border border-line-strong bg-surface-2 text-[13px] text-faint hover:text-ink hover:bg-surface-3 cursor-pointer w-80 justify-self-center"
        data-testid="open-palette"
      >
        <Search className="w-4 h-4" />
        <span className="flex-1 text-left">Search or run…</span>
        <Kbd>Ctrl K</Kbd>
      </button>

      <div className="flex items-center gap-1.5 justify-self-end">
        <IconButton icon={Undo2} label={shortcutLabel("Undo (Ctrl+Z)")} onClick={undo} disabled={!canUndo} data-testid="undo" />
        <IconButton icon={Redo2} label={shortcutLabel("Redo (Ctrl+Shift+Z)")} onClick={redo} disabled={!canRedo} data-testid="redo" />
        {vault.unlocked && (
          <Button size="md" icon={LockOpen} onClick={() => lockVault()} title="Lock the password vault. Open keystores and their keys stay in this window.">
            Lock password vault
          </Button>
        )}
        <IconButton icon={TerminalSquare} label={shortcutLabel("Terminal (Ctrl+`)")} onClick={toggleTerminal} data-testid="header-terminal" className="!w-9 !h-9" />
        <Button icon={FolderOpen} onClick={() => openFiles()} title={shortcutLabel("Open (Ctrl+O)")} aria-label={shortcutLabel("Open (Ctrl+O)")} className="!w-9 !px-0" data-testid="header-open" />
        <Button variant="primary" icon={FilePlus2} onClick={() => setNewKeystoreOpen(true)} title={shortcutLabel("New keystore (Ctrl+N)")} data-testid="header-new">
          New keystore
        </Button>
      </div>
    </header>
  );
};
