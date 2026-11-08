import React from "react";
import { ChevronRight, FilePlus2, FolderOpen, LockOpen, Redo2, Search, TerminalSquare, Undo2 } from "lucide-react";
import { useTerminal } from "./Terminal";
import { Button, IconButton, Kbd } from "./ui";
import { useStore } from "../state/store";
import { PAGE_TITLES } from "./Sidebar";
import { converterInfo } from "../lib/convert";

/** Top bar: breadcrumb on the left, global actions on the right. */
export const Header: React.FC<{ onOpenPalette: () => void }> = ({ onOpenPalette }) => {
  const { toggle: toggleTerminal } = useTerminal();
  const { tab, setTab, activeKeystore, canUndo, canRedo, undo, redo, openFiles, setNewKeystoreOpen, vault, lockVault, convertMode, openConverter } = useStore();
  return (
    <header className="h-14 px-6 grid grid-cols-[1fr_auto_1fr] items-center gap-4 shrink-0 bg-surface border-b border-line">
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-[13px] min-w-0">
        <button className="font-medium text-ink truncate hover:text-brand cursor-pointer" onClick={() => (tab === "convert" ? openConverter(null) : setTab(tab))}>
          {PAGE_TITLES[tab]}
        </button>
        {tab === "convert" && convertMode && (
          <>
            <ChevronRight className="w-3.5 h-3.5 text-subtle shrink-0" />
            <span className="text-muted truncate" data-testid="breadcrumb-converter">
              {converterInfo(convertMode).title}
            </span>
          </>
        )}
        {tab === "keystores" && activeKeystore && (
          <>
            <ChevronRight className="w-3.5 h-3.5 text-subtle shrink-0" />
            <span className="text-muted truncate" data-testid="breadcrumb-keystore">
              {activeKeystore.name}
              {activeKeystore.dirty && " •"}
            </span>
          </>
        )}
      </nav>

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
        <IconButton icon={Undo2} label="Undo (Ctrl+Z)" onClick={undo} disabled={!canUndo} data-testid="undo" />
        <IconButton icon={Redo2} label="Redo (Ctrl+Shift+Z)" onClick={redo} disabled={!canRedo} data-testid="redo" />
        {vault.unlocked && (
          <Button size="md" icon={LockOpen} onClick={() => lockVault()} title="Lock the password vault. Open keystores and their keys stay in this window.">
            Lock password vault
          </Button>
        )}
        <IconButton icon={TerminalSquare} label="Terminal (Ctrl+`)" onClick={toggleTerminal} className="!w-9 !h-9" />
        <Button icon={FolderOpen} onClick={() => openFiles()} title="Open (Ctrl+O)" aria-label="Open (Ctrl+O)" className="!w-9 !px-0" data-testid="header-open" />
        <Button variant="primary" icon={FilePlus2} onClick={() => setNewKeystoreOpen(true)} title="New keystore (Ctrl+N)" data-testid="header-new">
          New keystore
        </Button>
      </div>
    </header>
  );
};
