import React from "react";
import { FilePlus2, FolderOpen, LockOpen, Redo2, Search, Settings, TerminalSquare, Undo2 } from "lucide-react";
import { useTerminal } from "./Terminal";
import { Button, IconButton, Kbd } from "./ui";
import { useStore } from "../state/store";
import { shortcutLabel } from "../lib/platform";

/**
 * Top bar: search in the middle, global actions on the right. Page titles live in each page's header.
 */
export const Header: React.FC<{ onOpenPalette: () => void }> = ({ onOpenPalette }) => {
  const { toggle: toggleTerminal } = useTerminal();
  const { tab, setTab, canUndo, canRedo, undo, redo, openFiles, setNewKeystoreOpen, vault, lockVault } = useStore();
  return (
    <header className="shell-accent h-14 px-6 grid grid-cols-[1fr_auto_1fr] items-center gap-4 shrink-0 bg-surface border-b border-line">
      {/* No page title here: each page names itself in its own header. */}
      <div className="flex items-center justify-end gap-1.5">
        {canUndo && <IconButton icon={Undo2} label={shortcutLabel("Undo (Ctrl+Z)")} onClick={undo} data-testid="undo" />}
        {canRedo && <IconButton icon={Redo2} label={shortcutLabel("Redo (Ctrl+Shift+Z)")} onClick={redo} data-testid="redo" />}
      </div>

      <div className="flex items-center gap-1.5 justify-self-center">
        <button
          onClick={onOpenPalette}
          className="hidden md:inline-flex items-center gap-2 h-9 pl-3 pr-2 rounded-control border border-line-strong bg-surface-2 text-[13px] text-faint hover:text-ink hover:bg-surface-3 cursor-pointer w-80"
          data-testid="open-palette"
        >
          <Search className="w-4 h-4" />
          <span className="flex-1 text-left">Search or run…</span>
          <Kbd>Ctrl K</Kbd>
        </button>
        <IconButton icon={TerminalSquare} label={shortcutLabel("Terminal (Ctrl+`)")} onClick={toggleTerminal} data-testid="header-terminal" className="!w-9 !h-9 shrink-0 !text-brand" />
      </div>

      <div className="flex items-center gap-1.5 justify-self-end">
        {vault.unlocked && tab !== "vault" && (
          <Button
            icon={LockOpen}
            aria-label="Lock password vault"
            title="Lock the password vault. Open keystores and their keys stay in this window."
            onClick={() => lockVault()}
            className="!w-9 !px-0 !text-success"
            data-testid="header-lock-vault"
          />
        )}
        <Button icon={FolderOpen} onClick={() => openFiles()} title={shortcutLabel("Open (Ctrl+O)")} aria-label={shortcutLabel("Open (Ctrl+O)")} className="!w-9 !px-0" data-testid="header-open" />
        <Button variant="primary" icon={FilePlus2} onClick={() => setNewKeystoreOpen(true)} title={shortcutLabel("New keystore (Ctrl+N)")} data-testid="header-new">
          New keystore
        </Button>
        <IconButton
          icon={Settings}
          label={shortcutLabel("Settings (Ctrl+8)")}
          onClick={() => setTab("settings")}
          aria-current={tab === "settings" ? "page" : undefined}
          className={tab === "settings" ? "!w-9 !h-9 bg-surface-3 !text-brand" : "!w-9 !h-9"}
          data-testid="nav-settings"
        />
      </div>
    </header>
  );
};
