import React from "react";
import { Plus, TerminalSquare } from "lucide-react";
import { useTerminal } from "./Terminal";
import { Button } from "./ui";

interface HeaderProps {
  workspaceName: string;
  pageTitle: string;
  canUndo: boolean;
  canRedo: boolean;
  onUndo: () => void;
  onRedo: () => void;
  onOpenNewKeystoreModal: () => void;
}

/** Top bar of the content area: breadcrumb on the left, global actions on the right. */
export const Header: React.FC<HeaderProps> = ({
  workspaceName,
  pageTitle,
  canUndo,
  canRedo,
  onUndo,
  onRedo,
  onOpenNewKeystoreModal,
}) => {
  const { toggle: toggleTerminal } = useTerminal();

  return (
    <header className="h-14 px-8 flex items-center justify-between gap-4 shrink-0 bg-surface border-b border-line">
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-[13px] min-w-0">
        <span className="font-medium text-ink truncate">{pageTitle}</span>
      </nav>

      <div className="flex items-center gap-2">
        <Button icon={TerminalSquare} onClick={toggleTerminal} title="Toggle terminal (Ctrl+`)">
          Terminal
        </Button>
        <Button variant="primary" icon={Plus} onClick={onOpenNewKeystoreModal}>
          New keystore
        </Button>
      </div>
    </header>
  );
};
