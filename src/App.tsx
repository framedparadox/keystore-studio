import React, { useCallback, useEffect, useState } from "react";
import { Header } from "./components/Header";
import { Sidebar, useSidebarCollapsed } from "./components/Sidebar";
import { TerminalProvider, useTerminal } from "./components/Terminal";
import { ConfirmProvider, Spinner, ToastProvider } from "./components/ui";
import { CommandPalette } from "./components/CommandPalette";
import { DropOverlay, useWindowFileDrop } from "./components/DropZone";
import { NewKeystoreDialog, OpenPasswordDialog, SaveDialog, UnlockKeysDialog, VaultPromptDialog } from "./components/KeystoreDialogs";
import { BuildPkcs12Dialog } from "./components/AddEntryDialogs";
import { StoreProvider, useStore } from "./state/store";
import { HomeView } from "./views/HomeView";
import { KeystoresView } from "./views/KeystoresView";
import { CertificatesView } from "./views/CertificatesView";
import { WorkspacesView } from "./views/WorkspacesView";
import { ExamineView } from "./views/ExamineView";
import { CaSigningView } from "./views/CaSigningView";
import { ConvertView } from "./views/ConvertView";
import { ScannerView } from "./views/ScannerView";
import { VaultView } from "./views/VaultView";
import { SettingsView } from "./views/SettingsView";
import type { TabType } from "./types/crypto";

/** Ctrl+1 … Ctrl+9, then Ctrl+0. Pages added later take the next free key, so older shortcuts keep their numbers. */
const TAB_ORDER: TabType[] = ["home", "keystores", "workspaces", "examine", "ca_signing", "scanner", "vault", "settings", "convert", "certificates"];

const isEditable = (el: EventTarget | null) =>
  el instanceof HTMLElement && (el.isContentEditable || el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT");

/** Errors in one page never take the whole app down. */
class PageBoundary extends React.Component<{ children: React.ReactNode; resetKey: string }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidUpdate(prev: { resetKey: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="max-w-lg text-center">
          <h2 className="text-[16px] font-semibold text-ink">Something went wrong on this page</h2>
          <p className="text-[13px] text-muted mt-2 font-mono break-all">{this.state.error.message}</p>
          <button className="mt-4 text-brand font-medium cursor-pointer" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      </div>
    );
  }
}

const Shell: React.FC = () => {
  const store = useStore();
  const { toggle } = useTerminal();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useSidebarCollapsed();
  const onDrop = useCallback((paths: string[]) => void store.openFiles(paths), [store.openFiles]); // eslint-disable-line react-hooks/exhaustive-deps
  const dragging = useWindowFileDrop(onDrop);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (!mod) return;
      const key = e.key.toLowerCase();
      const ks = store.activeKeystore;
      const modalOpen = !!document.querySelector('[role="dialog"]');
      if (key === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      } else if (modalOpen) {
        return;
      } else if (key === "o") {
        e.preventDefault();
        void store.openFiles();
      } else if (key === "n") {
        e.preventDefault();
        store.setNewKeystoreOpen(true);
      } else if (key === "s") {
        e.preventDefault();
        if (ks && !ks.sealed) void store.save(ks.id, { saveAs: e.shiftKey });
      } else if ((key === "z" || key === "y") && !isEditable(e.target)) {
        e.preventDefault();
        if (key === "y" || e.shiftKey) store.redo();
        else store.undo();
      } else if (/^[0-9]$/.test(key)) {
        e.preventDefault();
        store.setTab(TAB_ORDER[(Number(key) + 9) % 10]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [store, toggle]);

  useEffect(() => {
    const dirty = store.keystores.some((k) => k.dirty);
    document.title = `${dirty ? "• " : ""}Keystore Studio${store.activeKeystore && store.tab === "keystores" ? ` — ${store.activeKeystore.name}` : ""}`;
  }, [store.keystores, store.activeKeystore, store.tab]);

  if (!store.ready) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-canvas text-muted gap-2 text-[13px]">
        <Spinner /> Starting Keystore Studio…
      </div>
    );
  }

  return (
    <div className="h-screen w-screen flex bg-canvas select-none overflow-hidden font-sans">
      <Sidebar collapsed={sidebarCollapsed} onCollapse={() => setSidebarCollapsed(true)} />
      <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
        <Header onOpenPalette={() => setPaletteOpen(true)} onExpandSidebar={sidebarCollapsed ? () => setSidebarCollapsed(false) : undefined} />
        <main className="flex-1 min-h-0 flex flex-col overflow-hidden relative">
          <PageBoundary resetKey={store.tab}>
            {store.tab === "home" && <HomeView />}
            {store.tab === "keystores" && <KeystoresView />}
            {store.tab === "certificates" && <CertificatesView />}
            {store.tab === "workspaces" && <WorkspacesView />}
            {store.tab === "examine" && <ExamineView />}
            {store.tab === "ca_signing" && <CaSigningView />}
            {store.tab === "convert" && <ConvertView />}
            {store.tab === "scanner" && <ScannerView />}
            {store.tab === "vault" && <VaultView />}
            {store.tab === "settings" && <SettingsView />}
          </PageBoundary>
        </main>
      </div>
      <OpenPasswordDialog />
      <SaveDialog />
      <NewKeystoreDialog />
      <BuildPkcs12Dialog open={store.buildPkcs12Open} onClose={() => store.setBuildPkcs12Open(false)} />
      <VaultPromptDialog />
      <UnlockKeysDialog />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <DropOverlay visible={dragging} />
    </div>
  );
};

export const App: React.FC = () => (
  <ToastProvider>
    <ConfirmProvider>
      <StoreProvider>
        <TerminalProvider>
          <Shell />
        </TerminalProvider>
      </StoreProvider>
    </ConfirmProvider>
  </ToastProvider>
);

export default App;
