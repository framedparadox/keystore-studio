import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Header } from "./components/Header";
import { Sidebar } from "./components/Sidebar";
import { HomeView } from "./views/HomeView";
import { WorkspacesView } from "./views/WorkspacesView";
import { KeystoresView } from "./views/KeystoresView";
import { CaSigningView } from "./views/CaSigningView";
import { ExamineView } from "./views/ExamineView";
import { ScannerView } from "./views/ScannerView";
import { VaultsView } from "./views/VaultsView";
import { SettingsView } from "./views/SettingsView";
import { TerminalProvider } from "./components/Terminal";
import { NewKeystoreModal } from "./components/NewKeystoreModal";
import { VaultLockScreen } from "./components/VaultLockScreen";
import {
  TabType,
  KeystoreFile,
  KeystoreFormat,
  Workspace,
  ExportPayloadResult,
} from "./types/crypto";
import { initialKeystores, initialWorkspaces } from "./data/mockData";
import { entryHealth, flattenEntries } from "./lib/metrics";

const PAGE_TITLES: Record<TabType, string> = {
  home: "Dashboard",
  workspaces: "Workspaces",
  keystores: "Keystores",
  ca_signing: "CA & Signing",
  examine: "Examine",
  scanner: "Security",
  passwords: "Vaults",
  settings: "Settings",
};

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<TabType>("home");
  const [keystores, setKeystores] = useState<KeystoreFile[]>(initialKeystores);
  const [activeKeystoreId, setActiveKeystoreId] = useState<string>(initialKeystores[0].id);

  // Workspaces State
  const [workspaces, setWorkspaces] = useState<Workspace[]>(initialWorkspaces);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState<string>(initialWorkspaces[0].id);

  // Undo / Redo History Stack
  const [history, setHistory] = useState<KeystoreFile[][]>([]);
  const [redoStack, setRedoStack] = useState<KeystoreFile[][]>([]);

  // Telemetry & Operations Counter (for Stats Dashboard)
  const [opsCount, setOpsCount] = useState<number>(4113);
  const [signaturesCount, setSignaturesCount] = useState<number>(18);

  const [isNewKeystoreModalOpen, setIsNewKeystoreModalOpen] = useState(false);
  const [newKeystoreFormat, setNewKeystoreFormat] = useState<KeystoreFormat>("PKCS12");
  const [examineSeed, setExamineSeed] = useState<string | null>(null);

  // Vault gate: only the Vaults tab (and its secrets) sit behind the master key. The rest of
  // the app — dashboard, keystores, CA signing, examine, security, settings — is usable
  // immediately; "loading" is a brief check of vault_status on mount, then "setup" (no vault
  // file yet) or "locked" (vault exists but not unlocked) until the master key is verified,
  // then "unlocked".
  const [vaultState, setVaultState] = useState<"loading" | "locked" | "setup" | "unlocked">(
    "loading"
  );

  useEffect(() => {
    let cancelled = false;
    invoke<{ exists: boolean; unlocked: boolean }>("vault_status")
      .then((status) => {
        if (cancelled) return;
        if (!status.exists) {
          setVaultState("setup");
        } else if (status.unlocked) {
          setVaultState("unlocked");
        } else {
          setVaultState("locked");
        }
      })
      .catch(() => {
        if (!cancelled) setVaultState("locked");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLockVault = () => {
    invoke("vault_lock").finally(() => setVaultState("locked"));
  };

  const pushState = (nextKeystores: KeystoreFile[]) => {
    setHistory((prev) => [...prev.slice(-19), keystores]);
    setRedoStack([]);
    setKeystores(nextKeystores);
  };

  const handleUndo = () => {
    if (history.length === 0) return;
    const prev = history[history.length - 1];
    setRedoStack((r) => [keystores, ...r]);
    setHistory((h) => h.slice(0, -1));
    setKeystores(prev);
  };

  const handleRedo = () => {
    if (redoStack.length === 0) return;
    const next = redoStack[0];
    setHistory((h) => [...h, keystores]);
    setRedoStack((r) => r.slice(1));
    setKeystores(next);
  };

  const handleUpdateKeystore = (updated: KeystoreFile) => {
    pushState(keystores.map((k) => (k.id === updated.id ? updated : k)));
  };

  const handleDeleteKeystore = (id: string) => {
    if (keystores.length <= 1) return;
    const next = keystores.filter((k) => k.id !== id);
    pushState(next);
    if (activeKeystoreId === id) {
      setActiveKeystoreId(next[0].id);
    }
  };

  const handleAddKeystore = (newKs: KeystoreFile) => {
    pushState([newKs, ...keystores]);
    setActiveKeystoreId(newKs.id);
    setOpsCount((c) => c + 1024);
    setCurrentTab("keystores");
  };

  const handleImportKeystores = (list: KeystoreFile[]) => {
    pushState([...list, ...keystores]);
    setActiveKeystoreId(list[0].id);
    setOpsCount((c) => c + 512 * list.length);
    setCurrentTab("keystores");
  };

  const handleExamineText = (text: string) => {
    setExamineSeed(text);
    setCurrentTab("examine");
  };

  const handleRecordOp = (increment = 256, isSig = false) => {
    setOpsCount((c) => c + increment);
    if (isSig) {
      setSignaturesCount((s) => s + 1);
    }
  };

  const handleExportAllCsv = async () => {
    const active = keystores.find((k) => k.id === activeKeystoreId) || keystores[0];
    if (!active) return;
    try {
      await invoke<ExportPayloadResult>("export_keystore_to_csv", { ks: active });
      handleRecordOp(128, false);
    } catch (e) {
      console.error(e);
    }
  };

  // Workspace Handlers
  const handleCreateWorkspace = (ws: Workspace) => {
    setWorkspaces((prev) => [ws, ...prev]);
    setActiveWorkspaceId(ws.id);
  };

  const handleDeleteWorkspace = (wsId: string) => {
    if (workspaces.length <= 1) return;
    const next = workspaces.filter((w) => w.id !== wsId);
    setWorkspaces(next);
    if (activeWorkspaceId === wsId) {
      setActiveWorkspaceId(next[0].id);
    }
  };

  const handleToggleEntryInWorkspace = (workspaceId: string, entryId: string) => {
    setWorkspaces((prev) =>
      prev.map((ws) => {
        if (ws.id !== workspaceId) return ws;
        const exists = ws.entryIds.includes(entryId);
        return {
          ...ws,
          updated_at: "Just now",
          entryIds: exists
            ? ws.entryIds.filter((id) => id !== entryId)
            : [...ws.entryIds, entryId],
        };
      })
    );
  };

  const totalEntries = keystores.reduce((sum, k) => sum + k.entries.length, 0);

  const atRiskCount = flattenEntries(keystores).filter(({ entry }) => entryHealth(entry) === "at-risk").length;
  const activeWorkspace = workspaces.find((w) => w.id === activeWorkspaceId) ?? workspaces[0];
  const openNewKeystore = () => {
    setNewKeystoreFormat("PKCS12");
    setIsNewKeystoreModalOpen(true);
  };

  return (
    <TerminalProvider>
    <div className="h-screen w-screen flex bg-canvas select-none overflow-hidden font-sans">
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        workspaces={workspaces}
        activeWorkspaceId={activeWorkspaceId}
        onSelectWorkspace={setActiveWorkspaceId}
        counts={{
          keystores: { value: keystores.length },
          workspaces: { value: workspaces.length },
          scanner: { value: atRiskCount, tone: "danger" },
        }}
      />

      <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
        <Header
          workspaceName={activeWorkspace?.name ?? "xkeystore"}
          pageTitle={PAGE_TITLES[currentTab]}
          canUndo={history.length > 0}
          canRedo={redoStack.length > 0}
          onUndo={handleUndo}
          onRedo={handleRedo}
          onOpenNewKeystoreModal={openNewKeystore}
          onLockVault={handleLockVault}
          showLockVault={currentTab === "passwords" && vaultState === "unlocked"}
        />

        <main className="flex-1 min-h-0 flex flex-col overflow-hidden relative">
          {currentTab === "home" && (
            <HomeView
              keystores={keystores}
              workspaces={workspaces}
              onSelectTab={setCurrentTab}
              onSelectKeystoreAndOpen={(ksId) => {
                setActiveKeystoreId(ksId);
                setCurrentTab("keystores");
              }}
              onSelectWorkspaceAndOpen={(wsId) => {
                setActiveWorkspaceId(wsId);
                setCurrentTab("workspaces");
              }}
              onOpenNewKeystoreWithFormat={(fmt) => {
                setNewKeystoreFormat(fmt || "PKCS12");
                setIsNewKeystoreModalOpen(true);
              }}
              onImportKeystores={handleImportKeystores}
              onExamineText={handleExamineText}
            />
          )}

          {currentTab === "workspaces" && (
            <WorkspacesView
              workspaces={workspaces}
              activeWorkspaceId={activeWorkspaceId}
              onSelectWorkspace={setActiveWorkspaceId}
              onCreateWorkspace={handleCreateWorkspace}
              onDeleteWorkspace={handleDeleteWorkspace}
              onToggleEntryInWorkspace={handleToggleEntryInWorkspace}
              keystores={keystores}
              onNavigateTab={setCurrentTab}
              onSelectKeystore={setActiveKeystoreId}
            />
          )}

          {currentTab === "keystores" && (
            <KeystoresView
              keystores={keystores}
              activeKeystoreId={activeKeystoreId}
              onSelectKeystore={setActiveKeystoreId}
              onUpdateKeystore={handleUpdateKeystore}
              onDeleteKeystore={handleDeleteKeystore}
              onOpenNewKeystoreModal={openNewKeystore}
              onRecordOp={handleRecordOp}
              workspaces={workspaces}
              onToggleEntryInWorkspace={handleToggleEntryInWorkspace}
            />
          )}

          {currentTab === "ca_signing" && (
            <CaSigningView
              keystores={keystores}
              activeKeystoreId={activeKeystoreId}
              onUpdateKeystore={handleUpdateKeystore}
              onRecordOp={handleRecordOp}
            />
          )}

          {currentTab === "examine" && (
            <ExamineView
              keystores={keystores}
              activeKeystoreId={activeKeystoreId}
              onUpdateKeystore={handleUpdateKeystore}
              onRecordOp={handleRecordOp}
              initialInput={examineSeed}
            />
          )}

          {currentTab === "scanner" && (
            <ScannerView
              keystores={keystores}
              onUpdateKeystore={handleUpdateKeystore}
              onRecordOp={handleRecordOp}
            />
          )}

          {currentTab === "passwords" && vaultState !== "unlocked" && (
            <VaultLockScreen
              mode={vaultState === "setup" ? "setup" : "unlock"}
              onUnlocked={() => setVaultState("unlocked")}
              inline
            />
          )}

          {currentTab === "passwords" && vaultState === "unlocked" && (
            <VaultsView keystores={keystores} onUpdateKeystore={handleUpdateKeystore} />
          )}

          {currentTab === "settings" && <SettingsView />}
        </main>
      </div>

      {/* New KeyStore Modal */}
      <NewKeystoreModal
        isOpen={isNewKeystoreModalOpen}
        onClose={() => setIsNewKeystoreModalOpen(false)}
        onAddKeystore={handleAddKeystore}
        defaultFormat={newKeystoreFormat}
      />
    </div>
    </TerminalProvider>
  );
};

export default App;
