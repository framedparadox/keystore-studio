import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Header } from "./components/Header";
import { Sidebar } from "./components/Sidebar";
import { PromptBar } from "./components/PromptBar";
import { OverviewView } from "./views/OverviewView";
import { KeystoresView } from "./views/KeystoresView";
import { CertificatesView } from "./views/CertificatesView";
import { TrustGraphView } from "./views/TrustGraphView";
import { ScannerView } from "./views/ScannerView";
import { CloudSyncView } from "./views/CloudSyncView";
import { JwtSshView } from "./views/JwtSshView";
import { NewKeystoreModal } from "./components/NewKeystoreModal";
import { TabType, KeystoreFile } from "./types/crypto";
import { initialKeystores } from "./data/mockData";

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<TabType>("overview");
  const [keystores, setKeystores] = useState<KeystoreFile[]>(initialKeystores);
  const [isNewKeystoreModalOpen, setIsNewKeystoreModalOpen] = useState(false);
  const [isPromptLoading, setIsPromptLoading] = useState(false);
  const [aiResponse, setAiResponse] = useState<{
    action: string;
    reply: string;
    cli: string;
    suggested_tab: string;
  } | null>(null);

  const handleAsk = async (prompt: string) => {
    setIsPromptLoading(true);
    try {
      const res = await invoke<{
        action: string;
        reply: string;
        cli: string;
        suggested_tab: string;
      }>("ask_certforge_ai", { prompt });
      setAiResponse(res);
      if (currentTab !== "overview") {
        setCurrentTab("overview");
      }
    } catch (e) {
      console.error(e);
      alert("Error processing query: " + e);
    } finally {
      setIsPromptLoading(false);
    }
  };

  const handleAddKeystore = (newKs: KeystoreFile) => {
    setKeystores([newKs, ...keystores]);
    setCurrentTab("keystores");
  };

  return (
    <div className="h-screen w-screen flex flex-col bg-[#EBF0F7] select-none overflow-hidden font-sans">
      {/* Top Application Header */}
      <Header onOpenNewKeystoreModal={() => setIsNewKeystoreModalOpen(true)} />

      {/* Main Container: Sidebar + Elevated White Card */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Vertical Navigation Rail */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          onOpenCliDrawer={() => {}}
        />

        {/* Central Workspace: Elevated Rounded White Card */}
        <main className="flex-1 mr-4 mb-3 bg-white rounded-2xl border border-[#DCE4EC] shadow-[0_2px_8px_rgba(0,0,0,0.02)] flex flex-col overflow-hidden relative">
          {/* Active View */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {currentTab === "overview" && (
              <OverviewView
                onSelectTab={setCurrentTab}
                onAsk={handleAsk}
                aiResponse={aiResponse}
              />
            )}
            {currentTab === "keystores" && <KeystoresView keystores={keystores} />}
            {currentTab === "certificates" && <CertificatesView />}
            {currentTab === "trust_graph" && <TrustGraphView />}
            {currentTab === "scanner" && <ScannerView />}
            {currentTab === "cloud" && <CloudSyncView />}
            {currentTab === "jwt_ssh" && <JwtSshView />}
            {currentTab === "settings" && (
              <div className="flex-1 flex flex-col p-8 overflow-y-auto">
                <h2 className="text-[20px] font-semibold text-[#1E293B]">CertForge Preferences</h2>
                <div className="mt-4 space-y-4 max-w-xl text-[13px] text-[#475569]">
                  <div className="p-4 bg-[#F8FAFC] rounded-xl border border-[#E2E8F0] space-y-2">
                    <span className="font-semibold text-[#0F172A] block">Zero-Dependency Client-Side Engine</span>
                    <p className="leading-relaxed">
                      All keys and certificate files are stored in your local operating system memory with zero telemetry or remote persistence.
                    </p>
                  </div>
                  <div className="p-4 bg-[#F8FAFC] rounded-xl border border-[#E2E8F0] space-y-2">
                    <span className="font-semibold text-[#0F172A] block">Post-Quantum Cryptography</span>
                    <p className="leading-relaxed">
                      NIST FIPS 204 (ML-DSA) and FIPS 203 (ML-KEM) lattice algorithms are enabled by default for next-generation security.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Bottom Action & Prompt Bar (matches screenshot) */}
          <PromptBar onAsk={handleAsk} isLoading={isPromptLoading} />
        </main>
      </div>

      {/* New Keystore Dialog */}
      <NewKeystoreModal
        isOpen={isNewKeystoreModalOpen}
        onClose={() => setIsNewKeystoreModalOpen(false)}
        onAddKeystore={handleAddKeystore}
      />
    </div>
  );
};

export default App;
