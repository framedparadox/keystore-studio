import React from "react";
import { 
  FolderArchive, 
  MessageSquare, 
  GitFork, 
  Trophy, 
  Cloud, 
  KeyRound, 
  Settings, 
  HelpCircle, 
  LogOut 
} from "lucide-react";
import { TabType } from "../types/crypto";

interface SidebarProps {
  currentTab: TabType;
  onSelectTab: (tab: TabType) => void;
  onOpenCliDrawer: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const topNavItems = [
    {
      id: "overview" as TabType,
      label: "Ask",
      icon: MessageSquare,
    },
    {
      id: "keystores" as TabType,
      label: "Keystores",
      icon: FolderArchive,
    },
    {
      id: "certificates" as TabType,
      label: "Certs & Keys",
      icon: KeyRound,
    },
    {
      id: "trust_graph" as TabType,
      label: "Trust Graph",
      icon: GitFork,
    },
    {
      id: "scanner" as TabType,
      label: "Scanner",
      icon: Trophy,
    },
    {
      id: "cloud" as TabType,
      label: "Cloud Sync",
      icon: Cloud,
    },
  ];

  return (
    <aside className="w-[76px] flex flex-col items-center justify-between py-3 select-none">
      {/* Top Navigation Items */}
      <div className="flex flex-col items-center space-y-4 w-full">
        {topNavItems.map((item) => {
          const isActive = currentTab === item.id;
          const IconComponent = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className="flex flex-col items-center justify-center group cursor-pointer w-full focus:outline-none"
            >
              <div
                className={`w-12 h-8 rounded-full flex items-center justify-center transition-all duration-200 ${
                  isActive
                    ? "bg-[#D3E3FD] text-[#0A3464]"
                    : "text-[#475569] group-hover:bg-[#E2E8F0]/70 group-hover:text-[#1E293B]"
                }`}
              >
                <IconComponent className={`w-[18px] h-[18px] ${isActive ? "text-[#0A3464]" : "text-[#475569]"}`} />
              </div>
              <span
                className={`text-[11px] font-medium tracking-tight mt-1 text-center transition-colors ${
                  isActive ? "text-[#0A3464] font-semibold" : "text-[#64748B] group-hover:text-[#1E293B]"
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </div>

      {/* Bottom Utility Items */}
      <div className="flex flex-col items-center space-y-3.5 w-full pt-4">
        <button
          onClick={() => onSelectTab("settings")}
          className="flex flex-col items-center justify-center group cursor-pointer w-full"
          title="Settings"
        >
          <div
            className={`w-10 h-8 rounded-full flex items-center justify-center transition ${
              currentTab === "settings"
                ? "bg-[#D3E3FD] text-[#0A3464]"
                : "text-[#475569] group-hover:bg-[#E2E8F0]/70 group-hover:text-[#1E293B]"
            }`}
          >
            <Settings className="w-4 h-4 text-[#475569]" />
          </div>
          <span className="text-[10px] text-[#64748B] mt-0.5">Settings</span>
        </button>

        <button
          onClick={() => alert("CertForge v1.0 • Next-Gen KeyStore Explorer\nZero-dependency native Rust + Tauri application.")}
          className="w-8 h-8 rounded-full flex items-center justify-center text-[#64748B] hover:text-[#1E293B] hover:bg-[#E2E8F0]/70 transition cursor-pointer"
          title="Help & Documentation"
        >
          <HelpCircle className="w-[18px] h-[18px]" />
        </button>

        <button
          onClick={() => alert("Keystores locked. Memory wiped securely.")}
          className="w-8 h-8 rounded-full flex items-center justify-center text-[#64748B] hover:text-[#DC2626] hover:bg-[#FEE2E2]/70 transition cursor-pointer"
          title="Lock / Clear Keystores"
        >
          <LogOut className="w-[18px] h-[18px]" />
        </button>
      </div>
    </aside>
  );
};
