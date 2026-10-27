import React from "react";
import {
  FolderArchive,
  Trophy,
  FileSignature,
  SearchCode,
  ShieldCheck,
  KeyRound,
  Settings,
  LogOut,
} from "lucide-react";
import { TabType } from "../types/crypto";

interface SidebarProps {
  currentTab: TabType;
  onSelectTab: (tab: TabType) => void;
  onLockAll: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab, onLockAll }) => {
  const topNavItems = [
    {
      id: "keystores" as TabType,
      label: "Sources",
      icon: FolderArchive,
    },
    {
      id: "dashboard" as TabType,
      label: "Stats",
      icon: Trophy,
    },
    {
      id: "ca_signing" as TabType,
      label: "CA & Sign",
      icon: FileSignature,
    },
    {
      id: "examine" as TabType,
      label: "Examine",
      icon: SearchCode,
    },
    {
      id: "scanner" as TabType,
      label: "Security",
      icon: ShieldCheck,
    },
  ];

  return (
    <aside className="w-[78px] flex flex-col items-center justify-between py-3 select-none shrink-0">
      {/* Top Navigation Items */}
      <div className="flex flex-col items-center space-y-3.5 w-full">
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
                    ? "bg-[#C2E7FF] text-[#0A3464]"
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
      <div className="flex flex-col items-center space-y-3 w-full pt-4">
        <button
          onClick={() => onSelectTab("passwords")}
          className="flex flex-col items-center justify-center group cursor-pointer w-full"
          title="Password Manager"
        >
          <div
            className={`w-10 h-8 rounded-full flex items-center justify-center transition ${
              currentTab === "passwords"
                ? "bg-[#C2E7FF] text-[#0A3464]"
                : "text-[#475569] group-hover:bg-[#E2E8F0]/70 group-hover:text-[#1E293B]"
            }`}
          >
            <KeyRound className="w-4 h-4" />
          </div>
          <span className="text-[10px] text-[#64748B] mt-0.5">Vaults</span>
        </button>

        <button
          onClick={() => onSelectTab("settings")}
          className="flex flex-col items-center justify-center group cursor-pointer w-full"
          title="Settings & Security Providers"
        >
          <div
            className={`w-10 h-8 rounded-full flex items-center justify-center transition ${
              currentTab === "settings"
                ? "bg-[#C2E7FF] text-[#0A3464]"
                : "text-[#475569] group-hover:bg-[#E2E8F0]/70 group-hover:text-[#1E293B]"
            }`}
          >
            <Settings className="w-4 h-4" />
          </div>
          <span className="text-[10px] text-[#64748B] mt-0.5">Settings</span>
        </button>

        <button
          onClick={onLockAll}
          className="w-8 h-8 rounded-full flex items-center justify-center text-[#64748B] hover:text-[#DC2626] hover:bg-[#FEE2E2]/70 transition cursor-pointer"
          title="Lock All KeyStores"
        >
          <LogOut className="w-[18px] h-[18px]" />
        </button>
      </div>
    </aside>
  );
};
