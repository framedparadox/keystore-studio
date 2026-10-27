import React from "react";
import {
  Home,
  Layers,
  FolderArchive,
  FileSignature,
  SearchCode,
  ShieldCheck,
  KeyRound,
  Settings,
} from "lucide-react";
import { TabType } from "../types/crypto";

interface SidebarProps {
  currentTab: TabType;
  onSelectTab: (tab: TabType) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const topNavItems: { id: TabType; label: string; icon: React.ElementType }[] = [
    {
      id: "home",
      label: "Home",
      icon: Home,
    },
    {
      id: "workspaces",
      label: "Workspaces",
      icon: Layers,
    },
    {
      id: "keystores",
      label: "KeyStores",
      icon: FolderArchive,
    },
    {
      id: "ca_signing",
      label: "CA & Sign",
      icon: FileSignature,
    },
    {
      id: "examine",
      label: "Examine",
      icon: SearchCode,
    },
    {
      id: "scanner",
      label: "Security",
      icon: ShieldCheck,
    },
  ];

  const bottomNavItems: { id: TabType; label: string; icon: React.ElementType }[] = [
    {
      id: "passwords",
      label: "Vaults",
      icon: KeyRound,
    },
    {
      id: "settings",
      label: "Settings",
      icon: Settings,
    },
  ];

  return (
    <aside className="w-[88px] flex flex-col items-center justify-between py-3 px-1.5 select-none shrink-0">
      {/* Top Primary Navigation Items */}
      <div className="flex flex-col items-center space-y-2.5 w-full">
        {topNavItems.map((item) => {
          const isActive = currentTab === item.id;
          const IconComponent = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className="flex flex-col items-center justify-center group cursor-pointer w-full focus:outline-none py-0.5"
            >
              <div
                className={`w-13 h-8 rounded-full flex items-center justify-center transition-all duration-200 ${
                  isActive
                    ? "bg-[#C2E7FF] text-[#0A3464] shadow-2xs"
                    : "text-[#475569] group-hover:bg-[#CBD5E1]/60 group-hover:text-[#0F172A]"
                }`}
              >
                <IconComponent className={`w-[18px] h-[18px] ${isActive ? "text-[#0A3464]" : "text-[#475569]"}`} />
              </div>
              <span
                className={`text-[11px] tracking-tight mt-1 text-center transition-colors ${
                  isActive ? "text-[#0A3464] font-bold" : "text-[#475569] font-medium group-hover:text-[#0F172A]"
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </div>

      {/* Bottom Utility Navigation Items: Vaults -> Settings */}
      <div className="flex flex-col items-center space-y-2.5 w-full pt-3 border-t border-[#CBD5E1]/80">
        {bottomNavItems.map((item) => {
          const isActive = currentTab === item.id;
          const IconComponent = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className="flex flex-col items-center justify-center group cursor-pointer w-full focus:outline-none py-0.5"
            >
              <div
                className={`w-13 h-8 rounded-full flex items-center justify-center transition-all duration-200 ${
                  isActive
                    ? "bg-[#C2E7FF] text-[#0A3464] shadow-2xs"
                    : "text-[#475569] group-hover:bg-[#CBD5E1]/60 group-hover:text-[#0F172A]"
                }`}
              >
                <IconComponent className={`w-[18px] h-[18px] ${isActive ? "text-[#0A3464]" : "text-[#475569]"}`} />
              </div>
              <span
                className={`text-[11px] tracking-tight mt-1 text-center transition-colors ${
                  isActive ? "text-[#0A3464] font-bold" : "text-[#475569] font-medium group-hover:text-[#0F172A]"
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </div>
    </aside>
  );
};
