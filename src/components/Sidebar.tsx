import React from "react";
import clsx from "clsx";
import {
  LayoutDashboard,
  Layers,
  FolderArchive,
  FileSignature,
  SearchCode,
  ShieldCheck,
  KeyRound,
  Settings,
} from "lucide-react";
import { TabType, Workspace } from "../types/crypto";

interface SidebarProps {
  currentTab: TabType;
  onSelectTab: (tab: TabType) => void;
  workspaces: Workspace[];
  activeWorkspaceId: string;
  onSelectWorkspace: (id: string) => void;
  counts: Partial<Record<TabType, { value: number; tone?: "neutral" | "danger" }>>;
}

type NavItem = { id: TabType; label: string; icon: React.ElementType };

const GROUPS: { label?: string; items: NavItem[] }[] = [
  { items: [{ id: "home", label: "Dashboard", icon: LayoutDashboard }] },
  {
    label: "Inventory",
    items: [
      { id: "keystores", label: "Keystores", icon: FolderArchive },
      { id: "workspaces", label: "Workspaces", icon: Layers },
      { id: "passwords", label: "Vaults", icon: KeyRound },
    ],
  },
  {
    label: "Operations",
    items: [
      { id: "ca_signing", label: "CA & Signing", icon: FileSignature },
      { id: "examine", label: "Examine", icon: SearchCode },
      { id: "scanner", label: "Security", icon: ShieldCheck },
    ],
  },
];

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  counts,
}) => {
  const NavButton: React.FC<{ item: NavItem }> = ({ item }) => {
    const active = currentTab === item.id;
    const count = counts[item.id];
    const Icon = item.icon;
    return (
      <button
        onClick={() => onSelectTab(item.id)}
        aria-current={active ? "page" : undefined}
        className={clsx(
          "w-full h-8 px-2.5 rounded-control flex items-center gap-2.5 text-[13px] transition cursor-pointer",
          active ? "bg-surface-3 text-ink font-semibold" : "text-muted font-medium hover:bg-surface-2 hover:text-ink"
        )}
      >
        <Icon className={clsx("w-4 h-4 shrink-0", active ? "text-brand" : "text-subtle")} />
        <span className="flex-1 text-left truncate">{item.label}</span>
        {count && count.value > 0 && (
          <span
            className={clsx(
              "min-w-5 h-5 px-1.5 rounded-full text-[11px] font-semibold tabular-nums flex items-center justify-center",
              count.tone === "danger" ? "bg-danger-tint text-danger" : "bg-surface-3 text-faint"
            )}
          >
            {count.value}
          </span>
        )}
      </button>
    );
  };

  return (
    <aside className="w-[240px] shrink-0 h-full flex flex-col bg-chrome border-r border-line">
      {/* Brand */}
      <button
        onClick={() => onSelectTab("home")}
        className="h-14 px-5 flex items-center gap-2.5 cursor-pointer shrink-0"
        aria-label="xkeystore dashboard"
      >
        <span className="w-7 h-7 rounded-control bg-brand flex items-center justify-center shadow-card">
          <KeyRound className="w-4 h-4 text-white" />
        </span>
        <span className="font-semibold text-[15px] tracking-[-0.01em] text-ink">xkeystore</span>
      </button>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 space-y-5 pt-1" aria-label="Primary">
        {GROUPS.map((g, i) => (
          <div key={i}>
            {g.label && (
              <div className="px-2.5 mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-subtle">{g.label}</div>
            )}
            <div className="space-y-0.5">
              {g.items.map((item) => (
                <NavButton key={item.id} item={item} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-3 py-3 border-t border-line">
        <NavButton item={{ id: "settings", label: "Settings", icon: Settings }} />
        <div className="mt-2 px-2.5 flex items-center gap-2 text-[11.5px] text-faint">
          <span className="w-1.5 h-1.5 rounded-full bg-success-fill" />
          Native Rust engine · offline
        </div>
      </div>
    </aside>
  );
};
