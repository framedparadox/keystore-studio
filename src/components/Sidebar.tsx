import React, { useEffect, useState } from "react";
import clsx from "clsx";
import { FileSignature, FolderArchive, KeyRound, LayoutDashboard, Layers, Lock, LockOpen, PanelLeftClose, PanelLeftOpen, SearchCode, Settings, ShieldCheck } from "lucide-react";
import type { TabType } from "../types/crypto";
import { useStore } from "../state/store";
import { entryHealth } from "../lib/metrics";

type NavItem = { id: TabType; label: string; icon: React.ElementType; shortcut: string };

export const NAV_GROUPS: { label?: string; items: NavItem[] }[] = [
  { items: [{ id: "home", label: "Dashboard", icon: LayoutDashboard, shortcut: "1" }] },
  {
    label: "Inventory",
    items: [
      { id: "keystores", label: "Keystores", icon: FolderArchive, shortcut: "2" },
      { id: "workspaces", label: "Workspaces", icon: Layers, shortcut: "3" },
    ],
  },
  {
    label: "Tools",
    items: [
      { id: "examine", label: "Examine", icon: SearchCode, shortcut: "4" },
      { id: "ca_signing", label: "CA & Signing", icon: FileSignature, shortcut: "5" },
    ],
  },
  {
    label: "Security",
    items: [
      { id: "scanner", label: "Security audit", icon: ShieldCheck, shortcut: "6" },
      { id: "vault", label: "Vault", icon: KeyRound, shortcut: "7" },
    ],
  },
];

export const PAGE_TITLES: Record<TabType, string> = {
  home: "Dashboard",
  keystores: "Keystores",
  workspaces: "Workspaces",
  examine: "Examine",
  ca_signing: "CA & Signing",
  scanner: "Security audit",
  vault: "Vault",
  settings: "Settings",
};

const COLLAPSED_KEY = "xkeystore.sidebarCollapsed";

export const Sidebar: React.FC = () => {
  const { tab, setTab, keystores, workspaces, vault } = useStore();
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSED_KEY) === "true";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    document.documentElement.style.setProperty("--sidebar-w", collapsed ? "64px" : "240px");
    try {
      localStorage.setItem(COLLAPSED_KEY, String(collapsed));
    } catch {
      /* private mode */
    }
  }, [collapsed]);

  const atRisk = keystores.flatMap((k) => k.entries).filter((e) => entryHealth(e) === "at-risk").length;
  const unsaved = keystores.some((k) => k.dirty);
  const counts: Partial<Record<TabType, { value: number; tone?: "danger" | "neutral" }>> = {
    keystores: { value: keystores.length },
    workspaces: { value: workspaces.length },
    scanner: { value: atRisk, tone: "danger" },
  };

  const NavButton: React.FC<{ item: NavItem }> = ({ item }) => {
    const active = tab === item.id;
    const count = counts[item.id];
    const Icon = item.id === "vault" ? (vault.unlocked ? LockOpen : Lock) : item.icon;
    return (
      <button
        onClick={() => setTab(item.id)}
        aria-current={active ? "page" : undefined}
        title={`${item.label} (Ctrl+${item.shortcut})`}
        data-testid={`nav-${item.id}`}
        className={clsx(
          "w-full h-8 rounded-control flex items-center text-[13px] transition cursor-pointer",
          collapsed ? "justify-center px-0" : "px-2.5 gap-2.5",
          active ? "bg-surface-3 text-ink font-semibold" : "text-muted font-medium hover:bg-surface-2 hover:text-ink"
        )}
      >
        <Icon className={clsx("w-4 h-4 shrink-0", active ? "text-brand" : "text-subtle")} />
        {!collapsed && (
          <>
            <span className="flex-1 text-left truncate">{item.label}</span>
            {item.id === "keystores" && unsaved && <span className="w-1.5 h-1.5 rounded-full bg-warning-fill" title="Unsaved changes" />}
            {item.id === "vault" && vault.exists && <span className={clsx("text-[11px]", vault.unlocked ? "text-success" : "text-faint")}>{vault.unlocked ? "Unlocked" : "Locked"}</span>}
            {count && count.value > 0 && (
              <span className={clsx("min-w-5 h-5 px-1.5 rounded-full text-[11px] font-semibold tabular-nums flex items-center justify-center", count.tone === "danger" ? "bg-danger-tint text-danger" : "bg-surface-3 text-faint")}>{count.value}</span>
            )}
          </>
        )}
      </button>
    );
  };

  return (
    <aside className={clsx("shrink-0 h-full flex flex-col bg-chrome border-r border-line transition-all duration-200 overflow-hidden", collapsed ? "w-[64px]" : "w-[240px]")}>
      <div className={clsx("h-14 flex items-center shrink-0", collapsed ? "justify-center px-0" : "px-5 gap-2.5")}>
        <button onClick={() => setTab("home")} className="flex items-center gap-2.5 cursor-pointer" aria-label="xkeystore dashboard" title="xkeystore">
          <span className="w-7 h-7 rounded-control bg-brand flex items-center justify-center shadow-card shrink-0">
            <KeyRound className="w-4 h-4 text-white" />
          </span>
          {!collapsed && <span className="font-semibold text-[15px] tracking-[-0.01em] text-ink">xkeystore</span>}
        </button>
      </div>

      <nav className={clsx("flex-1 overflow-y-auto space-y-5 pt-1", collapsed ? "px-2" : "px-3")} aria-label="Primary">
        {NAV_GROUPS.map((g, i) => (
          <div key={i}>
            {g.label && !collapsed && <div className="px-2.5 mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-subtle">{g.label}</div>}
            <div className="space-y-0.5">
              {g.items.map((item) => (
                <NavButton key={item.id} item={item} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className={clsx("py-3 border-t border-line", collapsed ? "px-2" : "px-3")}>
        <NavButton item={{ id: "settings", label: "Settings", icon: Settings, shortcut: "8" }} />
        {!collapsed && (
          <div className="mt-2 px-2.5 flex items-center gap-2 text-[11.5px] text-faint">
            <span className="w-1.5 h-1.5 rounded-full bg-success-fill" />
            Local Rust engine · offline
          </div>
        )}
        <button
          onClick={() => setCollapsed((c) => !c)}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className={clsx("mt-2 w-full h-8 rounded-control flex items-center text-[13px] text-muted font-medium hover:bg-surface-2 hover:text-ink transition cursor-pointer", collapsed ? "justify-center px-0" : "px-2.5 gap-2.5")}
        >
          {collapsed ? (
            <PanelLeftOpen className="w-4 h-4 shrink-0 text-subtle" />
          ) : (
            <>
              <PanelLeftClose className="w-4 h-4 shrink-0 text-subtle" />
              <span className="flex-1 text-left truncate">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
};
