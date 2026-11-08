import React, { useEffect, useState } from "react";
import clsx from "clsx";
import {
  ArrowLeftRight,
  Binary,
  ChevronDown,
  ChevronRight,
  FileBadge,
  FileKey2,
  FileOutput,
  FileSignature,
  FolderArchive,
  KeyRound,
  LayoutDashboard,
  Layers,
  Lock,
  LockOpen,
  Package,
  PanelLeftClose,
  PanelLeftOpen,
  Repeat,
  SearchCode,
  Settings,
  ShieldCheck,
} from "lucide-react";
import type { TabType } from "../types/crypto";
import { useStore } from "../state/store";
import { entryHealth } from "../lib/metrics";
import { CONVERTERS, type ConverterId } from "../lib/convert";

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
      { id: "convert", label: "Convert", icon: ArrowLeftRight, shortcut: "9" },
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
  convert: "Convert",
  scanner: "Security audit",
  vault: "Vault",
  settings: "Settings",
};

/** Icon for each converter, shared by the sidebar, the Convert page and the command palette. */
export const CONVERTER_ICONS: Record<ConverterId, React.ElementType> = {
  certificate: FileBadge,
  private_key: FileKey2,
  public_key: KeyRound,
  keystore: Repeat,
  pkcs12: Package,
  extract: FileOutput,
  encoding: Binary,
};

const COLLAPSED_KEY = "xkeystore.sidebarCollapsed";
const CONVERT_OPEN_KEY = "xkeystore.convertExpanded";

const readFlag = (key: string, fallback: boolean) => {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : v === "true";
  } catch {
    return fallback;
  }
};
const writeFlag = (key: string, value: boolean) => {
  try {
    localStorage.setItem(key, String(value));
  } catch {
    /* private mode */
  }
};

export const Sidebar: React.FC = () => {
  const { tab, setTab, keystores, workspaces, vault, convertMode, openConverter } = useStore();
  const [collapsed, setCollapsed] = useState(() => readFlag(COLLAPSED_KEY, false));
  const [convertOpen, setConvertOpen] = useState(() => readFlag(CONVERT_OPEN_KEY, true));
  useEffect(() => {
    document.documentElement.style.setProperty("--sidebar-w", collapsed ? "64px" : "240px");
    writeFlag(COLLAPSED_KEY, collapsed);
  }, [collapsed]);
  useEffect(() => writeFlag(CONVERT_OPEN_KEY, convertOpen), [convertOpen]);

  const atRisk = keystores.flatMap((k) => k.entries).filter((e) => entryHealth(e) === "at-risk").length;
  const unsaved = keystores.some((k) => k.dirty);
  const counts: Partial<Record<TabType, { value: number; tone?: "danger" | "neutral" }>> = {
    keystores: { value: keystores.length },
    workspaces: { value: workspaces.length },
    scanner: { value: atRisk, tone: "danger" },
  };

  const NavButton: React.FC<{ item: NavItem }> = ({ item }) => {
    const isConvert = item.id === "convert";
    // With the conversions listed underneath, the open one is highlighted instead of the parent.
    const active = tab === item.id && !(isConvert && convertMode && convertOpen && !collapsed);
    const count = counts[item.id];
    const Icon = item.id === "vault" ? (vault.unlocked ? LockOpen : Lock) : item.icon;
    return (
      <button
        onClick={() => {
          if (isConvert) {
            openConverter(null);
            setConvertOpen((open) => collapsed ? true : !open);
          } else setTab(item.id);
        }}
        aria-current={active ? "page" : undefined}
        aria-expanded={isConvert && !collapsed ? convertOpen : undefined}
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
            {isConvert && (convertOpen ? <ChevronDown className="w-3.5 h-3.5 shrink-0 text-subtle" /> : <ChevronRight className="w-3.5 h-3.5 shrink-0 text-subtle" />)}
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

  /** The conversions, listed under Convert so each one is a click away. */
  const ConvertItems: React.FC = () =>
    collapsed || !convertOpen ? null : (
      <div className="mt-0.5 mb-1 ml-[18px] pl-2 border-l border-line space-y-0.5" role="group" aria-label="Conversions">
        {CONVERTERS.map((c) => {
          const Icon = CONVERTER_ICONS[c.id];
          const active = tab === "convert" && convertMode === c.id;
          return (
            <button
              key={c.id}
              onClick={() => openConverter(c.id)}
              aria-current={active ? "page" : undefined}
              title={`${c.title} — ${c.short}`}
              data-testid={`nav-convert-${c.id}`}
              className={clsx(
                "w-full h-7 rounded-control flex items-center gap-2 px-2 text-[13px] transition cursor-pointer",
                active ? "bg-surface-3 text-ink font-semibold" : "text-muted font-medium hover:bg-surface-2 hover:text-ink"
              )}
            >
              <Icon className={clsx("w-3.5 h-3.5 shrink-0", active ? "text-brand" : "text-subtle")} />
              <span className="flex-1 text-left truncate">{c.nav}</span>
            </button>
          );
        })}
      </div>
    );

  return (
    <aside className={clsx("shrink-0 h-full flex flex-col bg-chrome border-r border-line transition-all duration-200 overflow-hidden", collapsed ? "w-[64px]" : "w-[240px]")}>
      <div className={clsx("h-14 flex items-center shrink-0", collapsed ? "justify-center px-0" : "px-5 gap-2.5")}>
        <button onClick={() => setTab("home")} className="flex items-center gap-2.5 cursor-pointer min-w-0" aria-label="xkeystore dashboard" title="xkeystore">
          <span className="w-7 h-7 rounded-control bg-brand flex items-center justify-center shadow-card shrink-0">
            <KeyRound className="w-4 h-4 text-white" />
          </span>
          {!collapsed && <span className="font-semibold text-[15px] tracking-[-0.01em] text-ink truncate">xkeystore</span>}
        </button>
        {!collapsed && (
          <button
            onClick={() => setCollapsed(true)}
            title="Collapse sidebar"
            aria-label="Collapse sidebar"
            className="ml-auto w-7 h-7 rounded-control flex items-center justify-center text-subtle hover:bg-surface-2 hover:text-ink transition cursor-pointer shrink-0"
          >
            <PanelLeftClose className="w-4 h-4" />
          </button>
        )}
      </div>
      {collapsed && (
        <div className="px-2 pb-1 flex justify-center shrink-0">
          <button
            onClick={() => setCollapsed(false)}
            title="Expand sidebar"
            aria-label="Expand sidebar"
            className="w-9 h-7 rounded-control flex items-center justify-center text-subtle hover:bg-surface-2 hover:text-ink transition cursor-pointer"
          >
            <PanelLeftOpen className="w-4 h-4" />
          </button>
        </div>
      )}

      <nav className={clsx("flex-1 overflow-y-auto pt-1", collapsed ? "px-2" : "px-3")} aria-label="Primary">
        {NAV_GROUPS.map((g, i) => (
          <div key={i}>
            {i > 0 && <div className={clsx("my-3 border-t border-line", collapsed ? "mx-1" : "mx-2.5")} role="separator" />}
            {g.label && !collapsed && <div className="px-2.5 mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-subtle">{g.label}</div>}
            <div className="space-y-0.5">
              {g.items.map((item) =>
                item.id === "convert" ? (
                  <React.Fragment key={item.id}>
                    <NavButton item={item} />
                    <ConvertItems />
                  </React.Fragment>
                ) : (
                  <NavButton key={item.id} item={item} />
                )
              )}
            </div>
          </div>
        ))}
      </nav>

      <div className={clsx("py-3 border-t border-line", collapsed ? "px-2" : "px-3")}>
        <NavButton item={{ id: "settings", label: "Settings", icon: Settings, shortcut: "8" }} />
      </div>
    </aside>
  );
};
