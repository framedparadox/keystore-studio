import React, { useEffect, useState, useSyncExternalStore } from "react";
import clsx from "clsx";
import {
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
  Moon,
  Package,
  PanelLeftClose,
  Repeat,
  SearchCode,
  ShieldCheck,
  Sun,
  TerminalSquare,
  Wrench,
} from "lucide-react";
import type { TabType } from "../types/crypto";
import { useStore } from "../state/store";
import { entryHealth } from "../lib/metrics";
import { CONVERTERS, type ConverterId } from "../lib/convert";
import { shortcutLabel } from "../lib/platform";
import { resolveTheme, systemTheme, watchSystemTheme } from "../lib/theme";
import { IconButton } from "./ui";
import { useTerminal } from "./Terminal";
import { showSettingsSection } from "../views/SettingsView";

type NavItem = { id: TabType; label: string; icon: React.ElementType; shortcut: string };

export const ConvertIcon: React.FC<React.HTMLAttributes<HTMLSpanElement>> = ({ className, ...props }) => (
  <span
    {...props}
    aria-hidden="true"
    className={clsx("shrink-0 bg-current", className)}
    style={{ mask: "url('/convert-icon.png') center / contain no-repeat", WebkitMask: "url('/convert-icon.png') center / contain no-repeat" }}
  />
);

export const NAV_GROUPS: { label?: string; items: NavItem[] }[] = [
  { items: [
    { id: "home", label: "Dashboard", icon: LayoutDashboard, shortcut: "1" },
    { id: "workspaces", label: "Workspaces", icon: Layers, shortcut: "3" },
  ] },
  {
    label: "Inventory",
    items: [
      { id: "keystores", label: "Keystores", icon: FolderArchive, shortcut: "2" },
      // Ctrl+0: the page came after 1–9 were taken, and the older shortcuts keep their numbers.
      { id: "certificates", label: "Certificates", icon: FileBadge, shortcut: "0" },
    ],
  },
  {
    label: "Tools",
    items: [
      { id: "examine", label: "Examine", icon: SearchCode, shortcut: "4" },
      { id: "ca_signing", label: "CA & Signing", icon: FileSignature, shortcut: "5" },
      { id: "convert", label: "Convert", icon: ConvertIcon, shortcut: "9" },
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
  certificates: "Certificates",
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

const COLLAPSED_KEY = "keystore-studio.sidebarCollapsed";
const CONVERT_OPEN_KEY = "keystore-studio.convertExpanded";

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

/**
 * Whether the sidebar is collapsed to its icon rail, remembered across launches. App owns it: the
 * sidebar provides controls to collapse and expand itself.
 */
export const useSidebarCollapsed = () => {
  const [collapsed, setCollapsed] = useState(() => readFlag(COLLAPSED_KEY, false));
  useEffect(() => {
    document.documentElement.style.setProperty("--sidebar-w", collapsed ? "64px" : "240px");
    writeFlag(COLLAPSED_KEY, collapsed);
  }, [collapsed]);
  return [collapsed, setCollapsed] as const;
};

export const Sidebar: React.FC<{ collapsed: boolean; onCollapse: () => void; onExpand: () => void }> = ({ collapsed, onCollapse, onExpand }) => {
  const { tab, setTab, keystores, certificates, workspaces, vault, convertMode, openConverter, settings, updateSettings } = useStore();
  const { toggle: toggleTerminal } = useTerminal();
  const system = useSyncExternalStore(watchSystemTheme, systemTheme, () => "light" as const);
  const theme = resolveTheme(settings.theme, system);
  const [convertOpen, setConvertOpen] = useState(() => readFlag(CONVERT_OPEN_KEY, false));
  useEffect(() => writeFlag(CONVERT_OPEN_KEY, convertOpen), [convertOpen]);

  const atRisk = keystores.flatMap((k) => k.entries).filter((e) => entryHealth(e) === "at-risk").length;
  const unsaved = keystores.some((k) => k.dirty);
  const counts: Partial<Record<TabType, { value: number; tone?: "danger" | "neutral" }>> = {
    keystores: { value: keystores.length },
    certificates: { value: certificates.length },
    workspaces: { value: workspaces.length },
    scanner: { value: atRisk, tone: "danger" },
  };

  const NavButton: React.FC<{ item: NavItem }> = ({ item }) => {
    const isConvert = item.id === "convert";
    // With the conversions listed underneath, the open one is highlighted instead of the parent.
    const active = tab === item.id && !(isConvert && convertMode && convertOpen && !collapsed);
    const count = counts[item.id];
    const vaultStatus = vault.unlocked ? "Vault unlocked" : "Vault locked";
    const VaultStatusIcon = vault.unlocked ? LockOpen : Lock;
    const Icon = item.id === "vault" && collapsed ? VaultStatusIcon : item.icon;
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
        aria-label={item.id === "vault" && collapsed && vault.exists ? vaultStatus : undefined}
        title={shortcutLabel(`${item.label} (Ctrl+${item.shortcut})${item.id === "vault" && vault.exists ? ` — ${vaultStatus}` : ""}`)}
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
            {item.id === "vault" && vault.exists && (
              <span role="img" aria-label={vaultStatus} title={vaultStatus} className={clsx("shrink-0", vault.unlocked ? "text-success" : "text-faint")}>
                <VaultStatusIcon className="w-4 h-4" aria-hidden />
              </span>
            )}
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
        <button onClick={() => setTab("home")} className="flex items-center gap-2.5 cursor-pointer min-w-0" aria-label="Keystore Studio dashboard" title="Keystore Studio">
          <img
            src="/icon.png"
            alt="Keystore Studio"
            className="w-7 h-7 rounded-control object-cover shadow-card shrink-0 dark:hidden"
          />
          <img
            src="/icon-l.png"
            alt="Keystore Studio"
            className="hidden w-7 h-7 rounded-control object-cover shadow-card shrink-0 dark:block"
          />
          {!collapsed && <span className="font-semibold text-[15px] tracking-[-0.01em] text-ink truncate">Keystore Studio</span>}
        </button>
      </div>
      <nav className={clsx("shell-accent flex-1 min-h-0 overflow-y-auto pt-1 flex flex-col", collapsed ? "px-2" : "px-3")} aria-label="Primary">
        {NAV_GROUPS.map((g, i) => (
          <div key={i} className="shrink-0">
            {i > 0 && <div className={clsx("my-3 border-t border-line", collapsed ? "mx-1" : "mx-2.5")} role="separator" />}
            {g.label && !collapsed && <div className="px-2.5 mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-faint">{g.label}</div>}
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
      <div className="shell-accent shrink-0 px-3 pb-3">
        <div className="w-1/2 mx-auto border-t border-line" role="separator" />
        <div className={clsx("flex items-center pt-2", collapsed ? "justify-center" : "justify-between")}>
          {collapsed ? (
            <IconButton icon={ChevronRight} label="Expand sidebar" onClick={onExpand} className="!w-9 !h-9" data-testid="sidebar-expand" />
          ) : (
            <>
              <IconButton icon={PanelLeftClose} label="Collapse sidebar" onClick={onCollapse} className="!w-9 !h-9" data-testid="sidebar-collapse" />
              <IconButton
                icon={theme === "dark" ? Sun : Moon}
                label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
                onClick={() => updateSettings({ theme: theme === "dark" ? "light" : "dark" })}
                className="!w-9 !h-9"
                data-testid="sidebar-theme"
              />
              <IconButton
                icon={Wrench}
                label="Tools"
                onClick={() => {
                  showSettingsSection("tools");
                  setTab("settings");
                }}
                className="!w-9 !h-9"
                data-testid="sidebar-tools"
              />
              <IconButton icon={TerminalSquare} label={shortcutLabel("Terminal (Ctrl+`)")} onClick={toggleTerminal} className="!w-9 !h-9" data-testid="sidebar-terminal" />
            </>
          )}
        </div>
      </div>
    </aside>
  );
};
