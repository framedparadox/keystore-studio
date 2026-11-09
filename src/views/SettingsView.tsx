import React, { useEffect, useRef, useState } from "react";
import { CheckCircle2, Clock, EyeOff, FolderOpen, Info, Keyboard, LifeBuoy, Monitor, Moon, Palette, RotateCcw, Settings2, ShieldCheck, Sun, TerminalSquare, Trash2 } from "lucide-react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { DEFAULT_SETTINGS, useStore, type Settings } from "../state/store";
import { FORMAT_INFO } from "../lib/keystore";
import { KEYSTORE_FORMATS, type KeystoreFormat } from "../types/crypto";
import { Button, Card, CardHeader, Checkbox, Kbd, Page, PageHeader, Segmented, Select, TextArea, TextInput, useConfirm, useToast } from "../components/ui";
import type { ThemePreference } from "../lib/theme";
import type { HelpLink } from "../lib/help";
import { HelpTopics } from "../components/HelpTopics";
import { PrivacyPolicy } from "../components/PrivacyPolicy";
import { TerminalHint, useTerminal } from "../components/Terminal";
import { joinPath, listFolderCommand, OS } from "../lib/platform";

const ENGINE = [
  "PKCS#12 reader/writer (PBES2/AES, legacy 3DES/RC2, SHA-1/SHA-2/PBMAC1 MACs, Java secret keys)",
  "JKS and JCEKS reader/writer (keytool compatible, incl. sealed secret keys) + read-only BKS v2",
  "X.509 certificates, PKCS#10 CSRs and v2 CRLs built and signed with your keys",
  "RSA (rsa), ECDSA P-256/384/521 (RustCrypto), Ed25519 (ed25519-dalek)",
  "CMS/PKCS#7 SignedData, JAR signing, RFC 3161 timestamps, JWS/JWT",
  "TLS inspection with rustls against the system trust store",
  "Vault: Argon2id + AES-256-GCM",
];

export const SHORTCUTS: [string, string][] = [
  ["Ctrl+O", "Open keystore or file"],
  ["Ctrl+N", "New keystore"],
  ["Ctrl+S", "Save keystore"],
  ["Ctrl+Shift+S", "Save keystore as…"],
  ["Ctrl+Z / Ctrl+Shift+Z", "Undo / redo"],
  ["Ctrl+K", "Command palette"],
  ["Ctrl+`", "Toggle terminal"],
  ["Ctrl+1 … Ctrl+8", "Switch page"],
  ["Ctrl+9", "Convert"],
  ["Ctrl+0", "Certificates"],
];

export type SectionId = "general" | "security" | "signing" | "terminal" | "shortcuts" | "data" | "help" | "about";

interface SectionDef {
  id: SectionId;
  label: string;
  icon: React.ElementType;
  /** Settings keys this section owns. Used for the "changed" marker and "Restore defaults". */
  keys: (keyof Settings)[];
}

const SECTIONS: SectionDef[] = [
  { id: "general", label: "General", icon: Settings2, keys: ["theme", "restoreSession", "defaultFormat", "rememberPasswordsByDefault", "criticalDays", "warningDays"] },
  { id: "security", label: "Security", icon: ShieldCheck, keys: ["requireKeyUnlock", "autoLockMinutes"] },
  { id: "signing", label: "Signing", icon: Clock, keys: ["tsaUrl", "tsaTrustPem", "timestampByDefault"] },
  { id: "terminal", label: "Terminal", icon: TerminalSquare, keys: ["terminalTimeoutSecs"] },
  { id: "shortcuts", label: "Keyboard shortcuts", icon: Keyboard, keys: [] },
  { id: "data", label: "Data", icon: FolderOpen, keys: [] },
  { id: "help", label: "Help", icon: LifeBuoy, keys: [] },
  { id: "about", label: "About", icon: Info, keys: [] },
];

/** Remembers the last section for the rest of the session, so returning to Settings lands where you left it. */
let rememberedSection: SectionId = "general";
const sectionListeners = new Set<(id: SectionId) => void>();

/** Shows a Settings section, e.g. Help from the command palette. Call before switching to the Settings page. */
export function showSettingsSection(id: SectionId) {
  rememberedSection = id;
  sectionListeners.forEach((l) => l(id));
}

const isChanged = (keys: (keyof Settings)[], settings: Settings) => keys.some((k) => settings[k] !== DEFAULT_SETTINGS[k]);

/*
 * Layout: every panel is a grid of cards. Cards sit side by side once the content column is wide
 * enough (@3xl = 48rem) and stack below that. The container query measures the content column,
 * so the layout follows the real space left after the sidebar, not the window size alone.
 */
const CardGrid: React.FC<{ children: React.ReactNode }> = ({ children }) => <div className="grid grid-cols-1 @3xl:grid-cols-2 gap-4 items-start">{children}</div>;

/** A card that spans the full row on wide content. */
const WideCard: React.FC<{ className?: string; children: React.ReactNode }> = ({ className, children }) => <Card className={`space-y-4 @3xl:col-span-2 ${className ?? ""}`}>{children}</Card>;

/**
 * A numeric setting that lets the user clear the field and retype. The typed text is shown as-is
 * while focused and clamped to [min, max] on every change; the clamped value is what gets stored.
 * (Showing the stored value during typing turned an empty field into the minimum, so "30" became "13".)
 */
const DraftNumber: React.FC<Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange" | "min" | "max" | "type"> & {
  label: string;
  hint?: string;
  value: number;
  min: number;
  max: number;
  onCommit: (value: number) => void;
}> = ({ value, min, max, onCommit, onBlur, ...rest }) => {
  const [draft, setDraft] = useState<string | null>(null);
  return (
    <TextInput
      {...rest}
      type="number"
      min={min}
      max={max}
      value={draft ?? String(value)}
      onChange={(e) => {
        setDraft(e.target.value);
        const n = Number(e.target.value);
        if (e.target.value.trim() !== "" && Number.isFinite(n)) onCommit(Math.min(max, Math.max(min, Math.round(n))));
      }}
      onBlur={(e) => {
        setDraft(null);
        onBlur?.(e);
      }}
    />
  );
};

/** Top navigation: one button per section, arrow keys move between them, a dot marks sections changed from defaults. */
const SettingsNav: React.FC<{ active: SectionId; onSelect: (id: SectionId) => void; settings: Settings; onRestore: () => void }> = ({ active, onSelect, settings, onRestore }) => {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});

  const move = (from: number, delta: number | "first" | "last") => {
    const last = SECTIONS.length - 1;
    const next = delta === "first" ? 0 : delta === "last" ? last : (from + delta + SECTIONS.length) % SECTIONS.length;
    onSelect(SECTIONS[next].id);
    refs.current[SECTIONS[next].id]?.focus();
  };

  return (
    <div className="sticky top-0 z-10 -mx-8 px-8 py-3 mb-5 bg-canvas/95 backdrop-blur border-b border-line flex items-center gap-3">
      {/* Narrow content: a dropdown, so the sections never need to scroll sideways. */}
      <div className="@md:hidden flex-1 min-w-0">
        <Select aria-label="Settings section" value={active} onChange={(e) => onSelect(e.target.value as SectionId)}>
          {SECTIONS.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
              {isChanged(s.keys, settings) ? " (changed)" : ""}
            </option>
          ))}
        </Select>
      </div>

      {/* Medium content: icon tabs. Wide content: icon and label. */}
      <div role="tablist" aria-label="Settings sections" className="hidden @md:flex flex-1 min-w-0 items-center gap-1">
        {SECTIONS.map((s, i) => {
          const selected = s.id === active;
          const changed = isChanged(s.keys, settings);
          return (
            <button
              key={s.id}
              ref={(el) => {
                refs.current[s.id] = el;
              }}
              id={`settings-tab-${s.id}`}
              type="button"
              role="tab"
              aria-label={s.label}
              title={s.label}
              aria-selected={selected}
              aria-controls={`settings-panel-${s.id}`}
              tabIndex={selected ? 0 : -1}
              data-testid={`settings-tab-${s.id}`}
              onClick={() => onSelect(s.id)}
              onKeyDown={(e) => {
                if (e.key === "ArrowRight") move(i, 1);
                else if (e.key === "ArrowLeft") move(i, -1);
                else if (e.key === "Home") move(i, "first");
                else if (e.key === "End") move(i, "last");
                else return;
                e.preventDefault();
              }}
              className={`relative h-9 px-2.5 @4xl:px-3 shrink-0 rounded-control text-[13px] font-medium inline-flex items-center gap-2 whitespace-nowrap transition cursor-pointer ${
                selected ? "bg-surface text-ink shadow-card border border-line" : "text-muted border border-transparent hover:bg-surface-3 hover:text-ink"
              }`}
            >
              <s.icon className={`w-4 h-4 shrink-0 ${selected ? "text-brand" : "text-subtle"}`} aria-hidden />
              <span className="hidden @4xl:inline">{s.label}</span>
              {changed && <span className="absolute top-1 right-1 @4xl:static w-1.5 h-1.5 rounded-full bg-brand" role="img" aria-label="Changed from default" />}
            </button>
          );
        })}
      </div>

      {/*
        Restores the open section only. It sits in the section bar, always in the same spot, and
        appears only when something in the section differs from its default. (A band above the
        cards pushed them down the moment a setting changed.)
      */}
      {isChanged(SECTIONS.find((s) => s.id === active)!.keys, settings) && (
        <Button size="sm" variant="ghost" icon={RotateCcw} onClick={onRestore} className="shrink-0" title="Restore this section's settings to their defaults" data-testid="settings-restore">
          Restore defaults
        </Button>
      )}
    </div>
  );
};

export const SettingsView: React.FC = () => {
  const { settings, updateSettings, appInfo, clearRecentFiles, resetAppData, recentFiles, keystores, setTab } = useStore();
  const confirm = useConfirm();
  const toast = useToast();
  const { open } = useTerminal();
  const [section, setSection] = useState<SectionId>(rememberedSection);
  const select = (id: SectionId) => {
    rememberedSection = id;
    setSection(id);
  };
  useEffect(() => {
    sectionListeners.add(setSection);
    return () => void sectionListeners.delete(setSection);
  }, []);
  const followHelpLink = (link: HelpLink) => ("tab" in link ? setTab(link.tab) : select(link.settings));
  const def = SECTIONS.find((s) => s.id === section)!;

  /** Restores the defaults for one section's keys only, with an undo. */
  const restore = (keys: (keyof Settings)[], label: string) => {
    const before = Object.fromEntries(keys.map((k) => [k, settings[k]])) as Partial<Settings>;
    updateSettings(Object.fromEntries(keys.map((k) => [k, DEFAULT_SETTINGS[k]])) as Partial<Settings>);
    toast.success(`${label} settings restored to defaults.`, { label: "Undo", onClick: () => updateSettings(before) });
  };

  const tsaUrl = settings.tsaUrl.trim();
  const tsaUrlInvalid = tsaUrl !== "" && !/^https?:\/\/\S+$/i.test(tsaUrl);

  const body = (() => {
    switch (section) {
      case "general":
        return (
          <CardGrid>
            <WideCard className="@3xl:flex @3xl:items-center @3xl:justify-between @3xl:gap-6 @3xl:space-y-0">
              <CardHeader title="Appearance" subtitle="Dark mode is pure black. System follows your operating system." icon={Palette} className="@3xl:!mb-0" />
              <Segmented<ThemePreference>
                label="Theme"
                value={settings.theme}
                onChange={(theme) => updateSettings({ theme })}
                options={[
                  { value: "system", label: <><Monitor className="w-3.5 h-3.5" aria-hidden /> System</> },
                  { value: "light", label: <><Sun className="w-3.5 h-3.5" aria-hidden /> Light</> },
                  { value: "dark", label: <><Moon className="w-3.5 h-3.5" aria-hidden /> Dark</> },
                ]}
              />
            </WideCard>
            <Card className="space-y-4">
              <CardHeader title="Startup and defaults" subtitle="How Keystore Studio starts and what it pre-fills." icon={Settings2} />
              <Checkbox checked={settings.restoreSession} onChange={(v) => updateSettings({ restoreSession: v })} label="Reopen keystores from the last session" hint="They start locked until you enter the password or unlock the vault." />
              <Select label="Default format for new keystores" value={settings.defaultFormat} onChange={(e) => updateSettings({ defaultFormat: e.target.value as KeystoreFormat })}>
                {KEYSTORE_FORMATS.map((f) => (
                  <option key={f} value={f}>
                    {FORMAT_INFO[f].label}
                  </option>
                ))}
              </Select>
              <Checkbox checked={settings.rememberPasswordsByDefault} onChange={(v) => updateSettings({ rememberPasswordsByDefault: v })} label="Pre-select “Remember password in vault”" />
            </Card>
            <Card className="space-y-4">
              <CardHeader title="Expiry warnings" subtitle="When certificates and keys are flagged." icon={ShieldCheck} />
              <div className="grid grid-cols-2 gap-3">
                <DraftNumber
                  data-testid="settings-critical-days"
                  label="Critical (days)"
                  min={1}
                  max={365}
                  value={settings.criticalDays}
                  // The warning window always contains the critical one, so it moves up with it.
                  onCommit={(v) => updateSettings({ criticalDays: v, warningDays: Math.max(settings.warningDays, v) })}
                  hint="Shown red"
                />
                <DraftNumber data-testid="settings-warning-days" label="Warning (days)" min={1} max={1095} value={settings.warningDays} onCommit={(v) => updateSettings({ warningDays: Math.max(settings.criticalDays, v) })} hint="Shown amber. Never lower than critical." />
              </div>
            </Card>
          </CardGrid>
        );

      case "security":
        return (
          <CardGrid>
            <Card className="space-y-4">
              <CardHeader title="Key access" subtitle="When a key pair can be used." icon={ShieldCheck} />
              <Checkbox
                checked={settings.requireKeyUnlock}
                onChange={(v) => updateSettings({ requireKeyUnlock: v })}
                label="Ask for the key password before a key pair can be used"
                hint="Key pairs open locked. Inspecting, exporting, copying or signing with one asks for its key password (the keystore password unless the key has its own) once per session."
              />
            </Card>
            <Card className="space-y-4">
              <CardHeader title="Vault" subtitle="When the encrypted vault locks itself." icon={Clock} />
              <Select label="Lock the vault after inactivity" value={settings.autoLockMinutes} onChange={(e) => updateSettings({ autoLockMinutes: Number(e.target.value) })}>
                {[5, 15, 30, 60, 240].map((m) => (
                  <option key={m} value={m}>
                    {m} minutes
                  </option>
                ))}
                <option value={0}>Never</option>
              </Select>
            </Card>
          </CardGrid>
        );

      case "signing":
        return (
          <CardGrid>
            <Card className="space-y-4">
              <CardHeader title="Timestamp authority" subtitle="Trusted timestamps for CMS and JAR signatures." icon={Clock} />
              <p className="text-[13px] text-muted">
                A trusted timestamp records <em>when</em> you signed, so signatures keep verifying after the signing certificate expires. Without one, verifiers reject an expired
                signer. This is the only network request signing makes, and only when it is switched on.
              </p>
              <TextInput
                label="Timestamp authority (TSA) URL"
                value={settings.tsaUrl}
                onChange={(e) => updateSettings({ tsaUrl: e.target.value })}
                placeholder="http://timestamp.digicert.com"
                error={tsaUrlInvalid ? "Must start with http:// or https://" : undefined}
                hint="Your certificate authority usually runs one. Free options include DigiCert and Sectigo."
              />
              <Checkbox
                checked={settings.timestampByDefault}
                onChange={(v) => updateSettings({ timestampByDefault: v })}
                label="Timestamp new signatures by default"
                hint={tsaUrl && !tsaUrlInvalid ? "Applies to CMS signatures and signed JARs." : "Set a TSA URL first."}
              />
            </Card>
            <Card className="space-y-4">
              <CardHeader title="Trust anchors" subtitle="Decides whether a timestamp is trusted." icon={ShieldCheck} />
              <TextArea
                label="TSA trust anchors (PEM)"
                value={settings.tsaTrustPem}
                onChange={(e) => updateSettings({ tsaTrustPem: e.target.value })}
                rows={6}
                mono
                hint="A timestamp is reported as trusted only when the token's certificates chain to this bundle. Leave it empty to record the time without a trust decision."
              />
            </Card>
          </CardGrid>
        );

      case "terminal":
        return (
          <CardGrid>
            <WideCard>
              <CardHeader title="Terminal" subtitle="A shell for keytool and openssl commands." icon={TerminalSquare} />
              <p className="text-[13px] text-muted">
                Toggle it anywhere with <Kbd>Ctrl+`</Kbd>. Commands run without a terminal attached, so interactive prompts are not supported; pass passwords as arguments (e.g.{" "}
                <code className="font-mono">-storepass</code>).
              </p>
              <div className="grid grid-cols-1 @md:grid-cols-[minmax(0,16rem)_auto] gap-4 items-end">
                <DraftNumber data-testid="settings-terminal-timeout" label="Stop commands after (seconds)" min={5} max={3600} value={settings.terminalTimeoutSecs} onCommit={(v) => updateSettings({ terminalTimeoutSecs: v })} />
                <div>
                  <Button icon={TerminalSquare} onClick={() => open()}>
                    Open terminal
                  </Button>
                </div>
              </div>
            </WideCard>
          </CardGrid>
        );

      case "shortcuts":
        return (
          <CardGrid>
            <WideCard>
              <CardHeader title="Keyboard shortcuts" subtitle={OS === "macos" ? "Ctrl also works in place of ⌘." : "On macOS these use ⌘ instead of Ctrl."} icon={Keyboard} />
              <ul className="grid grid-cols-1 @3xl:grid-cols-2 gap-x-8">
                {SHORTCUTS.map(([k, label]) => (
                  <li key={k} className="flex items-center justify-between gap-3 py-2.5 text-[13px] border-b border-line">
                    <span className="text-ink-2">{label}</span>
                    <Kbd>{k}</Kbd>
                  </li>
                ))}
              </ul>
            </WideCard>
          </CardGrid>
        );

      case "data":
        return (
          <CardGrid>
            <Card className="space-y-4">
              <CardHeader title="Data" subtitle="Where Keystore Studio keeps its own state." icon={FolderOpen} />
              <p className="text-[13px] text-muted">Session state, workspaces, labels and the encrypted vault live in:</p>
              <div className="p-3 rounded-control bg-surface-2 border border-line font-mono text-[12px] text-ink break-all select-text">{appInfo?.data_dir ?? "—"}</div>
              <div className="flex flex-wrap gap-2">
                {appInfo && (
                  <Button icon={FolderOpen} onClick={() => void revealItemInDir(joinPath(appInfo.data_dir, "state.json")).catch(() => toast.info("Nothing saved there yet."))}>
                    Show folder
                  </Button>
                )}
                <Button
                  onClick={() => {
                    const lines = [
                      `Keystore Studio ${appInfo?.version ?? "unknown"}`,
                      `platform ${appInfo?.platform ?? "unknown"}`,
                      `data_dir ${appInfo?.data_dir ?? ""}`,
                      ...keystores.map((k) => `${k.format} ${k.name} entries=${k.entries.length} locked=${k.entries.filter((e) => e.locked).length} aliases=${k.entries.map((e) => e.alias).join(",")}`),
                    ];
                    void navigator.clipboard.writeText(lines.join("\n")).then(
                      () => toast.success("Copied diagnostics. Passwords and key material are not included."),
                      () => toast.error("Could not copy diagnostics."),
                    );
                  }}
                >
                  Copy diagnostics
                </Button>
                <Button
                  icon={Trash2}
                  disabled={!recentFiles.length}
                  onClick={() => {
                    clearRecentFiles();
                    toast.success("Recent files cleared.");
                  }}
                >
                  Clear recent files
                </Button>
              </div>
              {appInfo && <TerminalHint command={listFolderCommand(appInfo.data_dir)} label="List" />}
            </Card>

            <Card className="space-y-4 border-danger/30">
              <CardHeader title="Reset app data" subtitle="Deletes workspaces, labels, the Certificates list, recent files and settings. Keystore and certificate files and the vault are not touched." icon={RotateCcw} />
              <div>
                <Button
                  variant="danger"
                  icon={RotateCcw}
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Reset Keystore Studio data?",
                      message: "Deletes workspaces, labels, the Certificates list, recent files and settings. Keystore and certificate files and the vault are not touched.",
                      confirmLabel: "Reset",
                      danger: true,
                    });
                    if (ok === true) {
                      await resetAppData();
                      toast.success("Application data reset.");
                    }
                  }}
                >
                  Reset app data
                </Button>
              </div>
            </Card>
          </CardGrid>
        );

      case "help":
        return (
          <CardGrid>
            <WideCard>
              <CardHeader title="Help" subtitle="Answers to common questions. Keyboard shortcuts have their own tab." icon={LifeBuoy} />
              <HelpTopics onNavigate={followHelpLink} />
            </WideCard>
          </CardGrid>
        );

      case "about":
        return (
          <CardGrid>
            <WideCard>
              <CardHeader title="About Keystore Studio" subtitle={appInfo ? `Version ${appInfo.version} · ${appInfo.platform}` : undefined} icon={Info} />
              <p className="text-[13px] text-muted">All cryptography runs locally in the bundled Rust engine. What the app stores and the few requests it makes are listed in the privacy policy below.</p>
              <ul className="grid grid-cols-1 @3xl:grid-cols-2 gap-x-8 gap-y-1.5 text-[13px]">
                {ENGINE.map((p) => (
                  <li key={p} className="flex items-start gap-2 text-ink-2">
                    <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-success shrink-0" />
                    {p}
                  </li>
                ))}
              </ul>
              <p className="text-[12px] text-faint">Not supported: Bouncy Castle BCFKS/UBER keystores (BKS v2 is read-only), hardware tokens (PKCS#11).</p>
            </WideCard>
            <WideCard>
              <CardHeader title="Privacy policy" subtitle="What Keystore Studio keeps, and what leaves your computer." icon={EyeOff} />
              <PrivacyPolicy dataDir={appInfo?.data_dir} />
            </WideCard>
          </CardGrid>
        );
    }
  })();

  return (
    <Page>
      <PageHeader title="Settings" description="Preferences are saved automatically on this computer." />
      {/* The container query measures the content column, which shrinks when the sidebar is open. */}
      <div className="@container">
        <SettingsNav active={section} onSelect={select} settings={settings} onRestore={() => restore(def.keys, def.label)} />
        <div role="tabpanel" id={`settings-panel-${section}`} aria-label={def.label} className="max-w-5xl min-w-0">
          {body}
        </div>
      </div>
    </Page>
  );
};
