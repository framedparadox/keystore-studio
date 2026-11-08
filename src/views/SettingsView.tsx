import React, { useRef, useState } from "react";
import { CheckCircle2, Clock, FolderOpen, Info, Keyboard, RotateCcw, Settings2, ShieldCheck, TerminalSquare, Trash2 } from "lucide-react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { DEFAULT_SETTINGS, useStore, type Settings } from "../state/store";
import { FORMAT_INFO } from "../lib/keystore";
import { KEYSTORE_FORMATS, type KeystoreFormat } from "../types/crypto";
import { Button, Card, CardHeader, Checkbox, Kbd, Page, PageHeader, Select, TextArea, TextInput, useConfirm, useToast } from "../components/ui";
import { TerminalHint, useTerminal } from "../components/Terminal";

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
];

type SectionId = "general" | "security" | "signing" | "terminal" | "shortcuts" | "data" | "about";

interface SectionDef {
  id: SectionId;
  label: string;
  icon: React.ElementType;
  /** Settings keys this section owns. Used for the "changed" marker and "Restore defaults". */
  keys: (keyof Settings)[];
}

const SECTIONS: SectionDef[] = [
  { id: "general", label: "General", icon: Settings2, keys: ["restoreSession", "defaultFormat", "rememberPasswordsByDefault", "criticalDays", "warningDays"] },
  { id: "security", label: "Security", icon: ShieldCheck, keys: ["requireKeyUnlock", "autoLockMinutes"] },
  { id: "signing", label: "Signing", icon: Clock, keys: ["tsaUrl", "tsaTrustPem", "timestampByDefault"] },
  { id: "terminal", label: "Terminal", icon: TerminalSquare, keys: ["terminalTimeoutSecs"] },
  { id: "shortcuts", label: "Keyboard shortcuts", icon: Keyboard, keys: [] },
  { id: "data", label: "Data", icon: FolderOpen, keys: [] },
  { id: "about", label: "About", icon: Info, keys: [] },
];

/** Remembers the last section for the rest of the session, so returning to Settings lands where you left it. */
let rememberedSection: SectionId = "general";

const isChanged = (keys: (keyof Settings)[], settings: Settings) => keys.some((k) => settings[k] !== DEFAULT_SETTINGS[k]);

/*
 * Layout: every panel is a grid of cards. Cards sit side by side once the content column is wide
 * enough (@3xl = 48rem) and stack below that. The container query measures the content column,
 * so the layout follows the real space left after the sidebar, not the window size alone.
 */
const CardGrid: React.FC<{ children: React.ReactNode }> = ({ children }) => <div className="grid grid-cols-1 @3xl:grid-cols-2 gap-4 items-start">{children}</div>;

/** A card that spans the full row on wide content. */
const WideCard: React.FC<{ className?: string; children: React.ReactNode }> = ({ className, children }) => <Card className={`space-y-4 @3xl:col-span-2 ${className ?? ""}`}>{children}</Card>;

const Group: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="space-y-3 pt-4 border-t border-line">
    <h3 className="text-[12px] font-semibold uppercase tracking-[0.06em] text-faint">{title}</h3>
    {children}
  </div>
);

/** Top navigation: one button per section, arrow keys move between them, a dot marks sections changed from defaults. */
const SettingsNav: React.FC<{ active: SectionId; onSelect: (id: SectionId) => void; settings: Settings }> = ({ active, onSelect, settings }) => {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});

  const move = (from: number, delta: number | "first" | "last") => {
    const last = SECTIONS.length - 1;
    const next = delta === "first" ? 0 : delta === "last" ? last : (from + delta + SECTIONS.length) % SECTIONS.length;
    onSelect(SECTIONS[next].id);
    refs.current[SECTIONS[next].id]?.focus();
  };

  return (
    <div className="sticky top-0 z-10 -mx-8 px-8 py-3 mb-5 bg-canvas/95 backdrop-blur border-b border-line">
      {/* Narrow content: a dropdown, so the sections never need to scroll sideways. */}
      <div className="@md:hidden">
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
      <div role="tablist" aria-label="Settings sections" className="hidden @md:flex items-center gap-1">
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
    </div>
  );
};

export const SettingsView: React.FC = () => {
  const { settings, updateSettings, appInfo, clearRecentFiles, resetAppData, recentFiles, keystores } = useStore();
  const confirm = useConfirm();
  const toast = useToast();
  const { open } = useTerminal();
  const [section, setSection] = useState<SectionId>(rememberedSection);
  const select = (id: SectionId) => {
    rememberedSection = id;
    setSection(id);
  };
  const def = SECTIONS.find((s) => s.id === section)!;
  const num = (v: string, min: number, max: number) => Math.min(max, Math.max(min, Number(v) || min));

  /** Restores the defaults for one section's keys only. */
  const restore = (keys: (keyof Settings)[], label: string) => {
    updateSettings(Object.fromEntries(keys.map((k) => [k, DEFAULT_SETTINGS[k]])) as Partial<Settings>);
    toast.success(`${label} restored to defaults.`);
  };

  const tsaUrl = settings.tsaUrl.trim();
  const tsaUrlInvalid = tsaUrl !== "" && !/^https?:\/\/\S+$/i.test(tsaUrl);
  const changed = isChanged(def.keys, settings);

  const body = (() => {
    switch (section) {
      case "general":
        return (
          <CardGrid>
            <Card className="space-y-4">
              <CardHeader title="Startup and defaults" subtitle="How xkeystore starts and what it pre-fills." icon={Settings2} className="!mb-0" />
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
              <CardHeader title="Expiry warnings" subtitle="When certificates and keys are flagged." icon={ShieldCheck} className="!mb-0" />
              <div className="grid grid-cols-2 gap-3">
                <TextInput label="Critical (days)" type="number" min={1} value={settings.criticalDays} onChange={(e) => updateSettings({ criticalDays: num(e.target.value, 1, 365) })} hint="Shown red" />
                <TextInput label="Warning (days)" type="number" min={1} value={settings.warningDays} onChange={(e) => updateSettings({ warningDays: Math.max(settings.criticalDays, num(e.target.value, 1, 1095)) })} hint="Shown amber. Never lower than critical." />
              </div>
            </Card>
          </CardGrid>
        );

      case "security":
        return (
          <CardGrid>
            <Card className="space-y-4">
              <CardHeader title="Key access" subtitle="When a key pair can be used." icon={ShieldCheck} className="!mb-0" />
              <Checkbox
                checked={settings.requireKeyUnlock}
                onChange={(v) => updateSettings({ requireKeyUnlock: v })}
                label="Ask for the key password before a key pair can be used"
                hint="Key pairs open locked. Inspecting, exporting, copying or signing with one asks for its key password (the keystore password unless the key has its own) once per session."
              />
            </Card>
            <Card className="space-y-4">
              <CardHeader title="Vault" subtitle="When the encrypted vault locks itself." icon={Clock} className="!mb-0" />
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
              <CardHeader title="Timestamp authority" subtitle="Trusted timestamps for CMS and JAR signatures." icon={Clock} className="!mb-0" />
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
              <CardHeader title="Trust anchors" subtitle="Decides whether a timestamp is trusted." icon={ShieldCheck} className="!mb-0" />
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
              <CardHeader title="Terminal" subtitle="A shell for keytool and openssl commands." icon={TerminalSquare} className="!mb-0" />
              <p className="text-[13px] text-muted">
                Toggle it anywhere with <Kbd>Ctrl+`</Kbd>. Commands run without a terminal attached, so interactive prompts are not supported; pass passwords as arguments (e.g.{" "}
                <code className="font-mono">-storepass</code>).
              </p>
              <div className="grid grid-cols-1 @md:grid-cols-[minmax(0,16rem)_auto] gap-4 items-end">
                <TextInput label="Stop commands after (seconds)" type="number" min={5} max={3600} value={settings.terminalTimeoutSecs} onChange={(e) => updateSettings({ terminalTimeoutSecs: num(e.target.value, 5, 3600) })} />
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
              <CardHeader title="Keyboard shortcuts" subtitle="On macOS use ⌘ instead of Ctrl." icon={Keyboard} className="!mb-0" />
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
              <CardHeader title="Data" subtitle="Where xkeystore keeps its own state." icon={FolderOpen} className="!mb-0" />
              <p className="text-[13px] text-muted">Session state, workspaces, labels and the encrypted vault live in:</p>
              <div className="p-3 rounded-control bg-surface-2 border border-line font-mono text-[12px] text-ink break-all select-text">{appInfo?.data_dir ?? "—"}</div>
              <div className="flex flex-wrap gap-2">
                {appInfo && (
                  <Button icon={FolderOpen} onClick={() => void revealItemInDir(`${appInfo.data_dir}/state.json`).catch(() => toast.info("Nothing saved there yet."))}>
                    Show folder
                  </Button>
                )}
                <Button
                  onClick={() => {
                    const lines = [
                      `xkeystore ${appInfo?.version ?? "unknown"}`,
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
              <TerminalHint command={`ls -la "${appInfo?.data_dir ?? "~"}"`} label="List" />
            </Card>

            <Card className="space-y-4 border-danger/30">
              <CardHeader title="Reset app data" subtitle="Deletes workspaces, labels, recent files and settings. Keystore files and the vault are not touched." icon={RotateCcw} className="!mb-0" />
              <div>
                <Button
                  variant="danger"
                  icon={RotateCcw}
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Reset xkeystore data?",
                      message: "Deletes workspaces, labels, recent files and settings. Keystore files and the vault are not touched.",
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

      case "about":
        return (
          <CardGrid>
            <WideCard>
              <CardHeader title="About xkeystore" subtitle={appInfo ? `Version ${appInfo.version} · ${appInfo.platform}` : undefined} icon={Info} className="!mb-0" />
              <p className="text-[13px] text-muted">
                All cryptography runs locally in the bundled Rust engine. Nothing is sent over the network except the TLS handshakes you start from Examine and optional RFC 3161
                timestamp requests when signing.
              </p>
              <ul className="grid grid-cols-1 @3xl:grid-cols-2 gap-x-8 gap-y-1.5 text-[12.5px]">
                {ENGINE.map((p) => (
                  <li key={p} className="flex items-start gap-2 text-ink-2">
                    <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-success shrink-0" />
                    {p}
                  </li>
                ))}
              </ul>
              <p className="text-[12px] text-faint">Not supported: Bouncy Castle BCFKS/UBER keystores (BKS v2 is read-only), hardware tokens (PKCS#11).</p>
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
        <SettingsNav active={section} onSelect={select} settings={settings} />
        <div role="tabpanel" id={`settings-panel-${section}`} aria-labelledby={`settings-tab-${section}`} className="max-w-5xl min-w-0">
          {/* Toolbar for the whole section. The reset is per section, so it lives here rather than on one card. */}
          <div className="flex items-center justify-between gap-3 mb-4 min-h-8">
            <p className="text-[12px] text-faint">{changed ? "Some settings in this section differ from the defaults." : ""}</p>
            {changed && (
              <Button size="sm" variant="ghost" icon={RotateCcw} onClick={() => restore(def.keys, def.label)}>
                Restore defaults
              </Button>
            )}
          </div>
          {body}
        </div>
      </div>
    </Page>
  );
};
