import React from "react";
import { CheckCircle2, FolderOpen, Keyboard, RotateCcw, Settings2, ShieldCheck, TerminalSquare, Trash2 } from "lucide-react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { useStore } from "../state/store";
import { FORMAT_INFO } from "../lib/keystore";
import { KEYSTORE_FORMATS, type KeystoreFormat } from "../types/crypto";
import { Button, Card, CardHeader, Checkbox, Kbd, Page, PageHeader, Select, TextInput, useConfirm, useToast } from "../components/ui";
import { TerminalHint, useTerminal } from "../components/Terminal";

const ENGINE = [
  "PKCS#12 reader/writer (PBES2/AES, legacy 3DES/RC2, SHA-1/SHA-2 MACs, Java secret keys)",
  "JKS and JCEKS reader/writer (keytool compatible, incl. sealed secret keys)",
  "X.509 certificates, PKCS#10 CSRs and v2 CRLs built and signed with your keys",
  "RSA (rsa), ECDSA P-256/384/521 (RustCrypto), Ed25519 (ed25519-dalek)",
  "CMS/PKCS#7 SignedData, JAR signing, JWS/JWT",
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
];

export const SettingsView: React.FC = () => {
  const { settings, updateSettings, appInfo, clearRecentFiles, resetAppData, recentFiles } = useStore();
  const confirm = useConfirm();
  const toast = useToast();
  const { open } = useTerminal();
  const num = (v: string, min: number, max: number) => Math.min(max, Math.max(min, Number(v) || min));

  return (
    <Page>
      <PageHeader title="Settings" description="Preferences are saved automatically on this computer." />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="space-y-4">
          <CardHeader title="General" icon={Settings2} className="!mb-0" />
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
          <CardHeader title="Expiry and vault" icon={ShieldCheck} className="!mb-0" />
          <div className="grid grid-cols-2 gap-3">
            <TextInput label="Critical (days)" type="number" min={1} value={settings.criticalDays} onChange={(e) => updateSettings({ criticalDays: num(e.target.value, 1, 365) })} hint="Shown red" />
            <TextInput label="Warning (days)" type="number" min={1} value={settings.warningDays} onChange={(e) => updateSettings({ warningDays: Math.max(settings.criticalDays, num(e.target.value, 1, 1095)) })} hint="Shown amber" />
          </div>
          <Select label="Lock the vault after inactivity" value={settings.autoLockMinutes} onChange={(e) => updateSettings({ autoLockMinutes: Number(e.target.value) })}>
            {[5, 15, 30, 60, 240].map((m) => (
              <option key={m} value={m}>
                {m} minutes
              </option>
            ))}
            <option value={0}>Never</option>
          </Select>
        </Card>

        <Card className="space-y-4">
          <CardHeader title="Terminal" icon={TerminalSquare} className="!mb-0" />
          <p className="text-[13px] text-muted">
            A shell for keytool/openssl commands. Toggle it anywhere with <Kbd>Ctrl+`</Kbd>. Commands run without a terminal attached, so interactive prompts are not supported; pass passwords as arguments (e.g. <code className="font-mono">-storepass</code>).
          </p>
          <TextInput label="Stop commands after (seconds)" type="number" min={5} max={3600} value={settings.terminalTimeoutSecs} onChange={(e) => updateSettings({ terminalTimeoutSecs: num(e.target.value, 5, 3600) })} />
          <Button icon={TerminalSquare} onClick={() => open()}>
            Open terminal
          </Button>
        </Card>

        <Card className="space-y-4">
          <CardHeader title="Keyboard shortcuts" icon={Keyboard} className="!mb-0" />
          <ul className="space-y-1.5">
            {SHORTCUTS.map(([k, label]) => (
              <li key={k} className="flex items-center justify-between text-[13px]">
                <span className="text-ink-2">{label}</span>
                <Kbd>{k}</Kbd>
              </li>
            ))}
          </ul>
          <p className="text-[12px] text-faint">On macOS use ⌘ instead of Ctrl.</p>
        </Card>

        <Card className="space-y-4">
          <CardHeader title="Data" icon={FolderOpen} className="!mb-0" />
          <p className="text-[13px] text-muted">Session state, workspaces, labels and the encrypted vault live in:</p>
          <div className="p-3 rounded-control bg-surface-2 border border-line font-mono text-[12px] text-ink break-all select-text">{appInfo?.data_dir ?? "—"}</div>
          <div className="flex flex-wrap gap-2">
            {appInfo && (
              <Button icon={FolderOpen} onClick={() => void revealItemInDir(`${appInfo.data_dir}/state.json`).catch(() => toast.info("Nothing saved there yet."))}>
                Show folder
              </Button>
            )}
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
          <TerminalHint command={`ls -la "${appInfo?.data_dir ?? "~"}"`} label="List" />
        </Card>

        <Card className="space-y-3">
          <CardHeader title="About xkeystore" subtitle={appInfo ? `Version ${appInfo.version} · ${appInfo.platform}` : undefined} icon={ShieldCheck} className="!mb-0" />
          <p className="text-[13px] text-muted">All cryptography runs locally in the bundled Rust engine. Nothing is sent over the network except the TLS handshakes you start from Examine.</p>
          <ul className="space-y-1.5 text-[12.5px]">
            {ENGINE.map((p) => (
              <li key={p} className="flex items-start gap-2 text-ink-2">
                <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-success shrink-0" />
                {p}
              </li>
            ))}
          </ul>
          <p className="text-[12px] text-faint">Not supported: Bouncy Castle BKS/BCFKS/UBER keystores, hardware tokens (PKCS#11), TSA timestamping.</p>
        </Card>
      </div>
    </Page>
  );
};
