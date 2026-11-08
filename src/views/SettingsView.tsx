import React from "react";
import { CheckCircle2, Clock, FolderOpen, Keyboard, RotateCcw, Settings2, ShieldCheck, TerminalSquare, Trash2 } from "lucide-react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { useStore } from "../state/store";
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

export const SettingsView: React.FC = () => {
  const { settings, updateSettings, appInfo, clearRecentFiles, resetAppData, recentFiles, keystores } = useStore();
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
          <Checkbox
            checked={settings.requireKeyUnlock}
            onChange={(v) => updateSettings({ requireKeyUnlock: v })}
            label="Ask for the key password before a key pair can be used"
            hint="Key pairs open locked. Inspecting, exporting, copying or signing with one asks for its key password (the keystore password unless the key has its own) once per session."
          />
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
          <CardHeader title="Signing" icon={Clock} className="!mb-0" />
          <p className="text-[13px] text-muted">
            A trusted timestamp records <em>when</em> you signed, so signatures keep verifying after the signing certificate expires. Without one, verifiers reject
            an expired signer. This is the only network request signing makes, and only when it is switched on.
          </p>
          <TextArea label="TSA trust anchors (PEM)" value={settings.tsaTrustPem} onChange={(e) => updateSettings({ tsaTrustPem: e.target.value })} rows={4} hint="A timestamp is reported as trusted only when the token's certificates chain to this bundle. Leave it empty to record the time without a trust decision." />
          <TextInput
            label="Timestamp authority (TSA) URL"
            value={settings.tsaUrl}
            onChange={(e) => updateSettings({ tsaUrl: e.target.value })}
            placeholder="http://timestamp.digicert.com"
            hint="Your certificate authority usually runs one. Free options include DigiCert and Sectigo."
          />
          <Checkbox
            checked={settings.timestampByDefault}
            onChange={(v) => updateSettings({ timestampByDefault: v })}
            label="Timestamp new signatures by default"
            hint={settings.tsaUrl.trim() ? "Applies to CMS signatures and signed JARs." : "Set a TSA URL first."}
          />
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
          <p className="text-[13px] text-muted">
            All cryptography runs locally in the bundled Rust engine. Nothing is sent over the network except the TLS handshakes you start from Examine and optional RFC 3161 timestamp requests when signing.
          </p>
          <ul className="space-y-1.5 text-[12.5px]">
            {ENGINE.map((p) => (
              <li key={p} className="flex items-start gap-2 text-ink-2">
                <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-success shrink-0" />
                {p}
              </li>
            ))}
          </ul>
          <p className="text-[12px] text-faint">Not supported: Bouncy Castle BCFKS/UBER keystores (BKS v2 is read-only), hardware tokens (PKCS#11).</p>
        </Card>
      </div>
    </Page>
  );
};
