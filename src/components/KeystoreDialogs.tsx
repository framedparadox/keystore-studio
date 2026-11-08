import React, { useLayoutEffect, useMemo, useState } from "react";
import { FilePlus2, FolderOpen, Lock, Save, ShieldCheck } from "lucide-react";
import { useStore } from "../state/store";
import { api, errorMessage } from "../lib/api";
import { FILTERS, baseName, pickSavePath, safeFileStem, withExtension } from "../lib/files";
import { FORMAT_EXTENSION, FORMAT_INFO, saveProblems } from "../lib/keystore";
import { KEYSTORE_FORMATS, type GenerateKeyPairInput, type KeystoreFormat } from "../types/crypto";
import { Alert, Button, Checkbox, Modal, PasswordInput, Select, Spinner, TextArea, TextInput, passwordStrength, useToast } from "./ui";

/** "Remember in vault" checkbox that explains how to enable it when the vault is unavailable. */
export const RememberPassword: React.FC<{ checked: boolean; onChange: (v: boolean) => void }> = ({ checked, onChange }) => {
  const { vault, requestVaultUnlock } = useStore();
  if (!vault.exists) {
    return (
      <Checkbox
        checked={false}
        onChange={() => requestVaultUnlock()}
        label="Remember the password in the vault"
        testId="remember-password"
        hint="Set up a master key first (opens the vault setup)."
      />
    );
  }
  if (!vault.unlocked) {
    return (
      <div className="flex items-start gap-2.5">
        <Checkbox checked={false} onChange={() => requestVaultUnlock(() => onChange(true))} label="Remember the password in the vault"
        testId="remember-password" hint="The vault is locked — checking this asks for your master key." />
      </div>
    );
  }
  return <Checkbox checked={checked} onChange={onChange} label="Remember the password in the vault"
        testId="remember-password" hint="Encrypted with your master key (AES-256-GCM)." />;
};

const StrengthHint: React.FC<{ password: string }> = ({ password }) => {
  if (!password) return null;
  const { score, label } = passwordStrength(password);
  const tone = score <= 1 ? "text-danger" : score === 2 ? "text-warning" : "text-success";
  return (
    <span className={tone}>
      Strength: {label}
      {password.length < 6 && " — keytool requires at least 6 characters"}
    </span>
  );
};

export const OpenPasswordDialog: React.FC = () => {
  const { pendingOpen, submitOpenPassword, cancelOpen, settings } = useStore();
  const [password, setPassword] = useState("");
  const [keyPasswords, setKeyPasswords] = useState("");
  const [remember, setRemember] = useState(settings.rememberPasswordsByDefault);
  const [busy, setBusy] = useState(false);
  useLayoutEffect(() => {
    setPassword("");
    setKeyPasswords("");
    setRemember(settings.rememberPasswordsByDefault);
    setBusy(false);
  }, [pendingOpen?.path]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!pendingOpen) return null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const extra: Record<string, string> = {};
    for (const line of keyPasswords.split(/\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const cut = trimmed.includes("=") ? trimmed.indexOf("=") : trimmed.indexOf(" ");
      if (cut <= 0) continue;
      extra[trimmed.slice(0, cut).trim()] = trimmed.slice(cut + 1).trim();
    }
    await submitOpenPassword(password, remember, extra);
    setBusy(false);
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={cancelOpen}
      icon={FolderOpen}
      title={`Open ${pendingOpen.name}`}
      description={<span className="font-mono break-all">{pendingOpen.path}</span>}
      size="sm"
      testId="open-password-dialog"
      footer={
        <>
          <Button onClick={cancelOpen} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="open-ks-form" disabled={busy || !password} data-testid="open-submit">
            {busy && <Spinner />} Open
          </Button>
        </>
      }
    >
      <form id="open-ks-form" onSubmit={submit} className="space-y-4">
        <p className="text-[13px] text-muted">
          This is a <strong className="text-ink">{FORMAT_INFO[pendingOpen.format as KeystoreFormat]?.label ?? pendingOpen.format}</strong> keystore. Enter its store password.
        </p>
        <PasswordInput label="Keystore password" value={password} onChange={setPassword} autoFocus data-testid="open-password" error={pendingOpen.error} />
        <TextArea label="Key passwords" value={keyPasswords} onChange={(e) => setKeyPasswords(e.target.value)} rows={3} placeholder={"alias=key-password\nother alias=another"} hint="Optional. One alias and its key password per line, when a key does not use the store password." />
        <RememberPassword checked={remember} onChange={setRemember} />
      </form>
    </Modal>
  );
};

export const SaveDialog: React.FC = () => {
  const { pendingSave, keystores, getPassword, completeSave, cancelSave, settings, rememberRequested } = useStore();
  const ks = keystores.find((k) => k.id === pendingSave?.keystoreId);
  const [format, setFormat] = useState<KeystoreFormat>("PKCS12");
  const [password, setPassword] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [remember, setRemember] = useState(false);
  const [mac, setMac] = useState<"pkcs12" | "pbmac1">("pkcs12");
  const [force, setForce] = useState(false);
  const [busy, setBusy] = useState(false);
  const current = ks ? getPassword(ks.id) ?? "" : "";

  // A file read from disk as JKS (or read-only BKS) is offered as PKCS#12, so the original stays as
  // it is. A keystore created here as JKS is saved as JKS: that is the format that was chosen.
  const migrating = !!ks && !!ks.path && (ks.format === "JKS" || ks.format === "BKS");
  useLayoutEffect(() => {
    if (!ks) return;
    setFormat(migrating || ks.format === "BKS" ? "PKCS12" : ks.format);
    setMac("pkcs12");
    setForce(false);
    setPassword(current);
    setConfirmPw(current);
    setRemember(settings.rememberPasswordsByDefault || rememberRequested(ks.id));
    setBusy(false);
  }, [pendingSave?.keystoreId]); // eslint-disable-line react-hooks/exhaustive-deps

  const problems = useMemo(() => (ks ? saveProblems(ks.entries, ks.format, format) : []), [ks, format]);

  if (!pendingSave || !ks) return null;
  const mismatch = password !== confirmPw;
  const submit = async () => {
    const defaultName = ks.path ? withExtension(baseName(ks.path), FORMAT_EXTENSION[format]) : withExtension(safeFileStem(ks.name), FORMAT_EXTENSION[format]);
    let path: string | null;
    try {
      path = await pickSavePath(`Save ${ks.name}`, defaultName, [FILTERS.keystores]);
    } catch (err) {
      return;
    }
    if (!path) return;
    setBusy(true);
    await completeSave({ path, password, format, remember, mac: format === "PKCS12" ? mac : undefined, force });
    setBusy(false);
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={cancelSave}
      icon={Save}
      title={pendingSave.mode === "save-as" ? `Save ${ks.name} as…` : `Save ${ks.name}`}
      description="Choose the format and password, then pick where to write the file."
      testId="save-dialog"
      footer={
        <>
          <Button onClick={cancelSave} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={busy || !password || mismatch || problems.length > 0} data-testid="save-choose-location">
            {busy && <Spinner />} Choose location and save…
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Select label="Format" value={format} onChange={(e) => setFormat(e.target.value as KeystoreFormat)} hint={FORMAT_INFO[format].description} data-testid="save-format">
          {KEYSTORE_FORMATS.map((f) => (
            <option key={f} value={f}>
              {FORMAT_INFO[f].label}
            </option>
          ))}
        </Select>
        <div className="grid grid-cols-2 gap-3">
          <PasswordInput label="Store password" value={password} onChange={setPassword} hint={<StrengthHint password={password} />} data-testid="save-password" />
          <PasswordInput label="Confirm password" value={confirmPw} onChange={setConfirmPw} error={mismatch && confirmPw ? "Passwords do not match" : undefined} data-testid="save-password-confirm" />
        </div>
        {!password && <p className="text-[12px] text-faint">A store password is required. An empty password is rejected so the file is never saved unprotected.</p>}
        {format === "PKCS12" && (
          <Select label="Integrity MAC" value={mac} onChange={(e) => setMac(e.target.value as "pkcs12" | "pbmac1")} hint="PBKDF2 iteration count is 10,000. PBMAC1 needs a reader from OpenSSL 3.4 or newer. The legacy MAC is the default.">
            <option value="pkcs12">Legacy PKCS#12 MAC (compatible)</option>
            <option value="pbmac1">PBMAC1 / PBKDF2-HMAC-SHA256</option>
          </Select>
        )}
        {migrating && (
          <Alert tone="info" title={ks.format === "JKS" ? "JKS uses SHA-1" : "BKS is read-only"}>
            {ks.format === "JKS"
              ? "PKCS#12 is selected so you can write a new file and leave the original JKS in place. Pick the original path only if you mean to replace it."
              : "The entries can be written as PKCS#12. This does not modify the BKS file unless you choose that same path."}
          </Alert>
        )}
        <Checkbox checked={force} onChange={setForce} label="Override if the file changed on disk" hint="A .bak of the previous bytes is written beside the file either way." />
        <RememberPassword checked={remember} onChange={setRemember} />
        {problems.map((p) => (
          <Alert key={p} tone="danger">
            {p}
          </Alert>
        ))}
      </div>
    </Modal>
  );
};

export const NewKeystoreDialog: React.FC = () => {
  const { newKeystoreOpen, setNewKeystoreOpen, createKeystore, settings, save } = useStore();
  const toast = useToast();
  const [format, setFormat] = useState<KeystoreFormat>(settings.defaultFormat);
  const [name, setName] = useState("keystore.p12");
  const [password, setPassword] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [remember, setRemember] = useState(settings.rememberPasswordsByDefault);
  const [withKey, setWithKey] = useState(true);
  const [alias, setAlias] = useState("server");
  const [cn, setCn] = useState("");
  const [alg, setAlg] = useState("ECDSA:P-256");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useLayoutEffect(() => {
    if (newKeystoreOpen) {
      setFormat(settings.defaultFormat);
      setName(`keystore.${FORMAT_EXTENSION[settings.defaultFormat]}`);
      setPassword("");
      setConfirmPw("");
      setError(null);
      setBusy(false);
    }
  }, [newKeystoreOpen, settings.defaultFormat]);

  if (!newKeystoreOpen) return null;
  const close = () => setNewKeystoreOpen(false);
  const mismatch = password !== confirmPw;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password.length < 6) return setError("Use a password of at least 6 characters (Java keytool rejects shorter ones).");
    if (mismatch) return setError("Passwords do not match.");
    setBusy(true);
    try {
      let initialEntry = null;
      if (withKey) {
        const [algorithm, param] = alg.split(":");
        const input: GenerateKeyPairInput = {
          alias: alias.trim() || "server",
          algorithm: algorithm as GenerateKeyPairInput["algorithm"],
          key_size: algorithm === "RSA" ? Number(param) : 0,
          curve: algorithm === "ECDSA" ? param : null,
          subject_dn: "",
          common_name: cn.trim() || alias.trim() || "server",
          validity_days: 365,
          is_ca: false,
          sans: cn.trim() ? [cn.trim()] : [],
          key_usage: [],
          extended_key_usage: [],
          labels: [],
        };
        initialEntry = await api.generateKeyPair(input, null);
      }
      const ks = createKeystore({ name: name.trim() || withExtension("keystore", FORMAT_EXTENSION[format]), format, password, remember, initialEntry });
      close();
      toast.success(`Created ${ks.name}. It is not on disk yet.`, { label: "Save now", onClick: () => void save(ks.id) });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={close}
      icon={FilePlus2}
      title="New keystore"
      description="Created in memory; choose where to save it with Save (Ctrl+S)."
      testId="new-keystore-dialog"
      footer={
        <>
          <Button onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="new-ks-form" disabled={busy} data-testid="new-keystore-create">
            {busy && <Spinner />} {busy && withKey ? "Generating key…" : "Create keystore"}
          </Button>
        </>
      }
    >
      <form id="new-ks-form" onSubmit={submit} className="space-y-4">
        <div>
          <span className="label">Format</span>
          <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Keystore format">
            {KEYSTORE_FORMATS.map((f) => (
              <button
                key={f}
                type="button"
                role="radio"
                aria-checked={format === f}
                data-testid={`format-${f}`}
                onClick={() => {
                  setFormat(f);
                  setName((n) => withExtension(n, FORMAT_EXTENSION[f]));
                }}
                className={`p-2.5 rounded-control border text-left transition cursor-pointer ${format === f ? "bg-brand-tint border-brand" : "bg-surface border-line-strong hover:bg-surface-2"}`}
              >
                <div className="font-semibold text-[13px] text-ink">{FORMAT_INFO[f].label}</div>
                <div className="text-[11.5px] text-faint leading-snug mt-0.5">{FORMAT_INFO[f].description}</div>
              </button>
            ))}
          </div>
        </div>
        <TextInput label="Name" value={name} onChange={(e) => setName(e.target.value)} required data-testid="new-keystore-name" />
        <div className="grid grid-cols-2 gap-3">
          <PasswordInput label="Store password" value={password} onChange={setPassword} hint={<StrengthHint password={password} />} data-testid="new-keystore-password" />
          <PasswordInput label="Confirm password" value={confirmPw} onChange={setConfirmPw} error={mismatch && confirmPw ? "Passwords do not match" : undefined} data-testid="new-keystore-password-confirm" />
        </div>
        <RememberPassword checked={remember} onChange={setRemember} />
        <div className="rounded-card border border-line p-3.5 space-y-3">
          <Checkbox checked={withKey} onChange={setWithKey} label="Generate an initial key pair" hint="A self-signed certificate you can replace later with a CA-signed one." />
          {withKey && (
            <div className="grid grid-cols-3 gap-3">
              <TextInput label="Alias" value={alias} onChange={(e) => setAlias(e.target.value)} data-testid="new-keystore-alias" />
              <TextInput label="Common name" placeholder="e.g. api.example.com" value={cn} onChange={(e) => setCn(e.target.value)} />
              <Select label="Key" value={alg} onChange={(e) => setAlg(e.target.value)}>
                <option value="ECDSA:P-256">ECDSA P-256</option>
                <option value="ECDSA:P-384">ECDSA P-384</option>
                <option value="RSA:2048">RSA 2048</option>
                <option value="RSA:3072">RSA 3072</option>
                <option value="RSA:4096">RSA 4096</option>
                <option value="Ed25519:0">Ed25519</option>
              </Select>
            </div>
          )}
        </div>
        {error && <Alert tone="danger">{error}</Alert>}
      </form>
    </Modal>
  );
};

export const VaultPromptDialog: React.FC = () => {
  const { vaultPromptOpen, closeVaultPrompt, onVaultUnlocked, vault } = useStore();
  const [key, setKey] = useState("");
  const [confirmKey, setConfirmKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useLayoutEffect(() => {
    setKey("");
    setConfirmKey("");
    setError(null);
  }, [vaultPromptOpen]);
  if (!vaultPromptOpen) return null;
  const setup = !vault.exists;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (setup && key.length < 8) return setError("The master key must be at least 8 characters.");
    if (setup && key !== confirmKey) return setError("The keys do not match.");
    setBusy(true);
    try {
      if (setup) await api.vaultInit(key);
      else await api.vaultUnlock(key);
      await onVaultUnlocked();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={closeVaultPrompt}
      icon={setup ? ShieldCheck : Lock}
      title={setup ? "Set up the vault" : "Unlock the vault"}
      description={setup ? "The master key encrypts remembered keystore passwords on this computer." : "Enter your master key to use remembered passwords."}
      size="sm"
      testId="vault-prompt"
      footer={
        <>
          <Button onClick={closeVaultPrompt} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="vault-prompt-form" disabled={busy || !key} data-testid="vault-prompt-submit">
            {busy && <Spinner />} {setup ? "Create vault" : "Unlock"}
          </Button>
        </>
      }
    >
      <form id="vault-prompt-form" onSubmit={submit} className="space-y-4">
        <PasswordInput label="Master key" value={key} onChange={setKey} autoFocus data-testid="vault-prompt-key" />
        {setup && <PasswordInput label="Confirm master key" value={confirmKey} onChange={setConfirmKey} data-testid="vault-prompt-confirm" />}
        {setup && <p className="text-[12px] text-faint">It is never stored and cannot be recovered. If you forget it you can reset the vault, which deletes the remembered passwords.</p>}
        {error && <Alert tone="danger">{error}</Alert>}
      </form>
    </Modal>
  );
};

/** Prompt for a per-entry key password (JKS/JCEKS keys protected separately from the store). */
/**
 * Asks for the key password of locked keys. Raised from anywhere through
 * `store.ensureKeyAccess`; runs the caller's follow-up once every requested key is unlocked.
 */
export const UnlockKeysDialog: React.FC = () => {
  const { pendingKeyUnlock: pending, cancelKeyUnlock, unlockKeys, keystores, isKeyLocked } = useStore();
  const toast = useToast();
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Progress when keys with different passwords are unlocked one password at a time.
  const [progress, setProgress] = useState<string | null>(null);
  useLayoutEffect(() => {
    setPw("");
    setError(null);
    setProgress(null);
  }, [pending]);
  if (!pending) return null;
  const ks = keystores.find((k) => k.id === pending.keystoreId);
  const locked = (ks?.entries ?? []).filter((e) => pending.entryIds.includes(e.id) && isKeyLocked(e));
  const one = locked.length === 1 ? locked[0] : null;
  const ownPassword = locked.some((e) => e.locked);
  const submit = async () => {
    setBusy(true);
    setError(null);
    const res = await unlockKeys(pending.keystoreId, pending.entryIds, pw);
    setBusy(false);
    if (res.error) {
      setError(res.error);
      return;
    }
    if (res.remaining > 0) {
      // Keys with different passwords: keep asking for the rest, and say so here (a toast would
      // sit behind this dialog).
      setPw("");
      setProgress(`Unlocked ${res.unlocked}. ${res.remaining} still need${res.remaining === 1 ? "s" : ""} a different key password.`);
      return;
    }
    const then = pending.then;
    cancelKeyUnlock();
    if (!one) toast.success(`Unlocked ${res.unlocked} key${res.unlocked === 1 ? "" : "s"} in ${ks?.name ?? "the keystore"}.`);
    // After this render, so the follow-up sees the keys unlocked.
    if (then) window.setTimeout(then, 0);
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={cancelKeyUnlock}
      icon={Lock}
      size="sm"
      testId="unlock-key-dialog"
      title={one ? `Unlock '${one.alias}'` : `Unlock ${locked.length} keys`}
      description={one ? `${one.entry_type === "KeyPair" ? "Key pair" : "Secret key"} in ${ks?.name ?? "the keystore"}` : `In ${ks?.name ?? "the keystore"}`}
      footer={
        <>
          <Button onClick={cancelKeyUnlock} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" disabled={busy || !pw} data-testid="unlock-key-submit" onClick={submit}>
            {busy && <Spinner />} Unlock
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (pw && !busy) void submit();
        }}
        className="space-y-3"
      >
        {progress && (
          <Alert tone="success" className="!py-2">
            <span data-testid="unlock-key-progress">{progress}</span>
          </Alert>
        )}
        <PasswordInput label="Key password" value={pw} onChange={setPw} error={error ?? undefined} autoFocus data-testid="unlock-key-password" />
        <p className="text-[12px] text-faint">
          {ownPassword
            ? "This key is protected by its own key password. After unlocking, saving keeps that password."
            : "Unless the key was given its own password, this is the keystore password. Keys stay unlocked until you lock them or close the keystore."}
        </p>
        {!one && locked.length > 1 && (
          <ul className="max-h-36 overflow-y-auto rounded-control border border-line divide-y divide-line text-[13px]">
            {locked.map((e) => (
              <li key={e.id} className="px-3 py-1.5 flex items-center gap-2">
                <Lock className="w-3 h-3 text-warning shrink-0" />
                <span className="truncate text-ink">{e.alias}</span>
              </li>
            ))}
          </ul>
        )}
      </form>
    </Modal>
  );
};
