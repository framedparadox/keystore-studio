import React, { useCallback, useEffect, useLayoutEffect, useState } from "react";
import { Eye, EyeOff, FolderOpen, KeyRound, Lock, LockOpen, RotateCcw, ShieldCheck, Trash2 } from "lucide-react";
import type { SecretSummary } from "../types/crypto";
import { api, errorMessage, passwordSecretId } from "../lib/api";
import { useStore } from "../state/store";
import { Alert, Button, Card, CardHeader, Column, CopyButton, DataTable, EmptyState, IconButton, KpiCard, Modal, Page, PageHeader, PasswordInput, Spinner, useConfirm, useToast } from "../components/ui";

const PREFIX = "keystore:";

const ChangeMasterKeyDialog: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const toast = useToast();
  const [oldKey, setOldKey] = useState("");
  const [newKey, setNewKey] = useState("");
  const [confirmKey, setConfirmKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useLayoutEffect(() => {
    setOldKey("");
    setNewKey("");
    setConfirmKey("");
    setError(null);
  }, [open]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (newKey.length < 8) return setError("The new master key must be at least 8 characters.");
    if (newKey !== confirmKey) return setError("The new keys do not match.");
    setBusy(true);
    try {
      await api.vaultChangeMasterKey(oldKey, newKey);
      toast.success("Master key changed. All stored passwords were re-encrypted.");
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      busy={busy}
      onClose={onClose}
      icon={RotateCcw}
      size="sm"
      title="Change master key"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="change-mk" disabled={busy || !oldKey || !newKey}>
            {busy && <Spinner />} Change
          </Button>
        </>
      }
    >
      <form id="change-mk" onSubmit={submit} className="space-y-3">
        <PasswordInput label="Current master key" value={oldKey} onChange={setOldKey} autoFocus />
        <PasswordInput label="New master key" value={newKey} onChange={setNewKey} />
        <PasswordInput label="Confirm new master key" value={confirmKey} onChange={setConfirmKey} />
        {error && <Alert tone="danger">{error}</Alert>}
      </form>
    </Modal>
  );
};

/** Setup or unlock form shown inside the page while the vault is unavailable. */
const VaultGate: React.FC<{ setup: boolean }> = ({ setup }) => {
  const { onVaultUnlocked, refreshVault } = useStore();
  const confirm = useConfirm();
  const toast = useToast();
  const [key, setKey] = useState("");
  const [confirmKey, setConfirmKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (setup && key.length < 8) return setError("The master key must be at least 8 characters.");
    if (setup && key !== confirmKey) return setError("The keys do not match.");
    setBusy(true);
    try {
      if (setup) await api.vaultInit(key);
      else await api.vaultUnlock(key);
      setKey("");
      setConfirmKey("");
      await onVaultUnlocked();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const reset = async () => {
    const ok = await confirm({
      title: "Reset the vault?",
      message: "This permanently deletes every remembered password. Your keystore files are not affected. You can then create a new master key.",
      confirmLabel: "Delete vault",
      danger: true,
    });
    if (ok !== true) return;
    try {
      await api.vaultReset();
      await refreshVault();
      toast.success("The vault was reset.");
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="flex justify-center py-6">
      <Card className="w-full max-w-md">
        <CardHeader icon={setup ? ShieldCheck : Lock} title={setup ? "Set up your vault" : "Vault locked"} subtitle={setup ? "Remember keystore passwords securely" : "Enter your master key"} />
        <form onSubmit={submit} className="space-y-4">
          <PasswordInput label="Master key" value={key} onChange={setKey} autoFocus data-testid="vault-key" />
          {setup && <PasswordInput label="Confirm master key" value={confirmKey} onChange={setConfirmKey} data-testid="vault-key-confirm" />}
          {error && <Alert tone="danger">{error}</Alert>}
          {setup && (
            <p className="text-[12px] text-faint leading-relaxed">
              The master key is stretched with Argon2id and encrypts each stored password with AES-256-GCM. It is never written to disk and cannot be recovered.
            </p>
          )}
          <Button variant="primary" type="submit" className="w-full" disabled={busy || !key} data-testid="vault-submit">
            {busy && <Spinner />} {setup ? "Create vault" : "Unlock"}
          </Button>
          {!setup && (
            <button type="button" onClick={reset} className="w-full text-center text-[12px] text-faint hover:text-danger cursor-pointer">
              Forgot the master key? Reset the vault…
            </button>
          )}
        </form>
      </Card>
    </div>
  );
};

export const VaultView: React.FC = () => {
  const { vault, refreshVault, lockVault, keystores, getPassword, openFiles, settings } = useStore();
  const toast = useToast();
  const confirm = useConfirm();
  const [secrets, setSecrets] = useState<SecretSummary[]>([]);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [changeOpen, setChangeOpen] = useState(false);

  const load = useCallback(async () => {
    if (!vault.unlocked) return;
    try {
      setSecrets(await api.vaultListSecrets());
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }, [vault.unlocked, toast]);
  useEffect(() => {
    void load();
    if (!vault.unlocked) setRevealed({});
  }, [load, vault.unlocked, vault.secret_count]);

  if (!vault.exists || !vault.unlocked) {
    return (
      <Page>
        <PageHeader icon={KeyRound} title="Vault" description="Remember keystore passwords under one master key, so keystores open without retyping them." />
        <VaultGate setup={!vault.exists} />
      </Page>
    );
  }

  const remembered = new Set(secrets.map((s) => s.id));
  const notRemembered = keystores.filter((k) => k.path && !k.sealed && getPassword(k.id) && !remembered.has(passwordSecretId(k.path)));

  const reveal = async (s: SecretSummary) => {
    if (revealed[s.id]) {
      const next = { ...revealed };
      delete next[s.id];
      return setRevealed(next);
    }
    try {
      const v = await api.vaultGetSecret(s.id);
      if (v !== null) setRevealed({ ...revealed, [s.id]: v });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  const forget = async (s: SecretSummary) => {
    const ok = await confirm({ title: `Forget the password for ${s.label}?`, message: "The keystore file is not affected; you will be asked for its password next time.", confirmLabel: "Forget", danger: true });
    if (ok !== true) return;
    await api.vaultDeleteSecret(s.id).catch((err) => toast.error(errorMessage(err)));
    await refreshVault();
    await load();
  };
  const remember = async (path: string, name: string, pw: string) => {
    try {
      await api.vaultStoreSecret(passwordSecretId(path), name, pw);
      await refreshVault();
      await load();
      toast.success(`Remembered the password for ${name}.`);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const columns: Column<SecretSummary>[] = [
    {
      id: "label",
      header: "Keystore",
      width: "40%",
      sortValue: (s) => s.label,
      cell: (s) => (
        <div className="min-w-0">
          <div className="font-medium text-ink truncate">{s.label}</div>
          <div className="text-[12px] text-faint font-mono truncate">{s.id.startsWith(PREFIX) ? s.id.slice(PREFIX.length) : s.id}</div>
        </div>
      ),
    },
    {
      id: "pw",
      header: "Password",
      cell: (s) => (
        <span className="inline-flex items-center gap-1">
          <span className="font-mono text-[12px] text-ink select-text">{revealed[s.id] ?? "••••••••••••"}</span>
          <IconButton icon={revealed[s.id] ? EyeOff : Eye} label={revealed[s.id] ? "Hide" : "Reveal"} onClick={() => reveal(s)} />
          {revealed[s.id] && <CopyButton value={revealed[s.id]} label="Copy password" />}
        </span>
      ),
    },
    { id: "updated", header: "Updated", sortValue: (s) => s.updated_at, cell: (s) => <span className="text-faint tabular-nums">{s.updated_at}</span> },
    {
      id: "act",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "120px",
      cell: (s) => (
        <span className="inline-flex gap-0.5">
          {s.id.startsWith(PREFIX) && <IconButton icon={FolderOpen} label="Open keystore" onClick={() => openFiles([s.id.slice(PREFIX.length)])} />}
          <IconButton icon={Trash2} label="Forget password" tone="danger" onClick={() => forget(s)} />
        </span>
      ),
    },
  ];

  return (
    <Page>
      <PageHeader
        icon={KeyRound}
        title="Vault"
        description="Keystore passwords remembered on this computer, encrypted with your master key."
        actions={
          <>
            <Button icon={RotateCcw} onClick={() => setChangeOpen(true)}>
              Change master key
            </Button>
            <Button icon={Lock} onClick={() => lockVault()} data-testid="vault-lock">
              Lock vault
            </Button>
          </>
        }
      />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <KpiCard label="Remembered passwords" value={secrets.length} icon={KeyRound} tone="brand" />
        <KpiCard label="Status" value="Unlocked" icon={LockOpen} tone="success" hint={settings.autoLockMinutes ? `Locks after ${settings.autoLockMinutes} min of inactivity` : "Auto-lock is off"} />
        <KpiCard label="Encryption" value="AES-256" icon={ShieldCheck} hint="GCM, key from Argon2id (19 MiB, t=2)" />
      </div>
      {notRemembered.length > 0 && (
        <Card className="mb-4">
          <CardHeader title="Open keystores without a remembered password" />
          <ul className="divide-y divide-line">
            {notRemembered.map((k) => (
              <li key={k.id} className="py-2.5 flex items-center justify-between gap-3">
                <span className="min-w-0">
                  <span className="block text-[13px] font-medium text-ink">{k.name}</span>
                  <span className="block text-[12px] text-faint font-mono truncate">{k.path}</span>
                </span>
                <Button size="sm" onClick={() => remember(k.path, k.name, getPassword(k.id)!)}>
                  Remember
                </Button>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Card padded={false} className="overflow-hidden">
        <DataTable<SecretSummary>
          label="Remembered passwords"
          columns={columns}
          rows={secrets}
          rowKey={(s) => s.id}
          initialSort={{ id: "label", dir: "asc" }}
          empty={<EmptyState icon={KeyRound} title="No passwords remembered yet" description="Tick “Remember the password in the vault” when opening or saving a keystore." />}
          footer={<span>Stored in the Keystore Studio data folder; only ciphertext is written to disk.</span>}
        />
      </Card>
      <ChangeMasterKeyDialog open={changeOpen} onClose={() => setChangeOpen(false)} />
    </Page>
  );
};
