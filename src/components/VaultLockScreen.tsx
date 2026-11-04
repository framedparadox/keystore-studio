import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ShieldCheck, Lock, Loader2 } from "lucide-react";

export type VaultLockScreenMode = "setup" | "unlock";

interface VaultLockScreenProps {
  mode: VaultLockScreenMode;
  onUnlocked: () => void;
  /** Render inline within the current page (Vaults tab) instead of as a fixed full-screen overlay. */
  inline?: boolean;
}

/**
 * Gate shown only for the Vaults tab, modeled on NewKeystoreModal's modal card styling. The
 * rest of the app (dashboard, keystores, CA signing, examine, security, settings) is never
 * blocked by the master key — only vault secrets are.
 *
 * - "setup" mode: no vault file exists yet (first run). Asks the user to choose and confirm a
 *   master key, then calls `vault_init`.
 * - "unlock" mode: a vault file exists but is locked. Asks for the master key and calls
 *   `vault_unlock`, showing an inline error on a wrong-key failure.
 */
export const VaultLockScreen: React.FC<VaultLockScreenProps> = ({ mode, onUnlocked, inline = false }) => {
  const [masterKey, setMasterKey] = useState("");
  const [confirmKey, setConfirmKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isSetup = mode === "setup";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (isSetup) {
      if (masterKey.length < 8) {
        setError("Master key must be at least 8 characters.");
        return;
      }
      if (masterKey !== confirmKey) {
        setError("Master key and confirmation do not match.");
        return;
      }
    } else if (!masterKey) {
      setError("Enter your master key.");
      return;
    }

    setBusy(true);
    try {
      if (isSetup) {
        await invoke("vault_init", { masterKey });
      } else {
        await invoke("vault_unlock", { masterKey });
      }
      onUnlocked();
    } catch (err) {
      setError(isSetup ? `Failed to initialize vault: ${err}` : "Incorrect master key.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className={
        inline
          ? "flex-1 min-h-0 flex items-center justify-center p-4"
          : "fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4"
      }
    >
      <div className="w-full max-w-md bg-surface rounded-panel border border-line-strong shadow-pop p-6 space-y-4">
        <div className="flex items-center space-x-2.5 pb-2 border-b border-line">
          <div className="w-9 h-9 rounded-card border border-line bg-surface shadow-card text-ink-2 flex items-center justify-center">
            {isSetup ? <ShieldCheck className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
          </div>
          <div>
            <h3 className="text-[17px] font-semibold text-ink">
              {isSetup ? "Set Up Master Key" : "Vault Locked"}
            </h3>
            <p className="text-[11.5px] text-faint">
              {isSetup
                ? "Choose a master key to encrypt vault secrets at rest"
                : "Enter your master key to unlock xkeystore"}
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 text-[12.5px]">
          <div>
            <label className="font-medium text-muted block mb-1.5">
              {isSetup ? "Master Key" : "Master Key / Passphrase"}
            </label>
            <input
              type="password"
              autoFocus
              value={masterKey}
              onChange={(e) => setMasterKey(e.target.value)}
              required
              className="field"
              placeholder="••••••••••••"
            />
          </div>

          {isSetup && (
            <div>
              <label className="font-medium text-muted block mb-1.5">Confirm Master Key</label>
              <input
                type="password"
                value={confirmKey}
                onChange={(e) => setConfirmKey(e.target.value)}
                required
                className="field"
                placeholder="••••••••••••"
              />
            </div>
          )}

          {error && (
            <p className="text-[12px] text-danger bg-danger-tint border border-danger/30 rounded-control px-3 py-2">
              {error}
            </p>
          )}

          {isSetup && (
            <p className="text-[11px] text-faint leading-relaxed">
              This master key encrypts stored passphrases and vault secrets. It is never written
              to disk and cannot be recovered if lost — store it somewhere safe.
            </p>
          )}

          <div className="pt-2 flex justify-end">
            <button
              type="submit"
              disabled={busy}
              className="px-5 py-2 bg-brand hover:bg-brand-deep text-white font-semibold rounded-control shadow-card cursor-pointer flex items-center space-x-1.5 disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>
                {busy
                  ? isSetup
                    ? "Initializing vault..."
                    : "Unlocking..."
                  : isSetup
                    ? "Create Master Key"
                    : "Unlock Vault"}
              </span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
