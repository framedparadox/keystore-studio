import React, { useState } from "react";
import { Eye, EyeOff, KeyRound, Lock, Unlock } from "lucide-react";
import { KeystoreFile } from "../types/crypto";
import { Badge, Button, Card, PageHeader } from "../components/ui";

interface VaultsViewProps {
  keystores: KeystoreFile[];
  onUpdateKeystore: (ks: KeystoreFile) => void;
}

export const VaultsView: React.FC<VaultsViewProps> = ({ keystores, onUpdateKeystore }) => {
  const [reveal, setReveal] = useState(false);

  return (
    <div className="flex-1 overflow-y-auto px-8 py-6">
      <PageHeader
        title="Vaults"
        description="Lock and unlock individual entries in each loaded keystore."
        actions={
          <Button icon={reveal ? EyeOff : Eye} onClick={() => setReveal(!reveal)}>
            {reveal ? "Mask passphrases" : "Reveal passphrases"}
          </Button>
        }
      />

      <div className="space-y-4">
        {keystores.map((ks) => (
          <Card key={ks.id} className="space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-surface-3">
              <div className="flex items-center gap-2.5">
                <KeyRound className="w-4 h-4 text-brand" />
                <span className="text-[15px] font-semibold text-ink">{ks.name}</span>
                <Badge tone="brand">{ks.format}</Badge>
              </div>
              <span className="font-mono text-[12.5px] text-muted">
                Store passphrase: <strong>{reveal ? "changeit#2026" : "••••••••••••"}</strong>
              </span>
            </div>

            {ks.entries.length === 0 && <p className="text-[12.5px] text-faint">No readable entries in this store.</p>}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {ks.entries.map((entry) => (
                <div
                  key={entry.id}
                  className="p-3 rounded-control bg-surface-2 border border-line flex items-center justify-between text-[12.5px]"
                >
                  <div>
                    <div className="font-semibold text-ink">{entry.alias}</div>
                    <div className="text-[11px] text-faint">
                      {entry.entry_type} • {reveal ? "unlocked-key-pass" : "••••••••"}
                    </div>
                  </div>
                  <button
                    onClick={() =>
                      onUpdateKeystore({
                        ...ks,
                        entries: ks.entries.map((en) => (en.id === entry.id ? { ...en, locked: !en.locked } : en)),
                      })
                    }
                    className={`px-3 py-1 rounded-full text-[11.5px] font-semibold flex items-center gap-1 cursor-pointer ${
                      entry.locked ? "bg-danger-tint text-danger" : "bg-success-tint text-success"
                    }`}
                  >
                    {entry.locked ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                    {entry.locked ? "Locked" : "Unlocked"}
                  </button>
                </div>
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};
