import React from "react";
import { CheckCircle2, ShieldCheck, TerminalSquare } from "lucide-react";
import { Button, Card, PageHeader } from "../components/ui";
import { TerminalHint, useTerminal } from "../components/Terminal";

const PROVIDERS = [
  "X.509 v3 certificate and PKCS#10 CSR engine (rcgen 0.13)",
  "RSA PKCS#1 / PKCS#8 (rsa 0.9)",
  "NIST P-256 elliptic curve (p256 0.13)",
  "Ed25519 signatures (ed25519-dalek 2.2)",
  "Post-quantum ML-KEM / ML-DSA (FIPS 203 / 204)",
  "JKS (0xFEEDFEED) and PKCS#12 serializer",
];

export const SettingsView: React.FC = () => {
  const { open } = useTerminal();

  return (
    <div className="flex-1 overflow-y-auto px-8 py-6">
      <PageHeader title="Settings" description="Cryptographic providers, export location and the built-in terminal." />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="space-y-3">
          <div className="flex items-center gap-2 text-brand-deep font-semibold text-[15px]">
            <ShieldCheck className="w-5 h-5 text-brand" />
            Native cryptographic providers
          </div>
          <p className="text-[13px] text-muted leading-relaxed">
            All cryptography runs inside the bundled Rust engine, with no external runtime to install.
          </p>
          <ul className="space-y-1.5 pt-1 text-[12px]">
            {PROVIDERS.map((p) => (
              <li key={p} className="flex items-center gap-2 text-ink-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-success shrink-0" />
                {p}
              </li>
            ))}
          </ul>
        </Card>

        <div className="space-y-4">
          <Card className="space-y-3">
            <h3 className="text-[15px] font-semibold text-ink">Export location</h3>
            <p className="text-[13px] text-muted">
              Exported certificates, keys, bundles, CSV inventories and keystore files are written to:
            </p>
            <div className="p-3 rounded-control bg-surface-2 border border-line-strong font-mono text-[12px] text-brand-deep">
              ~/Downloads/xkeystore_Exports/
            </div>
            <TerminalHint command="ls -la ~/Downloads/xkeystore_Exports" label="List exports" />
          </Card>

          <Card className="space-y-3">
            <h3 className="text-[15px] font-semibold text-ink">Terminal</h3>
            <p className="text-[13px] text-muted">
              A shell is built in. Toggle it anywhere with <kbd className="px-1.5 py-0.5 rounded bg-surface-3 font-mono text-[11px]">Ctrl+`</kbd>.
            </p>
            <Button icon={TerminalSquare} onClick={() => open()}>
              Open terminal
            </Button>
          </Card>
        </div>
      </div>
    </div>
  );
};
