import React, { useState } from "react";
import {
  AlertCircle,
  BookOpen,
  CheckCircle2,
  FilePlus2,
  FileSignature,
  FolderArchive,
  HelpCircle,
  Layers,
  SearchCode,
  TerminalSquare,
  X,
} from "lucide-react";
import { KeystoreFile, KeystoreFormat, TabType, Workspace } from "../types/crypto";
import { Badge, Button, Card, PageHeader } from "../components/ui";
import { DropZone, useFileDrop } from "../components/DropZone";
import { TerminalHint } from "../components/Terminal";
import { ImportResult, importFile } from "../lib/importFile";

interface HomeViewProps {
  keystores: KeystoreFile[];
  workspaces: Workspace[];
  onSelectTab: (tab: TabType) => void;
  onSelectKeystoreAndOpen: (ksId: string) => void;
  onSelectWorkspaceAndOpen: (wsId: string) => void;
  onOpenNewKeystoreWithFormat: (format?: KeystoreFormat) => void;
  onImportKeystores: (list: KeystoreFile[]) => void;
  onExamineText: (text: string) => void;
}

const FORMATS: KeystoreFormat[] = ["PKCS12", "JKS", "JCEKS", "BKS", "BCFKS", "UBER"];

const HELP: Record<string, { label: string; body: React.ReactNode }> = {
  formats: {
    label: "Keystore formats",
    body: (
      <ul className="list-disc pl-5 space-y-1.5">
        <li><strong>PKCS#12 (.p12 / .pfx):</strong> the standard archive for private keys, certificate chains and trusted roots.</li>
        <li><strong>JKS (.jks):</strong> the classic Java keystore, identified by the 0xFEEDFEED header.</li>
        <li><strong>JCEKS / BKS / BCFKS / UBER:</strong> variants that add secret keys or FIPS-oriented encryption.</li>
      </ul>
    ),
  },
  workspaces: {
    label: "Workspaces",
    body: (
      <p>
        Workspaces group certificates and keys by project, cluster or audit scope without changing the underlying
        keystore files. Assign entries from the Workspaces tab or the keystore table, and switch the active workspace from the header.
      </p>
    ),
  },
  pqc: {
    label: "Post-quantum",
    body: (
      <ul className="list-disc pl-5 space-y-1.5">
        <li><strong>ML-DSA-65 (FIPS 204):</strong> lattice-based signatures.</li>
        <li><strong>ML-KEM-768 (FIPS 203):</strong> key encapsulation for quantum-safe handshakes.</li>
        <li><strong>SLH-DSA (FIPS 205):</strong> stateless hash-based signatures.</li>
      </ul>
    ),
  },
  signing: {
    label: "CA and signing",
    body: (
      <ul className="list-disc pl-5 space-y-1.5">
        <li><strong>Sign CSR:</strong> issue a certificate from any key pair in a keystore.</li>
        <li><strong>Issue CRL:</strong> generate a signed revocation list.</li>
        <li><strong>Sign JAR:</strong> write <code>META-INF/MANIFEST.MF</code> and signature files.</li>
      </ul>
    ),
  },
};

interface ImportLogEntry {
  tone: "success" | "danger";
  title: string;
  detail?: string;
}

export const HomeView: React.FC<HomeViewProps> = ({
  keystores,
  workspaces,
  onSelectTab,
  onSelectKeystoreAndOpen,
  onSelectWorkspaceAndOpen,
  onOpenNewKeystoreWithFormat,
  onImportKeystores,
  onExamineText,
}) => {
  const [helpTopic, setHelpTopic] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<ImportLogEntry[]>([]);

  const handleFiles = async (files: File[]) => {
    setBusy(true);
    const results: ImportResult[] = [];
    for (const f of files) {
      try {
        results.push(await importFile(f));
      } catch (e) {
        results.push({ kind: "unsupported", fileName: f.name, reason: e instanceof Error ? e.message : String(e) });
      }
    }
    setBusy(false);

    setLog(
      results.map((r): ImportLogEntry => {
        if (r.kind === "keystore")
          return {
            tone: "success",
            title: `${r.fileName} → ${r.keystore.format} keystore, ${r.keystore.entries.length} entries`,
            detail: r.note,
          };
        if (r.kind === "examine") return { tone: "success", title: `${r.fileName} → opened in Examine` };
        return { tone: "danger", title: r.fileName, detail: r.reason };
      })
    );

    const stores = results.flatMap((r) => (r.kind === "keystore" ? [r.keystore] : []));
    const certs = results.flatMap((r) => (r.kind === "examine" ? [r.text] : []));
    if (stores.length) onImportKeystores(stores);
    else if (certs.length) onExamineText(certs[0]);
  };

  const { dragging, bind } = useFileDrop(handleFiles);

  return (
    <div {...bind} className="relative flex-1 overflow-y-auto px-8 py-4 flex flex-col">
      <PageHeader
        title="Home"
        description="Open a keystore or certificate by dropping it below, or start a new one."
        actions={
          <>
            <Button icon={Layers} onClick={() => onSelectTab("workspaces")}>
              Workspaces ({workspaces.length})
            </Button>
            <Button variant="primary" icon={FolderArchive} onClick={() => onSelectTab("keystores")}>
              Open keystores
            </Button>
          </>
        }
      />

      <DropZone dragging={dragging} busy={busy} onFiles={handleFiles} />

      {log.length > 0 && (
        <ul className="mt-3 space-y-1.5" aria-live="polite">
          {log.map((entry, i) => (
            <li
              key={i}
              className="flex items-start gap-2 rounded-control bg-surface border border-line px-3 py-2 text-[12.5px]"
            >
              {entry.tone === "success" ? (
                <CheckCircle2 className="w-4 h-4 mt-0.5 text-success shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 mt-0.5 text-danger shrink-0" />
              )}
              <div>
                <div className="font-semibold text-ink">{entry.title}</div>
                {entry.detail && <div className="text-faint">{entry.detail}</div>}
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* Quick actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 mt-4">
        <Card className="flex flex-col !p-4">
          <FilePlus2 className="w-5 h-5 text-brand mb-2" />
          <h3 className="text-[15px] font-semibold text-ink">New keystore</h3>
          <p className="text-[12.5px] text-faint mt-1 mb-2">Create an empty store.</p>
          <div className="flex flex-wrap gap-1.5 mt-auto">
            {FORMATS.map((fmt) => (
              <button
                key={fmt}
                onClick={() => onOpenNewKeystoreWithFormat(fmt)}
                className="px-2.5 py-1 rounded-control bg-surface-2 hover:bg-brand-soft border border-line text-ink-2 hover:text-brand-deep text-[11px] font-bold transition cursor-pointer"
              >
                {fmt}
              </button>
            ))}
          </div>
        </Card>

        <Card interactive className="flex flex-col !p-4" onClick={() => onSelectTab("examine")}>
          <SearchCode className="w-5 h-5 text-brand mb-2" />
          <h3 className="text-[15px] font-semibold text-ink">Examine</h3>
          <p className="text-[12.5px] text-faint mt-1">Inspect TLS servers, PEMs, diffs.</p>
        </Card>

        <Card interactive className="flex flex-col !p-4" onClick={() => onSelectTab("ca_signing")}>
          <FileSignature className="w-5 h-5 text-brand mb-2" />
          <h3 className="text-[15px] font-semibold text-ink">CA and signing</h3>
          <p className="text-[12.5px] text-faint mt-1">Sign CSRs, CRLs, JARs, JWTs.</p>
        </Card>

        <Card className="flex flex-col !p-4">
          <TerminalSquare className="w-5 h-5 text-brand mb-2" />
          <h3 className="text-[15px] font-semibold text-ink">Terminal</h3>
          <p className="text-[12.5px] text-faint mt-1 mb-2">Run shell commands in-app.</p>
          <div className="mt-auto">
            <TerminalHint command="ls -la ~/.keystore" label="Run" />
          </div>
        </Card>
      </div>

      {/* Keystores + workspaces */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-3">
        <Card className="!p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-[15px] font-semibold text-ink">Loaded keystores</h3>
            <Badge tone="brand">{keystores.length}</Badge>
          </div>
          <ul className="space-y-1.5">
            {keystores.slice(0, 2).map((ks) => (
              <li key={ks.id}>
                <button
                  onClick={() => onSelectKeystoreAndOpen(ks.id)}
                  className="w-full px-3 py-1.5 rounded-control bg-surface-2 hover:bg-brand-tint border border-line flex items-center justify-between text-left transition cursor-pointer"
                >
                  <span className="text-[12.5px] font-semibold text-ink truncate">{ks.name}</span>
                  <span className="text-[11px] font-semibold text-faint shrink-0 ml-3">
                    {ks.format} · {ks.entries.length} entries
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <Card className="!p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-[15px] font-semibold text-ink">Workspaces</h3>
            <Badge tone="brand">{workspaces.length}</Badge>
          </div>
          <ul className="space-y-1.5">
            {workspaces.slice(0, 2).map((ws) => (
              <li key={ws.id}>
                <button
                  onClick={() => onSelectWorkspaceAndOpen(ws.id)}
                  className="w-full px-3 py-1.5 rounded-control bg-surface-2 hover:bg-brand-tint border border-line flex items-center justify-between text-left transition cursor-pointer"
                >
                  <span className="text-[12.5px] font-semibold text-ink truncate">{ws.name}</span>
                  <span className="text-[11px] font-semibold text-faint shrink-0 ml-3">
                    {ws.environment} · {ws.entryIds.length} certs
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      {/* Help */}
      <div className="mt-auto pt-2 flex flex-wrap items-center gap-2">
        <HelpCircle className="w-4 h-4 text-faint" />
        <span className="text-[12.5px] text-faint mr-1">Help:</span>
        {Object.entries(HELP).map(([id, t]) => (
          <Button key={id} size="sm" variant="ghost" onClick={() => setHelpTopic(id)}>
            {t.label}
          </Button>
        ))}
      </div>

      {/* Whole-page drop overlay */}
      {dragging && (
        <div className="pointer-events-none absolute inset-0 rounded-panel border-2 border-dashed border-brand bg-brand/10" />
      )}

      {helpTopic && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
          onClick={() => setHelpTopic(null)}
        >
          <div
            className="w-full max-w-xl bg-surface rounded-panel border border-line-strong shadow-2xl p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between pb-3 border-b border-line">
              <div className="flex items-center gap-2.5">
                <BookOpen className="w-5 h-5 text-brand" />
                <h3 className="text-[17px] font-bold text-ink">{HELP[helpTopic].label}</h3>
              </div>
              <button onClick={() => setHelpTopic(null)} aria-label="Close help" className="p-1.5 text-faint hover:text-ink cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="py-4 text-[13px] text-ink-2 leading-relaxed select-text">{HELP[helpTopic].body}</div>
          </div>
        </div>
      )}
    </div>
  );
};
