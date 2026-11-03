import React, { useMemo, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CalendarClock,
  CheckCircle2,
  FilePlus2,
  FileSignature,
  FolderArchive,
  HelpCircle,
  KeyRound,
  Layers,
  SearchCode,
  ShieldCheck,
  Sparkles,
  Upload,
} from "lucide-react";
import { KeystoreFile, KeystoreFormat, TabType, Workspace } from "../types/crypto";
import {
  Badge,
  BarList,
  Button,
  Card,
  CardHeader,
  ColumnChart,
  DataTable,
  KpiCard,
  Meter,
  Modal,
  Page,
  PageHeader,
  ScoreRing,
  SegmentedBar,
} from "../components/ui";
import { EntryNameCell, ExpiryCell, HealthBadge } from "../components/entry";
import {
  ageBuckets,
  algorithmMix,
  daysUntilExpiry,
  entryHealth,
  expiryBuckets,
  FlatEntry,
  flattenEntries,
  formatDuration,
  summarize,
} from "../lib/metrics";
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

  const flat = useMemo(() => flattenEntries(keystores), [keystores]);
  const entries = useMemo(() => flat.map((f) => f.entry), [flat]);
  const s = useMemo(() => summarize(entries), [entries]);
  const expiry = useMemo(() => expiryBuckets(entries), [entries]);
  const ages = useMemo(() => ageBuckets(entries), [entries]);
  const algos = useMemo(() => algorithmMix(entries), [entries]);
  const health = useMemo(() => {
    const h = { healthy: 0, attention: 0, "at-risk": 0 };
    for (const e of entries) h[entryHealth(e)]++;
    return h;
  }, [entries]);
  const upcoming = useMemo(
    () =>
      flat
        .filter((f) => daysUntilExpiry(f.entry) !== null)
        .sort((a, b) => (daysUntilExpiry(a.entry) ?? 0) - (daysUntilExpiry(b.entry) ?? 0))
        .slice(0, 6),
    [flat]
  );

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
  const scoreTone = s.healthScore >= 85 ? "success" : s.healthScore >= 65 ? "warning" : "danger";

  return (
    <Page {...bind}>
      <PageHeader
        title="Dashboard"
        description={`Certificate and key health across ${keystores.length} keystores and ${workspaces.length} workspaces.`}
        actions={
          <>
            <Button icon={Layers} onClick={() => onSelectTab("workspaces")}>
              Workspaces
            </Button>
            <Button icon={FolderArchive} onClick={() => onSelectTab("keystores")}>
              Browse keystores
            </Button>
          </>
        }
      />

      {/* KPI strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <KpiCard
          label="Total entries"
          value={s.total}
          icon={KeyRound}
          tone="brand"
          hint={`Across ${keystores.length} keystores`}
          onClick={() => onSelectTab("keystores")}
        >
          <div className="flex items-center justify-between text-[12px] text-faint">
            <span><strong className="text-ink font-semibold">{s.keyPairs}</strong> key pairs</span>
            <span><strong className="text-ink font-semibold">{s.trusted}</strong> certs</span>
            <span><strong className="text-ink font-semibold">{s.secrets}</strong> secrets</span>
          </div>
        </KpiCard>
        <KpiCard
          label="Expiring in 90 days"
          value={s.expiring90}
          icon={CalendarClock}
          tone="warning"
          hint={s.expiring30 ? `${s.expiring30} within 30 days` : "None within 30 days"}
          hintTone={s.expiring30 ? "warning" : "neutral"}
          onClick={() => onSelectTab("keystores")}
        >
          <Meter value={s.total ? s.expiring90 / s.total : 0} tone="warning" label="Share of entries expiring within 90 days" />
        </KpiCard>
        <KpiCard
          label="Needs action"
          value={s.expired + s.weak}
          icon={AlertTriangle}
          tone="danger"
          hint={`${s.expired} expired · ${s.weak} weak ${s.weak === 1 ? "key" : "keys"}`}
          hintTone={s.expired + s.weak ? "danger" : "success"}
          onClick={() => onSelectTab("scanner")}
        >
          <Meter value={s.total ? (s.expired + s.weak) / s.total : 0} tone="danger" label="Share of entries needing action" />
        </KpiCard>
        <KpiCard
          label="Post-quantum ready"
          value={s.total ? `${Math.round((s.pqc / s.total) * 100)}%` : "—"}
          icon={Sparkles}
          tone="brand"
          hint={`${s.pqc} of ${s.total} entries`}
        >
          <Meter value={s.total ? s.pqc / s.total : 0} tone="brand" label="Share of post-quantum entries" />
        </KpiCard>
      </div>

      {/* Bento */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mt-4">
        {/* Posture — tall tile */}
        <Card className="lg:col-span-4 lg:row-span-2 flex flex-col">
          <CardHeader title="Security posture" subtitle="Weighted by expiry and key strength" icon={ShieldCheck} />
          <div className="flex items-center gap-5">
            <ScoreRing value={s.healthScore} tone={scoreTone} label="Inventory health score" />
            <div className="flex-1 space-y-2.5">
              {(
                [
                  ["healthy", "Healthy", "success"],
                  ["attention", "Renew soon", "warning"],
                  ["at-risk", "At risk", "danger"],
                ] as const
              ).map(([k, label, tone]) => (
                <div key={k} className="flex items-center justify-between text-[12.5px]">
                  <Badge tone={tone} dot>
                    {label}
                  </Badge>
                  <span className="font-semibold text-ink tabular-nums">{health[k]}</span>
                </div>
              ))}
            </div>
          </div>
          <dl className="grid grid-cols-2 gap-px mt-6 rounded-control overflow-hidden border border-line bg-line">
            {[
              ["Median key age", formatDuration(s.medianAgeDays)],
              ["Oldest key", formatDuration(s.oldestAgeDays)],
              ["Locked entries", String(s.locked)],
              ["Keystores", String(keystores.length)],
            ].map(([k, v]) => (
              <div key={k} className="bg-surface px-3.5 py-3">
                <dt className="text-[11.5px] text-faint">{k}</dt>
                <dd className="text-[15px] font-semibold text-ink mt-0.5">{v}</dd>
              </div>
            ))}
          </dl>
          <div className="mt-auto pt-5">
            <Button className="w-full" icon={ShieldCheck} onClick={() => onSelectTab("scanner")}>
              Open security review
            </Button>
          </div>
        </Card>

        <Card className="lg:col-span-4">
          <CardHeader title="Expiry horizon" subtitle="Entries by time to expiry" icon={CalendarClock} />
          <SegmentedBar
            label="Expiry horizon"
            parts={expiry.map((b) => ({
              key: b.key,
              label: b.label,
              value: b.count,
              fill: b.key === "critical" ? "bg-serious-fill" : undefined,
              tone:
                b.key === "expired" || b.key === "critical"
                  ? "danger"
                  : b.key === "warning"
                  ? "warning"
                  : b.key === "ok"
                  ? "success"
                  : "neutral",
            }))}
          />
        </Card>

        <Card className="lg:col-span-4">
          <CardHeader
            title="Key age"
            subtitle={`Median ${formatDuration(s.medianAgeDays)} since creation`}
            icon={KeyRound}
          />
          <ColumnChart label="Key age distribution" items={ages} height={92} />
        </Card>

        <Card className="lg:col-span-4">
          <CardHeader title="Algorithm mix" subtitle={`${algos.length} algorithm families`} />
          <BarList items={algos.slice(0, 5)} total={s.total} />
        </Card>

        <Card className="lg:col-span-4 flex flex-col">
          <CardHeader title="Import" subtitle="Keystores open in place; certificates open in Examine" icon={Upload} />
          <DropZone dragging={dragging} busy={busy} onFiles={handleFiles} className="flex-1 !py-4" />
          {log.length > 0 && (
            <ul className="mt-3 space-y-1.5" aria-live="polite">
              {log.map((entry, i) => (
                <li key={i} className="flex items-start gap-2 text-[12px]">
                  {entry.tone === "success" ? (
                    <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-success shrink-0" />
                  ) : (
                    <AlertCircle className="w-3.5 h-3.5 mt-0.5 text-danger shrink-0" />
                  )}
                  <div className="min-w-0">
                    <div className="font-medium text-ink truncate">{entry.title}</div>
                    {entry.detail && <div className="text-faint">{entry.detail}</div>}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {/* Upcoming expirations */}
        <Card padded={false} className="lg:col-span-8 overflow-hidden flex flex-col">
          <CardHeader
            bordered
            title="Upcoming expirations"
            subtitle="Soonest first, across every loaded keystore"
            actions={
              <Button size="sm" variant="ghost" onClick={() => onSelectTab("keystores")}>
                View all <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            }
          />
          <DataTable<FlatEntry>
            label="Upcoming expirations"
            rows={upcoming}
            rowKey={(r) => r.entry.id}
            onRowClick={(r) => onSelectKeystoreAndOpen(r.keystore.id)}
            columns={[
              { id: "alias", header: "Entry", width: "38%", cell: (r) => <EntryNameCell entry={r.entry} /> },
              {
                id: "ks",
                header: "Keystore",
                hideBelow: "xl",
                cell: (r) => <span className="text-muted truncate block">{r.keystore.name}</span>,
              },
              { id: "exp", header: "Expires", width: "220px", cell: (r) => <ExpiryCell entry={r.entry} /> },
              { id: "status", header: "Status", width: "130px", cell: (r) => <HealthBadge entry={r.entry} /> },
            ]}
          />
        </Card>

        {/* Quick actions */}
        <Card className="lg:col-span-4 flex flex-col">
          <CardHeader title="Quick actions" />
          <div className="rounded-control border border-line p-3.5">
            <div className="flex items-center gap-2 text-[13px] font-medium text-ink">
              <FilePlus2 className="w-4 h-4 text-subtle" /> New keystore
            </div>
            <div className="grid grid-cols-3 gap-1.5 mt-2.5">
              {FORMATS.map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => onOpenNewKeystoreWithFormat(fmt)}
                  className="h-7 rounded-[5px] border border-line bg-surface-2 hover:bg-brand-tint hover:border-brand-soft hover:text-brand-deep text-ink-2 text-[11.5px] font-semibold transition cursor-pointer"
                >
                  {fmt}
                </button>
              ))}
            </div>
          </div>
          <ul className="mt-2 divide-y divide-line">
            {[
              { icon: SearchCode, label: "Examine a server or PEM", tab: "examine" as TabType },
              { icon: FileSignature, label: "Sign a CSR, JAR or JWT", tab: "ca_signing" as TabType },
              { icon: ShieldCheck, label: "Rotate weak keys", tab: "scanner" as TabType },
            ].map((a) => (
              <li key={a.label}>
                <button
                  onClick={() => onSelectTab(a.tab)}
                  className="w-full flex items-center gap-2.5 py-2.5 text-[13px] text-ink-2 hover:text-ink cursor-pointer group"
                >
                  <a.icon className="w-4 h-4 text-subtle group-hover:text-brand" />
                  <span className="flex-1 text-left">{a.label}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-subtle group-hover:text-ink" />
                </button>
              </li>
            ))}
          </ul>
          <div className="mt-auto pt-2">
            <TerminalHint command="ls -la ~/.keystore" label="Run" />
          </div>
        </Card>

        {/* Keystores table */}
        <Card padded={false} className="lg:col-span-8 overflow-hidden flex flex-col">
          <CardHeader bordered title="Loaded keystores" subtitle={`${keystores.length} files open`} icon={FolderArchive} />
          <DataTable<KeystoreFile>
            label="Loaded keystores"
            rows={keystores}
            rowKey={(k) => k.id}
            onRowClick={(k) => onSelectKeystoreAndOpen(k.id)}
            columns={[
              {
                id: "name",
                header: "Name",
                width: "40%",
                sortValue: (k) => k.name,
                cell: (k) => (
                  <div className="min-w-0">
                    <div className="font-medium text-ink truncate">{k.name}</div>
                    <div className="text-[12px] text-faint truncate font-mono">{k.path}</div>
                  </div>
                ),
              },
              { id: "fmt", header: "Format", sortValue: (k) => k.format, cell: (k) => <Badge>{k.format}</Badge> },
              {
                id: "n",
                header: "Entries",
                align: "right",
                sortValue: (k) => k.entries.length,
                cell: (k) => <span className="text-ink">{k.entries.length}</span>,
              },
              {
                id: "risk",
                header: "Issues",
                align: "right",
                sortValue: (k) => k.entries.filter((e) => entryHealth(e) !== "healthy").length,
                cell: (k) => {
                  const n = k.entries.filter((e) => entryHealth(e) !== "healthy").length;
                  return n ? <Badge tone="warning">{n}</Badge> : <span className="text-subtle">—</span>;
                },
              },
              { id: "upd", header: "Updated", hideBelow: "xl", cell: (k) => <span className="text-faint">{k.updated_at}</span> },
            ]}
          />
        </Card>

        {/* Workspaces */}
        <Card padded={false} className="lg:col-span-4 overflow-hidden">
          <CardHeader bordered title="Workspaces" subtitle={`${workspaces.length} collections`} icon={Layers} />
          <ul className="divide-y divide-line">
            {workspaces.map((ws) => (
              <li key={ws.id}>
                <button
                  onClick={() => onSelectWorkspaceAndOpen(ws.id)}
                  className="w-full px-5 py-3 flex items-center gap-3 text-left hover:bg-surface-2 transition cursor-pointer"
                >
                  <div className="flex-1 min-w-0">
                    <div className="text-[13px] font-medium text-ink truncate">{ws.name}</div>
                    <div className="text-[12px] text-faint">{ws.entryIds.length} entries · updated {ws.updated_at}</div>
                  </div>
                  <Badge tone={ws.environment === "Production" ? "brand" : "neutral"}>{ws.environment}</Badge>
                </button>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      {/* Help */}
      <div className="mt-6 flex flex-wrap items-center gap-1.5">
        <HelpCircle className="w-4 h-4 text-subtle" />
        <span className="text-[12.5px] text-faint mr-1">Guides</span>
        {Object.entries(HELP).map(([id, t]) => (
          <Button key={id} size="sm" variant="ghost" onClick={() => setHelpTopic(id)}>
            {t.label}
          </Button>
        ))}
      </div>

      {/* Whole-page drop overlay */}
      {dragging && (
        <div className="pointer-events-none fixed inset-0 z-40 border-2 border-dashed border-brand bg-brand/5" />
      )}

      <Modal
        open={helpTopic !== null}
        onClose={() => setHelpTopic(null)}
        icon={BookOpen}
        title={helpTopic ? HELP[helpTopic].label : ""}
      >
        <div className="text-[13px] text-ink-2 leading-relaxed select-text">{helpTopic && HELP[helpTopic].body}</div>
      </Modal>
    </Page>
  );
};
