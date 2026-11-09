import React, { useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowLeftRight,
  ArrowRight,
  CalendarClock,
  Clock,
  FilePlus2,
  FileSignature,
  FolderArchive,
  FolderOpen,
  KeyRound,
  Layers,
  Lock,
  Play,
  SearchCode,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { useStore } from "../state/store";
import { Alert, Badge, BarList, Button, Card, CardHeader, ColumnChart, DataTable, EmptyState, Kbd, KpiCard, Meter, Page, PageHeader, ScoreRing, SegmentedBar } from "../components/ui";
import { EntryNameCell, ExpiryCell, HealthBadge } from "../components/entry";
import { useTerminal } from "../components/Terminal";
import { ageBuckets, algorithmMix, daysUntilExpiry, entryHealth, entryMix, expiryBuckets, FlatEntry, flattenEntries, formatDuration, summarize } from "../lib/metrics";
import { DropZone } from "../components/DropZone";
import { FORMAT_INFO } from "../lib/keystore";
import type { KeystoreFormat, OpenKeystore } from "../types/crypto";
import { nullInput } from "../lib/platform";

/*
 * Info boxes closed on the dashboard stay closed for the rest of the session (also across a reload,
 * through sessionStorage when the webview allows it).
 */
const NOTICES_KEY = "xkeystore.dismissedNotices";
const dismissedNotices: Set<string> = (() => {
  try {
    return new Set<string>(JSON.parse(sessionStorage.getItem(NOTICES_KEY) ?? "[]"));
  } catch {
    return new Set<string>();
  }
})();
const useNotices = () => {
  const [, rerender] = useState(0);
  return {
    dismissed: (id: string) => dismissedNotices.has(id),
    dismiss: (ids: string[]) => {
      ids.forEach((id) => dismissedNotices.add(id));
      try {
        sessionStorage.setItem(NOTICES_KEY, JSON.stringify([...dismissedNotices]));
      } catch {
        /* storage refused: closed until the app restarts */
      }
      rerender((n) => n + 1);
    },
  };
};

const RecentFiles: React.FC = () => {
  const { recentFiles, openFiles, keystores } = useStore();
  if (!recentFiles.length) return <p className="text-[13px] text-faint">Files you open appear here.</p>;
  return (
    <ul className="divide-y divide-line -mx-1">
      {recentFiles.slice(0, 6).map((f) => {
        const open = keystores.some((k) => k.path === f.path && !k.sealed);
        return (
          <li key={f.path}>
            <button onClick={() => openFiles([f.path])} className="w-full px-1 py-2.5 flex items-center gap-3 text-left hover:bg-surface-2 rounded-control cursor-pointer" title={f.path}>
              <FolderArchive className="w-4 h-4 text-subtle shrink-0" />
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] font-medium text-ink truncate">{f.name}</span>
                <span className="block text-[11.5px] text-faint font-mono truncate">{f.path}</span>
              </span>
              {open ? <Badge tone="success">Open</Badge> : <Badge>{FORMAT_INFO[f.format as KeystoreFormat]?.label ?? f.format}</Badge>}
            </button>
          </li>
        );
      })}
    </ul>
  );
};

// Two ready-made commands, one per column; the terminal itself takes any other.
const TERMINAL_SNIPPETS: { label: string; command: string }[] = [
  { label: "List keystore entries", command: "keytool -list -v -keystore keystore.p12 -storetype PKCS12 -storepass changeit" },
  { label: "Inspect a TLS server", command: `openssl s_client -connect example.com:443 -servername example.com -showcerts ${nullInput()}` },
];

const TerminalSection: React.FC = () => {
  const { open, toggle } = useTerminal();
  return (
    <Card padded={false} className="lg:col-span-12 overflow-hidden flex flex-col" data-testid="terminal-section">
      <CardHeader
        bordered
        title="Terminal"
        subtitle="Run keytool, openssl and friends without leaving xkeystore"
        icon={TerminalSquare}
        actions={
          <Button size="sm" variant="ghost" icon={TerminalSquare} onClick={toggle}>
            Open terminal <Kbd>Ctrl `</Kbd>
          </Button>
        }
      />
      <ul className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-line" data-testid="terminal-snippets">
        {TERMINAL_SNIPPETS.map((s) => (
          <li key={s.label} className="min-w-0 px-5 py-3 flex items-center gap-3">
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-medium text-ink">{s.label}</div>
              <code className="block text-[12px] text-faint font-mono truncate" title={s.command}>
                {s.command}
              </code>
            </div>
            <Button size="sm" icon={Play} onClick={() => open(s.command)}>
              Run
            </Button>
          </li>
        ))}
      </ul>
    </Card>
  );
};

export const HomeView: React.FC = () => {
  const { keystores, workspaces, setTab, selectKeystore, openFiles, setNewKeystoreOpen, setBuildPkcs12Open, vault, setActiveWorkspaceId, settings, desktop, openConverter } = useStore();
  const loaded = keystores.filter((k) => !k.sealed);
  const sealed = keystores.filter((k) => k.sealed);
  const flat = useMemo(() => flattenEntries(loaded), [loaded]);
  const entries = useMemo(() => flat.map((f) => f.entry), [flat]);
  const s = useMemo(() => summarize(entries), [entries]);
  const expiry = useMemo(() => expiryBuckets(entries), [entries, settings.criticalDays, settings.warningDays]); // eslint-disable-line react-hooks/exhaustive-deps
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
  const notices = useNotices();
  const scoreTone = s.healthScore >= 85 ? "success" : s.healthScore >= 65 ? "warning" : "danger";
  const unsaved = keystores.filter((k) => k.dirty).length;
  const openKs = (k: OpenKeystore) => {
    selectKeystore(k.id);
    setTab("keystores");
  };

  if (!loaded.length) {
    return (
      <Page>
        <PageHeader title="Welcome to xkeystore" description="A workbench for Java keystores, PKCS#12 files and X.509 certificates. Everything runs locally." />
        {!desktop && !notices.dismissed("browser-preview") && (
          <Alert tone="warning" className="mb-4" title="Browser preview" testId="browser-preview" onDismiss={() => notices.dismiss(["browser-preview"])}>
            The native engine is only available in the desktop app (pnpm tauri dev). Buttons that touch files or keys will report an error here.
          </Alert>
        )}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <Card className="lg:col-span-8" data-testid="get-started">
            <CardHeader title="Get started" />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {[
                { icon: FolderOpen, title: "Open a keystore", text: "PKCS#12, JKS or JCEKS — enter its password to view and edit entries.", action: () => openFiles(), testId: "welcome-open" },
                { icon: FilePlus2, title: "Create a keystore", text: "Start empty or with a fresh key pair and self-signed certificate.", action: () => setNewKeystoreOpen(true), testId: "welcome-new" },
                { icon: SearchCode, title: "Examine", text: "Inspect a TLS server, test a connection, or decode a certificate, CSR, key or JWT.", action: () => setTab("examine"), testId: "welcome-examine" },
                { icon: ArrowLeftRight, title: "Convert", text: "PEM ↔ DER, PKCS#7, PKCS#8, OpenSSH, JWK, and JKS ↔ PKCS#12.", action: () => openConverter(null), testId: "welcome-convert" },
                {
                  icon: FolderArchive,
                  title: "Create a PKCS#12",
                  text: "Bundle a certificate and its private key into a password-protected .p12 or .pfx.",
                  action: () => setBuildPkcs12Open(true),
                  testId: "welcome-build-p12",
                },
                // Six tiles fill the two-column grid. Five left the last one alone on its row.
                { icon: ShieldCheck, title: "Security audit", text: "Find expired, weak and expiring keys and certificates across every open keystore.", action: () => setTab("scanner"), testId: "welcome-audit" },
              ].map((a) => (
                <button key={a.title} onClick={a.action} data-testid={a.testId} className="text-left rounded-card border border-line p-4 hover:border-brand hover:bg-brand-tint/50 transition cursor-pointer">
                  <span className="flex items-center gap-2.5">
                    <a.icon className="w-5 h-5 text-brand shrink-0" aria-hidden />
                    <span className="text-[14px] font-semibold text-ink">{a.title}</span>
                  </span>
                  <span className="block text-[13px] text-faint mt-1.5">{a.text}</span>
                </button>
              ))}
            </div>
          </Card>
          {/* Open first, recent files under it. On wide windows the column is exactly as tall as Get
              started (it does not set the row height), and the recent files scroll inside their card. */}
          <div className="lg:col-span-4 lg:relative">
            <div className="flex flex-col gap-4 lg:absolute lg:inset-0">
              {/* Compact, as under Quick actions, so Recent files keeps room for its list. */}
              <DropZone onClick={() => openFiles()} className="shrink-0 !py-4" />
              <Card className="lg:flex-1 lg:min-h-0 flex flex-col" data-testid="recent-files">
                <CardHeader title="Recent files" icon={Clock} />
                <div className="min-h-0 overflow-y-auto -mx-1 px-1">
                  <RecentFiles />
                </div>
              </Card>
            </div>
          </div>
          <TerminalSection />
        </div>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader
        title="Dashboard"
        description={`Certificate and key health across ${loaded.length} open keystore${loaded.length === 1 ? "" : "s"}${workspaces.length ? ` and ${workspaces.length} workspaces` : ""}.`}
        actions={
          <>
            <Button icon={FolderOpen} onClick={() => openFiles()}>
              Open…
            </Button>
            <Button icon={FolderArchive} onClick={() => setBuildPkcs12Open(true)} data-testid="home-build-p12">
              Create PKCS#12…
            </Button>
            <Button variant="primary" icon={FilePlus2} onClick={() => setNewKeystoreOpen(true)}>
              New keystore
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <KpiCard label="Total entries" value={s.total} icon={KeyRound} tone="brand" hint={entryMix(s)} onClick={() => setTab("keystores")} />
        <KpiCard
          label={`Expiring within ${settings.warningDays} days`}
          value={s.expiringWarning}
          icon={CalendarClock}
          tone="warning"
          hint={s.expiringCritical ? `${s.expiringCritical} within ${settings.criticalDays} days` : `None within ${settings.criticalDays} days`}
          hintTone={s.expiringCritical ? "warning" : "neutral"}
          onClick={() => setTab("scanner")}
        >
          <Meter value={s.total ? s.expiringWarning / s.total : 0} tone="warning" label="Share of entries expiring soon" />
        </KpiCard>
        <KpiCard
          label="Needs action"
          value={s.expired + s.weak}
          icon={AlertTriangle}
          tone="danger"
          hint={`${s.expired} expired · ${s.weak} weak`}
          hintTone={s.expired + s.weak ? "danger" : "success"}
          onClick={() => setTab("scanner")}
        >
          <Meter value={s.total ? (s.expired + s.weak) / s.total : 0} tone="danger" label="Share of entries needing action" />
        </KpiCard>
        <KpiCard label="Keystores" value={keystores.length} icon={FolderArchive} hint={unsaved ? `${unsaved} with unsaved changes` : sealed.length ? `${sealed.length} locked` : "All saved"} hintTone={unsaved ? "warning" : "neutral"} onClick={() => setTab("keystores")} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mt-4">
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
                <div key={k} className="flex items-center justify-between text-[13px]">
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
              ["Locked keys", String(s.locked)],
              ["Workspaces", String(workspaces.length)],
            ].map(([k, v]) => (
              <div key={k} className="bg-surface px-3.5 py-3">
                <dt className="text-[11.5px] text-faint">{k}</dt>
                <dd className="text-[14px] font-semibold text-ink mt-0.5">{v}</dd>
              </div>
            ))}
          </dl>
          <div className="mt-auto pt-5">
            <Button className="w-full" icon={ShieldCheck} onClick={() => setTab("scanner")}>
              Open security audit
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
              tone: b.key === "expired" || b.key === "critical" ? "danger" : b.key === "warning" ? "warning" : b.key === "ok" ? "success" : "neutral",
            }))}
          />
        </Card>

        <Card className="lg:col-span-4">
          <CardHeader title="Key age" subtitle={`Median ${formatDuration(s.medianAgeDays)} since creation`} icon={KeyRound} />
          <ColumnChart label="Key age distribution" items={ages} height={92} />
        </Card>

        <Card className="lg:col-span-4">
          <CardHeader title="Algorithm mix" subtitle={`${algos.length} algorithm famil${algos.length === 1 ? "y" : "ies"}`} />
          <BarList items={algos.slice(0, 5)} total={s.total} />
        </Card>

        <Card className="lg:col-span-4">
          <CardHeader title="Recent files" icon={Clock} />
          <RecentFiles />
        </Card>

        <Card padded={false} className="lg:col-span-8 overflow-hidden flex flex-col">
          <CardHeader
            bordered
            title="Upcoming expirations"
            subtitle="Soonest first, across every open keystore"
            actions={
              <Button size="sm" variant="ghost" onClick={() => setTab("scanner")}>
                Audit <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            }
          />
          <DataTable<FlatEntry>
            label="Upcoming expirations"
            rows={upcoming}
            rowKey={(r) => r.entry.id}
            onRowClick={(r) => openKs(r.keystore as OpenKeystore)}
            empty={<EmptyState icon={CalendarClock} title="No certificates" description="Only secret keys are open; they do not expire." />}
            columns={[
              { id: "alias", header: "Entry", width: "40%", cell: (r) => <EntryNameCell entry={r.entry} meta={r.keystore.name} /> },
              { id: "exp", header: "Expires", width: "220px", cell: (r) => <ExpiryCell entry={r.entry} /> },
              { id: "status", header: "Status", width: "130px", cell: (r) => <HealthBadge entry={r.entry} /> },
            ]}
          />
        </Card>

        <Card className="lg:col-span-4 flex flex-col">
          <CardHeader title="Quick actions" />
          <ul className="divide-y divide-line">
            {[
              { icon: SearchCode, label: "Inspect a TLS server", tab: "examine" as const },
              { icon: FileSignature, label: "Sign a CSR, JAR or JWT", tab: "ca_signing" as const },
              { icon: ArrowLeftRight, label: "Convert certificates, keys or keystores", tab: "convert" as const },
              { icon: ShieldCheck, label: "Rotate weak or expiring keys", tab: "scanner" as const },
              { icon: Lock, label: vault.exists ? "Manage remembered passwords" : "Set up the password vault", tab: "vault" as const },
            ].map((a) => (
              <li key={a.label}>
                <button onClick={() => (a.tab === "convert" ? openConverter(null) : setTab(a.tab))} className="w-full flex items-center gap-2.5 py-2.5 text-[13px] text-ink-2 hover:text-ink cursor-pointer group">
                  <a.icon className="w-4 h-4 text-subtle group-hover:text-brand" />
                  <span className="flex-1 text-left">{a.label}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-subtle group-hover:text-ink" />
                </button>
              </li>
            ))}
          </ul>
          <DropZone onClick={() => openFiles()} className="mt-auto !py-4" />
        </Card>

        <Card padded={false} className="lg:col-span-8 overflow-hidden flex flex-col">
          <CardHeader bordered title="Keystores" subtitle={`${keystores.length} in this session`} icon={FolderArchive} />
          <DataTable<OpenKeystore>
            label="Keystores"
            rows={keystores}
            rowKey={(k) => k.id}
            onRowClick={openKs}
            columns={[
              {
                id: "name",
                header: "Name",
                width: "45%",
                sortValue: (k) => k.name,
                cell: (k) => (
                  <div className="min-w-0">
                    <div className="font-medium text-ink truncate flex items-center gap-1.5">
                      {k.name} {k.dirty && <Badge tone="warning">Unsaved</Badge>} {k.sealed && <Badge>Locked</Badge>}
                    </div>
                    <div className="text-[12px] text-faint truncate font-mono">{k.path || "Not saved yet"}</div>
                  </div>
                ),
              },
              { id: "fmt", header: "Format", sortValue: (k) => k.format, cell: (k) => <Badge>{FORMAT_INFO[k.format].label}</Badge> },
              { id: "n", header: "Entries", align: "right", sortValue: (k) => k.entries.length, cell: (k) => (k.sealed ? <span className="text-faint">—</span> : k.entries.length) },
              {
                id: "risk",
                header: "Issues",
                align: "right",
                sortValue: (k) => k.entries.filter((e) => entryHealth(e) !== "healthy").length,
                cell: (k) => {
                  const n = k.entries.filter((e) => entryHealth(e) !== "healthy").length;
                  return n ? <Badge tone="warning">{n}</Badge> : <span className="text-faint">—</span>;
                },
              },
            ]}
          />
        </Card>

        <Card padded={false} className="lg:col-span-4 overflow-hidden">
          <CardHeader bordered title="Workspaces" subtitle={`${workspaces.length} collections`} icon={Layers} />
          {workspaces.length === 0 ? (
            <div className="p-5 text-[13px] text-faint">
              Group entries across keystores by project or audit.{" "}
              <button className="text-brand font-medium cursor-pointer" onClick={() => setTab("workspaces")}>
                Create a workspace
              </button>
            </div>
          ) : (
            <ul className="divide-y divide-line">
              {workspaces.slice(0, 6).map((ws) => (
                <li key={ws.id}>
                  <button
                    onClick={() => {
                      setActiveWorkspaceId(ws.id);
                      setTab("workspaces");
                    }}
                    className="w-full px-5 py-3 flex items-center gap-3 text-left hover:bg-surface-2 transition cursor-pointer"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="text-[13px] font-medium text-ink truncate">{ws.name}</div>
                      <div className="text-[12px] text-faint">{ws.entryIds.length} entries</div>
                    </div>
                    <Badge tone={ws.environment === "Production" ? "brand" : "neutral"}>{ws.environment}</Badge>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <TerminalSection />
      </div>
    </Page>
  );
};
