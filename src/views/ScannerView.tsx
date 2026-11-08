import React, { useCallback, useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { AlertTriangle, CalendarClock, CheckCircle2, FileText, KeyRound, Link2Off, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";
import type { KeystoreEntry, OpenKeystore } from "../types/crypto";
import { api, errorMessage, isDesktop } from "../lib/api";
import { pickSavePath } from "../lib/files";
import { cnOf, findIssuingCa, renewalTerm } from "../lib/keystore";
import { csvField } from "../lib/csv";
import { Finding, daysUntilExpiry, entryHealth, findingsFor, formatDuration, summarize } from "../lib/metrics";
import { useStore } from "../state/store";
import { Alert, Badge, Button, Card, CardHeader, Column, DataTable, EmptyState, KpiCard, Modal, Page, PageHeader, ScoreRing, Segmented, Select, Spinner, useToast } from "../components/ui";
import { AlgorithmCell, EntryNameCell, ExpiryCell } from "../components/entry";

interface Row {
  entry: KeystoreEntry;
  ks: OpenKeystore;
  findings: Finding[];
}

const SEVERITY_TONE = { critical: "danger", high: "danger", medium: "warning", low: "neutral" } as const;
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 } as const;

const RotateDialog: React.FC<{ row: Row | null; onClose: () => void }> = ({ row, onClose }) => {
  const { keystores, replaceEntry } = useStore();
  const toast = useToast();
  const [spec, setSpec] = useState("ECDSA:P-256");
  const [busy, setBusy] = useState(false);
  const issuer = useMemo(() => (row ? findIssuingCa(row.entry, keystores) : null), [row, keystores]);
  if (!row) return null;
  const leaf = row.entry.certificate_chain[0];
  const selfSigned = !!leaf?.self_signed;
  const run = async () => {
    setBusy(true);
    try {
      const [alg, param] = spec.split(":");
      const rotated = await api.rotateKey(row.entry, alg, alg === "RSA" ? Number(param) : 0, alg === "ECDSA" ? param : null, issuer);
      replaceEntry(row.ks.id, { ...rotated, id: row.entry.id, labels: row.entry.labels });
      toast.success(`Rotated '${row.entry.alias}' to ${rotated.algorithm} ${rotated.key_size}-bit${issuer ? `, re-issued by ${issuer.alias}` : " (self-signed)"}. Save ${row.ks.name} to keep it.`);
      onClose();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={onClose}
      icon={RotateCcw}
      title={`Rotate key of ${row.entry.alias}`}
      description="Generates a new key and certificate with the same subject, SANs, usages and lifetime."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={run} disabled={busy} data-testid="rotate-submit">
            {busy && <Spinner />} Rotate
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Select label="New key" value={spec} onChange={(e) => setSpec(e.target.value)}>
          <option value="ECDSA:P-256">ECDSA P-256</option>
          <option value="ECDSA:P-384">ECDSA P-384</option>
          <option value="RSA:3072">RSA 3072</option>
          <option value="RSA:4096">RSA 4096</option>
          <option value="Ed25519:0">Ed25519</option>
        </Select>
        {selfSigned ? (
          <Alert tone="info">The current certificate is self-signed, so the new one will be self-signed too. Clients that pinned the old certificate must be updated.</Alert>
        ) : issuer ? (
          <Alert tone="success">The issuing CA '{issuer.alias}' ({keystores.find((ks) => ks.entries.some((e) => e.id === issuer.id))?.name}) is open; the new certificate will be issued by it.</Alert>
        ) : (
          <Alert tone="warning" title="Issuing CA not open">
            The certificate was issued by {cnOf(row.entry.issuer)}, which is not in any open keystore. The new certificate will be self-signed — afterwards generate a CSR for it and have your CA sign it.
          </Alert>
        )}
      </div>
    </Modal>
  );
};

export const ScannerView: React.FC = () => {
  const { keystores, replaceEntry, settings, openFiles, setTab, ensureKeyAccess } = useStore();
  const toast = useToast();
  const [filter, setFilter] = useState<"issues" | "all">("issues");
  const [rotate, setRotate] = useState<Row | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [chainNotes, setChainNotes] = useState<string[]>([]);

  const rows: Row[] = useMemo(() => keystores.flatMap((ks) => ks.entries.map((entry) => ({ entry, ks, findings: findingsFor(entry) }))), [keystores]);
  const sum = summarize(rows.map((r) => r.entry));
  const withIssues = rows.filter((r) => r.findings.some((f) => f.severity !== "low") || entryHealth(r.entry) !== "healthy");
  const visible = filter === "issues" ? withIssues : rows;
  const scoreTone = sum.healthScore >= 85 ? "success" : sum.healthScore >= 65 ? "warning" : "danger";
  const incomplete = rows.filter((r) => r.findings.some((f) => f.title === "Incomplete chain")).length;
  const sealed = keystores.filter((k) => k.sealed).length;

  /** Renewing uses the entry's key and the issuing CA's key, so both must be unlocked first. */
  const renewUnlocked = (r: Row) => {
    const ca = findIssuingCa(r.entry, keystores);
    const caKs = ca ? keystores.find((k) => k.entries.some((e) => e.id === ca.id)) : undefined;
    if (!ca || !caKs) return void renew(r);
    if (caKs.id === r.ks.id) return ensureKeyAccess(r.ks.id, [r.entry.id, ca.id], () => void renew(r));
    ensureKeyAccess(r.ks.id, [r.entry.id], () => ensureKeyAccess(caKs.id, [ca.id], () => void renew(r)));
  };

  /** Renew the certificate keeping the key: CSR → sign with the open issuing CA → install reply. */
  const renew = async (r: Row) => {
    const ca = findIssuingCa(r.entry, keystores);
    if (!ca) return toast.error(`The issuing CA (${cnOf(r.entry.issuer)}) is not open. Generate a CSR from the entry and send it to your CA instead.`);
    setBusyId(r.entry.id);
    try {
      const leaf = r.entry.certificate_chain[0];
      const term = renewalTerm(r.entry);
      const csr = await api.generateCsr(r.entry, {});
      const signed = await api.signCsr(
        {
          csr_pem: csr.csr_pem,
          validity_days: term.days,
          is_ca: !!leaf?.is_ca,
          path_len: leaf?.path_len ?? null,
          sans: [],
          key_usage: [],
          extended_key_usage: [],
          copy_requested_sans: true,
          copy_requested_usages: true,
          crl_distribution_points: leaf?.crl_distribution_points ?? [],
          ocsp_urls: leaf?.ocsp_urls ?? [],
          ca_issuer_urls: leaf?.ca_issuer_urls ?? [],
        },
        ca
      );
      const updated = await api.importCaReply(r.entry, { text: signed.chain_pem });
      replaceEntry(r.ks.id, { ...updated, id: r.entry.id, labels: r.entry.labels });
      toast.success(`Renewed '${r.entry.alias}' until ${signed.certificate.valid_to} (same key).${signed.validity_note ? ` ${signed.validity_note}` : ""} Save ${r.ks.name} to keep it.`);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusyId(null);
    }
  };

  const runValidateChains = useCallback(
    async (notify: boolean) => {
      const anchors = keystores
        .flatMap((k) =>
          k.entries.flatMap((e) => {
            const pems: string[] = [];
            if (e.entry_type === "TrustedCertificate" && e.certificate_chain[0]?.pem) pems.push(e.certificate_chain[0].pem);
            for (const c of e.certificate_chain) {
              if (c.is_ca && (c.self_signed || c === e.certificate_chain[0]) && c.pem) pems.push(c.pem);
            }
            return pems;
          })
        )
        .filter(Boolean)
        .join("");
      const notes: string[] = [];
      for (const ks of keystores) {
        for (const entry of ks.entries) {
          const leaf = entry.certificate_chain[0]?.pem;
          if (!leaf) continue;
          const problems = await api.validateChain(leaf, entry.certificate_chain.slice(1).map((c) => c.pem).join(""), anchors, null).catch(() => []);
          if (problems.length) notes.push(`${ks.name} / ${entry.alias}: ${problems[0]}`);
        }
      }
      setChainNotes(notes);
      if (notify) toast.success(notes.length ? `${notes.length} chain problem(s).` : "Every certificate chains to an open trust anchor.");
    },
    [keystores, toast]
  );

  useEffect(() => {
    if (isDesktop() && rows.length > 0) void runValidateChains(false);
    else setChainNotes([]);
  }, [rows.length, runValidateChains]);

  const exportReport = async () => {
    try {
      const path = await pickSavePath("Save security report", `xkeystore-security-report-${new Date().toISOString().slice(0, 10)}.csv`, [{ name: "CSV", extensions: ["csv"] }]);
      if (!path) return;
      const esc = (s: string) => csvField(s);
      const lines = ["Keystore,Alias,Type,Algorithm,Expires,Severity,Finding,Detail"];
      for (const r of rows) {
        for (const f of r.findings.length ? r.findings : [{ severity: "ok", title: "No findings", detail: "" } as unknown as Finding]) {
          lines.push([r.ks.path || r.ks.name, r.entry.alias, r.entry.entry_type, `${r.entry.algorithm} ${r.entry.key_size}`, r.entry.expiry_date, f.severity, f.title, f.detail].map((x) => esc(String(x))).join(","));
        }
      }
      await api.writeTextFile(path, lines.join("\n") + "\n");
      toast.success(`Saved the security report to ${path}`);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const columns: Column<Row>[] = [
    { id: "entry", header: "Entry", width: "26%", sortValue: (r) => r.entry.alias, cell: (r) => <EntryNameCell entry={r.entry} meta={r.ks.name} /> },
    { id: "alg", header: "Algorithm", sortValue: (r) => r.entry.algorithm, cell: (r) => <AlgorithmCell entry={r.entry} />, hideBelow: "xl" },
    { id: "exp", header: "Expires", width: "190px", sortValue: (r) => daysUntilExpiry(r.entry), cell: (r) => <ExpiryCell entry={r.entry} /> },
    {
      id: "finding",
      header: "Findings",
      sortValue: (r) => (r.findings[0] ? SEVERITY_RANK[r.findings[0].severity] : 9),
      cell: (r) =>
        r.findings.length === 0 ? (
          <Badge tone="success" icon={CheckCircle2}>
            No findings
          </Badge>
        ) : (
          <div className="space-y-1 whitespace-normal max-w-[380px]">
            {r.findings.slice(0, 3).map((f, i) => (
              <div key={i} className="flex items-start gap-1.5 text-[12px]">
                <Badge tone={SEVERITY_TONE[f.severity]}>{f.title}</Badge>
                <span className="text-faint leading-5">{f.detail}</span>
              </div>
            ))}
          </div>
        ),
    },
    {
      id: "fix",
      header: "Remediation",
      align: "right",
      width: "220px",
      cell: (r) =>
        r.entry.entry_type === "KeyPair" && !r.entry.locked ? (
          <div className="inline-flex items-center gap-1.5">
            {!r.entry.certificate_chain[0]?.self_signed && (
              <Button size="sm" icon={RefreshCw} disabled={busyId === r.entry.id} onClick={() => renewUnlocked(r)} title={renewalTerm(r.entry).note}>
                Renew
              </Button>
            )}
            <Button size="sm" icon={RotateCcw} onClick={() => ensureKeyAccess(r.ks.id, [r.entry.id], () => setRotate(r))} data-testid={`rotate-${r.entry.alias}`}>
              Rotate key
            </Button>
          </div>
        ) : r.entry.entry_type === "SecretKey" ? (
          <span className="text-[12px] text-faint whitespace-normal">{r.entry.is_weak ? "Generate a new AES key and re-encrypt data" : "—"}</span>
        ) : (
          <span className="text-[12px] text-faint whitespace-normal">{entryHealth(r.entry) === "healthy" ? "—" : "Import the CA's replacement certificate"}</span>
        ),
    },
  ];

  if (!rows.length) {
    return (
      <Page>
        <PageHeader title="Security audit" description="Finds expired, expiring and weak keys and certificates across every open keystore." />
        <Card className="py-14">
          <EmptyState
            icon={ShieldCheck}
            title={sealed ? "Unlock your keystores to audit them" : "Nothing to audit yet"}
            description={sealed ? `${sealed} keystore(s) from your last session are locked.` : "Open or create a keystore to see its security posture."}
            action={<Button variant="primary" onClick={() => (sealed ? setTab("keystores") : openFiles())}>{sealed ? "Go to keystores" : "Open keystore…"}</Button>}
          />
        </Card>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader
        title="Security audit"
        description="Finds expired, expiring and weak keys and certificates across every open keystore, with one-click remediation."
        actions={
          <div className="flex gap-2">
            <Button onClick={() => void runValidateChains(true)}>Validate chains</Button>
            <Button icon={FileText} onClick={exportReport}>
              Export report
            </Button>
          </div>
        }
      />
      {chainNotes.length > 0 && (
        <Alert tone="warning" className="mb-4" title="Chain validation">
          {chainNotes.slice(0, 6).join(" ")}
        </Alert>
      )}
      {sealed > 0 && (
        <Alert tone="info" className="mb-4">
          {sealed} locked keystore(s) are not included. Unlock them on the Keystores page.
        </Alert>
      )}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Card className="lg:col-span-4 lg:row-span-2 flex flex-col">
          <CardHeader title="Health score" subtitle={`${rows.length} entries in ${keystores.length - sealed} keystores`} icon={ShieldCheck} />
          <div className="flex-1 flex items-center gap-6">
            <ScoreRing value={sum.healthScore} tone={scoreTone} size={128} label="Health score" />
            <ul className="flex-1 space-y-3 text-[12.5px]">
              <li className="flex justify-between">
                <span className="text-muted">Healthy</span>
                <span className="font-semibold text-ink tabular-nums">{rows.length - withIssues.length}</span>
              </li>
              <li className="flex justify-between">
                <span className="text-muted">Need attention</span>
                <span className="font-semibold text-ink tabular-nums">{withIssues.length}</span>
              </li>
            </ul>
          </div>
          <p className="mt-4 pt-4 border-t border-line text-[12px] text-faint">Expired or weak entries count fully against the score; entries expiring within {settings.warningDays} days count half.</p>
        </Card>
        <KpiCard className="lg:col-span-4" label="Weak cryptography" value={sum.weak} icon={AlertTriangle} tone="danger" hint={sum.weak ? "Short keys, deprecated ciphers or SHA-1 signatures" : "No weak keys found"} hintTone={sum.weak ? "danger" : "success"} />
        <KpiCard
          className="lg:col-span-4"
          label={`Expired or expiring ≤ ${settings.criticalDays} days`}
          value={sum.expired + sum.expiringCritical}
          icon={CalendarClock}
          tone="warning"
          hint={`${sum.expired} expired · ${sum.expiringCritical} expiring`}
          hintTone={sum.expired + sum.expiringCritical ? "warning" : "success"}
        />
        <KpiCard className="lg:col-span-4" label="Incomplete chains" value={incomplete} icon={Link2Off} hint="CA-issued keys stored without their CA certificate" />
        <KpiCard className="lg:col-span-4" label="Oldest key" value={formatDuration(sum.oldestAgeDays)} icon={KeyRound} hint={`Median ${formatDuration(sum.medianAgeDays)} · ${sum.locked} locked`} />
      </div>

      <Card padded={false} className="mt-4 overflow-hidden">
        <div className="px-5 py-3 border-b border-line flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-[14px] font-semibold text-ink">Findings</h3>
            <p className="text-[12px] text-faint">Rotate replaces the key; Renew re-issues the certificate with the same key using the open issuing CA.</p>
          </div>
          <Segmented
            label="Audit filter"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "issues", label: "Needs action", count: withIssues.length },
              { value: "all", label: "All", count: rows.length },
            ]}
          />
        </div>
        <DataTable<Row>
          label="Security findings"
          columns={columns}
          rows={visible}
          rowKey={(r) => r.entry.id}
          initialSort={{ id: "finding", dir: "asc" }}
          empty={<EmptyState icon={CheckCircle2} title="Nothing needs action" description="Every entry passes the audit." />}
          footer={
            <span className={clsx(withIssues.length ? "text-warning" : "text-success")}>
              {visible.length} of {rows.length} entries {withIssues.length ? "· " + withIssues.length + " need action" : "· all healthy"}
            </span>
          }
        />
      </Card>
      <RotateDialog row={rotate} onClose={() => setRotate(null)} />
    </Page>
  );
};
