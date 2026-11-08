import React, { useCallback, useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { AlertTriangle, CalendarClock, CheckCircle2, FileText, KeyRound, Link2, Link2Off, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";
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

/** The entry a dialog acts on, by id: looked up from the store each render, never a snapshot. */
type Target = { ksId: string; entryId: string };

const RotateDialog: React.FC<{ target: Target | null; onClose: () => void }> = ({ target, onClose }) => {
  const { keystores, replaceEntry } = useStore();
  const toast = useToast();
  const [spec, setSpec] = useState("ECDSA:P-256");
  const [busy, setBusy] = useState(false);
  const ks = target ? keystores.find((k) => k.id === target.ksId) : undefined;
  const entry = ks?.entries.find((e) => e.id === target?.entryId);
  const issuer = useMemo(() => (entry ? findIssuingCa(entry, keystores) : null), [entry, keystores]);
  if (!ks || !entry) return null;
  const leaf = entry.certificate_chain[0];
  const selfSigned = !!leaf?.self_signed;
  const run = async () => {
    setBusy(true);
    try {
      const [alg, param] = spec.split(":");
      const rotated = await api.rotateKey(entry, alg, alg === "RSA" ? Number(param) : 0, alg === "ECDSA" ? param : null, issuer);
      replaceEntry(ks.id, { ...rotated, id: entry.id, labels: entry.labels });
      toast.success(`Rotated '${entry.alias}' to ${rotated.algorithm} ${rotated.key_size}-bit${issuer ? `, re-issued by ${issuer.alias}` : " (self-signed)"}. Save ${ks.name} to keep it.`);
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
      title={`Rotate key of ${entry.alias}`}
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
            The certificate was issued by {cnOf(entry.issuer)}, which is not in any open keystore. The new certificate will be self-signed — afterwards generate a CSR for it and have your CA sign it.
          </Alert>
        )}
      </div>
    </Modal>
  );
};

export const ScannerView: React.FC = () => {
  const { keystores, replaceEntry, settings, openFiles, setTab, ensureKeyAccess, currentKeystores, selectKeystore } = useStore();
  const toast = useToast();
  const [filter, setFilter] = useState<"issues" | "all">("issues");
  const [rotate, setRotate] = useState<Target | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [chainNotes, setChainNotes] = useState<string[]>([]);

  // The context enables the findings that depend on where an entry lives: a JKS store, a trust
  // anchor that is not open, a subject key id used twice. Siblings are every open entry.
  const rows: Row[] = useMemo(() => {
    const siblings = keystores.flatMap((k) => k.entries);
    return keystores.flatMap((ks) => ks.entries.map((entry) => ({ entry, ks, findings: findingsFor(entry, { format: ks.format, siblings }) })));
  }, [keystores]);
  const sum = summarize(rows.map((r) => r.entry));
  const withIssues = rows.filter((r) => r.findings.some((f) => f.severity !== "low") || entryHealth(r.entry) !== "healthy");
  const visible = filter === "issues" ? withIssues : rows;
  const scoreTone = sum.healthScore >= 85 ? "success" : sum.healthScore >= 65 ? "warning" : "danger";
  const incomplete = rows.filter((r) => r.findings.some((f) => f.title === "Incomplete chain")).length;
  const sealed = keystores.filter((k) => k.sealed).length;

  /**
   * Runs `then` once the entry's key and the key of its issuing CA are usable (each asks for its key
   * password when it is locked). `then` gets only ids: the entries are read again after the unlock.
   */
  const withSigningAccess = (r: Row, then: () => void) => {
    const ca = findIssuingCa(r.entry, keystores);
    const caKs = ca ? keystores.find((k) => k.entries.some((e) => e.id === ca.id)) : undefined;
    if (!ca || !caKs) return ensureKeyAccess(r.ks.id, [r.entry.id], then);
    if (caKs.id === r.ks.id) return ensureKeyAccess(r.ks.id, [r.entry.id, ca.id], then);
    ensureKeyAccess(r.ks.id, [r.entry.id], () => ensureKeyAccess(caKs.id, [ca.id], then));
  };

  /** Renew the certificate keeping the key: CSR → sign with the open issuing CA → install reply. */
  const renew = async (ksId: string, entryId: string) => {
    const all = currentKeystores();
    const ks = all.find((k) => k.id === ksId);
    const entry = ks?.entries.find((e) => e.id === entryId);
    if (!ks || !entry) return;
    const ca = findIssuingCa(entry, all);
    if (!ca) return toast.error(`The issuing CA (${cnOf(entry.issuer)}) is not open. Generate a CSR from the entry and send it to your CA instead.`);
    setBusyId(entry.id);
    try {
      const leaf = entry.certificate_chain[0];
      const term = renewalTerm(entry);
      const csr = await api.generateCsr(entry, {});
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
      const updated = await api.importCaReply(entry, { text: signed.chain_pem });
      replaceEntry(ks.id, { ...updated, id: entry.id, labels: entry.labels });
      toast.success(`Renewed '${entry.alias}' until ${signed.certificate.valid_to} (same key).${signed.validity_note ? ` ${signed.validity_note}` : ""} Save ${ks.name} to keep it.`);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusyId(null);
    }
  };

  const validationRun = React.useRef(0);
  const [validating, setValidating] = useState(false);
  const runValidateChains = useCallback(
    async (notify: boolean) => {
      // Edits start a new run; a slower, older run must not overwrite its result.
      const run = ++validationRun.current;
      setValidating(true);
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
          // A self-signed certificate is a trust anchor or a self-signed end entity: it has no chain
          // to build, and its expiry and self-signing are findings of their own. Reporting it here
          // only buried the CA-issued certificates whose chain is actually broken.
          if (!leaf || entry.certificate_chain[0]?.self_signed) continue;
          const problems = await api.validateChain(leaf, entry.certificate_chain.slice(1).map((c) => c.pem).join(""), anchors, null).catch(() => []);
          if (run !== validationRun.current) return;
          if (problems.length) notes.push(`${ks.name} / ${entry.alias}: ${problems[0]}`);
        }
      }
      if (run !== validationRun.current) return;
      setChainNotes(notes);
      setValidating(false);
      if (notify) toast.success(notes.length ? `${notes.length} chain problem${notes.length === 1 ? "" : "s"}.` : "Every certificate chains to an open trust anchor.");
    },
    [keystores, toast]
  );

  useEffect(() => {
    if (isDesktop() && rows.length > 0) void runValidateChains(false);
    else {
      setChainNotes([]);
      setValidating(false);
    }
    // Leaving the page abandons a run in progress.
    return () => {
      validationRun.current++;
    };
  }, [rows.length, runValidateChains]);
  const jksStores = keystores.filter((k) => !k.sealed && k.format === "JKS");

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
        // Every key pair gets the actions, including one with its own password: the click asks for the password first.
        r.entry.entry_type === "KeyPair" ? (
          <div className="inline-flex items-center gap-1.5">
            {!r.entry.certificate_chain[0]?.self_signed && (
              <Button size="sm" icon={RefreshCw} disabled={busyId === r.entry.id} onClick={() => withSigningAccess(r, () => void renew(r.ks.id, r.entry.id))} title={renewalTerm(r.entry).note} data-testid={`renew-${r.entry.alias}`}>
                Renew
              </Button>
            )}
            <Button size="sm" icon={RotateCcw} onClick={() => withSigningAccess(r, () => setRotate({ ksId: r.ks.id, entryId: r.entry.id }))} data-testid={`rotate-${r.entry.alias}`}>
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
            <Button icon={validating ? undefined : Link2} onClick={() => void runValidateChains(true)} disabled={validating} data-testid="validate-chains">
              {validating && <Spinner />} {validating ? "Validating…" : "Validate chains"}
            </Button>
            <Button icon={FileText} onClick={exportReport}>
              Export report
            </Button>
          </div>
        }
      />
      {chainNotes.length > 0 && (
        <Alert tone="warning" className="mb-4" title={`${chainNotes.length} certificate chain${chainNotes.length === 1 ? " does" : "s do"} not validate`}>
          <ul className="mt-1 space-y-0.5 list-disc pl-4" data-testid="chain-notes">
            {chainNotes.slice(0, 6).map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
          {chainNotes.length > 6 && <p className="mt-1 text-faint">And {chainNotes.length - 6} more.</p>}
        </Alert>
      )}
      {jksStores.length > 0 && (
        <Alert
          tone="warning"
          className="mb-4"
          title={`${jksStores.length === 1 ? `${jksStores[0].name} is` : `${jksStores.length} keystores are`} in the legacy JKS format`}
          action={
            <Button size="sm" onClick={() => (selectKeystore(jksStores[0].id), setTab("keystores"))} data-testid="audit-open-jks">
              Open {jksStores.length === 1 ? "it" : jksStores[0].name}
            </Button>
          }
        >
          JKS protects its integrity with SHA-1 and wraps keys with a proprietary scheme. Use Save as… to write the entries as PKCS#12, which Java has used by default since
          version 9.
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
          <div className="flex-1 flex flex-wrap items-center gap-x-6 gap-y-4">
            <ScoreRing value={sum.healthScore} tone={scoreTone} size={128} label="Health score" />
            <ul className="flex-1 min-w-[140px] space-y-3 text-[13px]">
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
      <RotateDialog target={rotate} onClose={() => setRotate(null)} />
    </Page>
  );
};
