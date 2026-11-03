import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Zap,
  Lock,
  CalendarClock,
  Sparkles,
  KeyRound,
} from "lucide-react";
import { KeystoreFile, KeystoreEntry, GenerateKeyPairInput } from "../types/crypto";
import {
  Button,
  Card,
  CardHeader,
  Column,
  DataTable,
  EmptyState,
  KpiCard,
  Meter,
  Page,
  PageHeader,
  ScoreRing,
  Segmented,
} from "../components/ui";
import { AlgorithmCell, EntryNameCell, ExpiryCell, HealthBadge } from "../components/entry";
import { daysUntilExpiry, entryHealth, formatDuration, isWeak, summarize } from "../lib/metrics";

type FlatEntry = { entry: KeystoreEntry; ks: KeystoreFile };

interface ScannerViewProps {
  keystores: KeystoreFile[];
  onUpdateKeystore: (updated: KeystoreFile) => void;
  onRecordOp: (increment?: number, isSig?: boolean) => void;
}

export const ScannerView: React.FC<ScannerViewProps> = ({
  keystores,
  onUpdateKeystore,
  onRecordOp,
}) => {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const allEntriesWithKs = keystores.flatMap((ks) =>
    ks.entries.map((entry) => ({ ks, entry }))
  );

  const weakEntries = allEntriesWithKs.filter((item) => isWeak(item.entry));
  const pqEntries = allEntriesWithKs.filter((item) => item.entry.is_post_quantum);
  const totalCount = allEntriesWithKs.length;

  const handleAutoRotateEntry = async (ks: KeystoreFile, entry: KeystoreEntry, targetAlg: string, targetBits: number) => {
    setBusyId(entry.id);
    try {
      const input: GenerateKeyPairInput = {
        alias: entry.alias,
        algorithm: targetAlg,
        key_size: targetBits,
        curve: targetAlg === "ECDSA" ? "secp256r1 (P-256)" : null,
        common_name: entry.alias,
        organization: "xkeystore Auto-Rotated Security",
        organizational_unit: "Automated Compliance Engine",
        locality: "San Francisco",
        state: "CA",
        country: "US",
        email: `security@${entry.alias}`,
        validity_days: 730,
        is_ca: entry.labels.includes("CA"),
        sans: [entry.alias],
        key_usage: ["Digital Signature", "Key Encipherment"],
        extended_key_usage: ["TLS Web Server Authentication"],
        signer_alias: null,
        labels: [...entry.labels.filter((l) => l !== "Weak-Key" && l !== "Legacy"), "Rotated-Safe"],
      };

      const rotated = await invoke<KeystoreEntry>("generate_keypair_entry", {
        input,
        issuerDn: entry.issuer,
      });

      const updatedKs: KeystoreFile = {
        ...ks,
        updated_at: "Just now",
        entries: ks.entries.map((en) => (en.id === entry.id ? { ...rotated, id: entry.id } : en)),
      };
      onUpdateKeystore(updatedKs);
      onRecordOp(targetBits, true);
      setToast(`Automatically rotated '${entry.alias}' to ${targetAlg}-${targetBits} inside ${ks.name}!`);
      setTimeout(() => setToast(null), 4000);
    } catch (e) {
      alert("Auto-rotation failed: " + e);
    } finally {
      setBusyId(null);
    }
  };

  const [filter, setFilter] = useState<"issues" | "all" | "pqc">("issues");
  const entries = allEntriesWithKs.map((f) => f.entry);
  const sum = summarize(entries);
  const issues = allEntriesWithKs.filter((f) => entryHealth(f.entry) !== "healthy");
  const rows =
    filter === "issues" ? issues : filter === "pqc" ? pqEntries : allEntriesWithKs;
  const scoreTone = sum.healthScore >= 85 ? "success" : sum.healthScore >= 65 ? "warning" : "danger";
  const RANK = { "at-risk": 0, attention: 1, healthy: 2 } as const;

  const columns: Column<FlatEntry>[] = [
    {
      id: "entry",
      header: "Entry",
      width: "28%",
      sortValue: (r) => r.entry.alias,
      cell: (r) => <EntryNameCell entry={r.entry} meta={r.ks.name} />,
    },
    { id: "alg", header: "Algorithm", sortValue: (r) => r.entry.algorithm, cell: (r) => <AlgorithmCell entry={r.entry} /> },
    {
      id: "exp",
      header: "Expires",
      width: "210px",
      sortValue: (r) => daysUntilExpiry(r.entry),
      cell: (r) => <ExpiryCell entry={r.entry} />,
    },
    {
      id: "finding",
      header: "Finding",
      sortValue: (r) => RANK[entryHealth(r.entry)],
      cell: (r) => <HealthBadge entry={r.entry} />,
    },
    {
      id: "fix",
      header: "Remediation",
      align: "right",
      width: "260px",
      cell: ({ ks, entry }) =>
        entry.entry_type === "KeyPair" ? (
          <div className="inline-flex items-center gap-1.5">
            <Button
              size="sm"
              icon={RefreshCw}
              disabled={busyId === entry.id}
              onClick={() => handleAutoRotateEntry(ks, entry, "RSA", 4096)}
              className={busyId === entry.id ? "[&_svg]:animate-spin" : undefined}
            >
              RSA-4096
            </Button>
            <Button
              size="sm"
              icon={Zap}
              disabled={busyId === entry.id}
              onClick={() => handleAutoRotateEntry(ks, entry, "ML-DSA-65", 1952)}
            >
              ML-DSA-65
            </Button>
          </div>
        ) : entry.entry_type === "SecretKey" ? (
          <span className="inline-flex items-center gap-1.5 text-[12px] text-faint">
            <Lock className="w-3.5 h-3.5" /> Symmetric, no rotation needed
          </span>
        ) : (
          <span className="text-[12px] text-faint">Replace via trust store import</span>
        ),
    },
  ];

  return (
    <Page>
      {toast && (
        <div
          role="status"
          className="fixed bottom-6 right-6 z-[60] max-w-md flex items-start gap-2.5 bg-surface border border-line shadow-pop rounded-card px-4 py-3 text-[13px] text-ink"
        >
          <CheckCircle2 className="w-4 h-4 mt-0.5 text-success shrink-0" />
          <span>{toast}</span>
        </div>
      )}

      <PageHeader
        title="Security"
        description="Audit every loaded keystore for weak, expired and expiring keys, and rotate them in place with the native engine."
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Card className="lg:col-span-4 lg:row-span-2 flex flex-col">
          <CardHeader title="Compliance score" subtitle={`Across ${totalCount} entries in ${keystores.length} keystores`} icon={ShieldCheck} />
          <div className="flex-1 flex items-center gap-6">
            <ScoreRing value={sum.healthScore} tone={scoreTone} size={128} label="Compliance score" />
            <ul className="flex-1 space-y-3 text-[12.5px]">
              <li className="flex items-center justify-between">
                <span className="text-muted">Healthy</span>
                <span className="font-semibold text-ink tabular-nums">{totalCount - issues.length}</span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-muted">Needs attention</span>
                <span className="font-semibold text-ink tabular-nums">{issues.length}</span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-muted">Runtime dependencies</span>
                <span className="font-semibold text-ink tabular-nums">0</span>
              </li>
            </ul>
          </div>
          <p className="mt-4 pt-4 border-t border-line text-[12px] text-faint">
            Score deducts fully for expired or weak keys and half for keys expiring within 90 days.
          </p>
        </Card>

        <KpiCard
          className="lg:col-span-4"
          label="Weak keys"
          value={weakEntries.length}
          icon={AlertTriangle}
          tone="danger"
          hint={weakEntries.length ? "RSA below 2048 bits — rotate now" : "All keys meet NIST 2030+"}
          hintTone={weakEntries.length ? "danger" : "success"}
        />
        <KpiCard
          className="lg:col-span-4"
          label="Expired or expiring ≤ 30 days"
          value={sum.expired + sum.expiring30}
          icon={CalendarClock}
          tone="warning"
          hint={`${sum.expired} expired · ${sum.expiring30} expiring`}
          hintTone={sum.expired + sum.expiring30 ? "warning" : "success"}
        />
        <KpiCard
          className="lg:col-span-4"
          label="Post-quantum ready"
          value={pqEntries.length}
          icon={Sparkles}
          tone="brand"
          hint="ML-DSA, ML-KEM and 256-bit symmetric"
        >
          <Meter value={totalCount ? pqEntries.length / totalCount : 0} label="Share of post-quantum entries" />
        </KpiCard>
        <KpiCard
          className="lg:col-span-4"
          label="Oldest key"
          value={formatDuration(sum.oldestAgeDays)}
          icon={KeyRound}
          hint={`Median ${formatDuration(sum.medianAgeDays)}`}
        />
      </div>

      <Card padded={false} className="mt-4 overflow-hidden">
        <div className="px-5 py-3 border-b border-line flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-[14px] font-semibold text-ink">Entry audit</h3>
            <p className="text-[12px] text-faint">Rotation replaces the key in place and keeps its alias and labels.</p>
          </div>
          <Segmented
            label="Audit filter"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "issues", label: "Needs action", count: issues.length },
              { value: "pqc", label: "Post-quantum", count: pqEntries.length },
              { value: "all", label: "All", count: totalCount },
            ]}
          />
        </div>
        <DataTable<FlatEntry>
          label="Entry audit"
          columns={columns}
          rows={rows.map((r) => ({ entry: r.entry, ks: r.ks }))}
          rowKey={(r) => r.entry.id}
          initialSort={{ id: "finding", dir: "asc" }}
          empty={<EmptyState icon={CheckCircle2} title="Nothing to fix" description="Every entry in this view passes the audit." />}
          footer={<span>{rows.length} of {totalCount} entries</span>}
        />
      </Card>
    </Page>
  );
};
