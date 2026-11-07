import React, { useState } from "react";
import clsx from "clsx";
import { AlertTriangle, ChevronDown, ChevronRight, ShieldCheck, ShieldAlert } from "lucide-react";
import type { CertificateInfo } from "../types/crypto";
import { cnOf } from "../lib/keystore";
import { Badge, CodeBlock, CopyButton } from "./ui";

export const ValidityBadge: React.FC<{ cert: CertificateInfo }> = ({ cert }) => {
  const now = Date.now() / 1000;
  if (cert.not_before > now) return <Badge tone="warning">Not yet valid</Badge>;
  if (cert.days_remaining < 0) return <Badge tone="danger">Expired</Badge>;
  const left = `${cert.days_remaining} day${cert.days_remaining === 1 ? "" : "s"} left`;
  if (cert.days_remaining <= 30) return <Badge tone="danger">{left}</Badge>;
  if (cert.days_remaining <= 90) return <Badge tone="warning">{left}</Badge>;
  return <Badge tone="success">Valid</Badge>;
};

const Row: React.FC<{ label: string; value?: React.ReactNode; copy?: string; mono?: boolean }> = ({ label, value, copy, mono }) =>
  value === undefined || value === null || value === "" ? null : (
    <tr>
      <th scope="row" className="w-[30%] align-top text-left font-medium text-faint bg-surface-2 border-b border-line px-3.5 py-2.5 text-[12.5px]">
        {label}
      </th>
      <td className={clsx("align-top border-b border-line px-3.5 py-2.5 text-ink break-all select-text", mono ? "font-mono text-[11.5px]" : "text-[12.5px]")}>
        <div className="flex items-start justify-between gap-2">
          <span className="min-w-0">{value}</span>
          {copy && <CopyButton value={copy} label={`Copy ${label}`} />}
        </div>
      </td>
    </tr>
  );

/** Field table for one certificate. */
export const CertificateDetails: React.FC<{ cert: CertificateInfo; showPem?: boolean }> = ({ cert, showPem }) => (
  <div className="space-y-3">
    <table className="w-full border border-line rounded-card overflow-hidden border-separate border-spacing-0">
      <tbody>
        <Row label="Subject" value={cert.subject} copy={cert.subject} mono />
        <Row label="Issuer" value={cert.issuer} copy={cert.issuer} mono />
        <Row label="Serial number" value={cert.serial_number} copy={cert.serial_number} mono />
        <Row label="Valid from" value={cert.valid_from} />
        <Row
          label="Valid until"
          value={
            <span className="inline-flex items-center gap-2">
              {cert.valid_to} <ValidityBadge cert={cert} />
            </span>
          }
        />
        <Row label="Public key" value={`${cert.public_key_algorithm}${cert.key_size ? ` ${cert.key_size}-bit` : ""}${cert.curve && cert.public_key_algorithm === "ECDSA" ? ` (${cert.curve})` : ""}`} />
        <Row label="Signature" value={cert.signature_algorithm} />
        <Row label="Version" value={`v${cert.version}`} />
        <Row label="Basic constraints" value={cert.is_ca ? `CA${cert.path_len != null ? `, path length ${cert.path_len}` : ""}` : "End entity"} />
        <Row label="Self-signed" value={cert.self_signed ? "Yes" : "No"} />
        <Row label="Subject alt. names" value={cert.sans.join(", ")} copy={cert.sans.join(", ")} mono />
        <Row label="Key usage" value={cert.key_usage.join(", ")} />
        <Row label="Extended key usage" value={cert.extended_key_usage.join(", ")} />
        <Row label="Subject key ID" value={cert.subject_key_id ?? undefined} mono />
        <Row label="Authority key ID" value={cert.authority_key_id ?? undefined} mono />
        <Row label="SHA-256" value={cert.sha256_fingerprint} copy={cert.sha256_fingerprint} mono />
        <Row label="SPKI SHA-256" value={cert.spki_sha256 || undefined} copy={cert.spki_sha256} mono />
        <Row label="SHA-1" value={cert.sha1_fingerprint} copy={cert.sha1_fingerprint} mono />
      </tbody>
    </table>
    {showPem && <CodeBlock label="PEM" value={cert.pem} maxHeight={200} />}
  </div>
);

export const ExtensionsList: React.FC<{ cert: CertificateInfo }> = ({ cert }) =>
  cert.extensions.length === 0 ? (
    <p className="text-[13px] text-faint">This certificate has no extensions (X.509 v1).</p>
  ) : (
    <div className="space-y-2">
      {cert.extensions.map((ext, i) => (
        <div key={i} className="p-3 bg-surface-2 rounded-control border border-line">
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold text-[13px] text-ink">{ext.name}</span>
            <span className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-faint">{ext.oid}</span>
              {ext.critical ? <Badge tone="danger">Critical</Badge> : <Badge>Non-critical</Badge>}
            </span>
          </div>
          <div className="mt-1.5 font-mono text-[11.5px] text-ink-2 break-all select-text">{ext.value || "—"}</div>
        </div>
      ))}
    </div>
  );

/** Collapsible certificate cards for a chain (leaf first). */
export const ChainView: React.FC<{
  certs: CertificateInfo[];
  actions?: (cert: CertificateInfo, index: number) => React.ReactNode;
  defaultOpen?: number;
}> = ({ certs, actions, defaultOpen = 0 }) => {
  const [open, setOpen] = useState<number | null>(defaultOpen);
  return (
    <ol className="space-y-2">
      {certs.map((c, i) => {
        const expanded = open === i;
        const role = i === 0 ? (c.is_ca ? "CA certificate" : "Leaf certificate") : c.self_signed ? "Root CA" : "Intermediate CA";
        return (
          <li key={c.sha256_fingerprint + i} className="rounded-card border border-line bg-surface overflow-hidden">
            <div className="flex items-center gap-3 px-4 py-3">
              <button onClick={() => setOpen(expanded ? null : i)} className="flex items-center gap-3 flex-1 min-w-0 text-left cursor-pointer" aria-expanded={expanded}>
                {expanded ? <ChevronDown className="w-4 h-4 text-subtle shrink-0" /> : <ChevronRight className="w-4 h-4 text-subtle shrink-0" />}
                <span className="w-7 h-7 rounded-control bg-surface-3 text-muted flex items-center justify-center shrink-0 text-[12px] font-semibold">{i + 1}</span>
                <span className="min-w-0">
                  <span className="block text-[13px] font-semibold text-ink truncate">{cnOf(c.subject)}</span>
                  <span className="block text-[12px] text-faint truncate">
                    {role} · issued by {cnOf(c.issuer)} · {c.public_key_algorithm} {c.key_size || ""}
                  </span>
                </span>
              </button>
              <ValidityBadge cert={c} />
              {actions?.(c, i)}
            </div>
            {expanded && (
              <div className="px-4 pb-4 space-y-3">
                <CertificateDetails cert={c} />
                <details>
                  <summary className="cursor-pointer text-[12.5px] font-medium text-brand">Extensions ({c.extensions.length})</summary>
                  <div className="mt-2">
                    <ExtensionsList cert={c} />
                  </div>
                </details>
                <CodeBlock label="PEM" value={c.pem} maxHeight={180} />
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
};

export const TrustBanner: React.FC<{ trusted: boolean; error?: string | null }> = ({ trusted, error }) =>
  trusted ? (
    <div className="flex items-center gap-2 rounded-control bg-success-tint border border-success/20 px-3.5 py-2.5 text-[13px] text-success font-medium">
      <ShieldCheck className="w-4 h-4" /> Chain is trusted by this computer and valid for the hostname.
    </div>
  ) : (
    <div className="flex items-start gap-2 rounded-control bg-danger-tint border border-danger/20 px-3.5 py-2.5 text-[13px] text-danger">
      <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" />
      <span>
        <strong className="font-semibold">Not trusted:</strong> {error ?? "verification failed"}
      </span>
    </div>
  );

export const WarningList: React.FC<{ warnings: string[] }> = ({ warnings }) =>
  warnings.length ? (
    <ul className="space-y-1.5">
      {warnings.map((w) => (
        <li key={w} className="flex items-start gap-2 text-[12.5px] text-warning">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" /> <span className="text-ink-2">{w}</span>
        </li>
      ))}
    </ul>
  ) : null;
