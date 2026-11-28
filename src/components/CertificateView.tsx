import React, { useState } from "react";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, CircleHelp, Network, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";
import type { CertificateInfo, OcspInfo, RevocationMethodResult } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { CERTIFICATE_ROLE_LABEL, certificateRole, cnOf } from "../lib/keystore";
import { CERTIFICATE_ROLE_VIEW } from "./certificate-icons";
import { extensionItems, LIST_OIDS, NAME_OIDS } from "../lib/certificates";
import { Alert, Badge, Button, Checkbox, CodeBlock, CopyButton, Segmented, Spinner, TextInput } from "./ui";

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
      <th scope="row" className="w-[30%] align-top text-left font-medium text-faint bg-surface-2 border-b border-line px-3.5 py-2.5 text-[13px]">
        {label}
      </th>
      <td className={clsx("align-top border-b border-line px-3.5 py-2.5 text-ink break-all select-text", mono ? "font-mono text-[11.5px]" : "text-[13px]")}>
        <div className="flex items-start justify-between gap-2">
          <span className="min-w-0">{value}</span>
          {copy && <CopyButton value={copy} label={`Copy ${label}`} />}
        </div>
      </td>
    </tr>
  );

/** The CN of a distinguished name, or null when it has none (cnOf would return the whole name). */
const cnOrNull = (dn: string) => (/(?:^|,\s*)CN=/.test(dn) ? cnOf(dn) : null);

/** A CN row under its distinguished name: the CN to copy, or "None" when the name has no CN. */
const CnRow: React.FC<{ label: string; dn: string }> = ({ label, dn }) => {
  const cn = cnOrNull(dn);
  return <Row label={label} value={cn ?? <span className="font-sans text-faint">None</span>} copy={cn ?? undefined} mono />;
};

/** Field table for one certificate. */
export const CertificateDetails: React.FC<{ cert: CertificateInfo; showPem?: boolean }> = ({ cert, showPem }) => (
  <div className="space-y-3">
    <table className="w-full border border-line rounded-card overflow-hidden border-separate border-spacing-0">
      <tbody>
        <Row label="Subject" value={cert.subject} copy={cert.subject} mono />
        <CnRow label="Subject CN" dn={cert.subject} />
        <Row label="Issuer" value={cert.issuer} copy={cert.issuer} mono />
        <CnRow label="Issuer CN" dn={cert.issuer} />
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

/** What each common extension is for, in a line. */
const EXTENSION_ABOUT: Record<string, string> = {
  "2.5.29.19": "Whether the certificate may issue others, and how deep below it.",
  "2.5.29.15": "The operations the key may be used for.",
  "2.5.29.37": "The purposes the certificate is valid for.",
  "2.5.29.17": "Other names the certificate covers: hosts, addresses, e-mail, URIs.",
  "2.5.29.18": "Other names of the issuer.",
  "2.5.29.14": "Identifies this certificate's public key.",
  "2.5.29.35": "Identifies the key that signed this certificate, to find the issuer.",
  "2.5.29.31": "Where the issuer publishes its certificate revocation list.",
  "1.3.6.1.5.5.7.1.1": "Where to ask about revocation (OCSP) and fetch the issuer's certificate.",
  "2.5.29.32": "The policies the certificate was issued under.",
  "2.5.29.30": "The names certificates below this CA may and may not use.",
  "1.3.6.1.4.1.11129.2.4.2": "Proof that the certificate was logged in Certificate Transparency.",
  "2.5.29.36": "Constraints on policy mapping below this CA.",
  "2.16.840.1.113730.1.1": "Netscape certificate type (legacy).",
};

/** A name item split into its kind and value: "DNS:example.com" → ["DNS", "example.com"]. */
const splitItem = (item: string): [string | null, string] => {
  const m = /^(DNS|email|URI|IP|DirName|RID|othername|keyid|serial):(.*)$/.exec(item) ?? /^(OCSP|CA Issuers) - (.*)$/.exec(item);
  return m ? [m[1], m[2]] : [null, item];
};

const ExtensionValue: React.FC<{ oid: string; value: string }> = ({ oid, value }) => {
  const items = extensionItems(oid, value);
  if (!items.length) return <span className="text-faint">—</span>;
  if (LIST_OIDS.has(oid) || oid === "2.5.29.19") {
    return (
      <div className="flex flex-wrap gap-1.5">
        {items.map((i) => (
          <Badge key={i} tone={oid === "2.5.29.19" && i === "CA" ? "brand" : "neutral"} className={clsx(oid === "2.5.29.32" && "font-mono")}>
            {i}
          </Badge>
        ))}
      </div>
    );
  }
  if (NAME_OIDS.has(oid)) {
    return (
      <ul className="space-y-1">
        {items.map((i, n) => {
          const [kind, rest] = splitItem(i);
          return (
            <li key={n} className="flex items-start gap-2 min-w-0">
              {kind && <Badge className="shrink-0">{kind === "keyid" ? "Key ID" : kind}</Badge>}
              <span className="font-mono text-[11.5px] text-ink-2 break-all select-text min-w-0 leading-5">{rest}</span>
            </li>
          );
        })}
      </ul>
    );
  }
  return <div className="font-mono text-[11.5px] text-ink-2 break-all select-text">{value}</div>;
};

/** The certificate's extensions, each with what it is for, its criticality, its OID and its value as items. */
export const ExtensionsList: React.FC<{ cert: CertificateInfo }> = ({ cert }) => {
  const critical = cert.extensions.filter((e) => e.critical).length;
  return cert.extensions.length === 0 ? (
    <p className="text-[13px] text-faint">This certificate has no extensions (X.509 v1).</p>
  ) : (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[12px] text-faint">
        <span>
          {cert.extensions.length} extension{cert.extensions.length === 1 ? "" : "s"}
        </span>
        <span aria-hidden>·</span>
        <span>{critical ? `${critical} critical` : "none critical"}</span>
      </div>
      <ul className="rounded-card border border-line divide-y divide-line overflow-hidden" data-testid="extensions-list">
        {cert.extensions.map((ext, i) => (
          <li key={i} className="grid gap-x-4 gap-y-2 px-4 py-3 sm:grid-cols-[minmax(11rem,15rem)_1fr]">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="font-semibold text-[13px] text-ink">{ext.name}</span>
                {ext.critical && <Badge tone="danger">Critical</Badge>}
              </div>
              <div className="mt-0.5 flex items-center gap-1 font-mono text-[11px] text-faint">
                <span className="truncate">{ext.oid}</span>
                <CopyButton value={ext.oid} label={`Copy OID of ${ext.name}`} />
              </div>
              {EXTENSION_ABOUT[ext.oid] && <p className="mt-1 text-[12px] text-faint leading-4">{EXTENSION_ABOUT[ext.oid]}</p>}
            </div>
            <div className="min-w-0 self-center">
              <ExtensionValue oid={ext.oid} value={ext.value} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
};

const ocspToneAndLabel = (r: OcspInfo): [React.ComponentProps<typeof Badge>["tone"], string] =>
  r.status === "good" ? ["success", "Good"] : r.status === "revoked" ? ["danger", "Revoked"] : ["warning", "Unknown"];

/**
 * Live RFC 6960 revocation check for one certificate against its issuer. Needs the issuer's PEM
 * (to hash its key/name into the request, and to check the responder's signature), so this only
 * appears where a chain is available — it cannot check a self-signed or orphaned certificate.
 */
export const OcspPanel: React.FC<{ cert: CertificateInfo; issuer: CertificateInfo }> = ({ cert, issuer }) => {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<OcspInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  if ((cert.ocsp_urls ?? []).length === 0 && !result) {
    return null;
  }
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.checkOcsp(cert.pem, issuer.pem));
    } catch (err) {
      setResult(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-wrap items-center gap-2.5">
      <Button icon={Network} onClick={() => void run()} disabled={busy}>
        {busy && <Spinner />} {busy ? "Checking…" : "Check revocation (OCSP)"}
      </Button>
      {error && <span className="text-[12px] text-danger">{error}</span>}
      {result && (
        <span className="inline-flex items-center gap-2 text-[12px] text-faint">
          <Badge tone={ocspToneAndLabel(result)[0]}>{ocspToneAndLabel(result)[1]}</Badge>
          {!result.signature_valid && (
            <span title={result.signature_warning ?? undefined}>
              <Badge tone="warning">Signature unverified</Badge>
            </span>
          )}
          {result.status === "revoked" && result.revocation_time && <span>since {result.revocation_time}</span>}
          <span>via {result.responder || result.url}</span>
        </span>
      )}
    </div>
  );
};

/** The logo of a certificate's place in its chain. */
const RoleTile: React.FC<{ cert: CertificateInfo; position: number; className: string }> = ({ cert, position, className }) => {
  const role = certificateRole(cert, position);
  const { icon: Icon, tile } = CERTIFICATE_ROLE_VIEW[role];
  return (
    <span title={CERTIFICATE_ROLE_LABEL[role]} data-cert-role={role} className={clsx("rounded-control border flex items-center justify-center shrink-0", tile, className)}>
      <Icon className="w-3.5 h-3.5" aria-hidden />
    </span>
  );
};

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
        const role = CERTIFICATE_ROLE_LABEL[certificateRole(c, i)];
        return (
          <li key={c.sha256_fingerprint + i} className="rounded-card border border-line bg-surface overflow-hidden">
            <div className="flex items-center gap-3 px-4 py-3">
              <button onClick={() => setOpen(expanded ? null : i)} className="flex items-center gap-3 flex-1 min-w-0 text-left cursor-pointer" aria-expanded={expanded}>
                {expanded ? <ChevronDown className="w-4 h-4 text-subtle shrink-0" /> : <ChevronRight className="w-4 h-4 text-subtle shrink-0" />}
                <RoleTile cert={c} position={i} className="w-7 h-7" />
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
                {!c.self_signed && certs[i + 1] && <OcspPanel cert={c} issuer={certs[i + 1]} />}
                <details>
                  <summary className="cursor-pointer text-[13px] font-medium text-brand">Extensions ({c.extensions.length})</summary>
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

/**
 * Checks a decoded certificate chain against this computer's trust store on demand (the same
 * roots `examineTls` trusts), for places that show a chain without having already run a live
 * handshake. `certs` is leaf-first, as `ChainView` and the detection engine order them.
 */
export const ChainValidation: React.FC<{ certs: CertificateInfo[] }> = ({ certs }) => {
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Off by default: checking revocation contacts the CA's OCSP responder or CRL server.
  const [checkRevocation, setCheckRevocation] = useState(false);
  const [checkedRevocation, setCheckedRevocation] = useState(false);
  const leaf = certs[0];
  if (!leaf || leaf.self_signed) {
    return null;
  }
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const anchors = await api.systemTrustAnchors();
      setProblems(await api.validateChain(leaf.pem, certs.slice(1).map((c) => c.pem).join(""), anchors, null, checkRevocation));
      setCheckedRevocation(checkRevocation);
    } catch (err) {
      setProblems(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-2.5">
      <Button icon={ShieldCheck} onClick={() => void run()} disabled={busy}>
        {busy && <Spinner />} {busy ? "Validating…" : "Validate against this computer's trust store"}
      </Button>
      <Checkbox
        checked={checkRevocation}
        onChange={setCheckRevocation}
        label="Also check revocation online"
        hint="Asks each certificate's OCSP responder, or downloads its CRL, which tells the CA this certificate is being checked."
        testId="validate-revocation"
      />
      {error && <Alert tone="danger">{error}</Alert>}
      {problems && problems.length === 0 && <TrustBanner trusted />}
      {problems && problems.length === 0 && checkedRevocation && <p className="text-[12px] text-faint">No certificate in the chain is revoked.</p>}
      {problems && problems.length > 0 && (
        <Alert tone="danger" title="Not trusted">
          <ul className="mt-1 space-y-0.5 list-disc pl-4">
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </Alert>
      )}
    </div>
  );
};

export const WarningList: React.FC<{ warnings: string[] }> = ({ warnings }) =>
  warnings.length ? (
    <ul className="space-y-1.5">
      {warnings.map((w) => (
        <li key={w} className="flex items-start gap-2 text-[13px] text-warning">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" /> <span className="text-ink-2">{w}</span>
        </li>
      ))}
    </ul>
  ) : null;

// ------------------------------------------------------------------------------------- verify

/** A certificate's role in its chain, for labels. */
const roleOf = (c: CertificateInfo, index: number) => CERTIFICATE_ROLE_LABEL[certificateRole(c, index)];

/** The chain drawn as a tree, root at the top and the certificate being verified at the bottom. */
export const ChainTree: React.FC<{ chain: CertificateInfo[]; complete: boolean }> = ({ chain, complete }) => {
  // `chain` is leaf first; the tree reads from the root down.
  const top = [...chain].reverse();
  return (
    <ol className="space-y-0" aria-label="Certificate chain" data-testid="verify-chain-tree">
      {!complete && (
        <li className="flex items-center gap-2 text-[12px] text-warning pb-2">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> Issuer “{cnOf(top[0].issuer)}” is not open, so the chain stops here.
        </li>
      )}
      {top.map((c, i) => (
        <li key={c.sha256_fingerprint} className="flex items-center gap-2 min-w-0 py-1" style={{ paddingLeft: i * 20 }}>
          {i > 0 && <span aria-hidden className="w-3 h-3 -mt-2 border-l border-b border-line-strong rounded-bl-[3px] shrink-0" />}
          <RoleTile cert={c} position={chain.length - 1 - i} className="w-6 h-6" />
          <span className="min-w-0">
            <span className="block text-[13px] font-medium text-ink truncate">{cnOf(c.subject)}</span>
            <span className="block text-[11.5px] text-faint truncate">
              {roleOf(c, chain.length - 1 - i)} · {c.public_key_algorithm}
              {c.key_size ? ` ${c.key_size}` : ""} · until {c.valid_to}
            </span>
          </span>
          <span className="ml-auto shrink-0">
            <ValidityBadge cert={c} />
          </span>
        </li>
      ))}
    </ol>
  );
};

const STATUS_TONE: Record<RevocationMethodResult["status"], React.ComponentProps<typeof Badge>["tone"]> = { good: "success", revoked: "danger", unknown: "warning" };
const STATUS_LABEL: Record<RevocationMethodResult["status"], string> = { good: "Not revoked", revoked: "Revoked", unknown: "Unknown" };

/** Revocation of one certificate by each OCSP responder and CRL it names, asked on demand. */
const RevocationRow: React.FC<{ cert: CertificateInfo; issuer: CertificateInfo; index: number; runAll: number }> = ({ cert, issuer, index, runAll }) => {
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<RevocationMethodResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ocsp = cert.ocsp_urls?.length ?? 0;
  const crl = cert.crl_distribution_points?.length ?? 0;
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResults(await api.checkRevocation(cert.pem, issuer.pem));
    } catch (err) {
      setResults(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  React.useEffect(() => {
    if (runAll > 0 && (ocsp || crl)) void run();
  }, [runAll]); // eslint-disable-line react-hooks/exhaustive-deps
  const overall = results?.some((r) => r.status === "revoked") ? "revoked" : results?.some((r) => r.status === "good") ? "good" : results ? "unknown" : null;
  return (
    <li className="px-4 py-3 space-y-2" data-testid={`verify-revocation-${index}`}>
      <div className="flex items-center gap-2 min-w-0">
        <span className="min-w-0 flex-1">
          <span className="block text-[13px] font-medium text-ink truncate">{cnOf(cert.subject)}</span>
          <span className="block text-[11.5px] text-faint truncate">
            {roleOf(cert, index)} · checked against {cnOf(issuer.subject)}
          </span>
        </span>
        {ocsp > 0 && <Badge>OCSP{ocsp > 1 ? ` ×${ocsp}` : ""}</Badge>}
        {crl > 0 && <Badge>CRL{crl > 1 ? ` ×${crl}` : ""}</Badge>}
        {overall && <Badge tone={STATUS_TONE[overall]}>{STATUS_LABEL[overall]}</Badge>}
        {ocsp || crl ? (
          <Button size="sm" icon={Network} onClick={() => void run()} disabled={busy} data-testid={`verify-revocation-run-${index}`}>
            {busy && <Spinner />} {busy ? "Checking…" : results ? "Check again" : "Check"}
          </Button>
        ) : (
          <span className="text-[12px] text-faint">Names no OCSP responder or CRL</span>
        )}
      </div>
      {error && <Alert tone="danger">{error}</Alert>}
      {results && results.length > 0 && (
        <ul className="space-y-1.5">
          {results.map((r, i) => {
            const Icon = r.status === "good" ? CheckCircle2 : r.status === "revoked" ? ShieldX : CircleHelp;
            return (
              <li key={i} className="flex items-start gap-2 text-[12px] min-w-0">
                <Icon className={clsx("w-3.5 h-3.5 mt-0.5 shrink-0", r.status === "good" ? "text-success" : r.status === "revoked" ? "text-danger" : "text-warning")} />
                <Badge className="shrink-0">{r.method.toUpperCase()}</Badge>
                <span className="min-w-0">
                  <span className="text-ink-2">{STATUS_LABEL[r.status]}</span>
                  {r.detail && <span className="text-faint"> · {r.detail}</span>}
                  <span className="block font-mono text-[11px] text-faint break-all">{r.url}</span>
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </li>
  );
};

type AnchorChoice = "system" | "chain";

/**
 * Verify a certificate: its chain as a tree, path validation against this computer's trust store or
 * the chain's own root (signatures, validity, constraints, optional hostname and revocation), and
 * a revocation check of each certificate by OCSP and CRL. `issuers` are nearest first.
 */
export const VerifyCertificate: React.FC<{ cert: CertificateInfo; issuers: CertificateInfo[] }> = ({ cert, issuers }) => {
  const chain = [cert, ...issuers];
  const top = chain[chain.length - 1];
  const complete = top.self_signed;
  const root = complete ? top : null;
  const [anchor, setAnchor] = useState<AnchorChoice>("system");
  const [hostname, setHostname] = useState("");
  const [checkRevocation, setCheckRevocation] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string[] | null>(null);
  const [checked, setChecked] = useState<{ anchor: AnchorChoice; revocation: boolean; hostname: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [runAll, setRunAll] = useState(0);
  const reset = () => {
    setProblems(null);
    setChecked(null);
    setError(null);
  };
  const validate = async () => {
    setBusy(true);
    setError(null);
    try {
      const anchors = anchor === "chain" && root ? root.pem : await api.systemTrustAnchors();
      const intermediates = issuers.filter((c) => !(anchor === "chain" && c === root)).map((c) => c.pem).join("");
      setProblems(await api.validateChain(cert.pem, intermediates, anchors, hostname.trim() || null, checkRevocation));
      setChecked({ anchor, revocation: checkRevocation, hostname: hostname.trim() });
    } catch (err) {
      setProblems(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const now = Date.now() / 1000;
  const timeProblems = chain.filter((c) => c.not_before > now || c.days_remaining < 0);
  const checkable = chain.slice(0, -1).map((c, i) => ({ c, issuer: chain[i + 1], i })).filter(({ c }) => !c.self_signed);
  return (
    <div className="space-y-5" data-testid="verify-certificate">
      <section className="space-y-2">
        <h4 className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-faint">Chain</h4>
        <div className="rounded-card border border-line px-4 py-3">
          <ChainTree chain={chain} complete={complete} />
        </div>
        <ul className="flex flex-wrap gap-1.5" aria-label="Quick checks">
          <li>
            <Badge tone={complete ? "success" : "warning"}>{complete ? `Chain complete · ${chain.length} certificate${chain.length === 1 ? "" : "s"}` : "Chain incomplete"}</Badge>
          </li>
          <li>
            <Badge tone={timeProblems.length ? "danger" : "success"}>{timeProblems.length ? `${timeProblems.length} outside validity period` : "All within validity period"}</Badge>
          </li>
          {cert.self_signed && (
            <li>
              <Badge tone="warning">Self-signed</Badge>
            </li>
          )}
        </ul>
      </section>

      <section className="space-y-3">
        <h4 className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-faint">Validate chain</h4>
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <div className="text-[12px] text-faint">Trust</div>
            <Segmented<AnchorChoice>
              label="Trust anchors"
              value={anchor}
              onChange={(v) => {
                setAnchor(v);
                reset();
              }}
              options={[
                { value: "system", label: "This computer's trust store" },
                ...(root ? [{ value: "chain" as const, label: `Its root (${cnOf(root.subject)})` }] : []),
              ]}
            />
          </div>
          <TextInput
            label="Hostname (optional)"
            value={hostname}
            onChange={(e) => {
              setHostname(e.target.value);
              reset();
            }}
            placeholder="www.example.com"
            className="!h-8 w-56"
            data-testid="verify-hostname"
          />
        </div>
        <Checkbox
          checked={checkRevocation}
          onChange={(v) => {
            setCheckRevocation(v);
            reset();
          }}
          label="Also check revocation online"
          hint="Asks each certificate's OCSP responder, or downloads its CRL, which tells the CA this certificate is being checked."
          testId="verify-revocation-toggle"
        />
        <Button variant="primary" icon={ShieldCheck} onClick={() => void validate()} disabled={busy} data-testid="verify-run">
          {busy && <Spinner />} {busy ? "Validating…" : "Validate"}
        </Button>
        {error && <Alert tone="danger">{error}</Alert>}
        {problems && problems.length === 0 && checked && (
          <div className="flex items-start gap-2 rounded-control bg-success-tint border border-success/20 px-3.5 py-2.5 text-[13px] text-success font-medium" data-testid="verify-trusted">
            <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" />
            <span>
              Valid: signatures, validity and constraints check out to {checked.anchor === "chain" && root ? `the root “${cnOf(root.subject)}”` : "a root this computer trusts"}
              {checked.hostname ? `, and it is valid for ${checked.hostname}` : ""}
              {checked.revocation ? ". No certificate in the chain is revoked." : "."}
            </span>
          </div>
        )}
        {problems && problems.length > 0 && (
          <Alert tone="danger" title="Not valid">
            <ul className="mt-1 space-y-0.5 list-disc pl-4" data-testid="verify-problems">
              {problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </Alert>
        )}
      </section>

      <section className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <h4 className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-faint">Revocation status</h4>
          {checkable.length > 1 && (
            <Button size="sm" icon={Network} onClick={() => setRunAll((n) => n + 1)} data-testid="verify-revocation-all">
              Check all
            </Button>
          )}
        </div>
        {checkable.length === 0 ? (
          <p className="text-[13px] text-faint">
            {cert.self_signed ? "A self-signed certificate has no issuer to ask about revocation." : `Open the issuer “${cnOf(cert.issuer)}” to check revocation: the request needs its key and name.`}
          </p>
        ) : (
          <ul className="rounded-card border border-line divide-y divide-line">
            {checkable.map(({ c, issuer, i }) => (
              <RevocationRow key={c.sha256_fingerprint} cert={c} issuer={issuer} index={i} runAll={runAll} />
            ))}
          </ul>
        )}
        <p className="text-[12px] text-faint">Checks go online only when you ask, to the URLs the certificates name.</p>
      </section>
    </div>
  );
};
