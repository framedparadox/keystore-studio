import React, { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Clock, Cpu, FileArchive, FileCheck2, FileSignature, FolderOpen, KeyRound, Plus, Save, ShieldCheck, Trash2, Unlock, XCircle } from "lucide-react";
import type { CertificateInfo, CmsSignResult, CmsVerifyResult, CrlInfo, CsrInfo, DhParamsResult, JarSignResult, JwtVerifyResult, KeystoreEntry, OpenKeystore, RevokedCertEntry, SignedCertificateResult, TimestampInfo } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { FILTERS, baseName, pickFile, pickSavePath, safeFileStem } from "../lib/files";
import { EXTENDED_KEY_USAGES, KEY_USAGES, cnOf, isCaEntry, splitList } from "../lib/keystore";
import { useStore } from "../state/store";
import { Alert, Badge, Button, Card, Checkbox, CodeBlock, EmptyState, Page, PageHeader, Segmented, Select, Spinner, TextArea, TextInput, useToast } from "../components/ui";
import { CertificateDetails } from "../components/CertificateView";
import { TerminalHint } from "../components/Terminal";
import { useSaveText, useSavedToast } from "../components/EntryDialogs";

type Tool = "csr" | "crl" | "cms" | "jwt" | "jar" | "dh";

interface Candidate {
  entry: KeystoreEntry;
  ks: OpenKeystore;
}

function useSigners(filter: (e: KeystoreEntry) => boolean): Candidate[] {
  const { keystores } = useStore();
  return useMemo(() => keystores.flatMap((ks) => ks.entries.filter(filter).map((entry) => ({ entry, ks }))), [keystores]); // eslint-disable-line react-hooks/exhaustive-deps
}

const usableKeyPair = (e: KeystoreEntry) => e.entry_type === "KeyPair" && !e.locked && !!e.private_key_pem && ["RSA", "ECDSA", "Ed25519"].includes(e.algorithm);

/// Shared TSA control. Returns the URL to pass to the signing call, or null to sign without a
/// timestamp. Defaults come from Settings so the URL is typed once, not per signature.
function useTimestamping() {
  const { settings } = useStore();
  const [enabled, setEnabled] = useState(settings.timestampByDefault && !!settings.tsaUrl.trim());
  const [url, setUrl] = useState(settings.tsaUrl);
  // Follow Settings while the user has not overridden anything in this panel.
  useEffect(() => {
    setUrl(settings.tsaUrl);
    setEnabled(settings.timestampByDefault && !!settings.tsaUrl.trim());
  }, [settings.tsaUrl, settings.timestampByDefault]);
  const tsaUrl = enabled && url.trim() ? url.trim() : null;
  const control = (
    <div className="space-y-2">
      <Checkbox
        checked={enabled}
        onChange={setEnabled}
        label="Add a trusted timestamp (RFC 3161)"
        hint="Proves when you signed, so the signature stays verifiable after your certificate expires."
      />
      {enabled && (
        <>
          <TextInput
            label="Timestamp authority URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="http://timestamp.digicert.com"
            data-testid="tsa-url"
          />
          {!url.trim() && <div className="text-[12px] text-warning">Enter a TSA URL, or clear the checkbox to sign without a timestamp.</div>}
          <div className="text-[12px] text-faint">This is the only network request signing makes. Set a default in Settings.</div>
        </>
      )}
    </div>
  );
  return { tsaUrl, control, enabled };
}

/// Shows what a TSA returned, or why an attached token does not match.
const TimestampBadge: React.FC<{ ts?: TimestampInfo | null }> = ({ ts }) => {
  if (!ts) return null;
  return (
    <div className="rounded-control border border-line bg-surface p-2.5 text-[12.5px] space-y-1" data-testid="timestamp-info">
      <div className="flex items-center gap-2">
        <Badge tone={ts.valid ? "success" : "danger"} icon={ts.valid ? Clock : XCircle}>
          {ts.valid ? "Timestamped" : "Timestamp invalid"}
        </Badge>
        {ts.time && <span className="text-muted">{ts.time}</span>}
      </div>
      {ts.authority && <div className="text-faint truncate">by {ts.authority}</div>}
      {ts.serial_number && (
        <div className="text-faint font-mono text-[11.5px] break-all">
          serial {ts.serial_number}
          {ts.hash_algorithm ? ` · ${ts.hash_algorithm}` : ""}
        </div>
      )}
      {ts.error && <div className="text-danger">{ts.error}</div>}
      {ts.chain_trusted === true && <div className="text-success">TSA certificate chains to the configured trust bundle.</div>}
      {ts.chain_trusted === false && <div className="text-danger">TSA certificate does not chain to the configured trust bundle.</div>}
      {ts.valid && ts.chain_trusted == null && <div className="text-faint">TSA certificate chain was not checked. Add a trust bundle in Settings to verify it.</div>}
    </div>
  );
};

/** Key picker. A locked key pair can be chosen; it must be unlocked before it signs anything. */
const SignerSelect: React.FC<{ label: string; candidates: Candidate[]; value: string; onChange: (id: string) => void; emptyHint: string; testId?: string; publicOnly?: boolean }> = ({
  label,
  candidates,
  value,
  onChange,
  emptyHint,
  testId,
  publicOnly,
}) => {
  const { isKeyLocked, ensureKeyAccess } = useStore();
  if (candidates.length === 0) {
    return (
      <Alert tone="info" title={label}>
        {emptyHint}
      </Alert>
    );
  }
  const chosen = candidates.find((c) => c.entry.id === value);
  const locked = !publicOnly && !!chosen && isKeyLocked(chosen.entry);
  return (
    <div className="space-y-2">
      <Select label={label} value={value} onChange={(e) => onChange(e.target.value)} data-testid={testId}>
        {candidates.map((c) => (
          <option key={c.entry.id} value={c.entry.id}>
            {c.entry.alias} — {c.entry.entry_type === "SecretKey" ? c.entry.algorithm : `${cnOf(c.entry.subject)} (${c.entry.algorithm})`} · {c.ks.name}
            {!publicOnly && isKeyLocked(c.entry) ? " · locked" : ""}
          </option>
        ))}
      </Select>
      {locked && chosen && (
        <Alert
          tone="warning"
          title={`'${chosen.entry.alias}' is locked`}
          action={
            <Button size="sm" icon={Unlock} onClick={() => ensureKeyAccess(chosen.ks.id, [chosen.entry.id])} data-testid={testId ? `${testId}-unlock` : undefined}>
              Unlock…
            </Button>
          }
        >
          Enter its key password to sign with it.
        </Alert>
      )}
    </div>
  );
};

/** The chosen candidate, or null while none is chosen or the chosen key is still locked. */
const useSelected = (candidates: Candidate[]) => {
  const { isKeyLocked } = useStore();
  const [id, setId] = useState("");
  useEffect(() => {
    if (!candidates.some((c) => c.entry.id === id)) setId((candidates.find((c) => !isKeyLocked(c.entry)) ?? candidates[0])?.entry.id ?? "");
  }, [candidates, id]); // eslint-disable-line react-hooks/exhaustive-deps
  const chosen = candidates.find((c) => c.entry.id === id) ?? null;
  return [chosen && !isKeyLocked(chosen.entry) ? chosen : null, id, setId] as const;
};

const FileOrPaste: React.FC<{ label: string; path: string | null; setPath: (p: string | null) => void; text: string; setText: (t: string) => void; placeholder: string; filters: typeof FILTERS[keyof typeof FILTERS][]; rows?: number; testId?: string }> = ({
  label,
  path,
  setPath,
  text,
  setText,
  placeholder,
  filters,
  rows = 7,
  testId,
}) => (
  <div>
    <div className="flex items-center justify-between mb-1.5">
      <span className="label !mb-0">{label}</span>
      <Button
        size="sm"
        icon={FolderOpen}
        onClick={async () => {
          const p = await pickFile(`Select ${label.toLowerCase()}`, filters).catch(() => null);
          if (p) {
            setPath(p);
            setText("");
          }
        }}
      >
        Choose file…
      </Button>
    </div>
    {path ? (
      <div className="flex items-center gap-2 rounded-control border border-line bg-surface-2 px-3 h-9 text-[12.5px]">
        <span className="font-mono truncate flex-1" title={path}>
          {path}
        </span>
        <button className="text-brand font-medium cursor-pointer" onClick={() => setPath(null)}>
          Clear
        </button>
      </div>
    ) : (
      <TextArea mono rows={rows} placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} data-testid={testId} />
    )}
  </div>
);

const ResultPane: React.FC<{ children?: React.ReactNode; empty: string }> = ({ children, empty }) => (
  <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line min-h-[320px] select-text">
    {children ?? <div className="h-full min-h-[280px] flex items-center justify-center text-center text-subtle text-[13px] px-6">{empty}</div>}
  </div>
);

async function sha256OfPem(pemText: string): Promise<string> {
  const b64 = pemText.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bin));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
}

// ====================================================================================== CSR

const usageLabels = (ids: string[] | undefined, dict: { id: string; label: string }[]) => {
  if (!ids?.length) return "none";
  return ids.map((id) => dict.find((d) => d.id === id)?.label ?? id).join(", ");
};

const SignCsrTool: React.FC = () => {
  const { keystores, replaceEntry, addEntries, activeKeystore, ensureKeyAccess } = useStore();
  const toast = useToast();
  const saveText = useSaveText();
  const cas = useSigners(isCaEntry);
  const [ca, caId, setCaId] = useSelected(cas);
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [info, setInfo] = useState<CsrInfo | null>(null);
  const [subject, setSubject] = useState("");
  const [days, setDays] = useState(397);
  const [notBefore, setNotBefore] = useState("");
  const [notAfter, setNotAfter] = useState("");
  const [crlUrl, setCrlUrl] = useState("");
  const [ocspUrl, setOcspUrl] = useState("");
  const [caIssuerUrl, setCaIssuerUrl] = useState("");
  const [isCa, setIsCa] = useState(false);
  const [pathLen, setPathLen] = useState("");
  const [extraSans, setExtraSans] = useState("");
  const [copySans, setCopySans] = useState(true);
  const [honorUsages, setHonorUsages] = useState(true);
  const [ku, setKu] = useState<string[]>([]);
  const [eku, setEku] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SignedCertificateResult | null>(null);
  const [match, setMatch] = useState<{ entry: KeystoreEntry; ks: OpenKeystore } | null>(null);

  const source = () => (path ? { path } : { text });
  useEffect(() => {
    setInfo(null);
    setResult(null);
    setHonorUsages(true);
  }, [path, text]);

  const inspect = async () => {
    try {
      const i = await api.inspectCsr(source());
      setInfo(i);
      setSubject(i.subject);
      setKu(i.key_usage ?? []);
      setEku(i.extended_key_usage ?? []);
      return i;
    } catch (err) {
      toast.error(errorMessage(err));
      return null;
    }
  };

  const sign = async () => {
    if (!ca) return;
    setBusy(true);
    try {
      const i = info ?? (await inspect());
      if (!i) return;
      const csrPem = path ? await api.readTextFile(path) : text;
      const res = await api.signCsr(
        {
          csr_pem: csrPem,
          subject_override: subject && subject !== i.subject ? subject : null,
          validity_days: Number(days),
          is_ca: isCa,
          path_len: isCa && pathLen.trim() !== "" ? Number(pathLen) : null,
          sans: splitList(extraSans),
          key_usage: honorUsages ? [] : ku,
          extended_key_usage: honorUsages ? [] : eku,
          copy_requested_sans: copySans,
          copy_requested_usages: honorUsages,
          not_before: notBefore,
          not_after: notAfter,
          crl_distribution_points: splitList(crlUrl),
          ocsp_urls: splitList(ocspUrl),
          ca_issuer_urls: splitList(caIssuerUrl),
        },
        ca.entry
      );
      setResult(res);
      // Find the key pair this certificate belongs to (requested from xkeystore).
      let found: Candidate | null = null;
      for (const ks of keystores) {
        for (const e of ks.entries) {
          if (e.entry_type === "KeyPair" && e.public_key_pem && (await sha256OfPem(e.public_key_pem)) === i.public_key_sha256) found = { entry: e, ks };
        }
      }
      setMatch(found);
      toast.success(`Issued a certificate for ${cnOf(res.certificate.subject)}, valid until ${res.certificate.valid_to}.${res.validity_note ? ` ${res.validity_note}` : ""}`);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const install = () => {
    // Installing a reply changes the key pair, so it needs the key unlocked like any other use.
    if (match) ensureKeyAccess(match.ks.id, [match.entry.id], () => void installReply());
  };
  const installReply = async () => {
    if (!result || !match) return;
    try {
      const updated = await api.importCaReply(match.entry, { text: result.chain_pem });
      replaceEntry(match.ks.id, { ...updated, id: match.entry.id, labels: match.entry.labels });
      toast.success(`Installed the certificate into '${match.entry.alias}' (${match.ks.name}). Save the keystore to keep it.`);
      setMatch(null);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-5 space-y-4">
        <SignerSelect label="Issuing CA" candidates={cas} value={caId} onChange={setCaId} emptyHint="Open a keystore that contains a CA key pair (or generate one with Add entry → Generate CA key pair)." testId="csr-ca" />
        <FileOrPaste label="Certificate signing request" path={path} setPath={setPath} text={text} setText={setText} placeholder="-----BEGIN CERTIFICATE REQUEST-----" filters={[FILTERS.csr]} testId="sign-csr-input" />
        {info && (
          <div className="rounded-control border border-line bg-surface p-3 text-[12.5px] space-y-1">
            <div className="flex items-center gap-2">
              {info.signature_valid ? <Badge tone="success" icon={CheckCircle2}>Signature valid</Badge> : <Badge tone="danger" icon={XCircle}>Signature invalid</Badge>}
              <span className="text-muted">
                {info.public_key_algorithm} {info.key_size}-bit
              </span>
            </div>
            <div className="font-mono text-[11.5px] text-ink break-all">{info.subject}</div>
            {info.sans.length > 0 && <div className="text-faint">Requested SANs: {info.sans.join(", ")}</div>}
            <div className="text-faint">
              Requested key usage: {usageLabels(info.key_usage, KEY_USAGES)}. Extended: {usageLabels(info.extended_key_usage, EXTENDED_KEY_USAGES)}.
            </div>
          </div>
        )}
        <TextInput label="Subject" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Taken from the CSR" hint="Edit to override the requested subject." className="font-mono !text-[12px]" />
        <div className="grid grid-cols-2 gap-3">
          <TextInput label="Validity (days)" type="number" min={1} value={days} onChange={(e) => setDays(Number(e.target.value))} />
          <TextInput label="Not before" type="date" value={notBefore} onChange={(e) => setNotBefore(e.target.value)} />
          <TextInput label="Not after" type="date" value={notAfter} onChange={(e) => setNotAfter(e.target.value)} />
          <TextInput label="CRL URL" value={crlUrl} onChange={(e) => setCrlUrl(e.target.value)} placeholder="http://ca.example/crl.pem" className="col-span-2" />
          <TextInput label="OCSP URL (AIA)" value={ocspUrl} onChange={(e) => setOcspUrl(e.target.value)} placeholder="http://ocsp.example" />
          <TextInput label="CA Issuers URL (AIA)" value={caIssuerUrl} onChange={(e) => setCaIssuerUrl(e.target.value)} placeholder="http://ca.example/ca.crt" />
          <TextInput label="Extra SANs" value={extraSans} onChange={(e) => setExtraSans(e.target.value)} placeholder="DNS:alt.example.com" />
          {isCa && <TextInput label="Path length constraint" type="number" min={0} value={pathLen} onChange={(e) => setPathLen(e.target.value)} placeholder="Unlimited" />}
        </div>
        <Checkbox checked={copySans} onChange={setCopySans} label="Copy the SANs requested in the CSR" />
        <Checkbox
          checked={honorUsages}
          disabled={isCa}
          onChange={(v) => {
            setHonorUsages(v);
            if (!v && info) {
              setKu(info.key_usage ?? []);
              setEku(info.extended_key_usage ?? []);
            }
          }}
          label="Use the key usage requested in the CSR"
          hint={isCa ? "A CA certificate uses certificate sign and CRL sign instead of the request." : undefined}
        />
        <Checkbox
          checked={isCa}
          onChange={(v) => {
            setIsCa(v);
            if (v) {
              setHonorUsages(false);
              setKu(["digitalSignature", "keyCertSign", "cRLSign"]);
              setEku([]);
            } else {
              setHonorUsages(true);
            }
          }}
          label="Issue a CA certificate (intermediate)"
        />
        {!honorUsages && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-1.5">
              {KEY_USAGES.map((k) => (
                <Checkbox key={k.id} checked={ku.includes(k.id)} onChange={() => setKu(ku.includes(k.id) ? ku.filter((x) => x !== k.id) : [...ku, k.id])} label={k.label} />
              ))}
            </div>
            {!isCa && (
              <div className="grid grid-cols-2 gap-1.5">
                {EXTENDED_KEY_USAGES.map((k) => (
                  <Checkbox key={k.id} checked={eku.includes(k.id)} onChange={() => setEku(eku.includes(k.id) ? eku.filter((x) => x !== k.id) : [...eku, k.id])} label={k.label} />
                ))}
              </div>
            )}
          </div>
        )}
        <div className="flex gap-2">
          <Button onClick={inspect} disabled={!path && !text.trim()}>
            Inspect CSR
          </Button>
          <Button variant="primary" className="flex-1" onClick={sign} disabled={busy || !ca || (!path && !text.trim())} data-testid="sign-csr-submit">
            {busy && <Spinner />} Sign with {ca?.entry.alias ?? "CA"}
          </Button>
        </div>
      </div>
      <ResultPane empty="Paste or choose a PKCS#10 request and sign it with a CA from one of your open keystores.">
        {result && (
          <div className="space-y-4">
            {match && (
              <Alert tone="info" title={`This certificate belongs to '${match.entry.alias}' in ${match.ks.name}`} action={<Button size="sm" variant="primary" onClick={install} data-testid="install-issued">Install</Button>}>
                Install it as the CA reply to replace the self-signed certificate.
              </Alert>
            )}
            <CertificateDetails cert={result.certificate} />
            <CodeBlock
              label="Certificate chain (PEM)"
              value={result.chain_pem}
              testId="issued-chain"
              actions={
                <>
                  <Button size="sm" icon={Save} onClick={() => saveText(`${safeFileStem(cnOf(result.certificate.subject))}.pem`, result.certificate.pem, "Certificate")}>
                    Certificate
                  </Button>
                  <Button size="sm" icon={Save} onClick={() => saveText(`${safeFileStem(cnOf(result.certificate.subject))}-chain.pem`, result.chain_pem, "Certificate chain")}>
                    Chain
                  </Button>
                  {activeKeystore && !activeKeystore.sealed && (
                    <Button
                      size="sm"
                      icon={Plus}
                      onClick={async () => {
                        try {
                          const added = await api.importTrustedCertificates(cnOf(result.certificate.subject).toLowerCase().replace(/\s+/g, "-"), { text: result.certificate.pem }, activeKeystore.entries.map((e) => e.alias));
                          addEntries(activeKeystore.id, added);
                          toast.success(`Added to ${activeKeystore.name} as a trusted certificate.`);
                        } catch (err) {
                          toast.error(errorMessage(err));
                        }
                      }}
                    >
                      Add to {activeKeystore.name}
                    </Button>
                  )}
                </>
              }
            />
          </div>
        )}
      </ResultPane>
    </div>
  );
};

// ====================================================================================== CRL

const CRL_REASONS = ["unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aACompromise"];

const CrlTool: React.FC = () => {
  const { keystores, desktop } = useStore();
  const toast = useToast();
  const saveText = useSaveText();
  const cas = useSigners(isCaEntry);
  const [ca, caId, setCaId] = useSelected(cas);
  const [days, setDays] = useState(30);
  const [crlNumber, setCrlNumber] = useState(1);
  const [revoked, setRevoked] = useState<RevokedCertEntry[]>([]);
  const [serial, setSerial] = useState("");
  const [reason, setReason] = useState("keyCompromise");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<CrlInfo | null>(null);
  const [ledger, setLedger] = useState<{ serial: string; subject: string; ski: string; not_after: string; profile: string; issuer_ski: string }[]>([]);

  const caSki = ca?.entry.certificate_chain[0]?.subject_key_id ?? "";

  useEffect(() => {
    setRevoked([]);
    setResult(null);
    if (!desktop || !caSki) {
      setCrlNumber(1);
      setLedger([]);
      return;
    }
    api.caNextCrlNumber(caSki).then((n) => setCrlNumber(n)).catch(() => setCrlNumber(1));
    api.ledgerSearch("").then((all) => setLedger(all.filter((r) => !r.issuer_ski || r.issuer_ski.toUpperCase() === caSki.toUpperCase()))).catch(() => setLedger([]));
  }, [ca?.entry.id, caSki, desktop]);

  const issued = useMemo(() => {
    if (!ca) return [];
    const fromOpen = keystores.flatMap((ks) => ks.entries.filter((e) => e.issuer === ca.entry.subject && e.id !== ca.entry.id && e.serial_number));
    const seen = new Set(fromOpen.map((e) => e.serial_number.toUpperCase()));
    const fromLedger = ledger
      .filter((r) => r.serial && !seen.has(r.serial.toUpperCase()))
      .map((r) => ({ id: `ledger:${r.serial}`, alias: r.profile, subject: r.subject, serial_number: r.serial, fromLedger: true as const }));
    return [
      ...fromOpen.map((e) => ({ id: e.id, alias: e.alias, subject: e.subject, serial_number: e.serial_number, fromLedger: false as const })),
      ...fromLedger,
    ];
  }, [keystores, ca, ledger]);
  const add = (s: string, r = reason) => {
    const clean = s.trim().replace(/[:\s]/g, "").toUpperCase();
    if (!clean) return;
    if (!/^(0X)?[0-9A-F]+$/.test(clean)) return toast.error(`'${s}' is not a hexadecimal serial number.`);
    if (revoked.some((x) => x.serial_number === clean)) return;
    setRevoked([...revoked, { serial_number: clean, revocation_date: new Date().toISOString(), reason: r }]);
    setSerial("");
  };
  const generate = async () => {
    if (!ca) return;
    setBusy(true);
    try {
      const res = await api.generateCrl(ca.entry, Number(days), Number(crlNumber), revoked);
      setResult(res);
      setCrlNumber(Number(crlNumber) + 1);
      toast.success(`Issued CRL #${res.crl_number} with ${res.revoked_entries.length} revoked certificate(s).`);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-5 space-y-4">
        <SignerSelect label="Issuing CA" candidates={cas} value={caId} onChange={setCaId} emptyHint="Open a keystore that contains a CA key pair." testId="crl-ca" />
        <div className="grid grid-cols-2 gap-3">
          <TextInput label="CRL number" type="number" min={1} value={crlNumber} onChange={(e) => setCrlNumber(Number(e.target.value))} hint="Must increase with every CRL." />
          <TextInput label="Next update (days)" type="number" min={1} value={days} onChange={(e) => setDays(Number(e.target.value))} />
        </div>
        <div>
          <span className="label">Revoked certificates</span>
          <div className="flex gap-2">
            <TextInput placeholder="Serial number (hex)" value={serial} onChange={(e) => setSerial(e.target.value)} className="font-mono" data-testid="crl-serial" />
            <Select value={reason} onChange={(e) => setReason(e.target.value)} className="!w-44">
              {CRL_REASONS.map((r) => (
                <option key={r}>{r}</option>
              ))}
            </Select>
            <Button icon={Plus} onClick={() => add(serial)} aria-label="Add serial" data-testid="crl-add" />
            <Button
              onClick={async () => {
                const path = await pickFile("Open a CRL", [FILTERS.certificates]).catch(() => null);
                if (!path) return;
                try {
                  const crl = await api.readCrl({ path });
                  setRevoked(crl.revoked_entries);
                  setCrlNumber(Number(crl.crl_number ?? 0) + 1);
                  toast.success(`Loaded ${crl.revoked_entries.length} revocation(s). The next CRL number is ${Number(crl.crl_number ?? 0) + 1}.`);
                } catch (err) {
                  toast.error(errorMessage(err));
                }
              }}
            >
              Open CRL…
            </Button>
          </div>
          {issued.length > 0 && (
            <Select className="mt-2" value="" onChange={(e) => e.target.value && add(e.target.value)} aria-label="Add a certificate issued by this CA">
              <option value="">Add a certificate issued by this CA…</option>
              {issued.map((e) => (
                <option key={e.id} value={e.serial_number}>
                  {e.alias} — {cnOf(e.subject)} ({e.serial_number.slice(0, 12)}…)
                </option>
              ))}
            </Select>
          )}
          {ledger.length > 0 && (
            <div className="mt-2 rounded-control border border-line bg-surface-2 p-2.5 space-y-1.5">
              <div className="text-[11.5px] font-medium text-faint">Issuance ledger ({ledger.length})</div>
              <ul className="space-y-1 max-h-32 overflow-y-auto">
                {ledger.map((r) => (
                  <li key={r.serial} className="flex items-center justify-between gap-2 text-[12px]">
                    <button type="button" className="text-left min-w-0 flex-1 hover:text-brand cursor-pointer" onClick={() => add(r.serial)} title="Click to add to revoked list">
                      <span className="font-mono text-ink">{r.serial.slice(0, 12)}…</span> · <span className="text-muted">{cnOf(r.subject)}</span>
                    </button>
                    <button
                      type="button"
                      aria-label={`Delete ledger entry ${r.serial}`}
                      className="text-faint hover:text-danger p-0.5 cursor-pointer"
                      onClick={async () => {
                        await api.ledgerDelete(r.serial).catch(() => undefined);
                        setLedger((l) => l.filter((x) => x.serial !== r.serial));
                      }}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <ul className="mt-2 space-y-1.5 max-h-48 overflow-y-auto">
            {revoked.map((r) => (
              <li key={r.serial_number} className="flex items-center justify-between gap-2 px-3 py-2 rounded-control border border-line bg-surface text-[12.5px]">
                <span className="min-w-0">
                  <span className="block font-mono text-ink truncate">{r.serial_number}</span>
                  <span className="text-faint">
                    {r.reason} · {r.revocation_date}
                  </span>
                </span>
                <button aria-label={`Remove ${r.serial_number}`} className="text-faint hover:text-danger p-1 cursor-pointer" onClick={() => setRevoked(revoked.filter((x) => x !== r))}>
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </li>
            ))}
            {revoked.length === 0 && <li className="text-[12.5px] text-subtle">No revoked certificates — the CRL will be empty, which is valid.</li>}
          </ul>
        </div>
        <Button variant="primary" className="w-full" onClick={generate} disabled={busy || !ca} data-testid="crl-generate">
          {busy && <Spinner />} Sign CRL with {ca?.entry.alias ?? "CA"}
        </Button>
        <TerminalHint command="openssl crl -in crl.pem -CAfile ca.pem -noout -text" label="Verify" />
      </div>
      <ResultPane empty="Add revoked serial numbers and sign a CRL with one of your CAs.">
        {result && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-[13px]">
              <Badge tone={result.signature_valid ? "success" : "danger"} icon={result.signature_valid ? CheckCircle2 : XCircle}>
                {result.signature_valid ? "Signature verified" : "Signature check failed"}
              </Badge>
              <span className="text-muted">
                CRL #{result.crl_number} · {result.signature_algorithm}
              </span>
            </div>
            <table className="w-full text-[12.5px] border border-line rounded-card overflow-hidden border-separate border-spacing-0">
              <tbody>
                {[
                  ["Issuer", result.issuer],
                  ["This update", result.this_update],
                  ["Next update", result.next_update],
                  ["Revoked", String(result.revoked_entries.length)],
                  ["SHA-256", result.sha256_fingerprint],
                ].map(([k, v]) => (
                  <tr key={k}>
                    <th className="w-[28%] text-left font-medium text-faint bg-surface-2 border-b border-line px-3 py-2">{k}</th>
                    <td className="border-b border-line px-3 py-2 font-mono text-[11.5px] break-all">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <CodeBlock label="CRL (PEM)" value={result.pem} actions={<Button size="sm" icon={Save} onClick={() => saveText(`${safeFileStem(cnOf(result.issuer))}-${result.crl_number}.crl`, result.pem, "CRL")}>Save</Button>} testId="crl-output" />
          </div>
        )}
      </ResultPane>
    </div>
  );
};

// ====================================================================================== CMS

const CmsTool: React.FC = () => {
  const { settings } = useStore();
  const toast = useToast();
  const saveText = useSaveText();
  const signers = useSigners(usableKeyPair);
  const [signer, signerId, setSignerId] = useSelected(signers);
  const [mode, setMode] = useState<"sign" | "verify">("sign");
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [detached, setDetached] = useState(true);
  const [busy, setBusy] = useState(false);
  const [signed, setSigned] = useState<CmsSignResult | null>(null);
  const [sigPath, setSigPath] = useState<string | null>(null);
  const [sigText, setSigText] = useState("");
  const [useEntry, setUseEntry] = useState(false);
  const [verified, setVerified] = useState<CmsVerifyResult | null>(null);
  const timestamping = useTimestamping();

  const sign = async () => {
    if (!signer) return;
    setBusy(true);
    try {
      setSigned(await api.cmsSign(path ? { path } : { text }, signer.entry, detached, timestamping.tsaUrl, settings.tsaTrustPem));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const verify = async () => {
    setBusy(true);
    try {
      const content = path ? { path } : text ? { text } : null;
      setVerified(await api.cmsVerify(sigPath ? { path: sigPath } : { text: sigText }, content, useEntry ? signers.find((c) => c.entry.id === signerId)?.entry ?? null : null, settings.tsaTrustPem));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-5 space-y-4">
        <Segmented label="CMS mode" value={mode} onChange={setMode} options={[{ value: "sign", label: "Sign" }, { value: "verify", label: "Verify" }]} />
        {mode === "sign" ? (
          <>
            <SignerSelect label="Signer" candidates={signers} value={signerId} onChange={setSignerId} emptyHint="Open a keystore with an RSA, ECDSA or Ed25519 key pair." testId="cms-signer" />
            <FileOrPaste label="Content to sign" path={path} setPath={setPath} text={text} setText={setText} placeholder="Text to sign, or choose any file" filters={[FILTERS.any]} testId="cms-content" />
            <Checkbox checked={detached} onChange={setDetached} label="Detached signature" hint="The signature file does not contain the content (like openssl cms -sign without -nodetach)." />
            {timestamping.control}
            <Button variant="primary" className="w-full" onClick={sign} disabled={busy || !signer || (!path && !text)} data-testid="cms-sign">
              {busy && <Spinner />} Sign
            </Button>
          </>
        ) : (
          <>
            <FileOrPaste label="Signature (PKCS#7 / CMS)" path={sigPath} setPath={setSigPath} text={sigText} setText={setSigText} placeholder="-----BEGIN PKCS7-----" filters={[FILTERS.cms]} rows={5} testId="cms-signature" />
            <FileOrPaste label="Signed content (for detached signatures)" path={path} setPath={setPath} text={text} setText={setText} placeholder="Original content" filters={[FILTERS.any]} rows={4} />
            <Checkbox checked={useEntry} onChange={setUseEntry} label="Use a keystore entry's certificate" hint="For signatures that do not embed the signer certificate." />
            {useEntry && <SignerSelect label="Signer certificate" candidates={signers} value={signerId} onChange={setSignerId} emptyHint="No key pairs open." publicOnly />}
            <Button variant="primary" className="w-full" onClick={verify} disabled={busy || (!sigPath && !sigText.trim())} data-testid="cms-verify">
              {busy && <Spinner />} Verify
            </Button>
          </>
        )}
        <TerminalHint command="openssl cms -verify -in signature.p7s -inform PEM -content data.txt -binary -noverify" label="Verify with OpenSSL" />
      </div>
      <ResultPane empty={mode === "sign" ? "Sign text or any file with a key pair from your keystores." : "Verify a CMS / PKCS#7 signature and see who signed it."}>
        {mode === "sign" && signed && (
          <div className="space-y-3">
            <div className="text-[13px]">
              <Badge tone="success" icon={CheckCircle2}>
                Signed
              </Badge>{" "}
              <span className="text-muted">
                {signed.algorithm} by {signed.signer_alias} · {signed.detached ? "detached" : "attached"} · {signed.byte_length} bytes
              </span>
            </div>
            <div className="text-[12px] text-faint font-mono break-all">Content SHA-256: {signed.content_sha256}</div>
            <TimestampBadge ts={signed.timestamp} />
            <CodeBlock label="Signature (PEM)" value={signed.cms_pem} testId="cms-output" actions={<Button size="sm" icon={Save} onClick={() => saveText(path ? `${baseName(path)}.p7s` : "signature.p7s", signed.cms_pem, "Signature")}>Save .p7s</Button>} />
          </div>
        )}
        {mode === "verify" && verified && (
          <div className="space-y-3" data-testid="cms-verify-result">
            <Alert tone={verified.valid ? "success" : verified.content_available ? "danger" : "warning"} title={verified.valid ? "Valid signature" : verified.content_available ? "Invalid signature" : "Content needed"}>
              {verified.message}
            </Alert>
            {verified.signers.map((s, i) => (
              <div key={i} className="rounded-control border border-line bg-surface p-3 text-[12.5px] space-y-1">
                <div className="font-semibold text-ink">{s.subject || "Unknown signer"}</div>
                <div className="text-faint">
                  {s.signature_algorithm} / {s.digest_algorithm}
                  {s.signing_time ? ` · signed ${s.signing_time}` : ""}
                </div>
                <div className="flex gap-2">
                  <Badge tone={s.signature_valid ? "success" : "danger"}>{s.signature_valid ? "Signature OK" : "Signature bad"}</Badge>
                  {s.content_digest_valid != null && <Badge tone={s.content_digest_valid ? "success" : "danger"}>{s.content_digest_valid ? "Content intact" : "Content modified"}</Badge>}
                </div>
                <TimestampBadge ts={s.timestamp} />
                {s.error && <div className="text-danger">{s.error}</div>}
              </div>
            ))}
            {verified.content_text && !verified.detached && <CodeBlock label="Embedded content" value={verified.content_text} maxHeight={160} wrap />}
          </div>
        )}
      </ResultPane>
    </div>
  );
};

// ====================================================================================== JWT

const JwtTool: React.FC = () => {
  const toast = useToast();
  const signers = useSigners((e) => usableKeyPair(e) || (e.entry_type === "SecretKey" && !e.locked && (e.algorithm.startsWith("Hmac") || e.algorithm === "AES")));
  const [signer, signerId, setSignerId] = useSelected(signers);
  const [algs, setAlgs] = useState<string[]>([]);
  const [alg, setAlg] = useState("");
  const [iss, setIss] = useState("");
  const [sub, setSub] = useState("");
  const [aud, setAud] = useState("");
  const [minutes, setMinutes] = useState(60);
  const [claims, setClaims] = useState('{\n  "scope": "read"\n}');
  const [token, setToken] = useState("");
  const [verifyResult, setVerifyResult] = useState<JwtVerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!signer) return setAlgs([]);
    api
      .jwtAlgorithms(signer.entry)
      .then((a) => {
        setAlgs(a);
        setAlg(a[0] ?? "");
      })
      .catch(() => setAlgs([]));
  }, [signer?.entry.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const sign = async () => {
    if (!signer) return;
    setBusy(true);
    try {
      const t = await api.jwtSign({ issuer: iss, subject: sub, audience: aud, validity_minutes: Number(minutes), custom_claims_json: claims, algorithm: alg }, signer.entry);
      setToken(t);
      setVerifyResult(await api.jwtVerify(t, signer.entry));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const verify = async () => {
    if (!signer || !token.trim()) return;
    try {
      setVerifyResult(await api.jwtVerify(token.trim(), signer.entry));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-5 space-y-4">
        <SignerSelect label="Key" candidates={signers} value={signerId} onChange={setSignerId} emptyHint="Open a keystore with a key pair (RS/ES/EdDSA) or an HMAC secret key (HS)." testId="jwt-signer" />
        {algs.length > 0 && (
          <Select label="Algorithm" value={alg} onChange={(e) => setAlg(e.target.value)}>
            {algs.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </Select>
        )}
        <div className="grid grid-cols-2 gap-3">
          <TextInput label="Issuer (iss)" value={iss} onChange={(e) => setIss(e.target.value)} placeholder="https://auth.example.com" />
          <TextInput label="Subject (sub)" value={sub} onChange={(e) => setSub(e.target.value)} placeholder="user-123" />
          <TextInput label="Audience (aud)" value={aud} onChange={(e) => setAud(e.target.value)} placeholder="api" />
          <TextInput label="Valid for (minutes)" type="number" min={1} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} />
        </div>
        <TextArea label="Additional claims (JSON object)" mono rows={4} value={claims} onChange={(e) => setClaims(e.target.value)} />
        <Button variant="primary" className="w-full" onClick={sign} disabled={busy || !signer || !alg} data-testid="jwt-sign">
          {busy && <Spinner />} Sign token
        </Button>
      </div>
      <ResultPane empty="Sign a JWT with a keystore key, or paste a token to verify it against the selected key.">
        <div className="space-y-3">
          <TextArea label="Token" mono rows={5} value={token} onChange={(e) => setToken(e.target.value)} placeholder="eyJhbGciOi…" className="break-all" data-testid="jwt-token" />
          <Button onClick={verify} disabled={!token.trim() || !signer} data-testid="jwt-verify">
            Verify with {signer?.entry.alias ?? "key"}
          </Button>
          {verifyResult && (
            <>
              <Alert tone={verifyResult.valid ? "success" : "danger"}>{verifyResult.message}</Alert>
              <div className="grid grid-cols-2 gap-3">
                <CodeBlock label="Header" value={verifyResult.info.header_json} maxHeight={160} />
                <CodeBlock label="Payload" value={verifyResult.info.payload_json} maxHeight={160} />
              </div>
            </>
          )}
        </div>
      </ResultPane>
    </div>
  );
};

// ====================================================================================== JAR

const JarTool: React.FC = () => {
  const { jarRequest, settings } = useStore();
  const toast = useToast();
  const savedToast = useSavedToast();
  const signers = useSigners(usableKeyPair);
  const [signer, signerId, setSignerId] = useSelected(signers);
  const [input, setInput] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<JarSignResult | null>(null);
  const timestamping = useTimestamping();
  useEffect(() => {
    if (jarRequest) setInput(jarRequest.path);
  }, [jarRequest]);
  const sign = async () => {
    if (!signer || !input) return;
    try {
      const out = await pickSavePath("Save signed JAR as", baseName(input).replace(/(\.\w+)$/, "-signed$1"), [FILTERS.jar]);
      if (!out) return;
      setBusy(true);
      const res = await api.jarSign(input, out, signer.entry, timestamping.tsaUrl, settings.tsaTrustPem);
      setResult(res);
      savedToast(`Signed ${res.entries_signed} entries; written to ${res.output_path}.`, res.output_path);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-5 space-y-4">
        <SignerSelect label="Signer" candidates={signers} value={signerId} onChange={setSignerId} emptyHint="Open a keystore with a code-signing key pair." testId="jar-signer" />
        <div>
          <span className="label">Archive</span>
          <div className="flex items-center gap-2">
            <Button
              icon={FolderOpen}
              onClick={async () => {
                const p = await pickFile("Select a JAR/WAR/ZIP", [FILTERS.jar]).catch(() => null);
                if (p) setInput(p);
              }}
            >
              Choose archive…
            </Button>
            {input && <span className="font-mono text-[12px] text-muted truncate">{input}</span>}
          </div>
        </div>
        <Alert tone="info">The original archive is never modified; you choose where to write the signed copy. Existing signatures are replaced.</Alert>
        {timestamping.control}
        <Button variant="primary" className="w-full" onClick={sign} disabled={busy || !signer || !input} data-testid="jar-sign">
          {busy && <Spinner />} Sign archive…
        </Button>
        <TerminalHint command={`jarsigner -verify -verbose -certs "${result?.output_path ?? "app-signed.jar"}"`} label="Verify" />
      </div>
      <ResultPane empty="Choose a JAR and a signing key. xkeystore writes MANIFEST.MF digests, the .SF file and a CMS signature block compatible with jarsigner.">
        {result && (
          <div className="space-y-3">
            <Alert tone="success" title="Archive signed">
              {result.entries_signed} entries · {result.signature_algorithm} · {result.signature_file_name}
            </Alert>
            <TimestampBadge ts={result.timestamp} />
            <CodeBlock label="META-INF/MANIFEST.MF" value={result.manifest_preview} maxHeight={260} />
          </div>
        )}
      </ResultPane>
    </div>
  );
};

// ======================================================================================= DH

const DhTool: React.FC = () => {
  const toast = useToast();
  const saveText = useSaveText();
  const [mode, setMode] = useState<"ffdhe" | "generate">("ffdhe");
  const [bits, setBits] = useState(2048);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DhParamsResult | null>(null);
  const sizes = mode === "ffdhe" ? [2048, 3072, 4096, 6144, 8192] : [1024, 1536, 2048];
  useEffect(() => {
    if (!sizes.includes(bits)) setBits(2048);
  }, [mode]); // eslint-disable-line react-hooks/exhaustive-deps
  const run = async () => {
    setBusy(true);
    try {
      setResult(await api.dhParams(bits, mode));
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-5 space-y-4">
        <Segmented label="DH source" value={mode} onChange={setMode} options={[{ value: "ffdhe", label: "RFC 7919 group" }, { value: "generate", label: "Generate new prime" }]} />
        <div>
          <span className="label">Prime size</span>
          <div className="grid grid-cols-5 gap-2">
            {sizes.map((b) => (
              <button key={b} onClick={() => setBits(b)} className={`h-9 rounded-control border text-[13px] font-semibold cursor-pointer ${bits === b ? "bg-brand-tint border-brand text-brand-deep" : "bg-surface border-line-strong text-ink-2"}`}>
                {b}
              </button>
            ))}
          </div>
        </div>
        {mode === "ffdhe" ? (
          <Alert tone="info">Standard groups (ffdhe2048 …) are the recommended choice for TLS: well-audited and instant.</Alert>
        ) : (
          <Alert tone="warning">Finding a {bits}-bit safe prime can take from seconds up to a few minutes.</Alert>
        )}
        <Button variant="primary" className="w-full" onClick={run} disabled={busy} data-testid="dh-generate">
          {busy && <Spinner />} {busy ? "Working…" : mode === "ffdhe" ? "Get parameters" : "Generate parameters"}
        </Button>
        <TerminalHint command="openssl dhparam -in dhparams.pem -check -noout" label="Check" />
      </div>
      <ResultPane empty="Produce PKCS#3 Diffie-Hellman parameters for servers that need a dhparam file.">
        {result && (
          <div className="space-y-3">
            <div className="text-[13px] text-muted">
              <Badge tone="success">{result.group}</Badge> {result.bit_size}-bit prime, generator {result.generator}
            </div>
            <CodeBlock label="DH parameters (PEM)" value={result.pem} actions={<Button size="sm" icon={Save} onClick={() => saveText(`dhparams-${result.bit_size}.pem`, result.pem, "DH parameters")}>Save</Button>} testId="dh-output" />
          </div>
        )}
      </ResultPane>
    </div>
  );
};

// ==================================================================================== page

export const CaSigningView: React.FC = () => {
  const { jarRequest, keystores, openFiles } = useStore();
  const [tool, setTool] = useState<Tool>("csr");
  useEffect(() => {
    if (jarRequest) setTool("jar");
  }, [jarRequest]);
  const loaded = keystores.some((k) => !k.sealed && k.entries.length);
  return (
    <Page>
      <PageHeader title="CA & Signing" description="Issue certificates and CRLs, and sign files, archives and tokens with keys from your open keystores." />
      <div className="mb-4 overflow-x-auto">
        <Segmented
          label="Signing tool"
          value={tool}
          onChange={setTool}
          options={[
            { value: "csr", label: <><FileSignature className="w-3.5 h-3.5" /> Sign CSR</> },
            { value: "crl", label: <><ShieldCheck className="w-3.5 h-3.5" /> Issue CRL</> },
            { value: "cms", label: <><FileCheck2 className="w-3.5 h-3.5" /> CMS / PKCS#7</> },
            { value: "jwt", label: <><KeyRound className="w-3.5 h-3.5" /> JWT</> },
            { value: "jar", label: <><FileArchive className="w-3.5 h-3.5" /> Sign JAR</> },
            { value: "dh", label: <><Cpu className="w-3.5 h-3.5" /> DH parameters</> },
          ]}
        />
      </div>
      {!loaded && tool !== "dh" && (
        <Alert tone="info" className="mb-4" action={<Button size="sm" onClick={() => openFiles()}>Open keystore…</Button>}>
          These tools use keys from your open keystores. Open or create one first.
        </Alert>
      )}
      <Card className="p-6">
        {tool === "csr" && <SignCsrTool />}
        {tool === "crl" && <CrlTool />}
        {tool === "cms" && <CmsTool />}
        {tool === "jwt" && <JwtTool />}
        {tool === "jar" && <JarTool />}
        {tool === "dh" && <DhTool />}
      </Card>
    </Page>
  );
};

export type { CertificateInfo };
