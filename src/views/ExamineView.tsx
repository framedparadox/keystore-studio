import React, { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { CheckCircle2, Clipboard, FileBadge, FileSearch, FolderOpen, GitCompare, Globe, Network, Plus, Save, Sparkles, XCircle } from "lucide-react";
import type { CertificateInfo, ConnectionTest, DetectionResult, KeystoreEntry, TlsInspectionResult } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { FILTERS, baseName, pickFile, safeFileStem } from "../lib/files";
import { cnOf } from "../lib/keystore";
import { connectTarget, parseTlsTarget } from "../lib/net";
import { useStore } from "../state/store";
import { Alert, Badge, Button, Card, CodeBlock, EmptyState, Page, PageHeader, PasswordInput, Segmented, Select, Spinner, TextArea, TextInput, useToast } from "../components/ui";
import { CertificateDetails, ChainView, TrustBanner, WarningList } from "../components/CertificateView";
import { TerminalHint } from "../components/Terminal";
import { useSaveText } from "../components/EntryDialogs";
import { useAddCertificateToKeystore, useKeepCertificates } from "../components/CertificateDialogs";

type Mode = "tls" | "connection" | "decode" | "compare";
/** A host and port handed to the TLS panel to inspect at once (from a connection test). */
type TlsSeed = { host: string; port: number };

/*
 * The last examine request (a dropped or opened file) each part acted on. A request is handled
 * once: module scope, because the page remounts whenever it is shown again, and acting on the
 * same request again switched back to Decode and re-read the old file on every visit.
 */
let modeHandledNonce = 0;
let decodeHandledNonce = 0;

/** "Add to keystore" for certificates found while examining: the active keystore, when it can be edited. */
function useImportCert() {
  const { activeKeystore } = useStore();
  const { add } = useAddCertificateToKeystore();
  const target = activeKeystore && !activeKeystore.sealed ? activeKeystore : null;
  return { target, importCert: (cert: CertificateInfo) => (target ? add(cert, target.id) : Promise.resolve()) };
}

// ====================================================================================== TLS

const TlsPanel: React.FC<{ seed?: TlsSeed | null; onSeedUsed?: () => void }> = ({ seed, onSeedUsed }) => {
  const saveText = useSaveText();
  const keep = useKeepCertificates();
  const { target, importCert } = useImportCert();
  const [host, setHost] = useState(seed?.host ?? "");
  const [port, setPort] = useState(seed?.port ?? 443);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<TlsInspectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  // What the engine will connect to: a URL or host:port typed into Host wins over the Port field.
  const endpoint = host.trim() ? parseTlsTarget(host, Number(port) || 443) : null;
  const shown = endpoint ?? { host: "example.com", port: Number(port) || 443 };
  // -servername takes a DNS name: an IP address is sent without SNI.
  const sni = /^[\d.]+$/.test(shown.host) || shown.host.includes(":") ? "" : ` -servername ${shown.host}`;
  const sClientCommand = `openssl s_client -connect ${connectTarget(shown)}${sni} -showcerts </dev/null`;
  const portFromHost = !!endpoint && endpoint.port !== (Number(port) || 443);
  const inspect = async (h: string, p: number) => {
    if (!h) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.examineTls(h, p));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const run = (e?: React.FormEvent) => {
    e?.preventDefault();
    void inspect(host.trim(), Number(port));
  };
  // Handed over from a connection test: inspect it straight away, once.
  useEffect(() => {
    if (!seed) return;
    onSeedUsed?.();
    void inspect(seed.host, seed.port);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="flex flex-wrap items-end gap-3">
        <TextInput label="Host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="example.com or https://example.com:8443" className="min-w-[320px]" autoFocus data-testid="tls-host" />
        <TextInput label="Port" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))} className="!w-24" data-testid="tls-port" />
        <Button variant="primary" type="submit" disabled={busy || !host.trim()} data-testid="tls-run">
          {busy && <Spinner />} {busy ? "Connecting…" : "Inspect"}
        </Button>
      </form>
      {host.trim() && !endpoint && <p className="text-[12px] text-danger -mt-3">Enter a host name, an IP address, or a URL such as https://example.com:8443.</p>}
      {portFromHost && endpoint && <p className="text-[12px] text-faint -mt-3">Connecting to port {endpoint.port}, taken from the address.</p>}
      <TerminalHint command={sClientCommand} label="Run with OpenSSL" />
      {error && <Alert tone="danger" title="Connection failed">{error}</Alert>}
      {result && (
        <div className="space-y-4" data-testid="tls-result">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[13px]">
            {[
              ["Endpoint", `${result.host}:${result.port}`],
              ["Address", result.address],
              ["Protocol", result.protocol],
              ["Cipher suite", result.cipher_suite],
              ["ALPN", result.alpn ?? "—"],
              ["Handshake", `${result.handshake_ms} ms`],
              ["Chain length", String(result.certificates.length)],
              ["Inspected", result.inspected_at],
            ].map(([k, v]) => (
              <div key={k} className="rounded-control border border-line bg-surface-2 px-3 py-2">
                <div className="text-[11.5px] text-faint">{k}</div>
                <div className="font-medium text-ink break-words">{v}</div>
              </div>
            ))}
          </div>
          <TrustBanner trusted={result.trusted} error={result.verification_error} />
          <ChainView
            certs={result.certificates}
            actions={(c, i) => (
              <>
                <Button size="sm" icon={Save} onClick={() => saveText(`${safeFileStem(cnOf(c.subject))}.pem`, c.pem, "Certificate")}>
                  Save
                </Button>
                <Button size="sm" icon={FileBadge} onClick={() => void keep([c], `${result.host}:${result.port}`)} data-testid={`tls-keep-${i}`}>
                  Add to Certificates
                </Button>
                {target && (
                  <Button size="sm" icon={Plus} onClick={() => importCert(c)}>
                    Add to {target.name}
                  </Button>
                )}
              </>
            )}
          />
          {result.certificates.length > 1 && (
            <Button icon={Save} onClick={() => saveText(`${safeFileStem(result.host)}-chain.pem`, result.certificates.map((c) => c.pem).join(""), "Certificate chain")}>
              Save full chain
            </Button>
          )}
        </div>
      )}
    </div>
  );
};

// ============================================================================== connection

const ms = (n: number | null | undefined) => (n == null ? "—" : n < 1 ? "<1 ms" : `${n} ms`);

/** Whether this machine can reach host:port over TCP: what `Test-NetConnection -Port` answers. */
const ConnectionPanel: React.FC<{ onInspectTls: (seed: TlsSeed) => void }> = ({ onInspectTls }) => {
  const [host, setHost] = useState("");
  const [port, setPort] = useState(443);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ConnectionTest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const endpoint = host.trim() ? parseTlsTarget(host, Number(port) || 443) : null;
  const shown = endpoint ?? { host: "example.com", port: Number(port) || 443 };
  const portFromHost = !!endpoint && endpoint.port !== (Number(port) || 443);
  const run = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!host.trim()) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.testConnection(host.trim(), Number(port)));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const r = result;
  const where = r ? connectTarget({ host: r.computer_name, port: r.remote_port }) : "";
  return (
    <div className="space-y-5">
      <form onSubmit={run} className="flex flex-wrap items-end gap-3">
        <TextInput label="Host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="example.com, 10.0.0.5 or https://example.com:8443" className="min-w-[320px]" autoFocus data-testid="conn-host" />
        <TextInput label="Port" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))} className="!w-24" data-testid="conn-port" />
        <Button variant="primary" type="submit" disabled={busy || !host.trim()} data-testid="conn-run">
          {busy && <Spinner />} {busy ? "Testing…" : "Test connection"}
        </Button>
      </form>
      {host.trim() && !endpoint && <p className="text-[12px] text-danger -mt-3">Enter a host name, an IP address, or a URL such as https://example.com:8443.</p>}
      {portFromHost && endpoint && <p className="text-[12px] text-faint -mt-3">Testing port {endpoint.port}, taken from the address.</p>}
      <TerminalHint command={`Test-NetConnection -ComputerName ${shown.host} -Port ${shown.port} -InformationLevel Detailed`} />
      {error && <Alert tone="danger" title="Could not test the connection">{error}</Alert>}
      {r && (
        <div className="space-y-4" data-testid="conn-result" data-succeeded={String(r.tcp_test_succeeded)} data-failure={r.failure ?? ""}>
          {r.tcp_test_succeeded ? (
            <Alert
              tone="success"
              title={`${where} is reachable`}
              action={
                <Button size="sm" icon={Globe} onClick={() => onInspectTls({ host: r.computer_name, port: r.remote_port })} data-testid="conn-inspect-tls">
                  Inspect TLS on this port
                </Button>
              }
            >
              A TCP connection to {r.remote_address} succeeded in {ms(r.tcp_ms)}{r.source_address ? `, from ${r.source_address}${r.interface_alias ? ` on ${r.interface_alias}` : ""}` : ""}.
            </Alert>
          ) : (
            <Alert tone="danger" title={r.failure === "name-resolution" ? `Cannot resolve ${r.computer_name}` : `Cannot reach ${where}`}>
              {r.hint}
            </Alert>
          )}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[13px]">
            {[
              ["Computer name", r.computer_name],
              ["Remote address", r.remote_address ?? "—"],
              ["Remote port", String(r.remote_port)],
              ["TCP test", r.tcp_test_succeeded ? `Succeeded in ${ms(r.tcp_ms)}` : "Failed"],
              ["Source address", r.source_address ?? "—"],
              ["Interface", r.interface_alias ?? "—"],
              ["Name resolved in", ms(r.resolve_ms)],
              ["Tested", r.tested_at],
            ].map(([k, v]) => (
              <div key={k} className="rounded-control border border-line bg-surface-2 px-3 py-2">
                <div className="text-[11.5px] text-faint">{k}</div>
                <div className="font-medium text-ink break-words">{v}</div>
              </div>
            ))}
          </div>
          <div>
            <div className="text-[12px] font-semibold text-faint mb-2">Name resolution{r.name_resolution.length ? ` · ${r.name_resolution.length} address${r.name_resolution.length === 1 ? "" : "es"}` : ""}</div>
            {r.name_resolution.length === 0 ? (
              <p className="text-[13px] text-faint">The name did not resolve to any address.</p>
            ) : (
              <ul className="rounded-control border border-line divide-y divide-line text-[13px]" data-testid="conn-addresses">
                {r.name_resolution.map((a) => {
                  const attempt = r.attempts.find((t) => t.address === a);
                  return (
                    <li key={a} className="px-3 py-2 flex items-center gap-2.5">
                      {attempt ? (
                        attempt.succeeded ? (
                          <CheckCircle2 className="w-4 h-4 text-success shrink-0" aria-label="Connected" />
                        ) : (
                          <XCircle className="w-4 h-4 text-danger shrink-0" aria-label="Failed" />
                        )
                      ) : (
                        <span className="w-4 h-4 shrink-0" aria-hidden />
                      )}
                      <span className="font-mono text-ink">{a}</span>
                      <span className="flex-1 min-w-0 truncate text-faint text-right" title={attempt?.error ?? undefined}>
                        {attempt ? (attempt.succeeded ? `connected in ${ms(attempt.elapsed_ms)}` : `${attempt.error} · ${ms(attempt.elapsed_ms)}`) : "not tried"}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// =================================================================================== decode

const DecodePanel: React.FC = () => {
  const { examineRequest, openFiles, setTab } = useStore();
  const toast = useToast();
  const keep = useKeepCertificates();
  const { target, importCert } = useImportCert();
  const [text, setText] = useState("");
  const [path, setPath] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (src?: { path?: string; text?: string }) => {
    const source = src ?? (path ? { path } : { text });
    if (!source.path && !source.text?.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.examineData(source, password || null));
    } catch (err) {
      setResult(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!examineRequest || examineRequest.nonce === decodeHandledNonce) return;
    decodeHandledNonce = examineRequest.nonce;
    if (examineRequest.path) {
      setPath(examineRequest.path);
      setText("");
    } else {
      setPath(null);
      setText(examineRequest.text ?? "");
    }
    void run(examineRequest.path ? { path: examineRequest.path } : { text: examineRequest.text });
  }, [examineRequest]); // eslint-disable-line react-hooks/exhaustive-deps

  const paste = async () => {
    try {
      const t = await navigator.clipboard.readText();
      if (!t.trim()) return toast.info("The clipboard is empty.");
      setPath(null);
      setText(t);
      void run({ text: t });
    } catch {
      toast.error("Clipboard access was denied. Paste into the text box with Ctrl+V instead.");
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-5 space-y-3">
        <div className="flex flex-wrap gap-2">
          <Button
            icon={FolderOpen}
            onClick={async () => {
              const p = await pickFile("Examine a file", [FILTERS.certificates, FILTERS.keys, FILTERS.keystores]).catch(() => null);
              if (p) {
                setPath(p);
                setText("");
                void run({ path: p });
              }
            }}
          >
            Open file…
          </Button>
          <Button icon={Clipboard} onClick={paste}>
            Paste clipboard
          </Button>
        </div>
        {path ? (
          <div className="flex items-center gap-2 rounded-control border border-line bg-surface-2 px-3 h-9 text-[13px]">
            <span className="font-mono truncate flex-1" title={path}>
              {path}
            </span>
            <button className="text-brand font-medium cursor-pointer" onClick={() => setPath(null)}>
              Clear
            </button>
          </div>
        ) : (
          <TextArea mono rows={12} placeholder={"Paste a certificate, chain, CSR, CRL, private/public key, PKCS#7, JWT or OpenSSH key…"} value={text} onChange={(e) => setText(e.target.value)} data-testid="decode-input" />
        )}
        <PasswordInput label="Password (for encrypted keys or keystores)" value={password} onChange={setPassword} />
        <Button variant="primary" className="w-full" icon={Sparkles} onClick={() => run()} disabled={busy || (!path && !text.trim())} data-testid="decode-run">
          {busy ? "Examining…" : "Examine"}
        </Button>
      </div>
      <div className="lg:col-span-7 bg-surface-2 rounded-card p-5 border border-line min-h-[360px] select-text" data-testid="decode-result">
        {error && <Alert tone="danger">{error}</Alert>}
        {!result && !error && <div className="h-full min-h-[320px] flex items-center justify-center text-faint text-[13px] text-center px-8">Drop a file on the window, open one, or paste data to identify and decode it.</div>}
        {result && (
          <div className="space-y-4">
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-[16px] font-semibold text-ink" data-testid="decode-title">
                  {result.title}
                </h3>
                <Badge tone="brand">{result.format}</Badge>
                <span className="text-[12px] text-faint">{result.byte_length.toLocaleString()} bytes</span>
              </div>
              <p className="text-[13px] text-muted mt-1">{result.summary}</p>
            </div>
            <WarningList warnings={result.warnings} />
            {result.kind === "keystore" && path && (
              <Button variant="primary" icon={FolderOpen} onClick={() => openFiles([path])}>
                Open {baseName(path)} as keystore
              </Button>
            )}
            {result.certificates.length > 0 && (
              <ChainView
                certs={result.certificates}
                actions={(c, i) => (
                  <>
                    <Button size="sm" icon={FileBadge} onClick={() => void keep([c], path ? baseName(path) : "Decoded")} data-testid={`decode-keep-${i}`}>
                      Add to Certificates
                    </Button>
                    {target && (
                      <Button size="sm" icon={Plus} onClick={() => importCert(c)}>
                        Add to {target.name}
                      </Button>
                    )}
                  </>
                )}
              />
            )}
            {result.csr && (
              <div className="space-y-3">
                <table className="w-full text-[13px] border border-line rounded-card overflow-hidden border-separate border-spacing-0 bg-surface">
                  <tbody>
                    {[
                      ["Subject", result.csr.subject],
                      ["Public key", `${result.csr.public_key_algorithm} ${result.csr.key_size}-bit${result.csr.curve ? ` (${result.csr.curve})` : ""}`],
                      ["Signature", `${result.csr.signature_algorithm} — ${result.csr.signature_valid ? "valid" : "INVALID"}`],
                      ["Requested SANs", result.csr.sans.join(", ") || "—"],
                      ["Public key SHA-256", result.csr.public_key_sha256],
                    ].map(([k, v]) => (
                      <tr key={k}>
                        <th className="w-[30%] text-left font-medium text-faint bg-surface-2 border-b border-line px-3 py-2">{k}</th>
                        <td className="border-b border-line px-3 py-2 font-mono text-[11.5px] break-all">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Button onClick={() => setTab("ca_signing")}>Sign it in CA & Signing</Button>
              </div>
            )}
            {result.crl && (
              <div className="space-y-2 text-[13px]">
                <div className="text-muted">
                  Issuer <span className="font-mono text-ink">{result.crl.issuer}</span> · this update {result.crl.this_update} · next update {result.crl.next_update}
                  {result.crl.crl_number && ` · CRL #${result.crl.crl_number}`}
                </div>
                <ul className="divide-y divide-line border border-line rounded-card bg-surface max-h-64 overflow-y-auto">
                  {result.crl.revoked_entries.map((r) => (
                    <li key={r.serial_number} className="px-3 py-2 flex justify-between gap-2">
                      <span className="font-mono">{r.serial_number}</span>
                      <span className="text-faint">
                        {r.reason} · {r.revocation_date}
                      </span>
                    </li>
                  ))}
                  {result.crl.revoked_entries.length === 0 && <li className="px-3 py-2 text-faint">No revoked certificates</li>}
                </ul>
              </div>
            )}
            {result.key && (
              <div className="space-y-3">
                <table className="w-full text-[13px] border border-line rounded-card overflow-hidden border-separate border-spacing-0 bg-surface">
                  <tbody>
                    {[
                      ["Type", `${result.key.kind} key${result.key.encrypted ? " (encrypted)" : ""}`],
                      ["Algorithm", result.key.algorithm],
                      ["Size", result.key.key_size ? `${result.key.key_size} bits` : "—"],
                      ["Curve", result.key.curve ?? "—"],
                      ["Format", result.key.format],
                      ["Public key SHA-256", result.key.public_key_sha256 ?? "—"],
                    ].map(([k, v]) => (
                      <tr key={k}>
                        <th className="w-[30%] text-left font-medium text-faint bg-surface-2 border-b border-line px-3 py-2">{k}</th>
                        <td className="border-b border-line px-3 py-2 font-mono text-[11.5px] break-all">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {result.key.public_key_pem && <CodeBlock label="Public key" value={result.key.public_key_pem} maxHeight={160} />}
              </div>
            )}
            {result.jwt && (
              <div className="space-y-3">
                <div className="text-[13px] text-muted">
                  Issued {result.jwt.issued_at ?? "—"} · expires {result.jwt.expires_at ?? "never"} {result.jwt.expired && <Badge tone="danger">Expired</Badge>}
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <CodeBlock label="Header" value={result.jwt.header_json} maxHeight={200} />
                  <CodeBlock label="Payload" value={result.jwt.payload_json} maxHeight={200} />
                </div>
                <p className="text-[12px] text-faint">Verify the signature in CA & Signing → JWT with the issuer's key.</p>
              </div>
            )}
            <div className="text-[11.5px] text-faint font-mono break-all">SHA-256 of input: {result.sha256}</div>
          </div>
        )}
      </div>
    </div>
  );
};

// ================================================================================== compare

interface Side {
  source: "entry" | "pem";
  entryId: string;
  pem: string;
  cert: CertificateInfo | null;
  publicKey?: string | null;
}

const CompareSide: React.FC<{ label: string; side: Side; set: (s: Side) => void; options: { entry: KeystoreEntry; ks: string }[] }> = ({ label, side, set, options }) => {
  const toast = useToast();
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="label !mb-0">{label}</span>
        <Segmented label={`${label} source`} value={side.source} onChange={(v) => set({ ...side, source: v })} options={[{ value: "entry", label: "Keystore entry" }, { value: "pem", label: "Paste PEM" }]} />
      </div>
      {side.source === "entry" ? (
        <Select
          value={side.entryId}
          onChange={(e) => {
            const opt = options.find((o) => o.entry.id === e.target.value);
            set({ ...side, entryId: e.target.value, cert: opt?.entry.certificate_chain[0] ?? null, publicKey: opt?.entry.public_key_pem });
          }}
        >
          <option value="">Choose…</option>
          {options.map((o) => (
            <option key={o.entry.id} value={o.entry.id}>
              {o.entry.alias} — {cnOf(o.entry.subject)} ({o.ks})
            </option>
          ))}
        </Select>
      ) : (
        <div className="space-y-2">
          <TextArea mono rows={4} placeholder="-----BEGIN CERTIFICATE-----" value={side.pem} onChange={(e) => set({ ...side, pem: e.target.value })} />
          <Button
            size="sm"
            onClick={async () => {
              try {
                const r = await api.examineData({ text: side.pem });
                if (!r.certificates.length) throw new Error("No certificate found in the pasted text.");
                set({ ...side, cert: r.certificates[0], publicKey: null });
              } catch (err) {
                toast.error(errorMessage(err));
              }
            }}
          >
            Parse
          </Button>
        </div>
      )}
    </div>
  );
};

const ComparePanel: React.FC = () => {
  const { keystores } = useStore();
  const options = useMemo(() => keystores.flatMap((ks) => ks.entries.filter((e) => e.certificate_chain.length).map((entry) => ({ entry, ks: ks.name }))), [keystores]);
  const empty: Side = { source: "entry", entryId: "", pem: "", cert: null };
  const [left, setLeft] = useState<Side>(empty);
  const [right, setRight] = useState<Side>(empty);
  const l = left.cert;
  const r = right.cert;
  const rows: { label: string; l: string; r: string }[] =
    l && r
      ? [
          { label: "Subject", l: l.subject, r: r.subject },
          { label: "Issuer", l: l.issuer, r: r.issuer },
          { label: "Serial", l: l.serial_number, r: r.serial_number },
          { label: "Valid from", l: l.valid_from, r: r.valid_from },
          { label: "Valid until", l: l.valid_to, r: r.valid_to },
          { label: "Public key", l: `${l.public_key_algorithm} ${l.key_size}`, r: `${r.public_key_algorithm} ${r.key_size}` },
          { label: "Signature", l: l.signature_algorithm, r: r.signature_algorithm },
          { label: "SANs", l: l.sans.join(", "), r: r.sans.join(", ") },
          { label: "Key usage", l: l.key_usage.join(", "), r: r.key_usage.join(", ") },
          { label: "Extended key usage", l: l.extended_key_usage.join(", "), r: r.extended_key_usage.join(", ") },
          { label: "CA", l: l.is_ca ? "Yes" : "No", r: r.is_ca ? "Yes" : "No" },
          { label: "Subject key ID", l: l.subject_key_id ?? "—", r: r.subject_key_id ?? "—" },
          { label: "SHA-256", l: l.sha256_fingerprint, r: r.sha256_fingerprint },
        ]
      : [];
  const sameKey = l && r && l.subject_key_id && l.subject_key_id === r.subject_key_id;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <CompareSide label="Left" side={left} set={setLeft} options={options} />
        <CompareSide label="Right" side={right} set={setRight} options={options} />
      </div>
      {l && r ? (
        <>
          <div className="flex flex-wrap gap-2">
            {l.sha256_fingerprint === r.sha256_fingerprint ? <Badge tone="success">Identical certificates</Badge> : <Badge>Different certificates</Badge>}
            {sameKey && <Badge tone="brand">Same public key (key identifier)</Badge>}
            {l.issuer === r.subject && <Badge tone="brand">Left is issued by right</Badge>}
            {r.issuer === l.subject && <Badge tone="brand">Right is issued by left</Badge>}
          </div>
          <div className="border border-line rounded-card overflow-hidden text-[13px] select-text">
            {rows.map((row) => {
              const diff = row.l !== row.r;
              return (
                <div key={row.label} className={clsx("grid grid-cols-12 border-b border-line last:border-0 px-3 py-2.5 items-start", diff ? "bg-warning-tint" : "bg-surface")}>
                  <div className="col-span-2 font-semibold text-muted">{row.label}</div>
                  <div className="col-span-5 font-mono text-[11.5px] text-ink pr-3 break-all">{row.l || "—"}</div>
                  <div className="col-span-5 font-mono text-[11.5px] text-ink pl-3 border-l border-line break-all">{row.r || "—"}</div>
                </div>
              );
            })}
          </div>
        </>
      ) : (
        <EmptyState icon={GitCompare} title="Choose two certificates" description="Pick entries from your open keystores or paste PEM certificates to compare them field by field." />
      )}
    </div>
  );
};

export const ExamineView: React.FC = () => {
  const { examineRequest } = useStore();
  const [mode, setMode] = useState<Mode>(() => (examineRequest && examineRequest.nonce !== modeHandledNonce ? "decode" : "tls"));
  const [tlsSeed, setTlsSeed] = useState<TlsSeed | null>(null);
  useEffect(() => {
    if (!examineRequest || examineRequest.nonce === modeHandledNonce) return;
    modeHandledNonce = examineRequest.nonce;
    setMode("decode");
  }, [examineRequest]);
  return (
    <Page>
      <PageHeader title="Examine" description="Inspect a live TLS server, test whether a server port can be reached from this machine, decode any certificate, key, CSR, CRL, PKCS#7 or JWT, or compare two certificates." />
      <div className="mb-4">
        <Segmented
          label="Examine mode"
          value={mode}
          onChange={setMode}
          options={[
            { value: "tls", label: <><Globe className="w-3.5 h-3.5" /> TLS server</> },
            { value: "connection", label: <><Network className="w-3.5 h-3.5" /> Connection</> },
            { value: "decode", label: <><FileSearch className="w-3.5 h-3.5" /> Decode</> },
            { value: "compare", label: <><GitCompare className="w-3.5 h-3.5" /> Compare</> },
          ]}
        />
      </div>
      <Card className="p-6">
        {mode === "tls" && <TlsPanel seed={tlsSeed} onSeedUsed={() => setTlsSeed(null)} />}
        {mode === "connection" && (
          <ConnectionPanel
            onInspectTls={(seed) => {
              setTlsSeed(seed);
              setMode("tls");
            }}
          />
        )}
        {mode === "decode" && <DecodePanel />}
        {mode === "compare" && <ComparePanel />}
      </Card>
    </Page>
  );
};

export { CertificateDetails };
