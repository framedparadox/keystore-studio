import React, { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { ArrowRight, CheckCircle2, ChevronLeft, ClipboardPaste, FileOutput, FolderOpen, Link2, Lock, Repeat, Sparkles, Unlock, X } from "lucide-react";
import type { CertificateInfo, ConvertResult, DataSource, DetectionResult, KeystoreEntry, KeystoreFile, KeystoreFormat, OpenKeystore, PemBundleOptions, Pkcs12Profile } from "../types/crypto";
import { Pkcs12ProfileSelect } from "../components/KeystoreDialogs";
import { KEYSTORE_FORMATS } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { FILTERS, baseName, pickFile, pickFiles, pickSavePath, type FileFilter } from "../lib/files";
import { issuerChain } from "../lib/certificates";
import { useCertificatePool } from "../components/CertificateDialogs";
import { ChainTree } from "../components/CertificateView";
import { FORMAT_EXTENSION, FORMAT_INFO, byTypeThenAlias, cnOf, entryTypeName, saveProblems } from "../lib/keystore";
import { CERT_OUTPUTS, CONVERTERS, KEY_OUTPUTS, PEM_LABELS, PUBLIC_OUTPUTS, cliHint, converterInfo, outputName, type ConverterId, type OutputTarget } from "../lib/convert";
import { useStore } from "../state/store";
import { Alert, Badge, Button, Card, Checkbox, CodeBlock, OptionList, Page, PageHeader, PasswordInput, Segmented, Select, Spinner, TextArea, TextInput, useToast } from "../components/ui";
import { FileOrText, usePkcs12Builder } from "../components/AddEntryDialogs";
import { EntryIcon } from "../components/entry";
import { TerminalHint } from "../components/Terminal";
import { CONVERTER_ICONS, ConvertIcon } from "../components/Sidebar";

// ================================================================================ shared

const Step: React.FC<{ title: string; hint?: React.ReactNode; children: React.ReactNode }> = ({ title, hint, children }) => (
  <section className="space-y-3">
    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
      <h3 className="text-[14px] font-semibold text-ink">{title}</h3>
      {hint && <span className="text-[12px] text-faint">{hint}</span>}
    </div>
    <div>{children}</div>
  </section>
);

const sourceOf = (path: string | null, text: string): DataSource | null => (path ? { path } : text.trim() ? { text } : null);

/** Identifies the input as the user provides it, so a wrong file is obvious before converting. */
function useDetection(source: DataSource | null, password: string) {
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const key = source ? source.path ?? source.text ?? "" : "";
  useEffect(() => {
    setResult(null);
    setError(null);
    if (!source) return;
    let live = true;
    const t = window.setTimeout(
      () =>
        api
          .examineData(source, password || null)
          .then((r) => live && setResult(r))
          .catch((err) => live && setError(errorMessage(err))),
      source.path ? 0 : 350
    );
    return () => {
      live = false;
      window.clearTimeout(t);
    };
  }, [key, password]); // eslint-disable-line react-hooks/exhaustive-deps
  return { result, error };
}

const Detected: React.FC<{ result: DetectionResult | null; error: string | null }> = ({ result, error }) => {
  if (error) return <p className="text-[12px] text-danger mt-2" data-testid="convert-detected-error">Not recognised: {error}</p>;
  if (!result) return null;
  return (
    <div className="mt-2 flex items-start gap-2 text-[13px]" data-testid="convert-detected">
      <Sparkles className="w-3.5 h-3.5 text-brand mt-0.5 shrink-0" />
      <div className="min-w-0">
        <span className="font-medium text-ink">{result.title}</span> <Badge>{result.format}</Badge>
        <div className="text-faint">{result.summary}</div>
      </div>
    </div>
  );
};

/** Runs a conversion as a preview, or validates it, asks where to save, and writes it. */
function useRunner() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ConvertResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const exec = async (fn: () => Promise<ConvertResult | null>) => {
    setBusy(true);
    setError(null);
    try {
      const r = await fn();
      if (r) {
        setResult(r);
        if (r.path) toast.success(`Wrote ${baseName(r.path)} (${r.byte_length.toLocaleString()} bytes).`, { label: "Show in folder", onClick: () => void revealItemInDir(r.path!).catch(() => undefined) });
      }
    } catch (err) {
      setResult(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return {
    busy,
    result,
    error,
    clear: () => {
      setResult(null);
      setError(null);
    },
    preview: (convert: (path: string | null) => Promise<ConvertResult>) => exec(() => convert(null)),
    /** Converts once without writing (so errors appear before the save dialog), then saves. */
    save: (convert: (path: string | null) => Promise<ConvertResult>, opts: { title: string; input?: string | null; stem: string; ext?: string; filters?: FileFilter[] }) =>
      exec(async () => {
        const dry = await convert(null);
        const path = await pickSavePath(opts.title, outputName(opts.input, opts.stem, opts.ext ?? dry.extension), opts.filters);
        if (!path) return null;
        return convert(path);
      }),
  };
}

const ResultPanel: React.FC<{ runner: ReturnType<typeof useRunner>; empty: string }> = ({ runner, empty }) => {
  const r = runner.result;
  return (
    <Card className="space-y-3" data-testid="convert-result">
      <h3 className="text-[14px] font-semibold text-ink">Result</h3>
      {runner.error && (
        <Alert tone="danger" title="Could not convert">
          <span data-testid="convert-error">{runner.error}</span>
        </Alert>
      )}
      {!r && !runner.error && <p className="text-[13px] text-faint">{empty}</p>}
      {r && (
        <>
          {r.path ? (
            <Alert
              tone="success"
              title="Saved"
              action={
                <Button size="sm" icon={FolderOpen} onClick={() => void revealItemInDir(r.path!).catch(() => undefined)}>
                  Show
                </Button>
              }
            >
              <span className="font-mono text-[12px] break-all" data-testid="convert-saved-path">
                {r.path}
              </span>
            </Alert>
          ) : (
            <Alert tone="info" title="Preview">
              Nothing was written. Use “Convert & save” to write a file.
            </Alert>
          )}
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[13px]">
            <div>
              <dt className="text-faint">Format</dt>
              <dd className="text-ink font-medium" data-testid="convert-format">
                {r.format}
              </dd>
            </div>
            <div>
              <dt className="text-faint">Size</dt>
              <dd className="text-ink tabular-nums">
                {r.byte_length.toLocaleString()} bytes · {r.count} {r.count === 1 ? "object" : "objects"}
              </dd>
            </div>
          </dl>
          {r.notes.length > 0 && (
            <ul className="space-y-1 text-[13px] text-muted" data-testid="convert-notes">
              {r.notes.map((n) => (
                <li key={n} className="flex items-start gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-subtle shrink-0" />
                  {n}
                </li>
              ))}
            </ul>
          )}
          {r.text && <CodeBlock label="Output" value={r.text} maxHeight={280} testId="convert-output" />}
          {r.sensitive && !r.text && <p className="text-[12px] text-faint">The output holds private key material, so it is not shown here.</p>}
          {/^[0-9a-f]{64}$/.test(r.sha256) && <div className="text-[11px] text-faint font-mono break-all">SHA-256 {r.sha256}</div>}
        </>
      )}
    </Card>
  );
};

const Actions: React.FC<{ runner: ReturnType<typeof useRunner>; disabled: boolean; onSave: () => void; onPreview?: () => void; saveLabel?: string; previewHint?: string }> = ({
  runner,
  disabled,
  onSave,
  onPreview,
  saveLabel = "Convert & save…",
  previewHint,
}) => (
  <div className="flex flex-wrap items-center gap-2 pt-1">
    <Button variant="primary" icon={ArrowRight} onClick={onSave} disabled={disabled || runner.busy} data-testid="convert-save">
      {runner.busy && <Spinner />} {saveLabel}
    </Button>
    {onPreview !== undefined && (
      <Button onClick={onPreview} disabled={disabled || runner.busy || !onPreview} title={previewHint} data-testid="convert-preview">
        Preview
      </Button>
    )}
  </div>
);

const targetOptions = (list: OutputTarget[]) => list.map((t) => ({ value: t.value, label: t.label, hint: t.hint, meta: `.${t.ext}`, testId: `convert-target-${t.value}` }));

const Layout: React.FC<{ form: React.ReactNode; side: React.ReactNode }> = ({ form, side }) => (
  <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
    <Card className="xl:col-span-7 space-y-6">{form}</Card>
    <div className="xl:col-span-5 space-y-4 xl:sticky xl:top-0">{side}</div>
  </div>
);

const Hint: React.FC<{ command: string | null }> = ({ command }) => (command ? <TerminalHint command={command} iconOnly /> : null);

// =========================================================================== certificate

/**
 * Root and intermediate certificates added to a leaf: from files, pasted text, or found among the
 * certificates open in the app. Shows the chain they make with the input as a tree.
 */
const ChainBuilder: React.FC<{ input: CertificateInfo[]; added: CertificateInfo[]; setAdded: (list: CertificateInfo[]) => void }> = ({ input, added, setAdded }) => {
  const toast = useToast();
  const pool = useCertificatePool();
  const [pasting, setPasting] = useState(false);
  const [pasted, setPasted] = useState("");
  const [busy, setBusy] = useState(false);
  const leaf = input[0];
  const have = new Set([...input, ...added].map((c) => c.sha256_fingerprint));
  const add = (certs: CertificateInfo[]) => {
    const fresh = certs.filter((c, i) => !have.has(c.sha256_fingerprint) && certs.findIndex((x) => x.sha256_fingerprint === c.sha256_fingerprint) === i);
    if (!fresh.length) toast.info(certs.length ? "Those certificates are already in the chain." : "No certificate found.");
    else setAdded([...added, ...fresh]);
    return fresh.length;
  };
  const read = async (sources: DataSource[]) => {
    setBusy(true);
    try {
      const found = (await Promise.all(sources.map((src) => api.examineData(src, null)))).flatMap((r) => r.certificates);
      return add(found);
    } catch (err) {
      toast.error(errorMessage(err));
      return 0;
    } finally {
      setBusy(false);
    }
  };
  const fromFiles = async () => {
    try {
      const paths = await pickFiles("Add root and intermediate certificates", [FILTERS.certificates]);
      if (paths.length) await read(paths.map((path) => ({ path })));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  // Issuers of the top of what is there so far, among everything open.
  const top = leaf ? [leaf, ...issuerChain(leaf, [...input, ...added])].pop()! : undefined;
  const suggestions = top && !top.self_signed ? issuerChain(top, pool).filter((c) => !have.has(c.sha256_fingerprint)) : [];
  const chain = leaf ? [leaf, ...issuerChain(leaf, [...input.slice(1), ...added])] : [];
  const loose = added.filter((c) => !chain.includes(c));
  return (
    <div className="space-y-3" data-testid="convert-chain">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" icon={FolderOpen} onClick={() => void fromFiles()} disabled={busy || !leaf} data-testid="convert-chain-files">
          Add files…
        </Button>
        <Button size="sm" icon={ClipboardPaste} onClick={() => setPasting((v) => !v)} disabled={busy || !leaf} aria-expanded={pasting} data-testid="convert-chain-paste">
          Paste…
        </Button>
        <Button
          size="sm"
          icon={Link2}
          onClick={() => add(suggestions)}
          disabled={busy || !suggestions.length}
          title={suggestions.length ? suggestions.map((c) => cnOf(c.subject)).join(" → ") : "No issuer of this certificate is open"}
          data-testid="convert-chain-find"
        >
          {suggestions.length ? `Add ${suggestions.length} issuer${suggestions.length === 1 ? "" : "s"} from open certificates` : "Find among open certificates"}
        </Button>
        {busy && <Spinner />}
      </div>
      {pasting && (
        <div className="space-y-2">
          <TextArea mono rows={6} label="Root or intermediate certificates (PEM)" placeholder="-----BEGIN CERTIFICATE-----" value={pasted} onChange={(e) => setPasted(e.target.value)} data-testid="convert-chain-text" />
          <Button
            size="sm"
            variant="primary"
            disabled={!pasted.trim() || busy}
            onClick={async () => {
              if (await read([{ text: pasted }])) {
                setPasted("");
                setPasting(false);
              }
            }}
            data-testid="convert-chain-add"
          >
            Add to chain
          </Button>
        </div>
      )}
      {leaf && (
        <div className="rounded-card border border-line px-4 py-3 space-y-2">
          <ChainTree chain={chain} complete={chain[chain.length - 1].self_signed} />
          {added.length > 0 && (
            <ul className="flex flex-wrap gap-1.5 pt-1" aria-label="Added certificates">
              {added.map((c) => (
                <li key={c.sha256_fingerprint}>
                  <span className="inline-flex items-center gap-1 h-6 pl-2 pr-1 rounded-control border border-line bg-surface-2 text-[12px] text-ink-2">
                    {cnOf(c.subject)}
                    {loose.includes(c) && <span className="text-warning" title="Did not issue any certificate in the chain"> · not linked</span>}
                    <button type="button" onClick={() => setAdded(added.filter((x) => x !== c))} aria-label={`Remove ${cnOf(c.subject)}`} className="w-4 h-4 flex items-center justify-center rounded hover:bg-surface-3 cursor-pointer">
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
};

const CertificatePanel: React.FC = () => {
  const runner = useRunner();
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [target, setTarget] = useState("pem");
  const [order, setOrder] = useState(true);
  const [added, setAdded] = useState<CertificateInfo[]>([]);
  const source = sourceOf(path, text);
  const detection = useDetection(source, "");
  const t = CERT_OUTPUTS.find((o) => o.value === target)!;
  const first = detection.result?.certificates[0];
  const stem = first ? cnOf(first.subject) : "certificate";
  const total = (detection.result?.certificates.length ?? 0) + added.length;
  const convert = (out: string | null) => api.convertCertificates(source!, target, order, out, added.map((c) => c.pem).join(""));
  return (
    <Layout
      form={
        <>
          <Step title="Certificate or chain" hint="PEM, DER, PKCS#7 or PkiPath">
            <FileOrText label="Input" filters={[FILTERS.certificates]} path={path} setPath={setPath} text={text} setText={setText} placeholder="-----BEGIN CERTIFICATE-----" testId="convert-input" />
            <Detected {...detection} />
          </Step>
          <Step title="Root and intermediate certificates" hint="Optional. Added to the leaf in every format that holds a chain.">
            <ChainBuilder input={detection.result?.certificates ?? []} added={added} setAdded={setAdded} />
          </Step>
          <Step title="Output format">
            <OptionList label="Certificate output format" value={target} onChange={setTarget} options={targetOptions(CERT_OUTPUTS)} columns={2} />
            {total > 1 && target === "der" && (
              <Alert tone="warning" className="mt-3">
                The chain holds {total} certificates. DER keeps only the first; choose PEM or PKCS#7 to keep them all.
              </Alert>
            )}
            <div className="mt-3">
              <Checkbox checked={order} onChange={setOrder} label="Order the chain leaf first, root last" hint="Recommended for servers. PKCS#7 bundles have no order." />
            </div>
          </Step>
          <Actions
            runner={runner}
            disabled={!source}
            onSave={() => runner.save(convert, { title: "Save converted certificate", input: path, stem, ext: t.ext })}
            onPreview={t.text ? () => runner.preview(convert) : undefined}
            previewHint={t.text ? undefined : "Binary output cannot be previewed"}
          />
        </>
      }
      side={
        <>
          <ResultPanel runner={runner} empty="Choose an input and a format. The converted certificate appears here." />
          <Hint command={cliHint("certificate", target, path)} />
        </>
      }
    />
  );
};

// ============================================================================ truststore

const TruststorePanel: React.FC = () => {
  const runner = useRunner();
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [format, setFormat] = useState<KeystoreFormat>("PKCS12");
  const [alias, setAlias] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const source = sourceOf(path, text);
  const detection = useDetection(source, "");
  const count = detection.result?.certificates.length ?? 0;
  const pwError = pw2 && pw !== pw2 ? "Passwords do not match" : undefined;
  const ready = !!source && pw.length > 0 && pw === pw2;
  const convert = (out: string | null) => api.convertTruststore(source!, format, pw, alias, out);
  return (
    <Layout
      form={
        <>
          <Step title="Certificates" hint="A CA bundle: PEM, DER, PKCS#7 or PkiPath">
            <FileOrText label="Input" filters={[FILTERS.certificates]} path={path} setPath={setPath} text={text} setText={setText} placeholder="-----BEGIN CERTIFICATE-----" testId="convert-input" />
            <Detected {...detection} />
          </Step>
          <Step title="Truststore format">
            <OptionList
              label="Truststore format"
              value={format}
              onChange={(v) => setFormat(v as KeystoreFormat)}
              columns={2}
              options={KEYSTORE_FORMATS.map((f) => ({ value: f, label: FORMAT_INFO[f].label, hint: FORMAT_INFO[f].description, meta: `.${FORMAT_EXTENSION[f]}`, testId: `convert-trust-format-${f}` }))}
            />
            <TextInput
              className="mt-3"
              label="Alias of the first certificate (optional)"
              value={alias}
              onChange={(e) => setAlias(e.target.value)}
              hint={`Every certificate becomes a trusted certificate entry named after its common name${format === "JKS" || format === "JCEKS" ? ", in lower case as keytool stores it" : ""}.`}
              data-testid="convert-trust-alias"
            />
          </Step>
          <Step title="Password">
            <div className="grid grid-cols-2 gap-3">
              <PasswordInput label="Truststore password" value={pw} onChange={setPw} data-testid="convert-trust-password" />
              <PasswordInput label="Confirm" value={pw2} onChange={setPw2} error={pwError} data-testid="convert-trust-password-confirm" />
            </div>
          </Step>
          <Actions runner={runner} disabled={!ready} saveLabel={count > 1 ? `Build truststore (${count} certificates)…` : "Build truststore…"} onSave={() => runner.save(convert, { title: "Save truststore", input: path, stem: "truststore", ext: FORMAT_EXTENSION[format], filters: [FILTERS.keystores] })} />
        </>
      }
      side={
        <>
          <ResultPanel runner={runner} empty="Choose the certificates, a format and a password. The truststore is written to a file." />
          <Hint command={cliHint("truststore", format, path)} />
        </>
      }
    />
  );
};

// =========================================================================== private key

const PrivateKeyPanel: React.FC = () => {
  const runner = useRunner();
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [inPw, setInPw] = useState("");
  const [target, setTarget] = useState("pkcs8_pem");
  const [outPw, setOutPw] = useState("");
  const [outPw2, setOutPw2] = useState("");
  const source = sourceOf(path, text);
  const detection = useDetection(source, inPw);
  const t = KEY_OUTPUTS.find((o) => o.value === target)!;
  const [comment, setComment] = useState("");
  const takesPassword = !!(t.needsPassword || t.optionalPassword);
  const pwError = takesPassword && outPw2 && outPw !== outPw2 ? "Passwords do not match" : undefined;
  const ready = !!source && (t.needsPassword ? !!outPw && outPw === outPw2 : !t.optionalPassword || outPw === outPw2);
  const convert = (out: string | null) => api.convertPrivateKey(source!, inPw || null, target, takesPassword && outPw ? outPw : null, out, comment);
  return (
    <Layout
      form={
        <>
          <Step title="Private key" hint="PKCS#8, encrypted PKCS#8, PKCS#1, SEC1, OpenSSH or JWK">
            <div className="space-y-3">
              <FileOrText label="Input" filters={[FILTERS.keys]} path={path} setPath={setPath} text={text} setText={setText} placeholder="-----BEGIN PRIVATE KEY-----" testId="convert-input" />
              <PasswordInput label="Password of the input key (only if it is encrypted)" value={inPw} onChange={setInPw} data-testid="convert-input-password" />
            </div>
            <Detected {...detection} />
          </Step>
          <Step title="Output format">
            <OptionList label="Private key output format" value={target} onChange={setTarget} options={targetOptions(KEY_OUTPUTS)} columns={2} />
            {target === "openssh" && (
              <TextInput className="mt-3" label="Comment" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="user@host" hint="Stored in the key and shown by ssh-keygen -l." data-testid="convert-comment" />
            )}
            {takesPassword && (
              <div className="grid grid-cols-2 gap-3 mt-3">
                <PasswordInput label={t.needsPassword ? "Password for the converted key" : "Password (optional)"} value={outPw} onChange={setOutPw} data-testid="convert-out-password" />
                <PasswordInput label="Confirm" value={outPw2} onChange={setOutPw2} error={pwError} data-testid="convert-out-password-confirm" />
              </div>
            )}
            {!t.needsPassword && !(t.optionalPassword && outPw) && (
              <Alert tone="warning" className="mt-3">
                This format is not encrypted. Anyone who can read the file can use the key.
              </Alert>
            )}
          </Step>
          <Actions runner={runner} disabled={!ready} onSave={() => runner.save(convert, { title: "Save converted private key", input: path, stem: "private-key", ext: t.ext, filters: [FILTERS.keys] })} />
        </>
      }
      side={
        <>
          <ResultPanel runner={runner} empty="Private keys are written to a file only; they are never shown on screen." />
          <Hint command={cliHint("private_key", target, path)} />
        </>
      }
    />
  );
};

// ============================================================================ public key

const PublicKeyPanel: React.FC = () => {
  const runner = useRunner();
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [inPw, setInPw] = useState("");
  const [target, setTarget] = useState("pem");
  const [comment, setComment] = useState("");
  const source = sourceOf(path, text);
  const detection = useDetection(source, inPw);
  const t = PUBLIC_OUTPUTS.find((o) => o.value === target)!;
  const first = detection.result?.certificates[0];
  const convert = (out: string | null) => api.convertPublicKey(source!, inPw || null, target, comment, out);
  return (
    <Layout
      form={
        <>
          <Step title="Anything with a public key" hint="Certificate, CSR, private key, public key, OpenSSH or JWK">
            <div className="space-y-3">
              <FileOrText label="Input" filters={[FILTERS.certificates, FILTERS.keys, FILTERS.csr]} path={path} setPath={setPath} text={text} setText={setText} placeholder="-----BEGIN CERTIFICATE----- or ssh-ed25519 AAAA… or { &quot;kty&quot;: … }" testId="convert-input" />
              <PasswordInput label="Password (only for an encrypted private key)" value={inPw} onChange={setInPw} />
            </div>
            <Detected {...detection} />
          </Step>
          <Step title="Output format">
            <OptionList label="Public key output format" value={target} onChange={setTarget} options={targetOptions(PUBLIC_OUTPUTS)} columns={2} />
            {target === "openssh" && (
              <TextInput className="mt-3" label="Comment" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="user@host" hint="Appended to the authorized_keys line." />
            )}
          </Step>
          <Actions
            runner={runner}
            disabled={!source}
            onSave={() => runner.save(convert, { title: "Save public key", input: path, stem: first ? cnOf(first.subject) : "public-key", ext: t.ext })}
            onPreview={t.text ? () => runner.preview(convert) : undefined}
            previewHint={t.text ? undefined : "Binary output cannot be previewed"}
          />
        </>
      }
      side={
        <>
          <ResultPanel runner={runner} empty="Preview shows the public key so you can copy it without saving a file." />
          <Hint command={cliHint("public_key", target, path)} />
        </>
      }
    />
  );
};

// ============================================================================= PEM <-> DER

const EncodingPanel: React.FC = () => {
  const runner = useRunner();
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [label, setLabel] = useState("");
  const source = sourceOf(path, text);
  const detection = useDetection(source, "");
  const toDer = text.trim() ? text.includes("-----BEGIN") : !!detection.result?.format.startsWith("PEM");
  const convert = (out: string | null) => api.convertEncoding(source!, toDer ? null : label || null, out);
  const sensitiveInput = detection.result?.kind === "private_key";
  return (
    <Layout
      form={
        <>
          <Step title="PEM or DER input" hint="Certificate, CSR, CRL, PKCS#7 or key">
            <FileOrText label="Input" filters={[FILTERS.certificates, FILTERS.keys, FILTERS.csr, FILTERS.crl]} path={path} setPath={setPath} text={text} setText={setText} placeholder="Paste PEM here, or choose a DER file" testId="convert-input" />
            <Detected {...detection} />
          </Step>
          <Step title="Direction">
            {source ? (
              <div className="flex items-center gap-2 text-[13px]" data-testid="convert-direction">
                <Badge tone="brand">{toDer ? "PEM" : "DER"}</Badge>
                <ArrowRight className="w-3.5 h-3.5 text-subtle" />
                <Badge tone="brand">{toDer ? "DER" : "PEM"}</Badge>
                <span className="text-faint">{toDer ? "The PEM armour is removed." : "The data is base64-encoded and wrapped in a PEM label."}</span>
              </div>
            ) : (
              <p className="text-[13px] text-faint">Chosen from the input: PEM becomes DER, DER (or bare base64) becomes PEM.</p>
            )}
            {!toDer && (
              <Select className="mt-3" label="PEM label" value={label} onChange={(e) => setLabel(e.target.value)} hint="Leave on automatic unless the content is something Keystore Studio does not recognise.">
                <option value="">Detect from the content</option>
                {PEM_LABELS.map((l) => (
                  <option key={l} value={l}>
                    {l}
                  </option>
                ))}
              </Select>
            )}
          </Step>
          <Actions
            runner={runner}
            disabled={!source}
            onSave={() => runner.save(convert, { title: toDer ? "Save DER" : "Save PEM", input: path, stem: "converted" })}
            onPreview={!toDer && !sensitiveInput ? () => runner.preview(convert) : undefined}
            previewHint={toDer ? "DER is binary and cannot be previewed" : undefined}
          />
        </>
      }
      side={
        <>
          <ResultPanel runner={runner} empty="Useful for CSRs, CRLs and keys that a tool wants in the other encoding." />
          <Hint command={cliHint("encoding", toDer ? "der" : label || "CERTIFICATE", path)} />
        </>
      }
    />
  );
};

// ======================================================================= keystore source

interface KeystoreSource {
  ks: KeystoreFile;
  password: string;
  /** The keystore open in the app, when the source is one. */
  fromApp: OpenKeystore | null;
  /** Display name and suggested output stem. */
  label: string;
  inputPath: string | null;
}

/** Picks the keystore to convert: one already open in the app, or a file read just for this. */
function useKeystoreSource() {
  const { keystores, activeKeystore, getPassword } = useStore();
  const openOnes = keystores.filter((k) => !k.sealed);
  const defaultOpen = activeKeystore && !activeKeystore.sealed ? activeKeystore : openOnes[0] ?? null;
  const [kind, setKind] = useState<"open" | "file">(defaultOpen ? "open" : "file");
  const [openId, setOpenId] = useState(defaultOpen?.id ?? "");
  const [path, setPath] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [keyPw, setKeyPw] = useState("");
  const [loaded, setLoaded] = useState<KeystoreFile | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedOpen = openOnes.find((k) => k.id === openId) ?? null;
  const source: KeystoreSource | null =
    kind === "open"
      ? selectedOpen
        ? { ks: selectedOpen, password: getPassword(selectedOpen.id) ?? "", fromApp: selectedOpen, label: selectedOpen.name, inputPath: selectedOpen.path || selectedOpen.name }
        : null
      : loaded && path
        ? { ks: loaded, password, fromApp: null, label: baseName(path), inputPath: path }
        : null;

  const load = async () => {
    if (!path) return;
    setLoading(true);
    setError(null);
    try {
      const locked = loaded?.entries.filter((e) => e.locked).map((e) => e.alias) ?? [];
      const keyPasswords = keyPw && locked.length ? Object.fromEntries(locked.map((a) => [a, keyPw])) : undefined;
      const file = await api.openKeystore(path, password, keyPasswords);
      if (keyPasswords && file.entries.filter((e) => e.locked).length === locked.length) setError("That key password does not unlock any of the locked keys.");
      setLoaded(file);
    } catch (err) {
      setLoaded(null);
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const lockedInFile = loaded?.entries.filter((e) => e.locked).length ?? 0;
  const ui = (
    <div className="space-y-3">
      <Segmented<"open" | "file">
        label="Keystore source"
        value={kind}
        onChange={setKind}
        options={[
          { value: "open", label: "Open in Keystore Studio", count: openOnes.length },
          { value: "file", label: "File on disk" },
        ]}
      />
      {kind === "open" ? (
        openOnes.length ? (
          <Select label="Keystore" value={openId} onChange={(e) => setOpenId(e.target.value)} data-testid="convert-ks-open">
            {openOnes.map((k) => (
              <option key={k.id} value={k.id}>
                {k.name} — {FORMAT_INFO[k.format].label}, {k.entries.length} {k.entries.length === 1 ? "entry" : "entries"}
              </option>
            ))}
          </Select>
        ) : (
          <Alert tone="info">No keystores are open. Choose “File on disk”, or open one first.</Alert>
        )
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Button
              icon={FolderOpen}
              onClick={async () => {
                const p = await pickFile("Choose a keystore", [FILTERS.keystores]).catch(() => null);
                if (p) {
                  setPath(p);
                  setLoaded(null);
                  setError(null);
                }
              }}
              data-testid="convert-ks-pick"
            >
              Choose keystore…
            </Button>
            {path && (
              <span className="font-mono text-[12px] truncate text-muted" title={path}>
                {path}
              </span>
            )}
          </div>
          {path && (
            <form
              className="flex items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void load();
              }}
            >
              <div className="flex-1">
                <PasswordInput label="Keystore password" value={password} onChange={setPassword} data-testid="convert-ks-password" />
              </div>
              <Button type="submit" disabled={!password || loading} data-testid="convert-ks-load">
                {loading && <Spinner />} {loaded ? "Reload" : "Open"}
              </Button>
            </form>
          )}
          {loaded && lockedInFile > 0 && (
            <form
              className="flex items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void load();
              }}
            >
              <div className="flex-1">
                <PasswordInput label={`Key password for ${lockedInFile} locked ${lockedInFile === 1 ? "key" : "keys"}`} value={keyPw} onChange={setKeyPw} data-testid="convert-ks-keypw" />
              </div>
              <Button type="submit" icon={Unlock} disabled={!keyPw || loading} data-testid="convert-ks-unlock">
                Unlock
              </Button>
            </form>
          )}
        </div>
      )}
      {error && <Alert tone="danger">{error}</Alert>}
      {source && (
        <div className="text-[13px] text-muted flex flex-wrap items-center gap-2" data-testid="convert-ks-summary">
          <Badge tone="brand">{FORMAT_INFO[source.ks.format].label}</Badge>
          <span>
            {source.ks.entries.length} {source.ks.entries.length === 1 ? "entry" : "entries"}
          </span>
          {source.ks.entries.some((e) => e.locked) && (
            <Badge tone="warning" icon={Lock}>
              {source.ks.entries.filter((e) => e.locked).length} locked by their own key password
            </Badge>
          )}
        </div>
      )}
    </div>
  );
  return { source, ui };
}

// ======================================================================= keystore format

const KeystorePanel: React.FC = () => {
  const { openFiles } = useStore();
  const runner = useRunner();
  const { source, ui } = useKeystoreSource();
  const [target, setTarget] = useState<KeystoreFormat>("PKCS12");
  const [keepPw, setKeepPw] = useState(true);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [mac, setMac] = useState<Pkcs12Profile>("pkcs12");
  const problems = source ? saveProblems(source.ks.entries, source.ks.format, target) : [];
  const newPw = keepPw ? source?.password ?? "" : pw;
  const pwError = !keepPw && pw && pw.length < 6 ? "At least 6 characters" : !keepPw && pw2 && pw !== pw2 ? "Passwords do not match" : undefined;
  const ready = !!source && !problems.length && !!newPw && (keepPw || (pw === pw2 && pw.length >= 6));
  const [written, setWritten] = useState<{ path: string; name: string; format: string; bytes: number } | null>(null);
  useEffect(() => setWritten(null), [source?.ks.id, target]);

  const convert = async () => {
    if (!source) return;
    const ext = FORMAT_EXTENSION[target];
    const sameExt = (source.inputPath ?? "").toLowerCase().endsWith(`.${ext}`);
    const path = await pickSavePath(`Save as ${FORMAT_INFO[target].label}`, outputName(source.inputPath, "keystore", ext, sameExt ? "-converted" : ""), [FILTERS.keystores]).catch(() => null);
    if (!path) return;
    if (source.ks.path && path === source.ks.path) {
      runner.clear();
      setWritten(null);
      return void runner.preview(() => Promise.reject(new Error("Choose a new file so the source keystore stays as it is.")));
    }
    // OpenSSL and Java read a PKCS#12 with one password, so keys with their own move to the keystore's.
    const separate = target === "PKCS12" ? source.ks.entries.filter((e) => e.key_password).length : 0;
    const entries = separate ? source.ks.entries.map((e) => (e.key_password ? { ...e, key_password: null } : e)) : source.ks.entries;
    await runner.preview(async () => {
      // Not the source file, so its "changed on disk" check does not apply.
      const res = await api.saveKeystore({ ...source.ks, entries, source_mtime_ms: null }, path, newPw, target, target === "PKCS12" ? mac : null, false);
      setWritten({ path: res.path, name: res.name, format: res.format, bytes: res.byte_length });
      return {
        path: res.path,
        format: `${FORMAT_INFO[res.format].label} keystore`,
        extension: ext,
        byte_length: res.byte_length,
        count: source.ks.entries.length,
        text: null,
        sensitive: true,
        notes: [
          `${source.label} was not changed.`,
          keepPw ? "Protected with the same password as the source." : "Protected with the new password.",
          ...(separate ? [`${separate} key${separate === 1 ? "" : "s"} with its own key password now use${separate === 1 ? "s" : ""} the keystore password, as PKCS#12 tools expect.`] : []),
        ],
        sha256: "—",
      };
    });
  };

  return (
    <Layout
      form={
        <>
          <Step title="Source keystore">
            {ui}
          </Step>
          <Step title="Output format">
            <OptionList
              label="Keystore output format"
              value={target}
              onChange={setTarget}
              options={KEYSTORE_FORMATS.map((f) => ({ value: f, label: FORMAT_INFO[f].label, hint: FORMAT_INFO[f].description, meta: `.${FORMAT_EXTENSION[f]}`, testId: `convert-format-${f}` }))}
            />
            {target === "PKCS12" && (
              <div className="mt-3">
                <Pkcs12ProfileSelect value={mac} onChange={setMac} testId="convert-pkcs12-profile" />
              </div>
            )}
          </Step>
          <Step title="Password">
            <div className="space-y-3">
              <Checkbox checked={keepPw} onChange={setKeepPw} label="Use the source keystore's password" />
              {!keepPw && (
                <div className="grid grid-cols-2 gap-3">
                  <PasswordInput label="New password" value={pw} onChange={setPw} data-testid="convert-ks-new-password" />
                  <PasswordInput label="Confirm" value={pw2} onChange={setPw2} error={pwError} data-testid="convert-ks-new-password-confirm" />
                </div>
              )}
              {keepPw && source && !source.password && <Alert tone="warning">The password of this keystore is not known. Enter a new one.</Alert>}
            </div>
          </Step>
          {problems.length > 0 && (
            <Alert tone="danger" title="This conversion would lose data">
              <ul className="list-disc pl-4 space-y-0.5">
                {problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </Alert>
          )}
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" icon={Repeat} onClick={convert} disabled={!ready || runner.busy} data-testid="convert-save">
              {runner.busy && <Spinner />} Convert & save…
            </Button>
            {written && (
              <Button icon={FolderOpen} onClick={() => openFiles([written.path])} data-testid="convert-open-result">
                Open {written.name}
              </Button>
            )}
          </div>
        </>
      }
      side={
        <>
          <ResultPanel runner={runner} empty="The converted keystore is written to a new file. The source is never modified." />
          <Hint command={cliHint("keystore", target, source?.ks.path || null)} />
        </>
      }
    />
  );
};

// ======================================================================= keystore -> PEM

const ExtractPanel: React.FC = () => {
  const { ensureKeyAccess, isKeyLocked, currentKeystores } = useStore();
  const runner = useRunner();
  const { source, ui } = useKeystoreSource();
  const [certs, setCerts] = useState<PemBundleOptions["certificates"]>("chain");
  const [keys, setKeys] = useState<PemBundleOptions["keys"]>("pkcs8");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [annotate, setAnnotate] = useState(false);
  const [picked, setPicked] = useState<ReadonlySet<string> | null>(null);
  useEffect(() => setPicked(null), [source?.ks.id, source?.ks.entries.length]);

  const entries = useMemo(() => [...(source?.ks.entries ?? [])].sort(byTypeThenAlias), [source?.ks.entries]);
  const chosen = entries.filter((e) => !picked || picked.has(e.id));
  // From an open keystore, private keys come out only after their key password was entered.
  const needUnlock = source?.fromApp && keys !== "none" ? chosen.filter((e) => e.entry_type === "KeyPair" && isKeyLocked(e)) : [];
  const pwError = keys === "encrypted" && pw2 && pw !== pw2 ? "Passwords do not match" : undefined;
  const ready = chosen.length > 0 && (certs !== "none" || keys !== "none") && (keys !== "encrypted" || (!!pw && pw === pw2));
  const options: PemBundleOptions = { certificates: certs, keys, password: keys === "encrypted" ? pw : null, annotate };
  /** Read again at call time: a key unlocked by `withKeys` is not in `chosen` as it was rendered. */
  const freshChosen = (): KeystoreEntry[] => {
    const appKs = source?.fromApp ? currentKeystores().find((k) => k.id === source.fromApp!.id) : undefined;
    if (!appKs) return chosen;
    return [...appKs.entries].sort(byTypeThenAlias).filter((e) => !picked || picked.has(e.id));
  };
  const convert = (out: string | null) => api.entriesToPem(freshChosen(), options, out);
  const withKeys = (fn: () => void) => (needUnlock.length && source?.fromApp ? ensureKeyAccess(source.fromApp.id, needUnlock.map((e) => e.id), fn) : fn());

  return (
    <Layout
      form={
        <>
          <Step title="Source keystore">
            {ui}
          </Step>
          {source && (
            <Step title="Entries" hint={`${chosen.length} of ${entries.length} selected`}>
              <div className="flex gap-2 mb-2">
                <Button size="sm" onClick={() => setPicked(null)}>
                  All
                </Button>
                <Button size="sm" onClick={() => setPicked(new Set())}>
                  None
                </Button>
              </div>
              <ul className="max-h-56 overflow-y-auto rounded-control border border-line divide-y divide-line" data-testid="convert-entries">
                {entries.map((e) => {
                  const on = !picked || picked.has(e.id);
                  return (
                    <li key={e.id}>
                      <label className="flex items-center gap-2.5 px-3 py-1.5 cursor-pointer hover:bg-surface-2">
                        <input
                          type="checkbox"
                          checked={on}
                          onChange={() => {
                            const base = new Set(picked ?? entries.map((x) => x.id));
                            if (on) base.delete(e.id);
                            else base.add(e.id);
                            setPicked(base);
                          }}
                        />
                        <EntryIcon type={e.entry_type} size="sm" locked={e.entry_type === "KeyPair" ? (source.fromApp ? isKeyLocked(e) : e.locked) : e.locked || undefined} />
                        <span className="text-[13px] text-ink truncate flex-1">{e.alias}</span>
                        <span className="text-[11.5px] text-faint shrink-0">{entryTypeName(e)}</span>
                      </label>
                    </li>
                  );
                })}
                {entries.length === 0 && <li className="px-3 py-2 text-[13px] text-faint">This keystore is empty.</li>}
              </ul>
            </Step>
          )}
          <Step title="What to write">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3">
                <span className="label !mb-0 w-28">Certificates</span>
                <Segmented<PemBundleOptions["certificates"]>
                  label="Certificates to include"
                  value={certs}
                  onChange={setCerts}
                  options={[
                    { value: "chain", label: "Full chain" },
                    { value: "leaf", label: "Leaf only" },
                    { value: "none", label: "None" },
                  ]}
                />
              </div>
              <Select label="Private keys" value={keys} onChange={(e) => setKeys(e.target.value as PemBundleOptions["keys"])} data-testid="convert-extract-keys">
                <option value="pkcs8">Unencrypted PKCS#8 (BEGIN PRIVATE KEY)</option>
                <option value="encrypted">Encrypted PKCS#8 (AES-256)</option>
                <option value="traditional">PKCS#1 / SEC1 (BEGIN RSA / EC PRIVATE KEY)</option>
                <option value="none">Don't include private keys</option>
              </Select>
              {keys === "encrypted" && (
                <div className="grid grid-cols-2 gap-3">
                  <PasswordInput label="Password for the keys" value={pw} onChange={setPw} />
                  <PasswordInput label="Confirm" value={pw2} onChange={setPw2} error={pwError} />
                </div>
              )}
              {keys !== "none" && keys !== "encrypted" && <Alert tone="warning">The private keys are written unencrypted. Protect the file.</Alert>}
              <Checkbox checked={annotate} onChange={setAnnotate} label="Label each entry with its alias" hint="Adds OpenSSL-style “Bag Attributes / friendlyName” lines between the PEM blocks." />
              {needUnlock.length > 0 && (
                <Alert tone="info" title={`${needUnlock.length} key pair${needUnlock.length === 1 ? " is" : "s are"} locked`}>
                  You will be asked for the key password before their private keys are written.
                </Alert>
              )}
            </div>
          </Step>
          <Actions
            runner={runner}
            disabled={!source || !ready}
            saveLabel="Save PEM…"
            onSave={() => withKeys(() => void runner.save(convert, { title: "Save PEM", input: source?.inputPath, stem: "keystore", ext: "pem" }))}
            onPreview={keys === "none" ? () => runner.preview(convert) : undefined}
            previewHint={keys === "none" ? undefined : "Private keys are never shown on screen"}
          />
        </>
      }
      side={
        <>
          <ResultPanel runner={runner} empty="One PEM file with the certificates and keys you chose, like openssl pkcs12 -nodes." />
          <Hint command={cliHint("extract", `${certs}:${keys}`, source?.ks.path || null)} />
        </>
      }
    />
  );
};

// ============================================================================ PKCS#12 build

const Pkcs12Panel: React.FC = () => {
  const builder = usePkcs12Builder("convert-p12");
  return (
    <Layout
      form={
        <>
          {builder.fields}
          <Button variant="primary" icon={FileOutput} onClick={builder.submit} disabled={builder.busy || !builder.ready} data-testid="convert-p12-submit">
            {builder.busy && <Spinner />} Create PKCS#12…
          </Button>
        </>
      }
      side={
        <>
          <Card className="space-y-2">
            <h3 className="text-[14px] font-semibold text-ink">How it works</h3>
            <ul className="text-[13px] text-muted space-y-1.5 list-disc pl-4">
              <li>The certificate can be a whole chain; extra certificates are ordered above the leaf.</li>
              <li>An encrypted private key needs its password; the passphrase protects the new file.</li>
              <li>The key must match the certificate, or nothing is written.</li>
            </ul>
          </Card>
          <Hint command={cliHint("pkcs12", "", builder.keyPath)} />
        </>
      }
    />
  );
};

// ================================================================================== page

const PANELS: Record<ConverterId, React.FC> = {
  certificate: CertificatePanel,
  truststore: TruststorePanel,
  private_key: PrivateKeyPanel,
  public_key: PublicKeyPanel,
  keystore: KeystorePanel,
  pkcs12: Pkcs12Panel,
  extract: ExtractPanel,
  encoding: EncodingPanel,
};

const Overview: React.FC = () => {
  const { openConverter } = useStore();
  return (
    <Page>
      <PageHeader icon={ConvertIcon} title="Convert" description="Change the format of certificates, keys and keystores. Everything runs locally; nothing leaves this computer." />
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {CONVERTERS.map((c, i) => {
          const Icon = CONVERTER_ICONS[c.id];
          // Seven tiles leave the last one alone on its row. It takes the full row, with its From/To beside it.
          const last = i === CONVERTERS.length - 1;
          const spanMd = last && CONVERTERS.length % 2 === 1;
          const spanXl = last && CONVERTERS.length % 3 === 1;
          return (
            <Card key={c.id} interactive onClick={() => openConverter(c.id)} data-testid={`convert-tile-${c.id}`} className={clsx("flex flex-col gap-3", spanMd && "md:col-span-2", spanXl && "xl:col-span-3 xl:flex-row xl:items-center xl:gap-8")} role="button" tabIndex={0} onKeyDown={(e) => {
              if (e.key !== "Enter" && e.key !== " ") return;
              e.preventDefault(); // Space would also scroll the page.
              openConverter(c.id);
            }}>
              <div className={clsx("flex items-start gap-3", spanXl && "xl:flex-1")}>
                <span className="w-9 h-9 rounded-card bg-brand-tint text-brand flex items-center justify-center shrink-0">
                  <Icon className="w-[18px] h-[18px]" />
                </span>
                <div className="min-w-0">
                  <h3 className="text-[14px] font-semibold text-ink">{c.title}</h3>
                  <p className="text-[13px] text-faint mt-0.5">{c.description}</p>
                </div>
              </div>
              <dl className={clsx("mt-auto grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-[12px]", spanXl && "xl:mt-0 xl:w-96 xl:shrink-0")}>
                <dt className="text-faint">From</dt>
                <dd className="text-ink-2 truncate" title={c.from}>
                  {c.from}
                </dd>
                <dt className="text-faint">To</dt>
                <dd className="text-ink-2 truncate" title={c.to}>
                  {c.to}
                </dd>
              </dl>
            </Card>
          );
        })}
      </div>
    </Page>
  );
};

export const ConvertView: React.FC = () => {
  const { convertMode, openConverter } = useStore();
  if (!convertMode) return <Overview />;
  const info = converterInfo(convertMode);
  const Panel = PANELS[convertMode];
  const Icon = CONVERTER_ICONS[convertMode];
  return (
    <Page>
      <PageHeader
        eyebrow={
          <button type="button" onClick={() => openConverter(null)} className="inline-flex items-center gap-1 text-brand font-medium hover:underline cursor-pointer" data-testid="convert-back">
            <ChevronLeft className="w-3.5 h-3.5" /> All conversions
          </button>
        }
        icon={Icon}
        title={info.title}
        description={info.description}
      />
      <div className={clsx("pb-8")} data-testid={`converter-${convertMode}`}>
        {/* Keyed so switching converters starts from a clean form. */}
        <Panel key={convertMode} />
      </div>
    </Page>
  );
};

export default ConvertView;
