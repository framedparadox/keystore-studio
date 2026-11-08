import React, { useEffect, useMemo, useState } from "react";
import { FolderOpen, KeyRound, Lock, ShieldCheck, Import, FileKey2, FolderArchive } from "lucide-react";
import type { GenerateKeyPairInput, KeystoreEntry, KeystoreFile, OpenKeystore } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { FILTERS, baseName, pickFile, pickSavePath, safeFileStem } from "../lib/files";
import { EXTENDED_KEY_USAGES, KEY_USAGES, aliasTaken, canHoldSecretKeys, cnOf, isCaEntry, profileUsages, pkcs12BuildReady, splitList, ENTRY_TYPE_LABEL, type CertProfileName } from "../lib/keystore";
import { useStore } from "../state/store";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { Alert, Badge, Button, Checkbox, Modal, PasswordInput, Select, Spinner, TextArea, TextInput, useToast } from "./ui";

type Profile = CertProfileName | "custom";

const PROFILE_LABELS: Record<CertProfileName, string> = {
  server: "TLS server",
  client: "TLS client / mTLS",
  codesign: "Code signing",
  ca: "Certificate authority",
};

/** CA key pairs from every loaded keystore that can issue certificates, with their lock state. */
export function useCaSigners() {
  const { keystores, isKeyLocked } = useStore();
  return useMemo(() => keystores.flatMap((ks) => ks.entries.filter(isCaEntry).map((entry) => ({ entry, ks, locked: isKeyLocked(entry) }))), [keystores, isKeyLocked]);
}

export const FileOrText: React.FC<{
  label: string;
  filters: typeof FILTERS[keyof typeof FILTERS][];
  path: string | null;
  setPath: (p: string | null) => void;
  text: string;
  setText: (t: string) => void;
  placeholder: string;
  testId?: string;
}> = ({ label, filters, path, setPath, text, setText, placeholder, testId }) => (
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
      <TextArea mono rows={6} placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} data-testid={testId} />
    )}
  </div>
);

// ----------------------------------------------------------------------------- key pair

export const GenerateKeyPairDialog: React.FC<{ keystore: OpenKeystore; open: boolean; onClose: () => void; presetCa?: boolean }> = ({ keystore, open, onClose, presetCa }) => {
  const { addEntries, ensureKeyAccess } = useStore();
  const toast = useToast();
  const signers = useCaSigners();
  const [alias, setAlias] = useState("");
  const [keySpec, setKeySpec] = useState("ECDSA:P-256");
  const [hash, setHash] = useState("SHA256");
  const [cn, setCn] = useState("");
  const [ou, setOu] = useState("");
  const [o, setO] = useState("");
  const [l, setL] = useState("");
  const [st, setSt] = useState("");
  const [c, setC] = useState("");
  const [email, setEmail] = useState("");
  const [fullDn, setFullDn] = useState("");
  const [useFullDn, setUseFullDn] = useState(false);
  const [sans, setSans] = useState("");
  const [days, setDays] = useState(365);
  const [notBefore, setNotBefore] = useState("");
  const [notAfter, setNotAfter] = useState("");
  const [crlUrl, setCrlUrl] = useState("");
  const [ocspUrl, setOcspUrl] = useState("");
  const [caIssuerUrl, setCaIssuerUrl] = useState("");
  const [signer, setSigner] = useState("");
  const [profile, setProfile] = useState<Profile>("server");
  const [isCa, setIsCa] = useState(false);
  const [pathLen, setPathLen] = useState("");
  const [ku, setKu] = useState<string[]>(() => profileUsages("server", "ECDSA").ku);
  const [eku, setEku] = useState<string[]>(() => profileUsages("server", "ECDSA").eku);
  const [labels, setLabels] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const applyProfile = (p: Profile, spec = keySpec) => {
    setProfile(p);
    if (p !== "custom") {
      const usage = profileUsages(p, spec.split(":")[0]);
      setIsCa(usage.isCa);
      setKu(usage.ku);
      setEku(usage.eku);
      if (usage.isCa) setDays((d) => (d < 1825 ? 3650 : d));
    }
  };

  useEffect(() => {
    if (!open) return;
    setAlias("");
    setCn("");
    setSans("");
    setError(null);
    setBusy(false);
    applyProfile(presetCa ? "ca" : "server");
    setDays(presetCa ? 3650 : 365);
  }, [open, presetCa]);

  if (!open) return null;
  const aliasError = alias.trim() && aliasTaken(keystore, alias) ? "An entry with this alias already exists" : undefined;
  const [algorithm, param] = keySpec.split(":");

  const submit = async (e?: React.FormEvent, caUnlocked = false) => {
    e?.preventDefault();
    setError(null);
    if (!alias.trim()) return setError("Enter an alias.");
    if (!useFullDn && !cn.trim()) return setError("Enter a common name (CN).");
    const chosen = signers.find((s) => s.entry.id === signer);
    if (chosen?.locked && !caUnlocked) {
      // Signing needs the CA's private key: ask for its key password, then carry on.
      ensureKeyAccess(chosen.ks.id, [chosen.entry.id], () => void submit(undefined, true));
      return;
    }
    setBusy(true);
    try {
      const input: GenerateKeyPairInput = {
        alias: alias.trim(),
        algorithm: algorithm as GenerateKeyPairInput["algorithm"],
        key_size: algorithm === "RSA" ? Number(param) : 0,
        curve: algorithm === "ECDSA" ? param : null,
        signature_hash: algorithm === "RSA" ? hash : null,
        subject_dn: useFullDn ? fullDn : "",
        common_name: cn,
        organizational_unit: ou,
        organization: o,
        locality: l,
        state: st,
        country: c,
        email,
        validity_days: Number(days),
        is_ca: isCa,
        path_len: isCa && pathLen.trim() !== "" ? Number(pathLen) : null,
        sans: splitList(sans),
        key_usage: ku,
        extended_key_usage: eku,
        labels: splitList(labels),
        not_before: notBefore,
        not_after: notAfter,
        crl_distribution_points: splitList(crlUrl),
        ocsp_urls: splitList(ocspUrl),
        ca_issuer_urls: splitList(caIssuerUrl),
      };
      const issuer = signers.find((s) => s.entry.id === signer)?.entry ?? null;
      const entry = await api.generateKeyPair(input, issuer);
      const [stored] = addEntries(keystore.id, [entry]);
      const note = entry.validity_note ? ` ${entry.validity_note}` : "";
      toast.success(`Generated ${entry.algorithm} key pair '${stored?.alias ?? entry.alias}'${issuer ? ` signed by ${issuer.alias}` : " (self-signed)"}.${note}`);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const toggle = (list: string[], set: (v: string[]) => void, id: string) => {
    set(list.includes(id) ? list.filter((x) => x !== id) : [...list, id]);
    setProfile("custom");
  };

  return (
    <Modal
      open
      busy={busy}
      onClose={onClose}
      icon={KeyRound}
      size="xl"
      title="Generate key pair"
      description={`Creates a private key and an X.509 certificate in ${keystore.name}.`}
      testId="generate-keypair-dialog"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="gen-kp-form" disabled={busy || !!aliasError} data-testid="generate-keypair-submit">
            {busy && <Spinner />} {busy ? (algorithm === "RSA" && Number(param) >= 4096 ? "Generating (RSA-4096 takes a few seconds)…" : "Generating…") : "Generate"}
          </Button>
        </>
      }
    >
      <form id="gen-kp-form" onSubmit={submit} className="grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-4">
        <div className="space-y-4">
          <TextInput label="Alias" value={alias} onChange={(e) => setAlias(e.target.value)} error={aliasError} placeholder="e.g. api-server" autoFocus data-testid="kp-alias" />
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Key"
              value={keySpec}
              onChange={(e) => {
                const next = e.target.value;
                setKeySpec(next);
                if (profile !== "custom") applyProfile(profile, next);
              }}
              data-testid="kp-key"
            >
              <optgroup label="Elliptic curve">
                <option value="ECDSA:P-256">ECDSA P-256 (recommended)</option>
                <option value="ECDSA:P-384">ECDSA P-384</option>
                <option value="ECDSA:P-521">ECDSA P-521</option>
                <option value="Ed25519:0">Ed25519</option>
              </optgroup>
              <optgroup label="RSA">
                <option value="RSA:2048">RSA 2048</option>
                <option value="RSA:3072">RSA 3072</option>
                <option value="RSA:4096">RSA 4096</option>
              </optgroup>
            </Select>
            {algorithm === "RSA" ? (
              <Select label="Signature hash" value={hash} onChange={(e) => setHash(e.target.value)}>
                <option value="SHA256">SHA-256</option>
                <option value="SHA384">SHA-384</option>
                <option value="SHA512">SHA-512</option>
              </Select>
            ) : (
              <TextInput label="Validity (days)" type="number" min={1} max={36500} value={days} onChange={(e) => setDays(Number(e.target.value))} />
            )}
          </div>
          {algorithm === "RSA" && <TextInput label="Validity (days)" type="number" min={1} max={36500} value={days} onChange={(e) => setDays(Number(e.target.value))} />}
          <div className="grid grid-cols-2 gap-3">
            <TextInput label="Not before" type="date" value={notBefore} onChange={(e) => setNotBefore(e.target.value)} hint="Optional. Otherwise the certificate starts now." />
            <TextInput label="Not after" type="date" value={notAfter} onChange={(e) => setNotAfter(e.target.value)} hint="Optional. Overrides the day count." />
          </div>
          <TextInput label="CRL distribution point" value={crlUrl} onChange={(e) => setCrlUrl(e.target.value)} placeholder="http://ca.example/crl.pem" />
          <div className="grid grid-cols-2 gap-3">
            <TextInput label="OCSP URL (AIA)" value={ocspUrl} onChange={(e) => setOcspUrl(e.target.value)} placeholder="http://ocsp.example" />
            <TextInput label="CA Issuers URL (AIA)" value={caIssuerUrl} onChange={(e) => setCaIssuerUrl(e.target.value)} placeholder="http://ca.example/ca.crt" />
          </div>
          <Select
            label="Signed by"
            value={signer}
            onChange={(e) => setSigner(e.target.value)}
            hint={
              !signers.length
                ? "No CA key pairs are open; the certificate will be self-signed."
                : signers.find((s) => s.entry.id === signer)?.locked
                  ? "This CA is locked. You will be asked for its key password."
                  : "Pick a CA from any open keystore, or self-sign."
            }
            data-testid="kp-signer"
          >
            <option value="">Self-signed</option>
            {signers.map((s) => (
              <option key={s.entry.id} value={s.entry.id}>
                {s.entry.alias} — {cnOf(s.entry.subject)} ({s.ks.name}){s.locked ? " · locked" : ""}
              </option>
            ))}
          </Select>
          <Select label="Certificate profile" value={profile} onChange={(e) => applyProfile(e.target.value as Profile)}>
            {(Object.entries(PROFILE_LABELS) as [CertProfileName, string][]).map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
            <option value="custom">Custom</option>
          </Select>
          <TextInput label="Subject alternative names" value={sans} onChange={(e) => setSans(e.target.value)} placeholder="api.example.com, *.example.com, 10.0.0.5" hint="Hostnames, IPs, e-mails or URIs, comma-separated." data-testid="kp-sans" />
          <TextInput label="Labels" value={labels} onChange={(e) => setLabels(e.target.value)} placeholder="production, team-a" />
        </div>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="label !mb-0">Subject</span>
            <button type="button" className="text-[12px] text-brand font-medium cursor-pointer" onClick={() => setUseFullDn((v) => !v)}>
              {useFullDn ? "Use fields" : "Enter full DN"}
            </button>
          </div>
          {useFullDn ? (
            <TextInput value={fullDn} onChange={(e) => setFullDn(e.target.value)} placeholder="CN=api.example.com, OU=Platform, O=Example Inc, C=US" className="font-mono !text-[12px]" />
          ) : (
            <div className="grid grid-cols-2 gap-3">
              <TextInput label="Common name (CN)" value={cn} onChange={(e) => setCn(e.target.value)} className="col-span-2" placeholder="api.example.com" data-testid="kp-cn" />
              <TextInput label="Organization (O)" value={o} onChange={(e) => setO(e.target.value)} />
              <TextInput label="Org. unit (OU)" value={ou} onChange={(e) => setOu(e.target.value)} />
              <TextInput label="Locality (L)" value={l} onChange={(e) => setL(e.target.value)} />
              <TextInput label="State (ST)" value={st} onChange={(e) => setSt(e.target.value)} />
              <TextInput label="Country (C)" value={c} onChange={(e) => setC(e.target.value.toUpperCase().slice(0, 2))} placeholder="US" />
              <TextInput label="E-mail" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
          )}
          <div className="rounded-card border border-line p-3.5 space-y-3">
            <Checkbox
              checked={isCa}
              onChange={(v) => {
                setIsCa(v);
                setProfile("custom");
              }}
              label="Certificate authority (BasicConstraints CA:TRUE)"
            />
            {isCa && <TextInput label="Path length constraint" type="number" min={0} value={pathLen} onChange={(e) => setPathLen(e.target.value)} placeholder="Unlimited" />}
            <div>
              <span className="label">Key usage</span>
              <div className="grid grid-cols-2 gap-1.5">
                {KEY_USAGES.map((k) => (
                  <Checkbox key={k.id} checked={ku.includes(k.id)} onChange={() => toggle(ku, setKu, k.id)} label={k.label} />
                ))}
              </div>
            </div>
            <div>
              <span className="label">Extended key usage</span>
              <div className="grid grid-cols-2 gap-1.5">
                {EXTENDED_KEY_USAGES.map((k) => (
                  <Checkbox key={k.id} checked={eku.includes(k.id)} onChange={() => toggle(eku, setEku, k.id)} label={k.label} />
                ))}
              </div>
            </div>
          </div>
        </div>
        {error && (
          <Alert tone="danger" className="lg:col-span-2">
            {error}
          </Alert>
        )}
      </form>
    </Modal>
  );
};

// ---------------------------------------------------------------------------- secret key

export const GenerateSecretKeyDialog: React.FC<{ keystore: OpenKeystore; open: boolean; onClose: () => void }> = ({ keystore, open, onClose }) => {
  const { addEntries } = useStore();
  const toast = useToast();
  const [alias, setAlias] = useState("");
  const [alg, setAlg] = useState("AES");
  const [bits, setBits] = useState(256);
  const [hexKey, setHexKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open) {
      setAlias("");
      setHexKey("");
      setError(null);
    }
  }, [open]);
  if (!open) return null;
  const sizes: Record<string, number[]> = { AES: [128, 192, 256], HmacSHA256: [256, 512], HmacSHA384: [384, 512], HmacSHA512: [512, 1024], DESede: [192] };
  const supported = canHoldSecretKeys(keystore.format);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!alias.trim()) return setError("Enter an alias.");
    if (aliasTaken(keystore, alias)) return setError("An entry with this alias already exists.");
    setBusy(true);
    try {
      const entry = await api.generateSecretKey({ alias: alias.trim(), algorithm: alg, key_size: bits, custom_hex: hexKey.trim() || null, labels: [] });
      addEntries(keystore.id, [entry]);
      toast.success(`Generated ${entry.algorithm} ${entry.key_size}-bit secret key '${entry.alias}'.`);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={onClose}
      icon={Lock}
      size="sm"
      title="Generate secret key"
      testId="secret-key-dialog"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="gen-sk-form" disabled={busy || !supported} data-testid="secret-key-submit">
            {busy && <Spinner />} Generate
          </Button>
        </>
      }
    >
      {!supported ? (
        <Alert tone="warning" title="JKS cannot store secret keys">
          Use “Save as…” to convert {keystore.name} to PKCS#12 or JCEKS first.
        </Alert>
      ) : (
        <form id="gen-sk-form" onSubmit={submit} className="space-y-4">
          <TextInput label="Alias" value={alias} onChange={(e) => setAlias(e.target.value)} autoFocus data-testid="sk-alias" />
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Algorithm"
              value={alg}
              onChange={(e) => {
                setAlg(e.target.value);
                setBits(sizes[e.target.value][sizes[e.target.value].length - 1]);
              }}
            >
              <option value="AES">AES</option>
              <option value="HmacSHA256">HMAC-SHA256</option>
              <option value="HmacSHA384">HMAC-SHA384</option>
              <option value="HmacSHA512">HMAC-SHA512</option>
              <option value="DESede">Triple DES (legacy)</option>
            </Select>
            <Select label="Size" value={bits} onChange={(e) => setBits(Number(e.target.value))} disabled={!!hexKey.trim()}>
              {sizes[alg].map((s) => (
                <option key={s} value={s}>
                  {s} bits
                </option>
              ))}
            </Select>
          </div>
          <TextInput label="Key material (optional)" value={hexKey} onChange={(e) => setHexKey(e.target.value)} placeholder="Hex; leave empty to generate randomly" className="font-mono !text-[12px]" hint="Import an existing key by pasting its hex value." />
          {alg === "DESede" && <Alert tone="warning">Triple DES is deprecated; use AES for new keys.</Alert>}
          {error && <Alert tone="danger">{error}</Alert>}
        </form>
      )}
    </Modal>
  );
};

// ------------------------------------------------------------------------- certificates

export const ImportCertificateDialog: React.FC<{ keystore: OpenKeystore; open: boolean; onClose: () => void; initialText?: string }> = ({ keystore, open, onClose, initialText }) => {
  const { addEntries } = useStore();
  const toast = useToast();
  const [alias, setAlias] = useState("");
  const [path, setPath] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open) {
      setAlias("");
      setPath(null);
      setText(initialText ?? "");
      setError(null);
    }
  }, [open, initialText]);
  if (!open) return null;
  const submit = async () => {
    setError(null);
    setBusy(true);
    try {
      const fallback = path ? baseName(path).replace(/\.[^.]+$/, "") : "trusted-cert";
      const entries = await api.importTrustedCertificates(alias.trim() || fallback, path ? { path } : { text }, keystore.entries.map((e) => e.alias));
      addEntries(keystore.id, entries);
      toast.success(entries.length === 1 ? `Imported trusted certificate '${entries[0].alias}' (${cnOf(entries[0].subject)}).` : `Imported ${entries.length} trusted certificates.`);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={onClose}
      icon={ShieldCheck}
      title="Import trusted certificates"
      description="PEM (one or many), DER or PKCS#7. A bundle creates one entry per certificate."
      testId="import-cert-dialog"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || (!path && !text.trim())} data-testid="import-cert-submit">
            {busy && <Spinner />} Import
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <TextInput label="Alias" value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="Defaults to the file name" data-testid="import-cert-alias" />
        <FileOrText label="Certificate" filters={[FILTERS.certificates]} path={path} setPath={setPath} text={text} setText={setText} placeholder="-----BEGIN CERTIFICATE-----" testId="import-cert-text" />
        {error && <Alert tone="danger">{error}</Alert>}
      </div>
    </Modal>
  );
};

export const ImportKeyPairDialog: React.FC<{ keystore: OpenKeystore; open: boolean; onClose: () => void }> = ({ keystore, open, onClose }) => {
  const { addEntries } = useStore();
  const toast = useToast();
  const [alias, setAlias] = useState("");
  const [keyPath, setKeyPath] = useState<string | null>(null);
  const [keyText, setKeyText] = useState("");
  const [keyPw, setKeyPw] = useState("");
  const [certPath, setCertPath] = useState<string | null>(null);
  const [certText, setCertText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open) {
      setAlias("");
      setKeyPath(null);
      setKeyText("");
      setKeyPw("");
      setCertPath(null);
      setCertText("");
      setError(null);
    }
  }, [open]);
  if (!open) return null;
  const submit = async () => {
    setError(null);
    if (!alias.trim()) return setError("Enter an alias.");
    if (aliasTaken(keystore, alias)) return setError("An entry with this alias already exists.");
    setBusy(true);
    try {
      const certs = certPath ? { path: certPath } : certText.trim() ? { text: certText } : null;
      const entry = await api.importKeyPair(alias.trim(), keyPath ? { path: keyPath } : { text: keyText }, keyPw || null, certs);
      addEntries(keystore.id, [entry]);
      toast.success(`Imported key pair '${entry.alias}' with a chain of ${entry.chain_length}.`);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={onClose}
      icon={FileKey2}
      size="lg"
      title="Import key pair"
      description="A private key (PKCS#8, PKCS#1 or SEC1; PEM or DER; optionally encrypted) and its certificate chain."
      testId="import-keypair-dialog"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || (!keyPath && !keyText.trim())} data-testid="import-keypair-submit">
            {busy && <Spinner />} Import
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <TextInput label="Alias" value={alias} onChange={(e) => setAlias(e.target.value)} data-testid="import-kp-alias" />
        <FileOrText label="Private key" filters={[FILTERS.keys]} path={keyPath} setPath={setKeyPath} text={keyText} setText={setKeyText} placeholder="-----BEGIN PRIVATE KEY-----" testId="import-kp-key" />
        <PasswordInput label="Key password (if encrypted)" value={keyPw} onChange={setKeyPw} />
        <FileOrText label="Certificate chain (optional if included above)" filters={[FILTERS.certificates]} path={certPath} setPath={setCertPath} text={certText} setText={setCertText} placeholder="-----BEGIN CERTIFICATE-----" testId="import-kp-certs" />
        {error && <Alert tone="danger">{error}</Alert>}
      </div>
    </Modal>
  );
};

// --------------------------------------------------------------------- from another store

export const ImportFromKeystoreDialog: React.FC<{ keystore: OpenKeystore; open: boolean; onClose: () => void }> = ({ keystore, open, onClose }) => {
  const { addEntries } = useStore();
  const toast = useToast();
  const [path, setPath] = useState<string | null>(null);
  const [pw, setPw] = useState("");
  const [source, setSource] = useState<KeystoreFile | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open) {
      setPath(null);
      setPw("");
      setSource(null);
      setSelected([]);
      setError(null);
    }
  }, [open]);
  if (!open) return null;
  const load = async () => {
    if (!path) return;
    setBusy(true);
    setError(null);
    try {
      const ks = await api.openKeystore(path, pw);
      setSource(ks);
      setSelected(ks.entries.filter((e) => !(e.entry_type === "SecretKey" && !canHoldSecretKeys(keystore.format))).map((e) => e.id));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const importSelected = () => {
    if (!source) return;
    const chosen = source.entries.filter((e) => selected.includes(e.id));
    const added = addEntries(keystore.id, chosen as KeystoreEntry[]);
    const renamed = added.filter((a, i) => a.alias !== chosen[i].alias).length;
    toast.success(`Imported ${added.length} entr${added.length === 1 ? "y" : "ies"} from ${source.name}${renamed ? ` (${renamed} renamed to avoid alias clashes)` : ""}.`);
    onClose();
  };
  return (
    <Modal
      open
      busy={busy}
      onClose={onClose}
      icon={Import}
      size="lg"
      title={`Import entries into ${keystore.name}`}
      description="Copy key pairs, certificates and secret keys from another keystore file."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          {source ? (
            <Button variant="primary" onClick={importSelected} disabled={!selected.length}>
              Import {selected.length} selected
            </Button>
          ) : (
            <Button variant="primary" onClick={load} disabled={busy || !path || !pw}>
              {busy && <Spinner />} Read keystore
            </Button>
          )}
        </>
      }
    >
      {!source ? (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Button
              icon={FolderOpen}
              onClick={async () => {
                const p = await pickFile("Select a keystore", [FILTERS.keystores]).catch(() => null);
                if (p) setPath(p);
              }}
            >
              Choose keystore…
            </Button>
            {path && <span className="font-mono text-[12.5px] text-muted truncate">{path}</span>}
          </div>
          <PasswordInput label="Its password" value={pw} onChange={setPw} />
          {error && <Alert tone="danger">{error}</Alert>}
        </div>
      ) : (
        <ul className="divide-y divide-line border border-line rounded-card">
          {source.entries.map((e) => {
            const unsupported = e.entry_type === "SecretKey" && !canHoldSecretKeys(keystore.format);
            return (
              <li key={e.id} className="px-4 py-2.5 flex items-center gap-3">
                <input
                  type="checkbox"
                  className="w-4 h-4"
                  disabled={unsupported}
                  checked={selected.includes(e.id)}
                  onChange={() => setSelected((s) => (s.includes(e.id) ? s.filter((x) => x !== e.id) : [...s, e.id]))}
                  aria-label={`Import ${e.alias}`}
                />
                <span className="flex-1 min-w-0">
                  <span className="block text-[13px] font-medium text-ink truncate">{e.alias}</span>
                  <span className="block text-[12px] text-faint truncate">{unsupported ? `${keystore.format} cannot hold secret keys` : e.entry_type === "SecretKey" ? e.subject : cnOf(e.subject)}</span>
                </span>
                <Badge>{ENTRY_TYPE_LABEL[e.entry_type]}</Badge>
                {aliasTaken(keystore, e.alias) && <Badge tone="warning">Will be renamed</Badge>}
              </li>
            );
          })}
        </ul>
      )}
    </Modal>
  );
};

// ------------------------------------------------------------------ build a PKCS#12 from files

/**
 * State, fields and submit action for building a .p12/.pfx from a certificate, its private key and
 * a passphrase, without an open keystore. The engine matches the key to the certificate before
 * writing, so a mismatched pair is reported here rather than producing a file no tool accepts.
 * Used by the "Create PKCS#12" dialog and inline on the Convert page; `testIdPrefix` keeps their
 * test ids apart.
 */
export function usePkcs12Builder(testIdPrefix = "build-p12") {
  const toast = useToast();
  const [alias, setAlias] = useState("");
  const [certPath, setCertPath] = useState<string | null>(null);
  const [certText, setCertText] = useState("");
  const [keyPath, setKeyPath] = useState<string | null>(null);
  const [keyText, setKeyText] = useState("");
  const [keyPw, setKeyPw] = useState("");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [mac, setMac] = useState<"pkcs12" | "pbmac1">("pkcs12");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const reset = () => {
    setAlias("");
    setCertPath(null);
    setCertText("");
    setKeyPath(null);
    setKeyText("");
    setKeyPw("");
    setPass("");
    setPass2("");
    setMac("pkcs12");
    setError(null);
    setDone(null);
  };

  const hasCert = !!certPath || !!certText.trim();
  const hasKey = !!keyPath || !!keyText.trim();
  const mismatch = !!pass2 && pass !== pass2;
  const ready = pkcs12BuildReady({ hasCertificate: hasCert, hasKey, passphrase: pass, confirm: pass2 });

  const submit = async () => {
    setError(null);
    setDone(null);
    const stem = alias.trim() || (certPath ? baseName(certPath).replace(/\.[^.]+$/, "") : "certificate");
    const path = await pickSavePath("Save PKCS#12", `${safeFileStem(stem)}.p12`, [FILTERS.keystores]).catch(() => null);
    if (!path) return;
    setBusy(true);
    try {
      const res = await api.buildPkcs12({
        path,
        key: keyPath ? { path: keyPath } : { text: keyText },
        certificate: certPath ? { path: certPath } : certText.trim() ? { text: certText } : null,
        keyPassword: keyPw || null,
        passphrase: pass,
        alias: alias.trim() || null,
        mac,
      });
      setDone(res.path);
      toast.success(`Wrote ${baseName(res.path)} (${res.byte_length.toLocaleString()} bytes). Open it with the passphrase you just set.`, {
        label: "Show in folder",
        onClick: () => void revealItemInDir(res.path).catch(() => undefined),
      });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const fields = (
    <div className="space-y-4">
      <FileOrText
        label="Certificate (or full chain)"
        filters={[FILTERS.certificates]}
        path={certPath}
        setPath={setCertPath}
        text={certText}
        setText={setCertText}
        placeholder="-----BEGIN CERTIFICATE-----"
        testId={`${testIdPrefix}-cert`}
      />
      <FileOrText
        label="Private key"
        filters={[FILTERS.keys]}
        path={keyPath}
        setPath={setKeyPath}
        text={keyText}
        setText={setKeyText}
        placeholder="-----BEGIN PRIVATE KEY-----"
        testId={`${testIdPrefix}-key`}
      />
      <PasswordInput label="Password of the private key (only if it is encrypted)" value={keyPw} onChange={setKeyPw} data-testid={`${testIdPrefix}-keypw`} />
      <div className="grid grid-cols-2 gap-3">
        <PasswordInput label="Passphrase for the new file" value={pass} onChange={setPass} data-testid={`${testIdPrefix}-pass`} />
        <PasswordInput
          label="Confirm passphrase"
          value={pass2}
          onChange={setPass2}
          error={mismatch ? "Passphrases do not match" : undefined}
          data-testid={`${testIdPrefix}-pass-confirm`}
        />
      </div>
      <TextInput
        label="Alias (friendly name)"
        value={alias}
        onChange={(e) => setAlias(e.target.value)}
        placeholder="Defaults to the certificate file name"
        data-testid={`${testIdPrefix}-alias`}
      />
      <Select
        label="Integrity MAC"
        value={mac}
        onChange={(e) => setMac(e.target.value as "pkcs12" | "pbmac1")}
        hint="The legacy MAC is read by every tool. PBMAC1 needs OpenSSL 3.4 or newer."
      >
        <option value="pkcs12">Legacy PKCS#12 MAC (compatible)</option>
        <option value="pbmac1">PBMAC1 (RFC 9579)</option>
      </Select>
      {error && <Alert tone="danger">{error}</Alert>}
      {done && (
        <Alert tone="success" title="PKCS#12 created">
          <span className="font-mono text-[12px] break-all">{done}</span>
        </Alert>
      )}
      <Alert tone="info">
        The key is matched against the certificate before anything is written. The file holds private key material — protect it with a strong passphrase.
      </Alert>
    </div>
  );

  return { fields, submit, ready, busy, done, reset, keyPath, certPath };
}

/** The PKCS#12 builder as a dialog, opened from the dashboard, command palette and Convert page. */
export const BuildPkcs12Dialog: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const builder = usePkcs12Builder("build-p12");
  const { reset } = builder;
  useEffect(() => {
    if (open) reset();
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!open) return null;
  return (
    <Modal
      open
      busy={builder.busy}
      onClose={onClose}
      icon={FolderArchive}
      size="lg"
      title="Create PKCS#12 (.p12 / .pfx)"
      description="Bundle a certificate and its private key into one password-protected file."
      testId="build-p12-dialog"
      footer={
        <>
          <Button onClick={onClose}>{builder.done ? "Close" : "Cancel"}</Button>
          <Button variant="primary" onClick={builder.submit} disabled={builder.busy || !builder.ready} data-testid="build-p12-submit">
            {builder.busy && <Spinner />} Create…
          </Button>
        </>
      }
    >
      {builder.fields}
    </Modal>
  );
};
