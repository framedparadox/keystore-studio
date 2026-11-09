import React, { useLayoutEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { Download, Eye, FileSignature, FolderOpen, Layers, Plus, Reply, Save, Tag, Trash2, Edit3, X, AlertTriangle, Unlock } from "lucide-react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import type { KeystoreEntry, OpenKeystore } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { FILTERS, pickFile, pickSavePath, safeFileStem } from "../lib/files";
import { EXPORT_TARGETS, aliasTaken, canonicalAlias, cnOf, ENTRY_TYPE_LABEL, splitList } from "../lib/keystore";
import { findingsFor } from "../lib/metrics";
import { useStore, uid } from "../state/store";
import { Alert, Badge, Button, CodeBlock, Modal, PasswordInput, Segmented, Select, Spinner, TextArea, TextInput, useConfirm, useToast } from "./ui";
import { CertificateDetails, ChainView, ExtensionsList } from "./CertificateView";
import { HealthBadge } from "./entry";

/** Toast with a "Show in folder" action for a file we just wrote. */
export function useSavedToast() {
  const toast = useToast();
  return (message: string, path: string) =>
    toast.success(message, {
      label: "Show in folder",
      onClick: () => void revealItemInDir(path).catch(() => undefined),
    });
}

/**
 * Saves text produced in the UI (CSR, CRL, JWT …) to a file the user picks. Resolves to the path
 * written, or null when the user cancelled or the write failed, so a dialog that stays open can
 * show the outcome where it happened.
 */
export function useSaveText() {
  const toast = useToast();
  const saved = useSavedToast();
  return async (defaultName: string, content: string, what = "File"): Promise<string | null> => {
    try {
      const path = await pickSavePath(`Save ${what}`, defaultName);
      if (!path) return null;
      await api.writeTextFile(path, content);
      saved(`${what} saved to ${path}`, path);
      return path;
    } catch (err) {
      toast.error(errorMessage(err));
      return null;
    }
  };
}

/** "Saved" note with Show in folder, for dialogs that stay open after writing a file. */
const SavedNote: React.FC<{ title: string; path: string }> = ({ title, path }) => (
  <Alert
    tone="success"
    title={title}
    action={
      <Button size="sm" icon={FolderOpen} onClick={() => void revealItemInDir(path).catch(() => undefined)}>
        Show in folder
      </Button>
    }
  >
    <span className="font-mono text-[12px] break-all" data-testid="saved-path">
      {path}
    </span>
  </Alert>
);

// ----------------------------------------------------------------------------------- export

export const ExportDialog: React.FC<{ entry: KeystoreEntry | null; keystoreId?: string; onClose: () => void }> = ({ entry: given, keystoreId, onClose }) => {
  const toast = useToast();
  const saved = useSavedToast();
  const { keystores, isKeyLocked, ensureKeyAccess } = useStore();
  // The entry as it is now: an unlock replaces it, and a copy taken before would still be locked.
  const entry = (given && keystoreId ? keystores.find((k) => k.id === keystoreId)?.entries.find((e) => e.id === given.id) : undefined) ?? given;
  const targets = useMemo(() => (entry ? EXPORT_TARGETS.filter((t) => t.appliesTo.includes(entry.entry_type)) : []), [entry?.id, entry?.entry_type]); // eslint-disable-line react-hooks/exhaustive-deps
  const [target, setTarget] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [written, setWritten] = useState<{ path: string; summary: string } | null>(null);
  useLayoutEffect(() => {
    setTarget(targets[0]?.id ?? "");
    setPw("");
    setPw2("");
    setPreview(null);
    setWritten(null);
  }, [entry?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!entry) return null;
  const t = targets.find((x) => x.id === target);
  const needsKey = t?.group === "Private key" || t?.group === "Secret key" || (t?.id === "pkcs12" && entry.entry_type !== "TrustedCertificate");
  // The session lock counts, not only the engine's: a key pair that opened locked must be unlocked
  // with its password before its private key leaves the app, whichever way this dialog was reached.
  const keyLocked = isKeyLocked(entry);
  const blocked = needsKey && (keyLocked || (entry.entry_type === "KeyPair" ? !entry.private_key_pem : !entry.secret_key_hex));
  const run = async () => {
    if (!t) return;
    try {
      const path = await pickSavePath(`Export ${entry.alias}`, `${safeFileStem(entry.alias)}.${t.ext}`);
      if (!path) return;
      setBusy(true);
      const res = await api.exportEntry(entry, t.id, path, t.needsPassword ? pw : null);
      setPreview(res.text ?? null);
      setWritten({ path: res.path, summary: `${res.format} · ${res.byte_length.toLocaleString()} bytes` });
      saved(`Exported ${entry.alias} as ${res.format} (${res.byte_length.toLocaleString()} bytes).`, res.path);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const groups = [...new Set(targets.map((x) => x.group))];
  return (
    <Modal
      open
      busy={busy}
      onClose={onClose}
      icon={Download}
      title={`Export ${entry.alias}`}
      description={ENTRY_TYPE_LABEL[entry.entry_type]}
      testId="export-dialog"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Close
          </Button>
          <Button variant="primary" onClick={run} disabled={busy || !t || blocked || (t.needsPassword && (!pw || pw !== pw2))} data-testid="export-run">
            {busy && <Spinner />} Export…
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Select
          label="Format"
          value={target}
          onChange={(e) => {
            setTarget(e.target.value);
            setWritten(null);
            setPreview(null);
          }}
          data-testid="export-format"
        >
          {groups.map((g) => (
            <optgroup key={g} label={g}>
              {targets
                .filter((x) => x.group === g)
                .map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.label}
                  </option>
                ))}
            </optgroup>
          ))}
        </Select>
        {t?.needsPassword && (
          <div className="grid grid-cols-2 gap-3">
            <PasswordInput label={t.id === "pkcs12" ? "PKCS#12 password" : "Encryption password"} value={pw} onChange={setPw} data-testid="export-password" />
            <PasswordInput label="Confirm" value={pw2} onChange={setPw2} error={pw2 && pw !== pw2 ? "Passwords do not match" : undefined} data-testid="export-password-confirm" />
          </div>
        )}
        {blocked && (
          <Alert
            tone="warning"
            title="The key is locked"
            action={
              keystoreId && keyLocked ? (
                <Button size="sm" icon={Unlock} onClick={() => ensureKeyAccess(keystoreId, [entry.id])} data-testid="export-unlock">
                  Unlock…
                </Button>
              ) : undefined
            }
          >
            Enter its key password before exporting {entry.entry_type === "SecretKey" ? "the key material" : "the private key"}.
          </Alert>
        )}
        {t?.sensitive && !blocked && (
          <Alert tone="warning" title="Sensitive export">
            {t.needsPassword ? "The file contains key material protected by the password above." : "The file contains unencrypted key material. Store it securely and delete it when no longer needed."}
          </Alert>
        )}
        {written && <SavedNote title={`Exported · ${written.summary}`} path={written.path} />}
        {preview && <CodeBlock label="Exported content" value={preview} maxHeight={220} />}
      </div>
    </Modal>
  );
};

// --------------------------------------------------------------------------------------- CSR

export const CsrDialog: React.FC<{ entry: KeystoreEntry | null; onClose: () => void }> = ({ entry, onClose }) => {
  const toast = useToast();
  const saveText = useSaveText();
  const [subject, setSubject] = useState("");
  const [sans, setSans] = useState("");
  const [hash, setHash] = useState("SHA256");
  const [busy, setBusy] = useState(false);
  const [pemOut, setPemOut] = useState<string | null>(null);
  const [savedTo, setSavedTo] = useState<string | null>(null);
  useLayoutEffect(() => {
    if (!entry) return;
    setSubject(entry.subject);
    setSans((entry.certificate_chain[0]?.sans ?? []).join(", "));
    setPemOut(null);
    setSavedTo(null);
  }, [entry?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  // Editing the request after generating it discards the old CSR, so what is shown and saved
  // always matches the fields.
  const edit = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setPemOut(null);
    setSavedTo(null);
  };
  if (!entry) return null;
  const generate = async () => {
    setBusy(true);
    try {
      const res = await api.generateCsr(entry, { subject_dn: subject, sans: splitList(sans), signature_hash: entry.algorithm === "RSA" ? hash : null });
      setPemOut(res.csr_pem);
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
      icon={FileSignature}
      title={`Certificate signing request for ${entry.alias}`}
      description="Send the CSR to your CA, then install the reply with “Import CA reply”."
      size="lg"
      testId="csr-dialog"
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          {pemOut ? (
            <Button variant="primary" icon={Save} onClick={async () => setSavedTo((await saveText(`${safeFileStem(entry.alias)}.csr`, pemOut, "CSR")) ?? savedTo)} data-testid="csr-save">
              Save CSR…
            </Button>
          ) : (
            <Button variant="primary" onClick={generate} disabled={busy} data-testid="csr-generate">
              {busy && <Spinner />} Generate CSR
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <TextInput label="Subject (RFC 4514)" value={subject} onChange={(e) => edit(setSubject)(e.target.value)} hint="Defaults to the current certificate's subject." className="font-mono !text-[12px]" />
        <TextInput label="Subject alternative names" value={sans} onChange={(e) => edit(setSans)(e.target.value)} hint="Comma-separated: DNS:host, IP:10.0.0.1, email:ops@example.com" />
        {entry.algorithm === "RSA" && (
          <Select label="Signature hash" value={hash} onChange={(e) => edit(setHash)(e.target.value)}>
            <option value="SHA256">SHA-256</option>
            <option value="SHA384">SHA-384</option>
            <option value="SHA512">SHA-512</option>
          </Select>
        )}
        {savedTo && <SavedNote title="CSR saved" path={savedTo} />}
        {pemOut && <CodeBlock label="PKCS#10 request" value={pemOut} testId="csr-output" />}
      </div>
    </Modal>
  );
};

// ----------------------------------------------------------------------------------- CA reply

export const CaReplyDialog: React.FC<{ keystore: OpenKeystore; entry: KeystoreEntry | null; onClose: () => void }> = ({ keystore, entry, onClose }) => {
  const { replaceEntry } = useStore();
  const toast = useToast();
  const [text, setText] = useState("");
  const [path, setPath] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useLayoutEffect(() => {
    setText("");
    setPath(null);
    setError(null);
  }, [entry?.id]);
  if (!entry) return null;
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.importCaReply(entry, path ? { path } : { text });
      replaceEntry(keystore.id, { ...updated, id: entry.id });
      toast.success(`Installed the CA reply for ${entry.alias}: chain of ${updated.chain_length}, issued by ${cnOf(updated.issuer)}.`);
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
      icon={Reply}
      title={`Import CA reply into ${entry.alias}`}
      description="The signed certificate (and optionally its chain) as PEM, DER or PKCS#7."
      testId="ca-reply-dialog"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={run} disabled={busy || (!path && !text.trim())} data-testid="ca-reply-import">
            {busy && <Spinner />} Install reply
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Button
            icon={FolderOpen}
            onClick={async () => {
              const p = await pickFile("Select the CA reply", [FILTERS.certificates]).catch(() => null);
              if (p) {
                setPath(p);
                setText("");
              }
            }}
          >
            Choose file…
          </Button>
          {path && (
            <span className="text-[13px] font-mono text-muted truncate">
              {path}{" "}
              <button className="text-brand cursor-pointer" onClick={() => setPath(null)}>
                (clear)
              </button>
            </span>
          )}
        </div>
        {!path && <TextArea mono rows={8} placeholder="-----BEGIN CERTIFICATE-----" value={text} onChange={(e) => setText(e.target.value)} data-testid="ca-reply-text" />}
        {error && <Alert tone="danger">{error}</Alert>}
      </div>
    </Modal>
  );
};

// ------------------------------------------------------------------------------ rename/labels

export const RenameDialog: React.FC<{ keystore: OpenKeystore; entry: KeystoreEntry | null; onClose: () => void }> = ({ keystore, entry, onClose }) => {
  const { renameEntry } = useStore();
  const toast = useToast();
  const [alias, setAlias] = useState("");
  useLayoutEffect(() => setAlias(entry?.alias ?? ""), [entry?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!entry) return null;
  const trimmed = alias.trim();
  const stored = trimmed ? canonicalAlias(keystore.format, trimmed) : "";
  const error = !stored ? "Alias must not be empty" : stored !== entry.alias && aliasTaken(keystore, stored, entry.id) ? "Another entry already uses this alias" : null;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (error || stored === entry.alias) return onClose();
    renameEntry(keystore.id, entry.id, stored);
    toast.success(`Renamed '${entry.alias}' to '${stored}'.`);
    onClose();
  };
  return (
    <Modal
      open
      onClose={onClose}
      icon={Edit3}
      size="sm"
      title="Rename alias"
      testId="rename-dialog"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="rename-form" disabled={!!error} data-testid="rename-submit">
            Rename
          </Button>
        </>
      }
    >
      <form id="rename-form" onSubmit={submit}>
        <TextInput label="Alias" value={alias} onChange={(e) => setAlias(e.target.value)} error={error ?? undefined} hint={keystore.format === "PKCS12" ? undefined : "JKS and JCEKS store aliases in lower case."} data-testid="rename-input" />
      </form>
    </Modal>
  );
};

export const LabelsDialog: React.FC<{ keystore: OpenKeystore; entry: KeystoreEntry | null; onClose: () => void }> = ({ keystore, entry, onClose }) => {
  const { setEntryLabels, keystores } = useStore();
  const [labels, setLabels] = useState<string[]>([]);
  const [draft, setDraft] = useState("");
  useLayoutEffect(() => {
    setLabels(entry?.labels ?? []);
    setDraft("");
  }, [entry?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const suggestions = useMemo(() => [...new Set(keystores.flatMap((k) => k.entries.flatMap((e) => e.labels)))].filter((l) => !labels.includes(l)).slice(0, 12), [keystores, labels]);
  if (!entry) return null;
  const add = (l: string) => {
    const v = l.trim();
    if (v && !labels.includes(v)) setLabels([...labels, v]);
    setDraft("");
  };
  return (
    <Modal
      open
      onClose={onClose}
      icon={Tag}
      size="sm"
      title={`Labels for ${entry.alias}`}
      description="Labels are Keystore Studio metadata; they are not written into the keystore file."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            data-testid="labels-save"
            onClick={() => {
              setEntryLabels(keystore.id, entry.id, draft.trim() ? [...labels, draft.trim()] : labels);
              onClose();
            }}
          >
            Save labels
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap gap-1.5 min-h-7">
          {labels.map((l) => (
            <span key={l} className="inline-flex items-center gap-1 h-6 pl-2 pr-1 rounded-control bg-brand-tint text-brand-deep text-[12px] font-medium">
              {l}
              <button aria-label={`Remove ${l}`} className="p-0.5 hover:text-danger cursor-pointer" onClick={() => setLabels(labels.filter((x) => x !== l))}>
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
          {labels.length === 0 && <span className="text-[13px] text-faint">No labels yet</span>}
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            add(draft);
          }}
          className="flex gap-2"
        >
          <TextInput placeholder="e.g. production, pci, rotate-q3" value={draft} onChange={(e) => setDraft(e.target.value)} data-testid="labels-input" />
          <Button type="submit" icon={Plus}>
            Add
          </Button>
        </form>
        {suggestions.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {suggestions.map((s) => (
              <button key={s} onClick={() => add(s)} className="h-6 px-2 rounded-control border border-line text-[12px] text-muted hover:bg-surface-2 cursor-pointer">
                + {s}
              </button>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
};

export const AssignWorkspaceDialog: React.FC<{ entry: KeystoreEntry | null; onClose: () => void }> = ({ entry, onClose }) => {
  const { workspaces, toggleWorkspaceEntry, saveWorkspace } = useStore();
  const [name, setName] = useState("");
  if (!entry) return null;
  return (
    <Modal open onClose={onClose} icon={Layers} title={`Workspaces for ${entry.alias}`} description="Group keystore entries and certificates by project or audit scope." footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <div className="space-y-2">
        {workspaces.map((ws) => {
          const on = ws.entryIds.includes(entry.id);
          return (
            <button
              key={ws.id}
              onClick={() => toggleWorkspaceEntry(ws.id, entry.id)}
              aria-pressed={on}
              className={clsx("w-full p-3 rounded-card border flex items-center justify-between cursor-pointer text-left transition", on ? "bg-brand-tint border-brand-soft-hover" : "bg-surface-2 border-line hover:border-line-strong")}
            >
              <span>
                <span className="block text-[13px] font-semibold text-ink">{ws.name}</span>
                <span className="block text-[12px] text-faint">
                  {ws.environment} · {ws.entryIds.length} entries
                </span>
              </span>
              <Badge tone={on ? "success" : "neutral"}>{on ? "Included" : "Add"}</Badge>
            </button>
          );
        })}
        {workspaces.length === 0 && <p className="text-[13px] text-faint">No workspaces yet — create one below.</p>}
        <form
          className="flex gap-2 pt-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (!name.trim()) return;
            const ws = { id: `ws-${uid()}`, name: name.trim(), description: "", environment: "Production" as const, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), entryIds: [entry.id] };
            saveWorkspace(ws);
            setName("");
          }}
        >
          <TextInput placeholder="New workspace name" value={name} onChange={(e) => setName(e.target.value)} />
          <Button type="submit" icon={Plus} disabled={!name.trim()}>
            Create & add
          </Button>
        </form>
      </div>
    </Modal>
  );
};

// -------------------------------------------------------------------------------- inspector

type InspectTab = "overview" | "chain" | "extensions" | "public" | "private";

export const EntryInspector: React.FC<{
  keystore: OpenKeystore;
  entry: KeystoreEntry | null;
  onClose: () => void;
  onAction: (action: "export" | "csr" | "reply" | "rename" | "labels" | "workspaces" | "delete" | "unlock", entry: KeystoreEntry) => void;
}> = ({ keystore, entry, onClose, onAction }) => {
  const confirm = useConfirm();
  const { isKeyLocked } = useStore();
  const [tab, setTab] = useState<InspectTab>("overview");
  const [revealed, setRevealed] = useState(false);
  useLayoutEffect(() => {
    setTab("overview");
    setRevealed(false);
  }, [entry?.id]);
  if (!entry) return null;
  const leaf = entry.certificate_chain[0];
  const findings = findingsFor(entry, { format: keystore.format, siblings: keystore.entries });
  // Session lock included: key material is shown only once the key password was entered.
  const keyLocked = isKeyLocked(entry);
  const tabs: { value: InspectTab; label: string }[] = [
    { value: "overview", label: "Overview" },
    ...(entry.chain_length > 0 ? [{ value: "chain" as const, label: `Chain (${entry.chain_length})` }, { value: "extensions" as const, label: `Extensions (${leaf?.extensions.length ?? 0})` }] : []),
    ...(entry.public_key_pem ? [{ value: "public" as const, label: "Public key" }] : []),
    ...(entry.entry_type !== "TrustedCertificate" ? [{ value: "private" as const, label: entry.entry_type === "SecretKey" ? "Key material" : "Private key" }] : []),
  ];
  const reveal = async () => {
    const ok = await confirm({
      title: "Show secret key material?",
      message: "The key will be displayed on screen. Make sure nobody can see your display.",
      confirmLabel: "Show",
    });
    if (ok === true) setRevealed(true);
  };
  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      icon={undefined}
      testId="entry-inspector"
      title={
        <span className="flex items-center gap-2">
          {entry.alias} <HealthBadge entry={entry} />
        </span>
      }
      description={`${ENTRY_TYPE_LABEL[entry.entry_type]} · ${entry.algorithm}${entry.key_size ? ` ${entry.key_size}-bit` : ""} · ${keystore.name}`}
      footer={
        <>
          <Button variant="danger" icon={Trash2} className="mr-auto" onClick={() => onAction("delete", entry)}>
            Delete
          </Button>
          <Button icon={Tag} onClick={() => onAction("labels", entry)}>
            Labels
          </Button>
          <Button icon={Layers} onClick={() => onAction("workspaces", entry)}>
            Workspaces
          </Button>
          <Button icon={Edit3} onClick={() => onAction("rename", entry)}>
            Rename
          </Button>
          {entry.entry_type === "KeyPair" && !keyLocked && (
            <>
              <Button icon={FileSignature} onClick={() => onAction("csr", entry)}>
                CSR
              </Button>
              <Button icon={Reply} onClick={() => onAction("reply", entry)}>
                CA reply
              </Button>
            </>
          )}
          <Button variant="primary" icon={Download} onClick={() => onAction("export", entry)}>
            Export…
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Segmented label="Inspector section" value={tab} onChange={setTab} options={tabs} />
        {tab === "overview" && (
          <div className="space-y-4">
            {entry.locked && (
              <Alert tone="warning" title="Private key locked" action={<Button size="sm" onClick={() => onAction("unlock", entry)}>Unlock key…</Button>}>
                This key uses a separate key password. It is preserved when saving to {keystore.format}, but cannot be used or exported until unlocked.
              </Alert>
            )}
            {findings.length > 0 && (
              <ul className="space-y-1.5">
                {findings.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 text-[13px]">
                    <AlertTriangle className={clsx("w-3.5 h-3.5 mt-0.5 shrink-0", f.severity === "critical" || f.severity === "high" ? "text-danger" : "text-warning")} />
                    <span>
                      <strong className="text-ink font-semibold">{f.title}.</strong> <span className="text-muted">{f.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {leaf ? (
              <CertificateDetails cert={leaf} />
            ) : (
              <table className="w-full border border-line rounded-card overflow-hidden border-separate border-spacing-0 text-[13px]">
                <tbody>
                  {[
                    ["Algorithm", entry.algorithm],
                    ["Key size", `${entry.key_size} bits`],
                    ["Created", entry.creation_date],
                    ["SHA-256 of key", entry.sha256_fingerprint],
                  ].map(([k, v]) => (
                    <tr key={k}>
                      <th className="w-[30%] text-left font-medium text-faint bg-surface-2 border-b border-line px-3.5 py-2.5">{k}</th>
                      <td className="border-b border-line px-3.5 py-2.5 font-mono text-[11.5px] break-all select-text">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
        {tab === "chain" && <ChainView certs={entry.certificate_chain} />}
        {tab === "extensions" && leaf && <ExtensionsList cert={leaf} />}
        {tab === "public" && entry.public_key_pem && <CodeBlock label="SubjectPublicKeyInfo (PEM)" value={entry.public_key_pem} />}
        {tab === "private" &&
          (keyLocked ? (
            <Alert tone="warning" title="The key is locked" action={<Button size="sm" icon={Unlock} onClick={() => onAction("unlock", entry)}>Unlock key…</Button>}>
              {entry.locked ? "This key uses a separate key password." : "Enter its key password to see the key material."}
            </Alert>
          ) : revealed ? (
            <CodeBlock
              label={entry.entry_type === "SecretKey" ? "Raw key (hex)" : "PKCS#8 private key (PEM)"}
              value={(entry.entry_type === "SecretKey" ? entry.secret_key_hex : entry.private_key_pem) ?? ""}
              wrap={entry.entry_type === "SecretKey"}
              testId="private-key-pem"
            />
          ) : (
            <div className="rounded-card border border-dashed border-line-strong p-8 text-center">
              <p className="text-[13px] text-muted mb-3">Key material is hidden.</p>
              <Button icon={Eye} onClick={reveal} data-testid="reveal-key">
                Reveal
              </Button>
            </div>
          ))}
      </div>
    </Modal>
  );
};
