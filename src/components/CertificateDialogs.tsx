import React, { useLayoutEffect, useState } from "react";
import clsx from "clsx";
import { AlertTriangle, ChevronDown, ClipboardPaste, Download, FileBadge, FolderArchive, Layers, X } from "lucide-react";
import type { CertificateInfo, OpenCertificate } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { aliasForCertificate, certificateName } from "../lib/certificates";
import { cnOf } from "../lib/keystore";
import { findingsFor } from "../lib/metrics";
import { useStore } from "../state/store";
import { Alert, Button, CodeBlock, Menu, Modal, PathText, Segmented, TextArea, useToast } from "./ui";
import { CertificateDetails, ExtensionsList } from "./CertificateView";
import { HealthBadge } from "./entry";

/*
 * Dialogs and actions for certificates on the Certificates page, shared with Workspaces and Examine.
 */

/** "Add to <keystore>" for a certificate: every keystore that is open and can be edited. */
export function useAddCertificateToKeystore() {
  const { keystores, addEntries, selectKeystore, setTab } = useStore();
  const toast = useToast();
  const targets = keystores.filter((k) => !k.sealed);
  const add = async (cert: CertificateInfo, keystoreId: string) => {
    const ks = keystores.find((k) => k.id === keystoreId && !k.sealed);
    if (!ks) {
      toast.error("Open or create a keystore first.");
      return;
    }
    try {
      const added = await api.importTrustedCertificates(aliasForCertificate(cert.subject), { text: cert.pem }, ks.entries.map((e) => e.alias));
      const [entry] = addEntries(ks.id, added);
      toast.success(`Added '${entry?.alias ?? added[0].alias}' to ${ks.name} as a trusted certificate.`, {
        label: "View",
        onClick: () => {
          selectKeystore(ks.id);
          setTab("keystores");
        },
      });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
  return { targets, add };
}

/** "Add to Certificates" for certificates found in Examine (a TLS server's chain, decoded data). */
export function useKeepCertificates() {
  const { addCertificates, setTab } = useStore();
  const toast = useToast();
  return async (certs: CertificateInfo[], source: string) => {
    try {
      const { added } = await addCertificates({ text: certs.map((c) => c.pem).join("") }, { source });
      const view = { label: "View", onClick: () => setTab("certificates") };
      if (!added.length) toast.info(certs.length === 1 ? `'${certificateName(certs[0].subject)}' is already in Certificates.` : "These certificates are already in Certificates.");
      else toast.success(added.length === 1 ? `Added '${added[0].entry.alias}' to Certificates.` : `Added ${added.length} certificates to Certificates.`, view);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };
}

/** A menu button listing the open keystores a certificate can be added to. */
export const AddToKeystoreMenu: React.FC<{ cert: CertificateInfo; size?: "sm" | "md" }> = ({ cert, size }) => {
  const { targets, add } = useAddCertificateToKeystore();
  if (!targets.length) return null;
  return (
    <Menu
      width={260}
      items={targets.map((k) => ({ label: k.name, hint: `${k.entries.length} ${k.entries.length === 1 ? "entry" : "entries"}`, icon: FolderArchive, onSelect: () => void add(cert, k.id), testId: `cert-add-to-${k.name}` }))}
      trigger={(p) => (
        <Button size={size} icon={FolderArchive} {...p} data-testid="cert-add-to-keystore">
          Add to keystore <ChevronDown className="w-3.5 h-3.5 -mr-1" />
        </Button>
      )}
    />
  );
};

type InspectTab = "overview" | "extensions" | "public" | "pem";

/** Details of one certificate on the Certificates page. */
export const CertificateInspector: React.FC<{
  certificate: OpenCertificate;
  onClose: () => void;
  onExport: () => void;
  onWorkspaces: () => void;
  /** Omitted where the certificate cannot be removed (e.g. opened from a workspace). */
  onRemove?: () => void;
}> = ({ certificate, onClose, onExport, onWorkspaces, onRemove }) => {
  const { certificates, keystores } = useStore();
  const [tab, setTab] = useState<InspectTab>("overview");
  useLayoutEffect(() => setTab("overview"), [certificate.id]);
  const { entry } = certificate;
  const leaf = entry.certificate_chain[0];
  // "Trust anchor not open" looks for the issuer among everything that is open.
  const siblings = [...certificates.map((c) => c.entry), ...keystores.flatMap((k) => k.entries)];
  const findings = findingsFor(entry, { siblings });
  const tabs: { value: InspectTab; label: string }[] = [
    { value: "overview", label: "Overview" },
    { value: "extensions", label: `Extensions (${leaf?.extensions.length ?? 0})` },
    ...(entry.public_key_pem ? [{ value: "public" as const, label: "Public key" }] : []),
    { value: "pem", label: "PEM" },
  ];
  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      testId="certificate-inspector"
      title={
        <span className="flex items-center gap-2 min-w-0">
          <span className="truncate">{entry.alias}</span> <HealthBadge entry={entry} />
        </span>
      }
      description={`${leaf?.is_ca ? "CA certificate" : "Certificate"} · ${entry.algorithm}${entry.key_size ? ` ${entry.key_size}-bit` : ""} · issued by ${leaf?.self_signed ? "itself" : cnOf(entry.issuer)}`}
      footer={
        <>
          {onRemove && (
            <Button variant="ghost" icon={X} className="mr-auto" onClick={onRemove} data-testid="cert-inspector-remove">
              Remove from list
            </Button>
          )}
          <Button icon={Layers} onClick={onWorkspaces} data-testid="cert-inspector-workspaces">
            Workspaces
          </Button>
          {leaf && <AddToKeystoreMenu cert={leaf} />}
          <Button variant="primary" icon={Download} onClick={onExport} data-testid="cert-inspector-export">
            Export…
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Segmented label="Inspector section" value={tab} onChange={setTab} options={tabs} />
        {tab === "overview" && (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-[13px] text-muted min-w-0">
              <span className="shrink-0 text-faint">Source</span>
              {certificate.path ? <PathText path={certificate.path} className="min-w-0" /> : <span className="text-ink-2">{certificate.source}</span>}
            </div>
            {findings.length > 0 && (
              <ul className="space-y-1.5" aria-label="Findings">
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
            {leaf && <CertificateDetails cert={leaf} />}
          </div>
        )}
        {tab === "extensions" && leaf && <ExtensionsList cert={leaf} />}
        {tab === "public" && entry.public_key_pem && <CodeBlock label="SubjectPublicKeyInfo (PEM)" value={entry.public_key_pem} />}
        {tab === "pem" && leaf && <CodeBlock label="Certificate (PEM)" value={leaf.pem} />}
      </div>
    </Modal>
  );
};

/** Paste PEM (or base64 DER) certificates onto the Certificates page. */
export const PasteCertificatesDialog: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const { addCertificates } = useStore();
  const toast = useToast();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useLayoutEffect(() => {
    if (!open) return;
    setText("");
    setError(null);
  }, [open]);
  if (!open) return null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const { added, duplicates } = await addCertificates({ text }, { source: "Pasted" });
      if (added.length) toast.success(`Added ${added.length === 1 ? `'${added[0].entry.alias}'` : `${added.length} certificates`} to Certificates${duplicates.length ? ` (${duplicates.length} already listed)` : ""}.`);
      else toast.info(duplicates.length === 1 ? `'${duplicates[0].entry.alias}' is already listed.` : "These certificates are already listed.");
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
      onClose={onClose}
      busy={busy}
      icon={ClipboardPaste}
      size="lg"
      title="Paste certificates"
      description="One or more PEM certificates, a PEM PKCS#7 bundle, or a base64 DER certificate."
      testId="cert-paste-dialog"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="cert-paste-form" icon={FileBadge} disabled={busy || !text.trim()} data-testid="cert-paste-submit">
            {busy ? "Reading…" : "Add certificates"}
          </Button>
        </>
      }
    >
      <form id="cert-paste-form" onSubmit={submit} className="space-y-3">
        <TextArea mono rows={12} label="Certificates" placeholder="-----BEGIN CERTIFICATE-----" value={text} onChange={(e) => setText(e.target.value)} autoFocus data-testid="cert-paste-input" />
        {error && <Alert tone="danger">{error}</Alert>}
      </form>
    </Modal>
  );
};
