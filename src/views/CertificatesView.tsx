import React, { useMemo, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { ClipboardPaste, Copy, Download, Eye, FileBadge, FolderArchive, FolderOpen, Layers, Lock, MoreHorizontal, Search, Shapes, ShieldCheck, X } from "lucide-react";
import type { OpenCertificate } from "../types/crypto";
import { errorMessage } from "../lib/api";
import { FILTERS, pickFiles } from "../lib/files";
import { cnOf, entryMatches } from "../lib/keystore";
import { daysUntilExpiry, entryHealth, summarize } from "../lib/metrics";
import { useStore } from "../state/store";
import { Button, Card, Column, DataTable, EmptyState, IconButton, IconHeader, Menu, MenuItem, Page, PageHeader, SearchInput, Segmented, StatStrip, useConfirm, useToast } from "../components/ui";
import { AlgorithmCell, EntryIcon, EntryNameCell, ExpiryCell, HealthIcon, LockIcon, NAME_COLUMN_CLASS } from "../components/entry";
import { AssignWorkspaceDialog, ExportDialog } from "../components/EntryDialogs";
import { CertificateInspector, PasteCertificatesDialog, useAddCertificateToKeystore } from "../components/CertificateDialogs";

type Kind = "all" | "ca" | "leaf";
const HEALTH_RANK = { "at-risk": 0, attention: 1, healthy: 2 } as const;

/** Copies text, falling back to a selection copy where the Clipboard API is refused. */
const copyText = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.cssText = "position:fixed;top:0;left:0;opacity:0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    return ok;
  }
};

/** What a certificate is, as one glyph: a shield for a root or intermediate CA, a badged document for an end entity. */
const KindIcon: React.FC<{ c: OpenCertificate }> = ({ c }) => {
  const leaf = c.entry.certificate_chain[0];
  const ca = !!leaf?.is_ca;
  const label = ca ? `CA certificate · ${leaf?.self_signed ? "root, self-signed" : "intermediate"}` : `End entity${leaf?.self_signed ? " · self-signed" : leaf?.sans[0] ? ` · ${leaf.sans[0]}` : ""}`;
  return (
    <span data-cert-kind={ca ? "ca" : "end-entity"} className="inline-flex">
      <EntryIcon type="TrustedCertificate" icon={ca ? ShieldCheck : FileBadge} label={label} />
    </span>
  );
};

export const CertificatesView: React.FC = () => {
  const { certificates, workspaces, removeCertificates, certificateFocus, openFiles } = useStore();
  const toast = useToast();
  const confirm = useConfirm();
  const { targets, add } = useAddCertificateToKeystore();
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState<Kind>("all");
  const [pasteOpen, setPasteOpen] = useState(false);
  // Ids, not copies: a certificate opened again or removed is looked up fresh.
  const [inspectId, setInspectId] = useState<string | null>(null);
  const [exportId, setExportId] = useState<string | null>(null);
  const [workspacesId, setWorkspacesId] = useState<string | null>(null);
  const byId = (id: string | null) => (id ? certificates.find((c) => c.id === id) ?? null : null);
  const inspecting = byId(inspectId);

  const entries = useMemo(() => certificates.map((c) => c.entry), [certificates]);
  const sum = summarize(entries);
  const cas = certificates.filter((c) => c.entry.certificate_chain[0]?.is_ca).length;
  const files = new Set(certificates.filter((c) => c.path).map((c) => c.path)).size;
  const q = search.trim().toLowerCase();
  const visible = certificates.filter((c) => {
    const isCa = !!c.entry.certificate_chain[0]?.is_ca;
    if (kind === "ca" && !isCa) return false;
    if (kind === "leaf" && isCa) return false;
    return !q || entryMatches(c.entry, q) || c.source.toLowerCase().includes(q) || c.entry.certificate_chain[0]?.sans.some((s) => s.toLowerCase().includes(q));
  });
  const workspacesOf = (c: OpenCertificate) => workspaces.filter((w) => w.entryIds.includes(c.id));
  const inWorkspaces = certificates.filter((c) => workspaces.some((w) => w.entryIds.includes(c.id))).length;

  const openCertificates = async () => {
    const paths = await pickFiles("Open certificates", [FILTERS.certificates]).catch((err) => {
      toast.error(errorMessage(err));
      return [] as string[];
    });
    // Through the same routing as Open and drag and drop: a keystore picked here opens as a keystore.
    if (paths.length) await openFiles(paths);
  };

  const remove = async (c: OpenCertificate) => {
    const inWorkspaces = workspacesOf(c);
    if (inWorkspaces.length) {
      const names = inWorkspaces.map((w) => `“${w.name}”`).join(", ");
      const ok = await confirm({
        title: `Remove '${c.entry.alias}' from Certificates?`,
        message: `It is in ${names}. It stays there, shown as not open, until you open the certificate again. The file is not changed.`,
        confirmLabel: "Remove",
      });
      if (ok !== true) return;
    }
    if (inspectId === c.id) setInspectId(null);
    const undo = removeCertificates([c.id]);
    toast.success(`Removed '${c.entry.alias}' from Certificates.`, { label: "Undo", onClick: undo });
  };

  const rowMenu = (c: OpenCertificate): MenuItem[] => {
    const leaf = c.entry.certificate_chain[0];
    return [
      { label: "Inspect", icon: Eye, onSelect: () => setInspectId(c.id) },
      { label: "Export…", hint: "PEM, DER, PKCS#7, public key or JWK", icon: Download, onSelect: () => setExportId(c.id), testId: "cert-menu-export" },
      {
        label: "Copy PEM",
        icon: Copy,
        onSelect: () => void copyText(leaf?.pem ?? "").then((ok) => (ok ? toast.success(`Copied the PEM of '${c.entry.alias}'.`) : toast.error("Could not copy to the clipboard."))),
        testId: "cert-menu-copy",
      },
      { label: "Workspaces…", icon: Layers, onSelect: () => setWorkspacesId(c.id), divider: true, testId: "cert-menu-workspaces" },
      ...(leaf
        ? targets.map((k, i) => ({ label: `Add to ${k.name}`, hint: i === 0 ? "As a trusted certificate" : undefined, icon: FolderArchive, onSelect: () => void add(leaf, k.id), divider: i === 0, testId: `cert-menu-add-${k.name}` }))
        : []),
      ...(c.path ? [{ label: "Show in folder", icon: FolderOpen, onSelect: () => void revealItemInDir(c.path).catch(() => undefined), divider: true }] : []),
      { label: "Remove from list", hint: "The file is not changed", icon: X, onSelect: () => void remove(c), danger: true, divider: true, testId: "cert-menu-remove" },
    ];
  };

  // Type and lock are glyphs alone, named in the tooltip and to screen readers. A certificate has no
  // private key, so its lock is always a dash; the column lines the page up with the keystore table.
  // As the table narrows the columns give way in the same order as there; status and actions stay.
  const columns: Column<OpenCertificate>[] = [
    {
      id: "kind",
      header: <IconHeader icon={Shapes} label="Type" />,
      width: "64px",
      align: "center",
      hideBelow: "md",
      sortValue: (c) => `${c.entry.certificate_chain[0]?.is_ca ? 0 : 1}${c.entry.alias.toLowerCase()}`,
      cell: (c) => <KindIcon c={c} />,
    },
    { id: "lock", header: <IconHeader icon={Lock} label="Lock status" />, width: "64px", align: "center", hideBelow: "md", cell: () => <LockIcon state="no-key" /> },
    {
      id: "name",
      header: "Certificate",
      className: NAME_COLUMN_CLASS,
      sortValue: (c) => c.entry.alias.toLowerCase(),
      cell: (c) => {
        const leaf = c.entry.certificate_chain[0];
        return <EntryNameCell entry={c.entry} icon="narrow" tile={<KindIcon c={c} />} meta={leaf?.self_signed ? "Self-signed" : `Issued by ${cnOf(c.entry.issuer)}`} />;
      },
    },
    { id: "alg", header: "Algorithm", hideBelow: "lg", sortValue: (c) => c.entry.algorithm, cell: (c) => <AlgorithmCell entry={c.entry} /> },
    { id: "expiry", header: "Expires", width: "160px", hideBelow: "sm", sortValue: (c) => daysUntilExpiry(c.entry), cell: (c) => <ExpiryCell entry={c.entry} /> },
    { id: "status", header: "Status", width: "88px", align: "center", sortValue: (c) => HEALTH_RANK[entryHealth(c.entry)], cell: (c) => <HealthIcon entry={c.entry} /> },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "112px",
      cell: (c) => (
        <div className="inline-flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
          <IconButton icon={Eye} label={`Inspect ${c.entry.alias}`} onClick={() => setInspectId(c.id)} data-testid={`cert-inspect-${c.entry.alias}`} />
          <IconButton icon={Layers} label={`Workspaces for ${c.entry.alias}`} onClick={() => setWorkspacesId(c.id)} data-testid={`cert-workspaces-${c.entry.alias}`} />
          <Menu items={rowMenu(c)} width={280} trigger={(p) => <IconButton icon={MoreHorizontal} label={`More actions for ${c.entry.alias}`} {...p} data-testid={`cert-menu-${c.entry.alias}`} />} />
        </div>
      ),
    },
  ];

  const kindOption = (value: Kind, label: React.ReactNode, count: number) => ({ value, label, count });

  return (
    <Page data-testid="certificates-page">
      <PageHeader
        icon={FileBadge}
        title="Certificates"
        description="Certificate files you open on their own (PEM, DER or PKCS#7) are listed here, one row per certificate. Add them to a keystore or a workspace. Removing one from the list never changes its file."
        actions={
          <>
            <Button icon={ClipboardPaste} onClick={() => setPasteOpen(true)} data-testid="cert-paste">
              Paste…
            </Button>
            <Button variant="primary" icon={FolderOpen} onClick={() => void openCertificates()} data-testid="cert-open">
              Open certificates…
            </Button>
          </>
        }
      />

      {certificates.length === 0 ? (
        <Card className="py-16">
          <EmptyState
            icon={FileBadge}
            title="No certificates open"
            description="Open a .pem, .crt, .cer, .der or .p7b file, drop one on the window, or paste PEM text. Each certificate in the file is listed here."
            action={
              <>
                <Button variant="primary" icon={FolderOpen} onClick={() => void openCertificates()} data-testid="cert-empty-open">
                  Open certificates…
                </Button>
                <Button icon={ClipboardPaste} onClick={() => setPasteOpen(true)}>
                  Paste…
                </Button>
              </>
            }
          />
        </Card>
      ) : (
        <>
          <Card padded={false} className="overflow-hidden flex flex-col">
            <div className="px-5 py-3 border-b border-line flex flex-wrap items-center gap-3">
              <Segmented<Kind>
                label="Filter by certificate type"
                value={kind}
                onChange={setKind}
                options={[
                  kindOption("all", "All", certificates.length),
                  kindOption("ca", <><ShieldCheck className="w-3.5 h-3.5" /> CAs</>, cas),
                  kindOption("leaf", <><FileBadge className="w-3.5 h-3.5" /> End entity</>, certificates.length - cas),
                ]}
              />
              <div className="flex-1" />
              <SearchInput value={search} onChange={setSearch} placeholder="Search certificates…" label="Search by name, subject, issuer, SAN, serial, fingerprint or file" className="w-full sm:w-64" />
            </div>
            <DataTable<OpenCertificate>
              label="Certificates"
              columns={columns}
              rows={visible}
              rowKey={(c) => c.id}
              selectedKey={inspectId ?? certificateFocus}
              onRowClick={(c) => setInspectId(c.id)}
              empty={
                <EmptyState
                  icon={Search}
                  title="No matching certificates"
                  description="Try a different search or filter."
                  action={
                    <Button
                      onClick={() => {
                        setSearch("");
                        setKind("all");
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              }
              footer={
                <>
                  <span>
                    Showing <strong className="text-ink font-semibold">{visible.length}</strong> of {certificates.length} certificates
                  </span>
                  <span>{inWorkspaces ? `${inWorkspaces} in workspaces` : ""}</span>
                </>
              }
            />
          </Card>
          <StatStrip
            className="mt-4"
            label="Certificates summary"
            items={[
              { label: "Certificates", value: sum.total, hint: `${cas} CA · ${sum.total - cas} end entity` },
              { label: "Expiring soon", value: sum.expiringWarning, hint: sum.expiringCritical ? `${sum.expiringCritical} critical` : "None critical", hintTone: sum.expiringCritical ? "warning" : "neutral" },
              { label: "Needs action", value: sum.expired + sum.weak, hint: `${sum.expired} expired · ${sum.weak} weak`, hintTone: sum.expired + sum.weak ? "danger" : "success" },
              { label: "Files", value: files, hint: certificates.length - certificates.filter((c) => c.path).length ? `${certificates.length - certificates.filter((c) => c.path).length} pasted or kept` : "Opened from disk" },
            ]}
          />
        </>
      )}

      {inspecting && (
        <CertificateInspector
          certificate={inspecting}
          onClose={() => setInspectId(null)}
          onExport={() => setExportId(inspecting.id)}
          onWorkspaces={() => setWorkspacesId(inspecting.id)}
          onRemove={() => void remove(inspecting)}
        />
      )}
      <ExportDialog entry={byId(exportId)?.entry ?? null} onClose={() => setExportId(null)} />
      <AssignWorkspaceDialog entry={byId(workspacesId)?.entry ?? null} onClose={() => setWorkspacesId(null)} />
      <PasteCertificatesDialog open={pasteOpen} onClose={() => setPasteOpen(false)} />
    </Page>
  );
};

export default CertificatesView;
