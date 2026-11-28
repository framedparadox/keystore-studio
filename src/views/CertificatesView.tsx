import React, { useMemo, useRef, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { Activity, ClipboardPaste, Copy, Download, Eye, FileBadge, FolderArchive, FolderOpen, Layers, MoreHorizontal, Search, Shapes, ShieldCheck, X } from "lucide-react";
import { certificateTree, issuerChain, type CertificateTreeRow } from "../lib/certificates";
import type { OpenCertificate } from "../types/crypto";
import { errorMessage } from "../lib/api";
import { FILTERS, pickFiles } from "../lib/files";
import { CERTIFICATE_ROLE_LABEL, certificateRole, cnOf, entryMatches, type CertificateRole } from "../lib/keystore";
import { CERTIFICATE_ROLE_VIEW } from "../components/certificate-icons";
import { daysUntilExpiry, entryHealth, summarize } from "../lib/metrics";
import { useStore } from "../state/store";
import { Alert, Button, Card, Column, DataTable, EmptyState, IconButton, IconHeader, Menu, MenuItem, Page, PageHeader, SearchInput, Segmented, StatStrip, useConfirm, useToast } from "../components/ui";
import { AlgorithmCell, EntryIcon, EntryNameCell, ExpiryDateCell, HealthIcon, LockIcon, NAME_COLUMN_CLASS, ValidityCell } from "../components/entry";
import { AssignWorkspaceDialog, ExportDialog } from "../components/EntryDialogs";
import { CertificateInspector, PasteCertificatesDialog, useAddCertificateToKeystore, useCertificatePool, VerifyCertificateDialog } from "../components/CertificateDialogs";

type Kind = "all" | CertificateRole;
const ROLE_RANK: Record<CertificateRole, number> = { root: 0, intermediate: 1, "end-entity": 2 };
const roleOf = (c: OpenCertificate) => certificateRole(c.entry.certificate_chain[0]);
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

/**
 * The tree connector in front of a certificate whose issuer is in the same file: an elbow from the
 * row above, and a line on down when a sibling follows.
 */
const TreeIndent: React.FC<{ depth: number; lastChild: boolean; children: React.ReactNode }> = ({ depth, lastChild, children }) =>
  depth === 0 ? (
    <>{children}</>
  ) : (
    <div className="relative flex items-center min-w-0 -my-2 py-2 h-[56px]" style={{ paddingLeft: depth * 22 }} data-tree-depth={depth}>
      <span aria-hidden className="absolute top-0 h-1/2 w-2.5 border-l border-b border-line-strong rounded-bl-[4px]" style={{ left: depth * 22 - 14 }} />
      {!lastChild && <span aria-hidden className="absolute top-1/2 bottom-0 border-l border-line-strong" style={{ left: depth * 22 - 14 }} />}
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );

/** What a certificate is, as one glyph: root, intermediate or end entity, each with its own logo. */
const KindIcon: React.FC<{ c: OpenCertificate; hint?: string; count?: number }> = ({ c, hint, count }) => {
  const leaf = c.entry.certificate_chain[0];
  const role = roleOf(c);
  const detail = role !== "end-entity" ? "" : leaf?.self_signed ? " · self-signed" : leaf?.sans[0] ? ` · ${leaf.sans[0]}` : "";
  const label = `${CERTIFICATE_ROLE_LABEL[role]}${detail}`;
  return (
    <span data-cert-kind={role} className="relative inline-flex">
      <EntryIcon type="TrustedCertificate" role={role} label={hint ? `${label} · ${hint}` : label} />
      {/* How many certificates the bundle holds; the row and the toggle's name say it in words. */}
      {count !== undefined && (
        <span aria-hidden data-bundle-count className="absolute -top-1.5 -right-1.5 min-w-4 h-4 px-1 rounded-full border border-surface bg-brand text-on-accent text-[10px] font-semibold leading-none tabular-nums flex items-center justify-center">
          {count}
        </span>
      )}
    </span>
  );
};

/** The icon of a bundle's top row: a button that shows and hides the rest of its chain. */
const BundleToggle: React.FC<{ row: CertificateTreeRow; onToggle: () => void }> = ({ row: { cert: c, groupSize, expanded }, onToggle }) => (
  <button
    type="button"
    onClick={(event) => {
      event.stopPropagation();
      onToggle();
    }}
    aria-expanded={expanded}
    aria-label={`${expanded ? "Hide" : "Show"} the ${groupSize - 1} issuer${groupSize === 2 ? "" : "s"} in ${c.source}`}
    className="inline-flex rounded-control cursor-pointer transition hover:ring-2 hover:ring-brand-soft"
    data-testid={`cert-expand-${c.entry.alias}`}
  >
    <KindIcon c={c} count={groupSize} hint={expanded ? "click to hide the chain" : "click to show the chain"} />
  </button>
);

export const CertificatesView: React.FC = () => {
  const { certificates, workspaces, removeCertificates, certificateFocus, openFiles, addCertificates, desktop } = useStore();
  const toast = useToast();
  const confirm = useConfirm();
  const { targets, add } = useAddCertificateToKeystore();
  const browserFileInput = useRef<HTMLInputElement>(null);
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState<Kind>("all");
  const [pasteOpen, setPasteOpen] = useState(false);
  // Ids, not copies: a certificate opened again or removed is looked up fresh.
  const [inspectId, setInspectId] = useState<string | null>(null);
  const [exportId, setExportId] = useState<string | null>(null);
  const [workspacesId, setWorkspacesId] = useState<string | null>(null);
  const [verifyId, setVerifyId] = useState<string | null>(null);
  const pool = useCertificatePool();
  const byId = (id: string | null) => (id ? certificates.find((c) => c.id === id) ?? null : null);
  const inspecting = byId(inspectId);
  const exporting = byId(exportId);
  const exportLeaf = exporting?.entry.certificate_chain[0];
  const exportChain = useMemo(() => (exportLeaf ? issuerChain(exportLeaf, pool) : []), [exportLeaf, pool]);

  const entries = useMemo(() => certificates.map((c) => c.entry), [certificates]);
  const sum = summarize(entries);
  const roleCounts: Record<CertificateRole, number> = { root: 0, intermediate: 0, "end-entity": 0 };
  for (const c of certificates) roleCounts[roleOf(c)]++;
  const files = new Set(
    certificates
      .map((c) => c.path || (!desktop && c.source !== "Pasted" ? `${c.source}\0${c.opened_at}` : ""))
      .filter(Boolean)
  ).size;
  const unfiled = certificates.filter((c) => !c.path && (desktop || c.source === "Pasted")).length;
  const q = search.trim().toLowerCase();
  const visible = certificates.filter((c) => {
    if (kind !== "all" && roleOf(c) !== kind) return false;
    return !q || entryMatches(c.entry, q) || c.source.toLowerCase().includes(q) || c.entry.certificate_chain[0]?.sans.some((s) => s.toLowerCase().includes(q));
  });
  // One tree per file: root, then what it issued. Groups keep the page's order.
  // Bundles start closed on their leaf; searching or filtering opens them so every match shows.
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const toggleGroup = (g: string) =>
    setOpenGroups((cur) => {
      const next = new Set(cur);
      if (next.has(g)) next.delete(g);
      else next.add(g);
      return next;
    });
  const filtering = !!q || kind !== "all";
  const tree = certificateTree(visible, filtering ? true : openGroups);
  // While filtering every bundle is held open, so its icon has nothing to toggle.
  const kindIcon = (row: CertificateTreeRow) => {
    if (!row.expandable || row.depth > 0) return <KindIcon c={row.cert} />;
    return filtering ? <KindIcon c={row.cert} count={row.groupSize} /> : <BundleToggle row={row} onToggle={() => toggleGroup(row.group)} />;
  };
  const workspacesOf = (c: OpenCertificate) => workspaces.filter((w) => w.entryIds.includes(c.id));
  const inWorkspaces = certificates.filter((c) => workspaces.some((w) => w.entryIds.includes(c.id))).length;

  const openCertificates = async () => {
    if (!desktop) {
      browserFileInput.current?.click();
      return;
    }
    const paths = await pickFiles("Open certificates", [FILTERS.certificates]).catch((err) => {
      toast.error(errorMessage(err));
      return [] as string[];
    });
    // Through the same routing as Open and drag and drop: a keystore picked here opens as a keystore.
    if (paths.length) await openFiles(paths);
  };

  const openBrowserFiles = async (files: FileList | File[]) => {
    let addedCount = 0;
    let duplicateCount = 0;
    for (const file of Array.from(files)) {
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        let binary = "";
        for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        const result = await addCertificates({ base64: btoa(binary) }, { source: file.name });
        addedCount += result.added.length;
        duplicateCount += result.duplicates.length;
      } catch (err) {
        toast.error(`Could not open ${file.name}: ${errorMessage(err)}`);
      }
    }
    if (addedCount) toast.success(`Added ${addedCount} certificate${addedCount === 1 ? "" : "s"} to the preview${duplicateCount ? ` (${duplicateCount} already listed)` : ""}.`);
    else if (duplicateCount) toast.info(duplicateCount === 1 ? "That certificate is already listed." : "Those certificates are already listed.");
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
      ...(desktop
        ? [
            { label: "Verify…", hint: "Chain, trust and revocation", icon: ShieldCheck, onSelect: () => setVerifyId(c.id), testId: "cert-menu-verify" },
            { label: "Export…", hint: "PEM, X.509, PKCS#7, SPC, PkiPath, public key", icon: Download, onSelect: () => setExportId(c.id), testId: "cert-menu-export" },
          ]
        : []),
      {
        label: "Copy PEM",
        icon: Copy,
        onSelect: () => void copyText(leaf?.pem ?? "").then((ok) => (ok ? toast.success(`Copied the PEM of '${c.entry.alias}'.`) : toast.error("Could not copy to the clipboard."))),
        testId: "cert-menu-copy",
      },
      { label: "Workspaces…", icon: Layers, onSelect: () => setWorkspacesId(c.id), divider: true, testId: "cert-menu-workspaces" },
      ...(desktop && leaf
        ? targets.map((k, i) => ({ label: `Add to ${k.name}`, hint: i === 0 ? "As a trusted certificate" : undefined, icon: FolderArchive, onSelect: () => void add(leaf, k.id), divider: i === 0, testId: `cert-menu-add-${k.name}` }))
        : []),
      ...(c.path ? [{ label: "Show in folder", icon: FolderOpen, onSelect: () => void revealItemInDir(c.path).catch(() => undefined), divider: true }] : []),
      { label: "Remove from list", hint: "The file is not changed", icon: X, onSelect: () => void remove(c), danger: true, divider: true, testId: "cert-menu-remove" },
    ];
  };

  // Type and lock are glyphs alone, named in the tooltip and to screen readers. A certificate has no
  // private key, so its lock is always a dash; the column lines the page up with the keystore table.
  // As the table narrows the columns give way in the same order as there; status and actions stay.
  const columns: Column<CertificateTreeRow>[] = [
    {
      id: "kind",
      header: <IconHeader icon={Shapes} label="Type" />,
      width: "64px",
      align: "center",
      hideBelow: "md",
      sortValue: ({ cert: c }) => `${ROLE_RANK[roleOf(c)]}${c.entry.alias.toLowerCase()}`,
      cell: kindIcon,
    },
    {
      id: "status",
      header: <IconHeader icon={Activity} label="Status" />,
      width: "64px",
      align: "center",
      sortValue: ({ cert: c }) => HEALTH_RANK[entryHealth(c.entry)],
      cell: ({ cert: c }) => <HealthIcon entry={c.entry} />,
    },
    {
      id: "name",
      header: "Certificate",
      className: NAME_COLUMN_CLASS,
      sortValue: ({ cert: c }) => c.entry.alias.toLowerCase(),
      cell: (row) => {
        const { cert: c, depth, lastChild, groupSize, expandable } = row;
        const leaf = c.entry.certificate_chain[0];
        const issued = leaf?.self_signed ? "Self-signed" : `Issued by ${cnOf(c.entry.issuer)}`;
        // The top of a bundle says what it holds.
        const meta = expandable ? `${issued} · bundle of ${groupSize} in ${c.source}` : issued;
        return (
          <TreeIndent depth={depth} lastChild={lastChild}>
            <EntryNameCell entry={c.entry} icon="narrow" tile={kindIcon(row)} meta={meta} />
          </TreeIndent>
        );
      },
    },
    { id: "alg", header: "Algorithm", hideBelow: "lg", sortValue: ({ cert: c }) => c.entry.algorithm, cell: ({ cert: c }) => <AlgorithmCell entry={c.entry} /> },
    { id: "expiry", header: "Expires", width: "136px", hideBelow: "sm", sortValue: ({ cert: c }) => daysUntilExpiry(c.entry), cell: ({ cert: c }) => <ExpiryDateCell entry={c.entry} /> },
    { id: "validity", header: "Validity", width: "112px", hideBelow: "md", sortValue: ({ cert: c }) => daysUntilExpiry(c.entry), cell: ({ cert: c }) => <ValidityCell entry={c.entry} /> },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      width: "96px",
      cell: ({ cert: c }) => (
        <div className="inline-flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
          {/* Shown only when the certificate is locked; a certificate alone has no key, so normally nothing. */}
          {c.entry.locked && <LockIcon state="locked" />}
          <IconButton icon={Layers} label={`Workspaces for ${c.entry.alias}`} onClick={() => setWorkspacesId(c.id)} data-testid={`cert-workspaces-${c.entry.alias}`} />
          <Menu items={rowMenu(c)} width={280} trigger={(p) => <IconButton icon={MoreHorizontal} label={`More actions for ${c.entry.alias}`} {...p} data-testid={`cert-menu-${c.entry.alias}`} />} />
        </div>
      ),
    },
  ];

  const roleOption = (role: CertificateRole, name: string) => {
    const Icon = CERTIFICATE_ROLE_VIEW[role].icon;
    return { value: role, label: <><Icon className="w-3.5 h-3.5" aria-hidden /> {name}</>, count: roleCounts[role] };
  };

  return (
    <Page data-testid="certificates-page">
      <PageHeader
        icon={FileBadge}
        title="Certificates"
        description={
          desktop
            ? "Certificate files you open on their own (PEM, DER or PKCS#7) are listed here, one row per certificate. Add them to a keystore or a workspace. Removing one from the list never changes its file."
            : "Open certificate files (PEM, DER or PKCS#7) to inspect them in this browser preview. Removing one from the list never changes its file."
        }
        actions={
          <>
            <IconButton icon={ClipboardPaste} label="Paste certificates" onClick={() => setPasteOpen(true)} className="!w-9 !h-9" data-testid="cert-paste" />
            <Button variant="primary" icon={FolderOpen} onClick={() => void openCertificates()} data-testid="cert-open">
              Open certificates…
            </Button>
          </>
        }
      />

      <input
        ref={browserFileInput}
        type="file"
        multiple
        accept=".pem,.crt,.cer,.der,.p7b,.p7c,.pkipath,.txt"
        className="hidden"
        aria-label="Choose certificate files"
        onChange={(event) => {
          if (event.currentTarget.files?.length) void openBrowserFiles(event.currentTarget.files);
          event.currentTarget.value = "";
        }}
      />
      {!desktop && (
        <Alert tone="info">
          Preview mode: certificates are parsed locally in this browser and saved in this browser. Keystore changes, verification and export require the desktop app.
        </Alert>
      )}

      {certificates.length === 0 ? (
        <Card className="py-16">
          <EmptyState
            icon={FileBadge}
            title="No certificates open"
            description={
              desktop
                ? "Open a .pem, .crt, .cer, .der or .p7b file, drop one on the window, or paste PEM text. Each certificate in the file is listed here."
                : "Choose a .pem, .crt, .cer, .der or .p7b file, or paste certificate text. Preview entries are stored in this browser."
            }
            action={
              <>
                <Button variant="primary" icon={FolderOpen} onClick={() => void openCertificates()} data-testid="cert-empty-open">
                  Open certificates…
                </Button>
                <IconButton icon={ClipboardPaste} label="Paste certificates" onClick={() => setPasteOpen(true)} className="!w-9 !h-9" />
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
                  { value: "all", label: "All", count: certificates.length },
                  roleOption("root", "Root"),
                  roleOption("intermediate", "Intermediate"),
                  roleOption("end-entity", "End entity"),
                ]}
              />
              <div className="flex-1" />
              <SearchInput value={search} onChange={setSearch} placeholder="Search certificates…" label="Search by name, subject, issuer, SAN, serial, fingerprint or file" className="w-full sm:w-64" />
            </div>
            <DataTable<CertificateTreeRow>
              label="Certificates"
              columns={columns}
              rows={tree}
              rowKey={(r) => r.cert.id}
              groupKey={(r) => r.group}
              tinted={(r) => r.expandable}
              selectedKey={inspectId ?? certificateFocus}
              onRowClick={(r) => setInspectId(r.cert.id)}
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
              { label: "Certificates", value: sum.total, hint: `${roleCounts.root} root · ${roleCounts.intermediate} intermediate · ${roleCounts["end-entity"]} end entity` },
              { label: "Expiring soon", value: sum.expiringWarning, hint: sum.expiringCritical ? `${sum.expiringCritical} critical` : "None critical", hintTone: sum.expiringCritical ? "warning" : "neutral" },
              { label: "Needs action", value: sum.expired + sum.weak, hint: `${sum.expired} expired · ${sum.weak} weak`, hintTone: sum.expired + sum.weak ? "danger" : "success" },
              { label: "Files", value: files, hint: unfiled ? `${unfiled} pasted${desktop ? " or kept" : ""}` : "Opened from disk" },
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
      <ExportDialog entry={exporting?.entry ?? null} chain={exportChain} onClose={() => setExportId(null)} />
      <VerifyCertificateDialog certificate={byId(verifyId)} onClose={() => setVerifyId(null)} />
      <AssignWorkspaceDialog entry={byId(workspacesId)?.entry ?? null} onClose={() => setWorkspacesId(null)} />
      <PasteCertificatesDialog open={pasteOpen} onClose={() => setPasteOpen(false)} />
    </Page>
  );
};

export default CertificatesView;
