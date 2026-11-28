import React from "react";
import clsx from "clsx";
import {
  Copy, Download, Eye, FilePlus2, FolderOpen, Infinity as InfinityIcon, Layers, LockOpen, Moon, MoreHorizontal, PanelLeftClose, PanelLeftOpen,
  Redo2, RefreshCw, Search, Settings, Sun, TerminalSquare, Undo2, Wrench, X,
} from "lucide-react";
import { CERTIFICATE_ROLE_LABEL, ENTRY_TYPE_LABEL } from "../lib/keystore";
import { CONVERTERS } from "../lib/convert";
import { EntryIcon, HEALTH_VIEWS, LockIcon } from "./entry";
import { CONVERTER_ICONS, NAV_GROUPS } from "./Sidebar";
import { badgeTones } from "./ui";

interface LegendItem {
  mark: React.ReactNode;
  label: string;
  meaning: string;
}

const glyph = (Icon: React.ElementType, className = "text-muted") => <Icon className={clsx("w-4 h-4", className)} aria-hidden />;

const status = (view: (typeof HEALTH_VIEWS)[keyof typeof HEALTH_VIEWS], meaning: string): LegendItem => ({
  mark: <span className={clsx("inline-flex items-center justify-center w-6 h-6 rounded-full border", badgeTones[view.tone])}>{glyph(view.icon, "!w-3.5 !h-3.5")}</span>,
  label: view.label,
  meaning,
});

/*
 * Built when rendered, not when the module loads: the sidebar's lists come through an import cycle
 * (Sidebar, Settings, Help, this legend). Entries draw the same components the app does.
 */
const legendGroups = (): { id: string; title: string; items: LegendItem[] }[] => [
  {
    id: "certificates",
    title: "Certificates",
    items: [
      { mark: <EntryIcon type="TrustedCertificate" role="root" />, label: CERTIFICATE_ROLE_LABEL.root, meaning: "A self-signed CA at the top of a chain." },
      { mark: <EntryIcon type="TrustedCertificate" role="intermediate" />, label: CERTIFICATE_ROLE_LABEL.intermediate, meaning: "A CA issued by another CA." },
      { mark: <EntryIcon type="TrustedCertificate" role="end-entity" />, label: CERTIFICATE_ROLE_LABEL["end-entity"], meaning: "A certificate that is not a CA, such as a server or client certificate." },
      {
        mark: <span className="min-w-4 h-4 px-1 rounded-full bg-brand text-on-accent text-[10px] font-semibold inline-flex items-center justify-center">3</span>,
        label: "Bundle count",
        meaning: "How many certificates from one file are grouped under this icon. Click the icon to show or hide them.",
      },
      { mark: <span className="w-8 h-5 rounded-sm border border-line-strong bg-bundle" />, label: "Bundle rows", meaning: "Certificates that came from the same file share this background." },
    ],
  },
  {
    id: "entries",
    title: "Keystore entries",
    items: [
      { mark: <EntryIcon type="KeyPair" locked />, label: `${ENTRY_TYPE_LABEL.KeyPair}, locked`, meaning: "A private key and its certificate. Enter the key password to use it." },
      { mark: <EntryIcon type="KeyPair" locked={false} />, label: `${ENTRY_TYPE_LABEL.KeyPair}, unlocked`, meaning: "The key is ready to use." },
      { mark: <EntryIcon type="TrustedCertificate" />, label: ENTRY_TYPE_LABEL.TrustedCertificate, meaning: "A certificate without a private key. CA certificates show the root or intermediate icon." },
      { mark: <EntryIcon type="SecretKey" />, label: ENTRY_TYPE_LABEL.SecretKey, meaning: "A symmetric key." },
    ],
  },
  {
    id: "locks",
    title: "Lock column",
    items: [
      { mark: <LockIcon state="locked" />, label: "Locked", meaning: "Needs the key password, or the key has a password of its own." },
      { mark: <LockIcon state="unlocked" />, label: "Unlocked", meaning: "The key can be used." },
      { mark: <LockIcon state="no-key" />, label: "No private key", meaning: "There is nothing to unlock." },
    ],
  },
  {
    id: "status",
    title: "Status",
    items: [
      status(HEALTH_VIEWS.healthy, "Valid, and not close to expiring."),
      status(HEALTH_VIEWS.renew, "Expires within the warning period set in Settings."),
      status(HEALTH_VIEWS.critical, "Expires within the critical period set in Settings."),
      status(HEALTH_VIEWS.expired, "The certificate is no longer valid."),
      status(HEALTH_VIEWS.weak, "Uses a weak key or signature algorithm."),
      { mark: glyph(InfinityIcon), label: "No expiry", meaning: "Secret keys do not expire." },
    ],
  },
  {
    id: "navigation",
    title: "Navigation",
    items: [
      ...NAV_GROUPS.flatMap((g) => g.items).map((item) => ({ mark: <item.icon className="w-4 h-4 text-muted" />, label: item.label, meaning: `Opens ${item.label}.` })),
      { mark: glyph(FolderOpen), label: "Folder workspace", meaning: "A workspace that follows a folder." },
    ],
  },
  {
    id: "conversions",
    title: "Conversions",
    items: CONVERTERS.map((c) => ({ mark: glyph(CONVERTER_ICONS[c.id]), label: c.nav, meaning: c.short })),
  },
  {
    id: "actions",
    title: "Buttons",
    items: [
      { mark: glyph(Search), label: "Search", meaning: "Find entries or run a command." },
      { mark: glyph(FolderOpen), label: "Open", meaning: "Open a keystore or certificate file." },
      { mark: glyph(FilePlus2), label: "New keystore", meaning: "Create a keystore." },
      { mark: glyph(Eye), label: "Inspect", meaning: "Show the details." },
      { mark: glyph(Download), label: "Export", meaning: "Save a copy in another format." },
      { mark: glyph(Copy), label: "Copy", meaning: "Copy to the clipboard." },
      { mark: glyph(Layers), label: "Workspaces", meaning: "Add to or remove from workspaces." },
      { mark: glyph(MoreHorizontal), label: "More actions", meaning: "Open the menu for a row." },
      { mark: glyph(X), label: "Remove or close", meaning: "Removing from a list or workspace keeps the file." },
      { mark: glyph(RefreshCw), label: "Rescan", meaning: "Read a workspace folder again." },
      { mark: glyph(Undo2), label: "Undo", meaning: "Undo the last keystore edit." },
      { mark: glyph(Redo2), label: "Redo", meaning: "Redo the edit." },
      { mark: glyph(LockOpen, "text-success"), label: "Lock vault", meaning: "Shown while the vault is unlocked. Click to lock it." },
      { mark: glyph(TerminalSquare), label: "Terminal", meaning: "Show or hide the terminal." },
      { mark: glyph(Settings), label: "Settings", meaning: "Open Settings." },
      { mark: glyph(Wrench), label: "Tools", meaning: "Choose where command line tools are found." },
      { mark: <span className="inline-flex gap-1">{glyph(Moon)}{glyph(Sun)}</span>, label: "Theme", meaning: "Switch between dark and light." },
      { mark: <span className="inline-flex gap-1">{glyph(PanelLeftClose)}{glyph(PanelLeftOpen)}</span>, label: "Sidebar", meaning: "Collapse or expand the sidebar." },
    ],
  },
];

/** The legend groups with the items that match a search; all of them when the search is empty. */
export const searchLegend = (query: string) => {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return legendGroups()
    .map((g) => ({ ...g, items: g.items.filter((i) => words.every((w) => `${g.title} ${i.label} ${i.meaning} icon logo legend`.toLowerCase().includes(w))) }))
    .filter((g) => g.items.length > 0);
};

export const IconLegend: React.FC<{ groups: ReturnType<typeof searchLegend> }> = ({ groups }) => (
  <section aria-labelledby="help-legend" data-testid="icon-legend">
    <h3 id="help-legend" className="text-[12px] font-semibold uppercase tracking-wide text-faint mb-2">
      Icon legend
    </h3>
    <div className="rounded-card border border-line divide-y divide-line bg-surface">
      {groups.map((g) => (
        <div key={g.id} className="px-4 py-3" data-testid={`legend-${g.id}`}>
          <h4 className="text-[13px] font-semibold text-ink mb-2">{g.title}</h4>
          <dl className="grid grid-cols-1 @3xl:grid-cols-2 gap-x-6 gap-y-2.5">
            {g.items.map((i) => (
              <div key={i.label} className="flex items-center gap-3 min-w-0">
                <span className="w-10 flex justify-center shrink-0" aria-hidden>
                  {i.mark}
                </span>
                <div className="min-w-0">
                  <dt className="text-[13px] font-medium text-ink">{i.label}</dt>
                  <dd className="text-[12px] text-faint">{i.meaning}</dd>
                </div>
              </div>
            ))}
          </dl>
        </div>
      ))}
    </div>
  </section>
);
