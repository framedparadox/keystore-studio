import { createLucideIcon, FileBadge } from "lucide-react";
import type { CertificateRole } from "../lib/keystore";

/*
 * Logos for a certificate's place in a chain, drawn on the same grid as the other icons: a shield
 * lettered R for a root and I for an intermediate. An end entity keeps the badged document.
 */
const SHIELD = "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z";

export const RootCertificateIcon = createLucideIcon("shield-root", [
  ["path", { d: SHIELD, key: "shield" }],
  ["path", { d: "M9.5 16V8h3a2.25 2.25 0 0 1 0 4.5h-3", key: "bowl" }],
  ["path", { d: "m12.5 12.5 2.5 3.5", key: "leg" }],
]);

export const IntermediateCertificateIcon = createLucideIcon("shield-intermediate", [
  ["path", { d: SHIELD, key: "shield" }],
  ["path", { d: "M12 8v8", key: "stem" }],
  ["path", { d: "M9.5 8h5", key: "top" }],
  ["path", { d: "M9.5 16h5", key: "foot" }],
]);

/** Icon and tile for each role. The tiles differ too: solid, shaded and plain. */
export const CERTIFICATE_ROLE_VIEW: Record<CertificateRole, { icon: React.ElementType; tile: string }> = {
  root: { icon: RootCertificateIcon, tile: "bg-brand border-brand text-on-accent" },
  intermediate: { icon: IntermediateCertificateIcon, tile: "bg-brand-soft border-brand-soft-hover text-ink" },
  "end-entity": { icon: FileBadge, tile: "bg-surface border-line-strong text-ink-2" },
};
