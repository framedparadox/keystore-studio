import React from "react";
import { ExternalLink } from "lucide-react";
import { openUrl } from "@tauri-apps/plugin-opener";

/**
 * The privacy policy, shown under Settings → About. It describes what the code does: keep it in
 * step with any change that stores data, reads files or makes a network request. The network
 * requests today are the TLS inspection and connection test in Examine (src-tauri/src/tls.rs,
 * netcheck.rs), revocation checks against a CA's OCSP responder or CRL server (ocsp.rs,
 * revocation.rs) and RFC 3161 timestamps (tsa.rs). There is no telemetry, update check or crash
 * reporting.
 */
export const PRIVACY_UPDATED = "25 November 2026";
export const ISSUES_URL = "https://github.com/framedparadox/keystore-studio/issues";

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section className="space-y-1.5">
    <h4 className="text-[13px] font-semibold text-ink">{title}</h4>
    {children}
  </section>
);

const Bullets: React.FC<{ items: React.ReactNode[] }> = ({ items }) => (
  <ul className="list-disc pl-5 space-y-1 marker:text-subtle">
    {items.map((item, i) => (
      <li key={i}>{item}</li>
    ))}
  </ul>
);

export const PrivacyPolicy: React.FC<{ dataDir?: string }> = ({ dataDir }) => {
  const folder = dataDir ? <code className="font-mono text-[12px] text-ink break-all select-text">{dataDir}</code> : "the app data folder (see Settings → Data)";
  return (
    <div className="space-y-4 text-[13px] text-muted leading-relaxed" data-testid="privacy-policy">
      <p className="text-ink-2">
        <strong className="font-semibold text-ink">Keystore Studio collects no personal data.</strong> It has no accounts, no analytics, no advertising, no crash reporting and no
        automatic update checks. Your keystores, keys and passwords never leave your computer.
      </p>

      <Section title="What stays on your computer">
        <p>Keystore Studio reads and writes only the files you open, save or export. It keeps its own state in {folder}:</p>
        <Bullets
          items={[
            "Settings, workspaces, labels, the paths of recent and open files, and the certificates listed under Certificates (public certificates only).",
            "The vault, if you set one up: keystore passwords encrypted with AES-256-GCM under a key derived from your master key with Argon2id. The master key is never stored.",
            "A record of the certificates you issue as a CA (serial number, subject, key identifiers and expiry date) and the last CRL number of each CA, so later CRLs can revoke them.",
          ]}
        />
        <p>Keystore passwords you do not save in the vault are held in memory only while the app runs.</p>
      </Section>

      <Section title="What leaves your computer, and only when you ask">
        <Bullets
          items={[
            <>
              <strong className="font-medium text-ink-2">Inspecting a TLS server or testing a connection</strong> (Examine) connects to the host and port you enter, the same way a
              browser or openssl would.
            </>,
            <>
              <strong className="font-medium text-ink-2">Checking revocation</strong>, when you press Check revocation (OCSP) or tick the revocation option when validating a
              chain, contacts the OCSP responder or CRL server named in the certificate. An OCSP request carries the certificate's serial number and hashes of its issuer's name
              and key, which tells the CA that the certificate is being checked. Keys and passwords are not sent.
            </>,
            <>
              <strong className="font-medium text-ink-2">Trusted timestamps</strong>, when you turn them on under Settings → Signing, send a hash of what you signed to the
              timestamp authority you chose, with the app name and version as the user agent. The content itself and your keys are not sent.
            </>,
            <>
              <strong className="font-medium text-ink-2">Terminal commands</strong> run on your computer with your permissions; anything they send over the network is up to the
              command you run.
            </>,
          ]}
        />
        <p>Those services handle the request under their own privacy policies. Keystore Studio makes no other network requests.</p>
      </Section>

      <Section title="Clipboard">
        <p>
          Keystore Studio writes to the clipboard only when you copy something. Copy diagnostics includes the app version, platform, data folder, and the names and aliases of open
          keystores, never passwords or key material.
        </p>
      </Section>

      <Section title="Your control">
        <p>
          Settings → Data → Reset app data clears settings, workspaces, labels, recent files and the Certificates list. Records of issued certificates are deleted one by one in
          CA &amp; Signing, and resetting the vault on the Vault page deletes the remembered passwords. Deleting the data folder removes everything Keystore Studio keeps.
        </p>
      </Section>

      <Section title="Changes and contact">
        <p>
          A change to this policy ships with the app version that makes it and is shown here. Questions:{" "}
          <button
            type="button"
            className="inline-flex items-center gap-1 text-brand font-medium hover:underline cursor-pointer"
            onClick={() => void openUrl(ISSUES_URL).catch(() => window.open(ISSUES_URL, "_blank", "noopener"))}
          >
            open an issue on GitHub <ExternalLink className="w-3 h-3" aria-hidden />
          </button>
          .
        </p>
      </Section>

      <p className="text-[12px] text-faint">Last updated {PRIVACY_UPDATED}.</p>
    </div>
  );
};
