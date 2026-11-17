/**
 * Help topics shown under Settings → Help. Plain data so the page can search it and tests can
 * check it. Answers describe what the app does today; keep them in step with the code.
 */
import type { TabType } from "../types/crypto";

/** Where a topic's button goes: a page, or a Settings section. */
export type HelpLink = { label: string; tab: TabType } | { label: string; settings: "general" | "security" | "signing" | "terminal" | "shortcuts" | "data" | "about" };

export interface HelpTopic {
  id: string;
  question: string;
  answer: string[];
  link?: HelpLink;
}

export interface HelpGroup {
  id: string;
  title: string;
  topics: HelpTopic[];
}

export const HELP_GROUPS: HelpGroup[] = [
  {
    id: "start",
    title: "Getting started",
    topics: [
      {
        id: "formats",
        question: "Which files can Keystore Studio open?",
        answer: [
          "Keystores: PKCS#12 (.p12, .pfx), JKS and JCEKS, and Bouncy Castle's BKS (versions 1 and 2), UBER and BCFKS. All six open, edit and save, and Save as converts between them. Java needs the Bouncy Castle provider to read the last three.",
          "Certificates (PEM, DER, PKCS#7, PkiPath, Netscape sequences), private keys (PKCS#8 including scrypt and legacy PBE, PKCS#1, SEC1, DSA, OpenSSL-encrypted PEM, OpenSSH, JWK), public keys (PEM, DER, OpenSSH, SSH2, JWK), CSRs, CRLs and JWTs open in Examine or under Certificates. JAR files open for signing.",
          "Open a file with Ctrl+O, by dropping it anywhere on the window, or from Recent files on the Dashboard.",
        ],
      },
      {
        id: "new",
        question: "How do I create a keystore?",
        answer: [
          "Use New keystore (Ctrl+N). Pick a format, a name and a password, and optionally generate a first key pair with a self-signed certificate.",
          "The keystore exists only in memory until you save it with Ctrl+S, which asks where to put the file.",
        ],
      },
      {
        id: "save",
        question: "What happens when I save?",
        answer: [
          "Save writes the keystore back to its file in the same format. If the file was changed by another program since you opened it, Keystore Studio asks before replacing it.",
          "Save as (Ctrl+Shift+S) can write another format. JKS cannot hold secret keys, and a key that is still locked by its own key password can only be saved back to its original format, so Keystore Studio lists anything that would be lost before writing.",
        ],
      },
      {
        id: "undo",
        question: "Can I undo a change?",
        answer: [
          "Yes. Ctrl+Z undoes and Ctrl+Shift+Z redoes edits to open keystores, up to 30 steps. Labels and workspaces are Keystore Studio's own notes, not edits to the file, so they are not part of undo.",
        ],
      },
    ],
  },
  {
    id: "passwords",
    title: "Passwords, keys and the vault",
    topics: [
      {
        id: "locked-after-restart",
        question: "Why are my keystores locked after a restart?",
        answer: [
          "Keystore Studio reopens the keystores from your last session by file path but never keeps their passwords in plain form. Each one stays locked until you enter its password on the Keystores page.",
          "If you saved the password in the vault, unlock the vault instead: every locked keystore with a remembered password opens at once.",
        ],
        link: { label: "Open the vault", tab: "vault" },
      },
      {
        id: "key-password",
        question: "What is the difference between the keystore password and a key password?",
        answer: [
          "The keystore password opens the file. Each private key can also have a key password of its own; usually it is the same as the keystore password.",
          "By default a key pair opens locked and asks for its key password the first time you inspect, export, copy or sign with it, then stays unlocked for the session. You can turn that off under Settings → Security.",
        ],
        link: { label: "Key access settings", settings: "security" },
      },
      {
        id: "vault",
        question: "What does the vault do?",
        answer: [
          "The vault remembers keystore passwords so you do not have to type them again. They are encrypted with AES-256-GCM under a key derived from your master key with Argon2id. The master key itself is never written to disk.",
          "The vault locks itself after a period of inactivity, which you can change under Settings → Security.",
        ],
        link: { label: "Open the vault", tab: "vault" },
      },
      {
        id: "forgot-master",
        question: "I forgot my master key.",
        answer: [
          "It cannot be recovered. On the Vault page, choose “Forgot the master key? Reset the vault…”. That deletes the remembered passwords only; your keystore files are not touched. You can then set up a new master key.",
        ],
        link: { label: "Open the vault", tab: "vault" },
      },
    ],
  },
  {
    id: "certs",
    title: "Certificates and signing",
    topics: [
      {
        id: "audit",
        question: "How do I find expiring or weak certificates?",
        answer: [
          "The Security audit lists expired, expiring and weak keys and certificates across every open keystore, with a fix for each. The Dashboard summarises the same findings.",
          "The critical and warning windows (30 and 90 days by default) are set under Settings → General.",
        ],
        link: { label: "Open the security audit", tab: "scanner" },
      },
      {
        id: "ca",
        question: "How do I sign a CSR or issue a certificate?",
        answer: [
          "Open a keystore that holds a CA key pair (a key pair whose certificate is a CA), then use CA & Signing. It signs CSRs, issues and renews certificates, and creates CRLs. The same page signs JAR files, CMS/PKCS#7 payloads and JWTs.",
        ],
        link: { label: "Open CA & Signing", tab: "ca_signing" },
      },
      {
        id: "timestamps",
        question: "Should I add a timestamp to signatures?",
        answer: [
          "A trusted timestamp records when you signed, so the signature keeps verifying after the signing certificate expires. Set a timestamp authority (TSA) URL under Settings → Signing. Only a hash of what you signed is sent to the TSA.",
        ],
        link: { label: "Signing settings", settings: "signing" },
      },
      {
        id: "convert",
        question: "How do I convert between formats?",
        answer: [
          "Convert handles PEM ↔ DER, PKCS#7 bundles, certificates into a truststore, PKCS#8, traditional and OpenSSH private keys, OpenSSH, SSH2 and JWK public keys, and keystores between all six formats. Each converter also shows the matching openssl, ssh-keygen or keytool command.",
        ],
        link: { label: "Open Convert", tab: "convert" },
      },
      {
        id: "examine",
        question: "How do I check a server's certificate?",
        answer: [
          "In Examine, enter a host and port. Keystore Studio connects, shows the chain the server sends and checks it against your system's trusted roots. Test connection only checks that the port is reachable.",
        ],
        link: { label: "Open Examine", tab: "examine" },
      },
    ],
  },
  {
    id: "trouble",
    title: "Troubleshooting",
    topics: [
      {
        id: "wrong-password",
        question: "“That password does not open this keystore.”",
        answer: [
          "The password did not decrypt the file. Passwords are case-sensitive. For a PKCS#12 file made by another tool, the keystore password is the export password chosen when it was created.",
        ],
      },
      {
        id: "terminal-stopped",
        question: "A terminal command stopped or did nothing.",
        answer: [
          "The built-in terminal runs one command at a time without a keyboard attached, so tools that wait for input fail straight away. Pass passwords as arguments, for example keytool -storepass.",
          "Commands are stopped after 120 seconds by default; change that under Settings → Terminal.",
        ],
        link: { label: "Terminal settings", settings: "terminal" },
      },
      {
        id: "report",
        question: "How do I report a problem?",
        answer: [
          "Under Settings → Data, Copy diagnostics puts the app version, platform, data folder and the names of open keystores and their aliases on the clipboard. It never includes passwords or key material. Paste it into your report.",
        ],
        link: { label: "Data settings", settings: "data" },
      },
    ],
  },
];

/** Topics whose question or answer contains every word of the query (case-insensitive). */
export function searchHelp(query: string, groups: HelpGroup[] = HELP_GROUPS): HelpGroup[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return groups;
  return groups
    .map((g) => ({
      ...g,
      topics: g.topics.filter((t) => {
        const text = `${t.question} ${t.answer.join(" ")}`.toLowerCase();
        return words.every((w) => text.includes(w));
      }),
    }))
    .filter((g) => g.topics.length);
}
