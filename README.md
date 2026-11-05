# xkeystore

A native desktop workbench for Java keystores, PKCS#12 files and X.509 certificates, built with
Rust, Tauri v2 and React. All cryptography runs locally in the bundled Rust engine; nothing leaves
your machine except TLS handshakes you start from **Examine**.

## Features

| Area | What you can do |
| --- | --- |
| **Keystores** | Open, create, edit and save **PKCS#12**, **JKS** and **JCEKS** files (keytool/OpenSSL compatible). Convert between formats and change passwords with *Save as…*. Key pairs, trusted certificates and secret keys. Per-key passwords (JKS/JCEKS) are preserved and can be unlocked. Undo/redo, cut/copy/paste between keystores, rename, labels, CSV inventory export. Unsaved-changes tracking with a guard on close/quit. |
| **Entries** | Generate RSA (2048–4096), ECDSA (P-256/384/521) and Ed25519 key pairs with certificates that are self-signed or issued by any open CA; generate AES/HMAC/3DES secret keys; import trusted certificates (PEM/DER/PKCS#7, bundles), key pairs from PEM/DER (PKCS#8, encrypted PKCS#8, PKCS#1, SEC1) or from another keystore. Generate CSRs, install CA replies. |
| **Export** | Certificate (PEM/DER), full chain, PKCS#7 (PEM/DER), PkiPath, public key (PEM, OpenSSH, JWK), private key (encrypted or plain PKCS#8, JWK), single-entry PKCS#12, secret key (hex, JWK). |
| **CA & Signing** | Sign CSRs (with CSR inspection and one-click installation into the matching key pair), issue v2 CRLs, CMS/PKCS#7 sign & verify (attached/detached), JWT sign & verify (RS/ES/EdDSA/HS), JAR signing (jarsigner-verifiable), DH parameters (RFC 7919 groups or freshly generated safe primes). |
| **Examine** | Live TLS inspection (protocol, cipher, ALPN, chain, trust and hostname verdict against the OS trust store), decode anything (certificates, chains, CSRs, CRLs, keys, PKCS#7, JWTs, OpenSSH keys, keystores), compare two certificates. |
| **Security audit** | Health score and findings (expired/expiring, weak keys and digests, deprecated ciphers, incomplete chains, self-signed servers), key rotation that keeps subject/SANs/usages and is re-issued by the original CA when it is open, same-key renewal, CSV report. |
| **Workspaces** | Group entries from several keystores by project or audit scope; persisted across sessions. |
| **Vault** | Remember keystore passwords under one master key (Argon2id → AES-256-GCM), auto-lock after inactivity, change master key (re-encrypts every secret), reset if forgotten. Keystores from the last session reopen automatically once the vault is unlocked. |
| **Productivity** | Window-wide drag and drop, command palette (`Ctrl+K`), keyboard shortcuts, built-in terminal (`Ctrl+\``) with ready-made keytool/openssl commands, recent files, session restore. |

### Keyboard shortcuts

`Ctrl+O` open · `Ctrl+N` new keystore · `Ctrl+S` save · `Ctrl+Shift+S` save as · `Ctrl+Z` / `Ctrl+Shift+Z` undo/redo ·
`Ctrl+K` command palette · `` Ctrl+` `` terminal · `Ctrl+1…8` switch page (⌘ on macOS).

### Not supported

Bouncy Castle BKS/BCFKS/UBER keystores (xkeystore explains how to convert them), PKCS#11 tokens,
RFC 3161 timestamping and PBMAC1-protected PKCS#12 files. Post-quantum (ML-DSA/ML-KEM/SLH-DSA) keys
written by newer JDKs load and save losslessly but cannot be used for signing.

## Development

Requirements: Node 22 + pnpm 10, Rust (stable, edition 2024), and the
[Tauri system dependencies](https://v2.tauri.app/start/prerequisites/) for your OS.

```bash
pnpm install
pnpm tauri dev          # desktop app with hot reload
pnpm tauri build        # release bundles (.deb/.AppImage, .dmg, .msi …)
```

`pnpm dev` serves the UI in a browser for layout work only; the native engine is unavailable there.

## Testing

```bash
pnpm typecheck          # TypeScript
pnpm test               # frontend unit tests (Vitest)
pnpm test:rust          # Rust unit tests + interop tests against keytool, jarsigner and openssl
pnpm test:e2e           # builds the app and drives a full user journey via tauri-driver
```

- **Interop tests** (`src-tauri/tests/interop.rs`) round-trip keystores, CSRs, CRLs, CMS, JARs, DH
  parameters and exports through the real `keytool`, `jarsigner`, `openssl` and `ssh-keygen`, and
  run a TLS handshake against `openssl s_server`. Each test is skipped if its tool is missing.
- **End-to-end** (`e2e/app.e2e.mjs`) needs `tauri-driver` (`cargo install tauri-driver --locked`)
  and WebKitWebDriver (`webkit2gtk-driver` on Debian/Ubuntu); on a headless machine run it with
  `xvfb-run -a`. It creates, saves, edits, signs, audits, restarts and restores a session, and
  verifies the written files with keytool/openssl. Native file dialogs are scripted only when the
  app is started with `XKEYSTORE_E2E=1`.

CI (`.github/workflows/ci.yml`) runs all of the above on Ubuntu.

## Architecture

```
src/                      React UI
  state/store.tsx         app state: open keystores (+ in-memory passwords), undo/redo, workspaces,
                          labels, settings, vault status, open/save/close flows, session persistence
  lib/api.ts              typed wrappers for every Tauri command
  views/                  one file per page; components/ shared UI (see DESIGN.md)
src-tauri/src/            Rust engine
  keys.rs  x509.rs        keys, signing/verification, certificate/CSR/CRL building and parsing
  pkcs12.rs jks.rs        keystore codecs (javaser.rs: JCEKS sealed secret keys), pbe.rs: PBE schemes
  ops.rs entry.rs         entry operations and display models
  cms.rs jwt.rs jar.rs dh.rs tls.rs detect.rs export.rs
  vault.rs                master-key vault; terminal.rs: built-in shell
  lib.rs                  Tauri commands (all run off the UI thread)
```

### Data and security

- Keystore contents and passwords are held in memory only; they reach disk solely in the keystore
  files you save (written atomically, then read back to verify before replacing the original).
- Session state (paths of open keystores, workspaces, labels, recent files, settings) is stored in
  the app data folder (`~/.local/share/xkeystore`, `~/Library/Application Support/xkeystore`,
  `%APPDATA%\xkeystore`; override with `XKEYSTORE_DATA_DIR`). No key material is stored there.
- Remembered passwords are sealed individually with AES-256-GCM under the vault key (bound to their
  ID as associated data); the master key itself is never stored.
- The webview runs under a strict Content Security Policy.

## Design

UI conventions (tokens, components, layout) are documented in [DESIGN.md](DESIGN.md). Static HTML
explorations live in [`mockups/`](mockups/index.html).

## License

MIT — see [LICENSE](LICENSE).
