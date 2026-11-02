# xkeystore

A native desktop workbench for keystores and X.509 certificates, built with Rust, Tauri v2 and React.

All cryptography runs inside the bundled Rust engine.

## Features

- **Drag and drop** — drop `.jks`, `.jceks`, `.bks`, `.bcfks`, `.uber`, `.p12`/`.pfx`, `.pem`, `.crt`, `.cer`, `.der`, `.csr`, `.crl` or `.key` files on the Home page. Java keystores are listed immediately (aliases and certificates); certificates and CSRs open in Examine. Encrypted stores (PKCS#12 and friends) are added and stay locked until unlocked.
- **Keystores** — create, inspect, edit and convert between PKCS#12, JKS, JCEKS, BKS, BCFKS and UBER. Cut/copy/paste entries, rename aliases, lock entries, undo/redo, save to disk, export an inventory CSV.
- **Workspaces** — group certificates and keys across keystores by project, environment or audit scope.
- **Examine** — inspect a live TLS server, a pasted PEM/CSR/CRL/JWT, or compare two certificates.
- **CA and signing** — sign CSRs, issue CRLs, sign JARs and CMS payloads, mint JWTs, generate DH parameters.
- **Security scan** — flag weak, expired and legacy entries and rotate keys.
- **Built-in terminal** — toggle with `Ctrl+`` (or the header button). Views that have a command-line equivalent offer a pre-filled command; nothing runs until you press Enter.

## Development

```bash
pnpm install
pnpm tauri dev      # desktop app
pnpm dev            # UI only in the browser (Tauri commands and terminal unavailable)
pnpm build          # type-check and bundle the UI
```

## Design

UI conventions (tokens, shape/type scale, components) are documented in [DESIGN.md](DESIGN.md).

## Mockups

Static HTML explorations live in [`mockups/`](mockups/index.html).

## License

See [LICENSE](LICENSE).
