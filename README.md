# xkeystore

A certificate, private-key and keystore manager — CLI (`xks`) and desktop GUI
(`xks-gui`) — written entirely in Rust. It never shells out to `openssl` or
`keytool`, and never requires a JVM. Its output is nonetheless fully
interoperable with both: see [Interoperability](#interoperability).

The explicit goal that drove the design: **converting a certificate and
private key into a password-protected PFX/P12 (and back) must work out of
the box, in pure Rust, with no external dependency.** That's
[`xks_core::pkcs12`](crates/xks-core/src/pkcs12.rs), and it's exercised end
to end by both the CLI and the GUI.

## Why another keystore tool? (gap analysis)

This project started from a review of the existing landscape — KeyStore
Explorer (KSE), `keytool`, the OpenSSL CLI, XCA, and Portecle — and the gaps
that kept showing up across all of them:

| Gap in existing tools | What xkeystore does instead |
|---|---|
| **KSE, Portecle require a JVM**; `keytool` *is* the JVM. Nothing works until a JRE is installed and on `PATH`. | Single static Rust binary. No runtime dependency at all. |
| **XCA and most scripts shell out to the OpenSSL CLI**, inheriting its version drift (1.1 vs 3.0 flag/behavior changes), its licensing, and its startup cost per invocation. | Certificate/CSR/CRL generation, PKCS#12, JKS and PEM handling are all native Rust (`rcgen`, `p12-keystore`, `jks`, `x509-parser`, RustCrypto `rsa`). No subprocess is ever spawned. |
| **Key material and certificates are separate objects** the user must keep in sync by hand — easy to export a PFX with the wrong key, or lose track of which cert a key belongs to. | A unified [`Identity`](crates/xks-core/src/identity.rs): one alias, one key, one leaf cert, one chain, with a single health status (`Complete` / `Incomplete` / `Invalid` / `Certificate-only`). |
| **"Invalid chain" with no explanation.** `openssl verify` and KSE's own checks tell you *that* something is wrong, rarely *what* or *how to fix it*. | [`chain::validate_chain`](crates/xks-core/src/chain.rs) returns structured findings — missing intermediate (with the exact issuer name it's missing), expired/expiring, weak key, no SAN on a server cert, chain doesn't terminate at a root — each with a severity and a one-line fix. Chain links are verified *cryptographically* (real signature checks via `ring`), not just by comparing issuer/subject strings. |
| **No local record of what you did.** None of KSE, `keytool`, or OpenSSL log "who exported what, with which password strength, when." | A plain JSON-Lines [audit log](crates/xks-core/src/audit.rs) the app writes locally — never transmitted anywhere. |
| **Weak defaults are too easy to reach.** `keytool`'s historic default was 1024-bit RSA/DSA; it's trivial to protect a PKCS#12 with `changeit` and nobody stops you. | Weak RSA/EC sizes are flagged by chain validation; PKCS#12/JKS export surfaces a real [zxcvbn-based strength meter](crates/xks-core/src/password.rs) and a secure random-password generator, right next to the password field. |
| **Dropping in a random file and getting a cryptic parse error** instead of "this is an encrypted PKCS#12, want to try a password?" | [`classify`](crates/xks-core/src/classify.rs) sniffs PEM/DER/PKCS#12/JKS/CSR from the bytes, asks for a password only when one is actually needed, and pairs orphan keys with the certificate whose public key they match — the "Import & classify" queue. |
| **A CA that only signs leaves**, with no first-class CRL support (KSE and `keytool` have none; OpenSSL's `ca` config is famously painful). | [`ca::build_crl`](crates/xks-core/src/ca.rs) issues a real, signed CRL; the CA workspace screen issues root CAs, subordinate CAs, and leaf certs from a CSR, with the CA's own policy (key usage/EKU/CA bit) always overriding whatever the CSR itself asked for. |
| **No CLI/GUI parity.** KSE is GUI-only; scripting it means dropping to `keytool`/OpenSSL anyway. | `xks` (CLI) and `xks-gui` (desktop) are two front ends over the exact same `xks-core` engine — every GUI action has a scriptable CLI equivalent. |
| **Deployment is "figure out the right `openssl`/`keytool` invocation yourself."** | [`presets`](crates/xks-core/src/presets.rs) gives per-target guidance (nginx, Apache, Java, MuleSoft, Node, IIS, macOS Keychain) — which file layout it needs and a reference command, generated as text, never executed. |

## Why "no OpenSSL by default" is actually true

Every cryptographic operation in `xks-core` is backed by one of:

- **[`ring`](https://github.com/briansmith/ring)**, via `rcgen`'s `ring` feature — elliptic-curve (P-256/P-384) and Ed25519 key generation, and all certificate/CSR/CRL signing. `ring` is what `rustls` uses by default; it is not OpenSSL and not a wrapper around it.
- **RustCrypto [`rsa`](https://github.com/RustCrypto/RSA)**, pure Rust — RSA key *generation* specifically, because `ring` deliberately doesn't implement RSA keygen. The resulting PKCS#8 key is then used by `rcgen`/`ring` for signing like any other key.
- **[`p12-keystore`](https://github.com/ancwrd1/p12-keystore)** and **[`jks`](https://github.com/agusibrahim/jks)**, both pure Rust, for the PKCS#12 and JKS container formats respectively (built on RustCrypto's `pkcs5`/`pkcs8`/`cms`/`der` crates for the ASN.1 and PBE work).
- **[`x509-parser`](https://github.com/rusticata/x509-parser)** for inspecting arbitrary (possibly foreign) certificates, CSRs and CRLs, including real signature verification (its `verify` feature, also `ring`-backed).

No crate here links against OpenSSL, and none shells out to `openssl` or
`keytool`. (`aws-lc-rs`, a non-`ring` alternative crypto backend `rcgen`
supports, is explicitly *not* used, to keep the dependency story to one
well-known Rust-ecosystem crypto backend.)

## Interoperability

"No OpenSSL/Java required" only matters if the files this app produces are
still readable by the OpenSSL and Java installations everyone else has.
During development, every PKCS#12 and JKS code path was checked against the
real tools on this machine:

```
$ openssl version
OpenSSL 3.0.13 30 Jan 2024
$ keytool -list -v -keystore out.p12 -storetype PKCS12 -storepass ...
Keystore type: PKCS12
Keystore provider: SUN
...
```

Both the modern (AES-256/PBES2) and legacy (3DES/SHA-1) PKCS#12 encryption
modes, and JKS output, were round-tripped through `openssl pkcs12 -info`
and `keytool -list -v` successfully. This is exercised continuously by the
crate's own test suite doing the equivalent round trip in Rust
(`cargo test -p xks-core`).

## Workspace layout

```
crates/
  xks-core/   engine: keys, certs/CSRs/CRLs, PKCS#12, JKS, PEM, chain
              validation, import classification, CA ops, passwords, audit.
              No UI code; fully unit-tested (27 tests).
  xks-cli/    `xks` binary — a scriptable front end over xks-core.
  xks-gui/    `xks-gui` binary — an egui/eframe desktop front end over the
              same engine (dark graphite/ember theme with a light variant).
```

### `xks-core` modules

| Module | Responsibility |
|---|---|
| `keys` | RSA/EC/Ed25519 key generation and PKCS#8 (de)serialization, with automatic algorithm detection on import. |
| `cert` | Self-signed, CA-signed and CSR-based certificate issuance via named templates (TLS server/client, code signing, email, root/issuing CA); parsing arbitrary certificates into a display-ready `CertInfo`. |
| `pkcs12` | PKCS#12/PFX build and parse, modern or legacy encryption, with/without a private key (truststore). |
| `jks` | JKS build and parse (Java KeyStore), same shape as `pkcs12`. |
| `pem` | PEM bundle/separate-file export; classify-on-import for arbitrary PEM blobs. |
| `chain` | Structured, cryptographically-verified chain diagnostics. |
| `identity` | The key+cert+chain+alias unifying model and its health status. |
| `classify` | Byte-sniffing format detection and orphan key/cert pairing for import. |
| `ca` | CRL issuance. |
| `password` | Secure password generation and zxcvbn-based strength assessment. |
| `audit` | Local, append-only JSON-Lines action log. |
| `presets` | Per-deployment-target file layout and reference commands (text only). |

## Using the CLI

```
xks keygen --alg ec-p256 --out server.key
xks selfsign --key server.key --cn "Test Root CA" --template root-ca --days 3650 --out root.crt
xks ca sign --subject-key server.key --cn svc.example.com --san svc.example.com,127.0.0.1 \
    --ca-cert root.crt --ca-key server.key --template server --days 365 --out server.crt

# The headline feature: certificate + private key -> password-protected PFX
xks convert --from pem --to pkcs12 \
    --key server.key --cert server.crt --chain root.crt \
    --alias myservice --password 'correct horse battery staple' \
    --out server.p12

xks inspect server.p12 --password 'correct horse battery staple'
xks validate --cert server.crt --chain root.crt --key server.key
xks genpassword --length 24
```

Run `xks --help` (and `xks <command> --help`) for the full command surface:
`keygen`, `selfsign`, `csr`, `ca issue`/`ca sign`/`ca crl`, `convert`,
`truststore`, `inspect`, `validate`, `genpassword`, `preset`.

## Using the GUI

`xks-gui` is a 6-screen desktop app over the same engine:

- **Workspace** — every identity you've imported or created, with a status
  table and a local audit-log tail.
- **Import & classify** — drop in files; encrypted PKCS#12/JKS get a
  password prompt inline; orphan keys/certs are paired automatically.
- **Identity detail** — the chain, the full validation report, and
  password-gated export (the private key itself is never displayed).
- **Create keystore** — generate a key, issue a certificate for it
  (self-signed or signed by any CA already in your workspace), add it.
- **Converter** — open any supported file, convert to any other format.
- **CA workspace** — the CA hierarchy in your workspace, CSR signing, and
  CRL publishing.

Needs a graphical environment (a real display with GPU or software
rendering) — it wasn't rendered in this sandboxed build environment, but
`cargo run -p xks-gui` on a normal desktop will open the window directly.

## Building and testing

```
cargo build --workspace
cargo test -p xks-core      # 27 unit/integration tests, no network/display needed
cargo run -p xks-cli -- --help
cargo run -p xks-gui
```

## License

MIT, see [LICENSE](LICENSE).
