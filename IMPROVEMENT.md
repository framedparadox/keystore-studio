# Improvement plan

Written for: developers working on xkeystore.

This document records why the gaps in the README's "Not supported" section exist, and what is
planned to close them. It is the companion to [DESIGN.md](DESIGN.md), which describes what the app
does today.

## Status

| # | Item | State |
|---|------|-------|
| 1 | RFC 3161 timestamping for JAR and CMS signatures | in progress |
| 2 | macOS and Windows build and test matrix | in progress |
| 3 | Fuzzing the file parsers | in progress |
| 4 | PBMAC1-protected PKCS#12 | in progress |
| 5 | Bouncy Castle BKS and BCFKS reading | in progress |

---

## Why the gaps exist

One rule shaped the original scope: **ship no cryptography that cannot be checked against an
independent implementation.** Every format xkeystore writes is verified by a second tool in the
test suite — `keytool`, `openssl`, `jarsigner` or `ssh-keygen` — because a keystore writer that
produces files only it can read is worse than no writer at all. Each gap below traces back to a
missing reference tool, missing hardware, or a deliberate decision, not to a limit of the design.

### The toolchain moved

The original work ran in a Linux container with **OpenSSL 3.0** and **Java 21**. The development
machine now has **OpenSSL 4.1** and **Java 25**. Two items on the list were artifacts of the older
toolchain:

- **PBMAC1 is now testable.** `openssl pkcs12 -export -pbmac1_pbkdf2` exists in OpenSSL 3.4 and
  later. OpenSSL 3.0 could not produce such a file, so there was nothing to test a reader against.
  Verified working on the current machine.
- **The Ed25519 CMS note was wrong and has been removed.** It described a limit of OpenSSL 3.0, not
  of xkeystore. The app has always signed correctly with Ed25519, and `jarsigner` confirmed those
  signatures. OpenSSL 4.1 verifies them too, so the caveat is obsolete and the note misled readers
  into thinking the app was at fault.

### Per-item reasoning

**1. RFC 3161 timestamping.** A signature without a trusted timestamp stops verifying once the
signing certificate expires, because a verifier cannot tell whether the signature was made while
the certificate was valid. This is the most consequential gap, since it silently degrades
signatures that were correct when produced. It was skipped because it needs an HTTP round trip to a
timestamp authority, and the app was otherwise fully offline with a strict content security policy
and no network permission beyond the TLS inspector. `openssl ts` can act as a local authority, so
this is testable without reaching the internet.

**2. macOS and Windows.** Everything was built and end-to-end tested on Linux only. The CI
workflow has never run on GitHub, so its first run may well fail. Tauri's webview differs by
platform — WebKitGTK on Linux, WKWebView on macOS, WebView2 on Windows — and so do path handling,
the native trust store and file dialogs, which are the areas most likely to break.

**3. Fuzzing.** The PKCS#12, JKS, JCEKS, ASN.1, PEM and CMS decoders all read untrusted input: a
user opens a file they were sent. Today they are covered by unit and interop tests, which only
exercise well-formed input. Malformed input is exactly what a parser gets wrong, and these parsers
do arithmetic on attacker-controlled lengths. Fuzzing is the cheapest way to find panics and
hangs. Rust's bounds checking means a panic is the likely failure, not memory corruption — a
crash and lost work rather than code execution, but still worth fixing. Skipped originally only
for time.

**4. PBMAC1 in PKCS#12.** Defined by RFC 9579, PBMAC1 replaces the PKCS#12 KDF with PBKDF2 for
integrity protection, fixing the weak legacy key derivation. The reader already detects such files
and reports them clearly rather than failing with a confusing password error
([pkcs12.rs](src-tauri/src/pkcs12.rs)). The building blocks — PBKDF2 and HMAC — are already in
[pbe.rs](src-tauri/src/pbe.rs). It was left undone purely because OpenSSL 3.0 could not generate a
test file.

**5. BKS and BCFKS.** Bouncy Castle's own keystore formats, common on Android. No maintained Rust
crate reads them, so support means implementing the formats directly, and test files require the
Bouncy Castle jar, which the container did not have. The app detects both and explains how to
convert them, which is the honest failure mode. Reading is worth far more than writing here: users
need to migrate away from BKS, not create new BKS files.

**6. PKCS#11 tokens (still out of scope).** Keys on a hardware token cannot be exported; signing
must happen on the device through a vendor `.so`/`.dll` with a PIN prompt. That breaks the core
assumption that a keystore is a file loaded into memory, and it needs either real hardware or
SoftHSM to test. This is a larger architectural change — a second kind of key that lives behind a
handle — and is deliberately deferred rather than planned.

---

## Beyond the five items

Recorded here so the reasoning is not lost, roughly in order of value.

**Correctness and security**
- Chain validation against the system trust store, with optional OCSP and CRL revocation checks.
  The app parses and builds CRLs but never checks one while validating.
- Zeroize passwords and decrypted key material after use. Rust moves and copies buffers freely, so
  this needs `zeroize` on the types that hold secrets, not scattered manual clearing.
- An `unsafe`-free audit and `cargo-deny` in CI for advisories and licences.

**Workflow**
- Migrate legacy JKS and JCEKS to PKCS#12 in one action. JKS is deprecated and this is the single
  most common real task.
- Compare two keystores, and bulk edit or delete entries.
- Certificate templates for TLS server, client authentication and code signing, so the right key
  usage and extended key usage are set without knowing the OIDs.

**Platform integration**
- Unlock the vault with the macOS Keychain or Touch ID, and the Windows and Linux equivalents,
  instead of only a master password.
- Code signing and notarization for the macOS `.dmg` and an Authenticode-signed Windows installer,
  plus a release workflow that publishes installers. Without this, macOS Gatekeeper blocks the app.

**Quality**
- More frontend tests. Ten unit tests is thin, and the end-to-end suite runs on Linux only.
- A log file and a "copy diagnostics" button, so a bug report carries the failing file's structure
  without the user having to send the file itself.
- An accessibility pass for screen readers and keyboard-only navigation.
