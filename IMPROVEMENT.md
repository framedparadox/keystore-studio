# Improvement plan

Written for: developers working on xkeystore.

This document records why the gaps in the README's "Not supported" section exist, and what is
planned to close them. It is the companion to [DESIGN.md](DESIGN.md), which describes what the app
does today.

## Status

| # | Item | State |
|---|------|-------|
| 1 | RFC 3161 timestamping for JAR and CMS signatures | **done** — implemented, cross-checked with `openssl ts` and `jarsigner` |
| 2 | macOS and Windows build and test matrix | **written, unverified** — CI has never run; needs a push to GitHub |
| 3 | Fuzzing the file parsers | **done** — 5 libFuzzer targets + a stable-Rust robustness suite; no crashes found |
| 4 | PBMAC1-protected PKCS#12 | **done** — read and write, round-tripped against OpenSSL 4.1 |
| 5 | Bouncy Castle BKS and BCFKS reading | **partly** — detection fixed; decoder blocked on test fixtures |

Test counts after this work: **49 Rust unit** (was 38), **13 interop** (was 10), **4 robustness**
(new, thousands of malformed inputs), **10 frontend**. `cargo deny check` passes clean.

### 1. Timestamping — done

`src-tauri/src/tsa.rs` requests an RFC 3161 token over the CMS signature value and attaches it to
the SignerInfo as the unsigned `id-aa-timeStampToken` attribute, which is where `jarsigner` and
`openssl ts` look for it. Available for CMS signatures and signed JARs; the TSA URL is set once in
Settings and can be overridden per signature.

Decisions worth knowing:

- **A TSA failure aborts signing.** Silently writing an unstamped file when the user asked for a
  timestamp is worse than refusing, because they would only find out when a verifier rejects it
  years later.
- **The nonce must come back.** A response that omits the nonce we sent is rejected, not skipped —
  otherwise leaving the field out would be a way around the replay check.
- **The TSA's own signature is not verified in-app.** That needs a TSA trust store, which the app
  does not have, so a reported timestamp means "this token covers this signature and the authority
  named in it claims this time". `openssl ts -verify` and `jarsigner -verify` do check it, and the
  interop tests use them. Verifying the chain in-app is listed under "Beyond the five items".

### 2. macOS and Windows — in progress

`.github/workflows/ci.yml` now runs the Rust engine and its interop tests on Linux, macOS and
Windows, builds the installer for each (`.deb`, `.dmg`, `.msi`), and adds a lint job
(`clippy -D warnings`, `cargo fmt --check`, `cargo-deny`).

Two things are worth knowing:

- **macOS ships LibreSSL as `openssl`.** It has no `pkcs12 -export -pbmac1_pbkdf2` and a different
  `ts` implementation, so the matrix installs real OpenSSL and puts it first on `PATH`. Without
  that, the interop tests would quietly skip on macOS and the matrix would prove nothing.
- **The end-to-end journey stays Linux-only.** It drives the real app through `tauri-driver` and
  `WebKitWebDriver`; there is no equivalent WebDriver for WKWebView or WebView2, so on the other
  platforms CI proves the engine and the installer build, not the UI journey.

The installers are unsigned. macOS Gatekeeper will block an unsigned `.dmg` on an end user's
machine, so a release needs signing and notarization — listed under "Beyond the five items", since
it needs secrets rather than code.

### 3. Fuzzing — in progress

Two halves, deliberately:

- **`src-tauri/tests/robustness.rs`** runs on stable Rust in CI on every push. It asserts one total
  contract — every parser returns `Ok` or `Err` and never panics, hangs or aborts — over a
  hand-written corpus of malformed DER, PEM and keystore headers, a deep-nesting case aimed at
  stack overflow, and single-byte truncations, bit flips and forged length headers of *real*
  keystores. Valid files reach much deeper into a decoder than random bytes do, which is where
  length arithmetic actually goes wrong. `XKS_MUTATION_POINTS=2000` runs a deeper local sweep.
- **`src-tauri/fuzz/`** holds five libFuzzer targets (`examine`, `keystore`, `x509`, `cms`,
  `keys`), run briefly in CI and for longer campaigns by hand. These explore far more inputs via
  coverage feedback but need nightly Rust.

Any crash found by the fuzzer should be added to the corpus in `robustness.rs`, so the stable
suite keeps it fixed.

**It found a real bug on the first run.** The `keys` target produced a 31-byte input that aborted
the process with "attempt to add with overflow" inside `yasna`: when skipping an
indefinite-length BER construction, its reader computes `self.pos + length` *before* the bounds
check (`yasna-0.5.2/src/reader/mod.rs:349`), so a nested header declaring a length near
`usize::MAX` panics instead of returning a parse error. Reachable from
`pbe::decrypt_pkcs8`, which means **opening a malicious key file crashed the app and lost unsaved
work**.

Upgrading does not help: yasna 0.6.0 fixed the identical bug on line 282 but left line 349
untouched. The fix is therefore in this codebase — `util::check_der_lengths` validates every
length header before any untrusted bytes reach yasna, and is called at the boundaries
(`pkcs12::decode`, `cms::verify`, `tsa::verify_token`, `pbe::decrypt_pkcs8`).

Writing that guard took two attempts, and the second one is the point: the first version walked the
byte stream linearly, which descended into the contents of primitives — encrypted payloads and key
material are arbitrary bytes, not tags — and **rejected valid PKCS#12 files**. The
`the_unmutated_files_still_open` test caught it immediately. The working version walks the
structure, descending only into constructed values. A hardening check that breaks valid files is
worse than the bug it fixes, so that test earns its place.

This required splitting the crate: the Tauri command layer moved to `src/commands.rs` behind the
default `tauri-app` feature, so `--no-default-features` builds the engine alone. Linking the
Tauri, WebKit and dialog-plugin stack into an AddressSanitizer build fails outright, and none of it
is needed to parse a file. The split is a cleaner boundary regardless: the engine now has no GUI
dependency.

### 4. PBMAC1 — done

The PKCS#12 reader verifies PBMAC1 (RFC 9579) instead of explaining that it cannot, and
`pkcs12::encode_with_mac` can write it. **Writing still defaults to the legacy PKCS#12 MAC**,
because every implementation reads that one and PBMAC1 needs OpenSSL 3.4+; the stronger MAC is
opt-in rather than a silent compatibility break.

Per the RFC the outer `MacData` salt and iteration count are decorative for PBMAC1 — only the
PBKDF2 parameters are authoritative — so files whose outer and inner values disagree still open. A
regression test rewrites those outer values to garbage and asserts the file still reads.

---

### 5. BKS and BCFKS — detection improved, decoder deferred

What changed: detection now distinguishes **BCFKS** from **BKS/UBER** and reports the right one.
This is not cosmetic. The old code lumped them together and always printed
`-srcstoretype BKS`, so a user with a `.bcfks` file was handed a conversion command that fails.
BCFKS is matched structurally (it is DER: `SEQUENCE { version, … }`); BKS/UBER by their header,
now also checking the iteration count so arbitrary files are not misreported as keystores. The
error message is a complete, pasteable `keytool -importkeystore` command, and four tests cover it —
including that a valid PKCS#12, JKS or JCEKS file is never mistaken for a Bouncy Castle one.

**The decoder is deliberately not written.** This project's rule is to ship no cryptography that
cannot be checked against an independent implementation, and I could not produce test files:
generating them means loading `bcprov.jar` as a Java security provider, which runs third-party code
and was blocked in this environment. Writing a BKS parser from the format description alone, with
nothing to verify it against, is exactly the kind of unverified crypto the rule exists to prevent —
a decoder that silently mis-parses a key is worse than one that refuses the file and tells you how
to convert it.

To finish this item:

1. Generate fixtures with Bouncy Castle on a machine where that is permitted — BKS v1 and v2,
   UBER, and BCFKS, each with a key pair, a trusted certificate and a secret key.
2. Commit them as test fixtures (they contain only throwaway keys).
3. Implement the decoders, asserting against those fixtures and round-tripping through `keytool`
   the way `tests/interop.rs` already does for the supported formats.

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
Bouncy Castle jar. Reading is worth far more than writing here: users need to migrate away from
BKS, not create new BKS files.

See "Item 5, and why the decoder is not written yet" below for the current state.

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
- Verify the timestamp authority's own certificate chain in-app, so a timestamp can be reported as
  trusted rather than merely well-formed. Needs a TSA trust store and a policy for which
  authorities count; see the note in `src/tsa.rs`.
- Replace `crypto-bigint` 0.5.5 once p256/p384/p521 publish releases built on `elliptic-curve`
  0.14. The pinned version has known secret-dependent branches (RUSTSEC-2026-0387) in code that
  underlies ECDSA. Not exploitable in a local desktop tool, which has no remote timing surface, but
  it should not stay pinned. Tracked in `deny.toml`.
- Adopt `rustfmt`. The codebase is written to a wider line than rustfmt's default, so enabling it
  reformats every file; worth doing as its own commit rather than as a side effect of turning on
  CI. `cargo fmt --check` is deliberately absent from the lint job until then.

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
- A scheduled long fuzzing campaign (hours, not the 60-second CI smoke run) with a corpus kept
  between runs, so coverage accumulates instead of restarting from scratch each time.
- A log file and a "copy diagnostics" button, so a bug report carries the failing file's structure
  without the user having to send the file itself.
- An accessibility pass for screen readers and keyboard-only navigation.
