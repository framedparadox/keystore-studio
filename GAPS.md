# Certificate and keystore backlog

Written for developers working on xkeystore. This is a code review of the engine
(`src-tauri/src`) and the UI that drives it (`src/`), focused on certificate and keystore
operations: what is wrong, what a `keytool` / `openssl` user will look for and not find, and the
order to tackle it.

[IMPROVEMENT.md](IMPROVEMENT.md) records why the original five gaps exist (timestamping, CI,
fuzzing, PBMAC1, Bouncy Castle). Three of those are done. This file is the remaining work,
including defects found in the code that is already shipped. [DESIGN.md](DESIGN.md) is the visual
language and is out of scope here.

Rule that still applies: do not ship cryptography that cannot be checked against `keytool`,
`openssl`, `jarsigner` or `ssh-keygen`. New codecs and new certificate extensions need a fixture
and an interop assertion in `src-tauri/tests/interop.rs`.

## How to use the todo list

Each item has an id (`C1`, `K2`, …). The checklist at the bottom is the work queue. An item is
done when the "Done when" line is true and a test covers it. Do the defects in section 1 before
adding features that sit on the same code.

---

## What already works

So this list is not read as "rebuild the PKI":

- Open, edit and save PKCS#12, JKS and JCEKS, plus read-only BKS v2 (`bks::decode`). Convert between writable formats with Save as or Migrate to PKCS#12. Atomic write, `.bak` backup on replace, and read-back verification before replacing the file (`keystore::save_with`).
- Key pairs (RSA, P-256/384/521, Ed25519), trusted certificates, secret keys (AES, HMAC, DESede). Per-key passwords on JKS/JCEKS load as locked entries and can be unlocked.
- Generate, CSR, sign CSR, install a CA reply, rotate a key, renew with the same key when the issuer is open.
- Export PEM/DER/PKCS#7/PkiPath/JWK/OpenSSH/encrypted PKCS#8/traditional PKCS#1 & SEC1/single-entry PKCS#12, plus OpenSSH private-key import (`keys::from_openssh_str`).
- CMS and JAR signing with an RFC 3161 timestamp token. PBMAC1 read and write in both the engine and the Save dialog.
- Chain ordering by AKI/SKI plus issuer name and verified signature (`x509::build_chain`). Live TLS inspection against the OS trust store.
- Opaque PKCS#8 (DSA, Ed448, X25519, X448, RSA-PSS, ML-DSA, ML-KEM, SLH-DSA) loads and saves. Those keys cannot sign. That limitation is stated in the README and should stay until there is an interop tool.

---

## 1. Defects

These change the bytes a developer gets, or the chain the app believes.

### C1. ECDSA and Ed25519 certificates are stamped with `keyEncipherment`

`GenerateKeyPairDialog` always sends the profile's key usage. The TLS server and TLS client
profiles hard-code `keyEncipherment`:

```12:16:src/components/AddEntryDialogs.tsx
const PROFILES: Record<Exclude<Profile, "custom">, { label: string; isCa: boolean; ku: string[]; eku: string[] }> = {
  server: { label: "TLS server", isCa: false, ku: ["digitalSignature", "keyEncipherment"], eku: ["serverAuth", "clientAuth"] },
  client: { label: "TLS client / mTLS", isCa: false, ku: ["digitalSignature", "keyEncipherment"], eku: ["clientAuth"] },
  codesign: { label: "Code signing", isCa: false, ku: ["digitalSignature"], eku: ["codeSigning"] },
  ca: { label: "Certificate authority", isCa: true, ku: ["digitalSignature", "keyCertSign", "cRLSign"], eku: [] },
};
```

The engine only drops `keyEncipherment` when the caller leaves key usage empty
(`ops::default_key_usage`). The dialog never does that, so an ECDSA or Ed25519 server certificate
gets a critical key usage the key cannot perform. `keytool -genkeypair -keyalg EC` does not set
that bit. The TLS server profile also always adds `clientAuth`.

**Done when:** the profile applied to a non-RSA key is `digitalSignature` (plus `keyAgreement`
only if we deliberately want it), the server profile's EKU is `serverAuth` unless the user opts
into client auth, and an interop test compares the extension bits with `openssl x509 -text`.

### C2. Signing a CSR throws away the request's key usage and extended key usage

`sign_csr` copies SANs and then applies engine defaults, because the CA view always sends
`key_usage: []`:

```213:214:src/views/CaSigningView.tsx
      const res = await api.signCsr(
        { csr_pem: csrPem, subject_override: subject && subject !== i.subject ? subject : null, validity_days: Number(days), is_ca: isCa, sans: splitList(extraSans), key_usage: [], extended_key_usage: isCa ? [] : eku, copy_requested_sans: copySans },
```

`build_csr` only puts SAN into the extension request (`ops::generate_csr`). A code-signing CSR
produced outside this app, or a CSR this app just wrote, is issued as a TLS certificate
(`serverAuth` + `clientAuth`, and `keyEncipherment` for RSA).

**Done when:** a CSR can carry KU and EKU, the sign form shows what the CSR asked for, and issuing
uses that request unless the operator overrides it. A unit test signs a code-signing CSR and
asserts the issued EKU.

### C3. Chain building treats "could not verify" as "issued by"

```870:875:src-tauri/src/x509.rs
/// True if `child` was issued by `parent` (name match plus signature check when possible).
pub fn issued_by(child: &[u8], parent: &[u8]) -> bool {
    match (cert_summary(child), cert_summary(parent)) {
        (Ok(c), Ok(p)) => c.issuer_raw == p.subject_raw && verify_certificate_signature(child, &p.spki).unwrap_or(true),
        _ => false,
    }
}
```

A bad signature of a supported algorithm returns `Ok(false)` and is rejected. An error — unknown
signature algorithm, unknown curve, a CA certificate that does not parse as a key we can use —
becomes `true`. The first certificate in the pool with a matching issuer name is then welded on.
Two CAs with the same subject, or a DSA/post-quantum link we cannot check, produce a chain that
looks complete.

**Done when:** `issued_by` returns false on `Err`. Matching prefers authority key identifier to
subject key identifier, then falls back to a verified signature. Unverifiable links stay in the
bag and are reported as unverified, rather than as the parent. A test with two same-subject
certificates and a garbage signature must not attach the wrong parent.

### C4. JCEKS aliases are not stored the way Java stores them

Java's JKS and JCEKS implementations lowercase aliases (`convertAlias`). This encoder lowercases
JKS only:

```281:284:src-tauri/src/jks.rs
        // JKS aliases are case-insensitive.
        let alias = if kind == Kind::Jks { entry.alias.to_lowercase() } else { entry.alias.clone() };
        if !seen.insert(alias.to_lowercase()) {
```

The rename dialog does the same (`format === "JKS"` only) and then toasts the un-lowercased
string. A JCEKS entry created as `API` is `API` in this app and `api` after `keytool` loads and
saves it. Labels and workspace membership are keyed by `path::alias`, so they detach.

PKCS#12 is a different case. OpenSSL preserves case; Java's PKCS12 keystore lowercases on its own
read. Do not lowercase PKCS#12 on write. Do warn, in the entry or the save dialog, that `keytool`
will fold a mixed-case PKCS#12 alias.

**Done when:** JKS and JCEKS writes and renames lowercase, with a test that `keytool -list` shows
the same alias this app shows. PKCS#12 case is preserved, with a test that an OpenSSL file
containing `API` still reads back as `API`.

### C5. "Quantum safe" counts ordinary AES keys

```168:183:src-tauri/src/entry.rs
pub fn secret_key_entry(...) -> KeystoreEntry {
    ...
        is_post_quantum: bits >= 256 && !algorithm.starts_with("DES"),
```

`summarize().quantumSafe` counts that flag. A 256-bit AES key increments the post-quantum total
next to ML-DSA. Blowfish and ChaCha20 loaded from a store are also unmarked as weak unless they
are shorter than 128 bits (`assess_secret` only special-cases DES, Triple DES, RC2, RC4).

**Done when:** `is_post_quantum` is true only for ML-DSA, ML-KEM and SLH-DSA. Blowfish (and any
other secret algorithm we accept but would not generate) is a weakness finding. The scanner test
fixtures cover both.

### C6. Issuance constraints are stored and then ignored

`ops::issuer_from` rejects a non-CA, an expired CA, and a CA without `keyCertSign`. It does not
look at `notBefore`, so a CA that is not valid yet can issue. `path_len` is written onto the
certificate and never counted when the CA signs a subordinate CA. `ops::validity` silently
shortens `notAfter` to the CA's expiry. The toast shows that resulting date and never says the
requested lifetime was reduced.

Renewal picks the issuer by subject string, first open entry wins:

```105:107:src/views/ScannerView.tsx
  const renew = async (r: Row) => {
    const ca = keystores.flatMap((ks) => ks.entries).find((e) => isCaEntry(e) && e.subject === r.entry.issuer && e.id !== r.entry.id);
```

Two CAs with the same subject, or a renewed CA whose subject matches and whose key does not, will
sign. The check should be authority key id against the CA's subject key id, which both sides
already have on `CertificateInfo`.

**Done when:** issuing fails with a specific error when the CA is not yet valid, when a path
length would be exceeded, or when the AKI does not match the selected CA. If validity is clamped,
the result tells the caller the requested date and the date actually used. Renewal uses AKI/SKI.

### C7. Distinct key passwords do not survive an unlock and save

JKS/JCEKS decode keeps a locked blob and writes it back unchanged (`jks::encode`, `entry.locked`).
The moment the user unlocks, the entry holds a plaintext PKCS#8 and the next save wraps it with
the store password (`jks_protect` / `jceks_protect`). There is no `keytool -keypasswd`. PKCS#12
save rejects locked entries entirely (`pkcs12::encode`), so a JKS with one locked key cannot be
converted until that key is unlocked, which then discards the separate password.

The save dialog's warning covers format changes. It does not say that saving an unlocked key
collapses its key password into the store password.

**Done when:** an entry remembers "this key password differs from the store password" across
unlock, and save can re-wrap with that key password. A command or dialog changes a key password
without changing the store password. An interop test: `keytool -keypasswd`, open here, save,
`keytool` still accepts the key password and rejects the store password for that alias.

---

## 2. Certificate operations that are missing

The parser already displays AIA, CRL distribution points, certificate policies, name constraints
and SCTs (`x509::describe_extension`). The builder can emit only basic constraints, key usage,
extended key usage, SAN, subject key id and authority key id (`x509::build_certificate` adds the
two key ids itself). Everything a private CA needs to be operable by someone else is absent.

### C8. Issued certificates do not point at their CRL or OCSP

`build_crl` writes a v2 CRL with CRL number and AKI. Nothing writes a CRL distribution point or
an authority info access (OCSP, caIssuers) onto the certificate. A verifier cannot find the CRL
this app just produced. CRL numbers live in `localStorage` under `xkeystore.crlNumbers`, keyed by
CA alias, not by subject key id, and not in the keystore. Generating a CRL starts from the rows
the user typed. There is no "open this CRL, add a serial, re-sign".

The reason list in the UI omits `aACompromise` and `removeFromCRL`, both of which the encoder and
parser already know. Revocation time is a `YYYY-MM-DD` at UTC midnight (`parse_day`), so a
revocation loses the time of day.

**Done when:** a CA entry has an issuance profile (CRL URLs, OCSP URL, caIssuers URL, optional
policy OID) applied by both "generate key pair" and "sign CSR". CRL state for a CA is a file the
user opens: parse, append, bump the CRL number, re-sign. Round-trip the file through
`openssl crl`.

### C9. No private-CA ledger

Serials are 128 random bits (`util::random_serial`), which is fine for uniqueness and useless for
operations. The app does not remember what it issued. Renewal and revocation depend on the
certificate still sitting in an open keystore. A CA that signed a CSR for a machine that is not
in this app has no inventory to revoke from.

**Done when:** each issuance appends a local record (serial, subject, SKI, notAfter, profile,
issuing CA SKI) that the CRL tool can search. The record contains no private key. Deleting the
record is explicit.

### C10. Validity is "now, for N days" and nothing else

`ops::validity` sets `notBefore` to now minus 60 seconds and `notAfter` to that plus the day
count, capped at 36,500 days and at the CA expiry. There is no backdate, no explicit end date,
no "valid until the CA expires", and no warning when the chosen lifetime exceeds the CA
Baseline / Apple 398-day server limit. Renewal re-uses the old certificate's full lifetime
(`ScannerView`), so a 10-year leaf is renewed for 10 years.

**Done when:** the sign and generate forms can set notBefore and notAfter as dates, the engine
rejects `notAfter <= notBefore`, and the scanner's default renewal is "from now, for the same
length, clamped to the CA and to a caller-supplied cap".

### C11. Profiles exist in one dialog

The four profiles (server, client, code signing, CA) live as a constant in
`AddEntryDialogs.tsx`. Sign CSR, renewal and rotation each invent their own extension set.
Rotation drops the signature hash and rebuilds KU by translating display labels back to ids
(`ops::rotate_key`); any usage it does not recognise is dropped on the floor.

**Done when:** one profile module is used by generate, sign, renew and rotate. Rotation and
renewal keep KU, EKU, basic constraints, path length, SAN and (once C8 exists) AIA/CRL DP.
Unknown extensions on the old certificate are reported as "not copied" rather than discarded
silently.

### C12. Chain validation stops at "the names line up"

`build_chain` does not check validity overlap, basic constraints, path length, key usage, name
constraints or a trust anchor. Those checks exist only inside the live TLS handshake, and only
against the OS trust store (`tls::inspect`). There is no "validate this entry against these
trusted certificates", which is the operation a developer needs for a private CA that is not in
the system store.

TLS inspection reports stapled OCSP only to the extent rustls checks it during the handshake. It
does not fetch a CRL, and the verifier deliberately turns a failed chain into a successful
handshake so the certificate can still be displayed (`Recorder::verify_server_cert` returns
`Ok`). That is right for an inspector. It is not a substitute for a validate button.

**Done when:** a command takes a leaf plus a set of trust anchors (and optional intermediates)
and returns a path, or a list of failures (expired, not yet valid, bad signature, not a CA, path
length, name constraints, EKU, hostname). The scanner uses it for every key pair and trusted
certificate. CRL/OCSP fetching is a follow-on (C18), not a blocker for path validation.

### C13. CSR and import gaps a developer hits immediately

| Gap | Where it shows up |
| --- | --- |
| CSR has no challenge password, and no KU/EKU (see C2) | `ops::generate_csr` |
| `otherName`, `directoryName` and registered ID SANs are parsed for display and then dropped on sign (`sans_from_strings` filters them) | `ops.rs` |
| Legacy OpenSSL `Proc-Type: 4,ENCRYPTED` PEM is rejected with a conversion hint | `keys::from_bytes` |
| OpenSSH private keys are not imported | `keys::from_bytes` accepts PKCS#8, PKCS#1 and SEC1 |
| Export is PKCS#8 and JWK. There is no PKCS#1 or SEC1 PEM export for tools that still demand `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` | `export::TARGETS` |
| RSA-PSS, DSA, Ed448, X25519 and X448 load as `PrivateKey::Opaque` and cannot sign, even when the key material is an RSA key with PSS parameters | `keys.rs` |
| Engine still accepts RSA-1024 (`PrivateKey::generate` allows 1024..=16384). The dialog does not offer it. A caller of the command can | `keys.rs` |
| No SPKI fingerprint (the pin developers actually configure). The certificate model has MD5, SHA-1 and SHA-256 of the whole certificate | `CertificateInfo` |
| MD5 fingerprint is still computed and shown. It trains people to pin the wrong value | `x509::parse_certificate` |

**Done when:** each row is either implemented with an interop check, or explicitly rejected in
the UI with the same sentence the engine returns. RSA generation below 2048 fails in
`PrivateKey::generate`. SPKI SHA-256 is on the certificate view and in the CSV inventory.

### C14. CMS, JAR and JWT are sign-only

CMS verify and sign (attached, detached, one signer, optional timestamp) work. There is no
encryption/enveloping, no countersignature, no multiple signers, and no attribute certificates.
JAR signing is the v1 `jarsigner` signature. APK v2/v3 is out of scope unless we deliberately
add it; say so in the JAR tool rather than accepting an `.apk` and producing a signature Android
will ignore. `probe_file` currently treats `.apk` as a JAR.

JWT sign/verify covers RS, ES, EdDSA and HMAC. It does not check `aud` / `iss` / `nbf` policy
beyond what the caller types, and it has no `kid` rotation story other than the alias copied
into the JWK `kid`.

**Done when:** the JAR tool refuses `.apk` with a one-line explanation, or gains a tested v2
scheme. CMS enveloping is a later project (needs a recipient certificate and an interop vector
with `openssl cms -encrypt`); do not start it in the same change as C1–C7.

---

## 3. Keystore operations that are missing

### K1. Saving is a full rewrite with a fixed policy

`pkcs12::encode` always uses PBES2 / AES-256-CBC and the legacy PKCS#12 MAC at
`pbe::DEFAULT_ITERATIONS` (10_000). `encode_with_mac(..., MacKind::Pbmac1)` exists and is tested.
The Save dialog cannot select it, and it cannot keep the encryption it found on open. Re-saving
a Java or OpenSSL file therefore:

- re-encrypts every unlocked key with the store password (C7)
- replaces the MAC and the iteration count
- duplicates intermediate certificates, one cert bag per chain, with no alias on the extras
- gives secret-key bags a new `localKeyId` of the form `Time {millis}` on every save, so anything
  matching a secret key by local key id breaks

JKS integrity is SHA-1 because the format says so. Saving a JKS re-applies that. The UI should
say so and offer "save as PKCS#12" as the default when the source is JKS.

There is no "this file changed on disk" check. `open` records `updated_at` from mtime and `save`
never reads it again. Two windows, or this app plus `keytool`, and the later save wins.

**Done when:** Save as can choose legacy MAC or PBMAC1, shows the iteration count, and refuses
to overwrite when the file's mtime is newer than the copy we opened (with an explicit Override).
A `.bak` of the previous bytes is written next to the file before the replace. Secret-key
`localKeyId` is stable for a given alias and key.

### K2. One-step migrate, diff, and bulk edit

Save as already converts format, and the dialog blocks the two cases that would drop data
(secret keys into JKS, locked keys into another format). What is missing is the task people
open the app for:

- "Convert this JKS to PKCS#12" as one action that picks the destination, explains SHA-1 and key
  passwords, and leaves the original in place.
- Diff two keystores, or a keystore against its on-disk version: alias added, removed, and
  certificate whose fingerprint changed.
- Multi-select delete, export and label. `deleteEntries` accepts a list of ids; the table is
  one row at a time.
- Clone an entry under a new alias (same key material and chain).

### K3. Passwords and locking

- Open asks for the store password only. Per-key passwords are a second dialog per alias. A
  store with twenty key passwords needs twenty prompts. Accept a map at open (the command
  already takes `keyPasswords`) from a file or a repeated field.
- Empty store passwords are rejected (`keystore::encode`). Java and OpenSSL both allow them.
  Keep the rejection, and say why in the dialog instead of a generic engine error after the
  user has already picked a path.
- Locking the vault seals stored passwords. It does not drop `passwords` in the UI store or the
  PKCS#8 PEM sitting on every entry, and undo history keeps full keystore snapshots. That matches
  the current design (the vault is a password safe, not a session lock). The lock control reads
  as a session lock. Either make lock also forget in-memory keys and passwords, or rename the
  control so it does not imply that.
- `zeroize` is used for the vault key (`vault.rs`) and nowhere else. Store passwords, key
  passwords and PKCS#8 bytes are ordinary `String` / `Vec<u8>` that Rust copies. Add `zeroize`
  on the types that own secrets, including the password map when a keystore closes.

### K4. Formats still refused, with the work named

| Format | State | Next step |
| --- | --- | --- |
| BKS, UBER, BCFKS | Detected. The error is a pasteable `keytool -importkeystore` command. Decoder not written, on purpose: no fixture has been checked against Bouncy Castle. | Generate fixtures (key pair, trusted cert, secret key) for BKS v1, BKS v2, UBER and BCFKS. Commit them. Read-only decoder. Assert against the fixtures and against `keytool` after conversion. Do not write these formats. |
| PKCS#11 | Out of scope for the file model. | Leave it out until there is a SoftHSM test and a second key type that signs without exporting. |
| Post-quantum | Round-trip only. | Signing waits on an interop tool and on the `crypto-bigint` upgrade in section 5. |

### K5. Inventory and findings the scanner cannot see

`findingsFor` reports expiry, the engine's weak-algorithm list, self-signed server certificates,
a chain of length 1, and locked keys. It does not report:

- JKS as a store (SHA-1 integrity, proprietary key wrap)
- missing SAN on a server certificate, or a CN that is a hostname while SAN is empty
- lifetime over 398 days on a certificate with `serverAuth`
- CA certificate with no path length, when the user asked for a subordinate CA
- trusted certificate that is expired, or that does not chain to anything else open
- duplicate subject key ids across entries
- secret key algorithm the app would not generate (Blowfish, DES, HMAC-SHA1)

The CSV inventory omits path, format, locked, chain length and EKU. The security report CSV
escapes quotes and does not neutralise formula injection; `export::inventory_csv` does.

**Done when:** those findings exist in `metrics.ts` with unit tests, and both CSVs share one
escaping helper.

---

## 4. Security hygiene

Tracked here so they are not mixed up with feature work.

| Id | Item | Notes |
| --- | --- | --- |
| S1 | Zeroize secret material | C7 and K3. `zeroize` is already a dependency. |
| S2 | Typed errors | Every command returns `Res<T> = Result<T, String>`. The open dialog cannot tell "wrong password" from "truncated file" except by matching English. Introduce a small error enum at the keystore boundary (`WrongPassword`, `Unrecognized`, `Unsupported`, `Invalid`) and map it in `errorMessage`. |
| S3 | Private keys in the webview | Every entry sent to React includes `private_key_pem`. Undo stores full snapshots. `state.json` does not: persisted keystores are path, name and format only. Long term, the UI should hold entry ids and ask the engine to sign or export. That is a large cut. Until then, do not add new copies of the PEM (logs, toasts, terminal history, diagnostics). |
| S4 | TSA chain | A timestamp means "this token covers this signature and names this time". The TSA certificate is not validated. Needs a trust store and a policy for which authorities count. See `tsa.rs` and IMPROVEMENT.md. |
| S5 | `crypto-bigint` 0.5.5 | RUSTSEC-2026-0387, secret-dependent branches under ECDSA. No remote timing surface in a desktop tool. Upgrade when p256/p384/p521 allow it. Already ignored in `deny.toml`; delete the ignore when the upgrade lands. |
| S6 | MD5 and SHA-1 display | Keep SHA-1 available as a fingerprint people still compare. Stop computing MD5, or move it behind a disclosure. C5 and C13. |
| S7 | Diagnostics | A log plus "copy diagnostics" that records versions, format, entry counts and the parser error, and never the password or the key. IMPROVEMENT.md already asks for this. |

---

## 5. Already recorded, still open

These are real and are not repeated as new findings above. Status is from the tree as reviewed,
not from the older status table in IMPROVEMENT.md.

| Item | State |
| --- | --- |
| RFC 3161 on CMS and JAR | Done. Token request/attach, TSA CMS signature verification, `timeStamping` EKU check, and `TSTInfo` `Accuracy.millis`/`extensions` parsing are verified (`tsa.rs`). |
| PBMAC1 read/write in the engine | Done and exposed in `SaveDialog`. |
| Fuzz targets and the yasna length guard | Done (6 robustness tests in `tests/robustness.rs`). A long scheduled campaign is still absent. |
| GitHub Actions matrix for macOS and Windows | Workflow is written. It has not been proven by a push. Installers are unsigned; macOS Gatekeeper will block an unsigned `.dmg`. |
| BKS / BCFKS / UBER decoder | Done. BKS v2 read-only decoder (`bks.rs`) plus content detection for BKS v1/v2, UBER, and BCFKS (`keystore.rs`, `detect.rs`). |
| PKCS#11 | K4. Out of scope until the model changes. |
| OS trust store, OCSP, CRL during validation | `x509::validate_chain` (including `NameConstraints`, wildcard/IP SAN checks, anchor self-signatures, and CA `pathLen`) is wired into `ScannerView.tsx`. Network revocation fetching is the step after that. |
| rustfmt | Done (`src-tauri/rustfmt.toml`, `cargo fmt --check` clean). |
| Frontend tests | 18 unit tests in `src/lib/lib.test.ts`. Store/dialog/view components are still untested. E2E is Linux-only because `tauri-driver` has no WKWebView or WebView2 driver. |
| `keytool_keystores_open_in_xkeystore` | Parallelized across formats in `tests/interop.rs`. |
| Accessibility | Not reviewed in depth here. Keyboard focus and `aria-label` on icon buttons are already required by DESIGN.md; there has been no pass with a screen reader. |

---

## 6. Todo list

Work top to bottom. Each box is one change with its test. Do not start K4 or CMS enveloping
while C1–C7 are open; those defects ship in files people will trust.

### Milestone A — correct the bytes we already write

- [x] **A1. C1** Fix profiles so non-RSA certificates do not get `keyEncipherment`, and the server profile does not force `clientAuth`. Interop against `openssl x509 -text`. *(Verified: `src/lib/keystore.ts:52-66`, `tests/interop.rs:ec_server_extensions_match_openssl_text`.)*
- [x] **A2. C4** Lowercase JKS and JCEKS aliases on write and rename. Preserve PKCS#12 case. Add a `keytool -list` assertion and an OpenSSL PKCS#12 case assertion. Fix the rename toast to show the stored alias. *(Verified: `jks.rs:280`, `EntryDialogs.tsx:283-289`, `tests/interop.rs:jceks_alias_case_matches_keytool`.)*
- [x] **A3. C5** Stop marking AES-256 as post-quantum. Flag Blowfish and other legacy secret algorithms in `assess_secret`. *(Verified: `entry.rs:117-134, 189`.)*
- [x] **A4. C3** `issued_by` must not treat verification errors as success. Prefer AKI/SKI. Test the two-CA same-subject case. *(Verified: `x509.rs:1032-1047, 1344-1371`.)*
- [x] **A5. C6** Enforce CA `notBefore` and path length. Return a distinct message when validity is clamped. Renewal selects the CA by key id. *(Verified: `ops.rs:142-215`, `src/lib/keystore.ts:74-86`.)*
- [x] **A6. C2** Put KU and EKU in the CSR. The sign form shows the request and uses it unless overridden. Unit test a code-signing CSR. *(Verified: `ops.rs:307-325`, `CaSigningView.tsx`, `x509.rs`.)*

### Milestone B — keystore save is safe to repeat

- [x] **B1. C7** Preserve a distinct key password across unlock and save. Add change-key-password. Interop with `keytool -keypasswd`. *(Verified: `jks.rs`, `pkcs12.rs`, `bks.rs`, `ops.rs`, `entry.rs`, `KeystoreDialogs.tsx`.)*
- [x] **B2. K1** Save dialog: MAC choice (legacy or PBMAC1), visible iteration count, mtime conflict, `.bak` before replace, stable secret-key `localKeyId`. *(Verified: `keystore.rs:260-289`, `pkcs12.rs:467-490`, `store.tsx`, `KeystoreDialogs.tsx`.)*
- [x] **B3. K1** When the open file is JKS, the save dialog explains SHA-1 integrity and offers PKCS#12 as the recommended target without discarding the original. *(Verified: `KeystoreDialogs.tsx:118, 183-189`.)*
- [x] **B4. K5** Scanner findings for store format, missing SAN, long server lifetime, and duplicate SKIs. One CSV escaper for inventory and the security report. *(Verified: `src/lib/metrics.ts:39-105`, `src/lib/csv.ts`, `src/lib/lib.test.ts`.)*
- [x] **B5. S2** Typed keystore errors, mapped in the open and save dialogs. *(Verified: `src/lib/api.ts:38-47`, `keystore.rs`, `jks.rs`, `bks.rs`, `pkcs12.rs`.)*

### Milestone C — a private CA can operate

- [x] **C-a. C11** One profile implementation shared by generate, sign, renew and rotate. Renewal default lifetime is from today, clamped, and the cap is visible. *(Verified: `ops.rs:399-475`, `x509.rs`, `ScannerView.tsx`, `src/lib/keystore.ts`.)*
- [x] **C-b. C10** notBefore and notAfter as dates on generate and sign. *(Verified: `ops.rs:142-167`, `AddEntryDialogs.tsx:235-236`, `CaSigningView.tsx:298-299`.)*
- [x] **C-c. C8** AIA and CRL distribution point on issued certificates. Open, extend and re-sign a CRL. Persist the CRL number with the CA, not in `localStorage`. `openssl crl` round-trip. Add the missing revocation reasons and a full revocation timestamp. *(Verified: `x509.rs:405-413, 569-595, 1143-1155`, `commands.rs`, `AddEntryDialogs.tsx`, `CaSigningView.tsx`.)*
- [x] **C-d. C9** Append-only issuance ledger (no key material) that the CRL tool can search. *(Verified: `commands.rs:344-455`, `CaSigningView.tsx`.)*
- [x] **C-e. C12** Validate a chain against trust anchors the user picks. Wire the result into the scanner. *(Verified: `x509.rs:1168-1375`, `commands.rs:485-493`, `ScannerView.tsx`.)*
- [x] **C-f. C13** SPKI SHA-256 on the certificate view and in CSV. Reject RSA below 2048 in `PrivateKey::generate`. Decide PKCS#1/SEC1 export and OpenSSH private-key import; implement with interop or surface the existing rejection in the import dialog. *(Verified: `x509.rs:882`, `keys.rs:110, 211`, `export.rs:64-66`, `CertificateView.tsx:61`.)*

### Milestone D — daily keystore work

- [x] **D1. K2** "Migrate to PKCS#12" action that writes a new file and leaves the source untouched. *(Verified: `KeystoresView.tsx:350-368`.)*
- [x] **D2. K2** Diff two keystores (and the open copy against disk): added, removed, fingerprint changed. *(Verified: `src/lib/diff.ts`, `KeystoresView.tsx:138-148, 656-672`.)*
- [x] **D3. K2** Multi-select delete, export and label. Clone entry. *(Verified: `KeystoresView.tsx:289, 503-538`.)*
- [x] **D4. K3** Supply several key passwords at open. Explain the empty-password rejection in the dialog. *(Verified: `jks.rs`, `bks.rs`, `pkcs12.rs`, `KeystoreDialogs.tsx`.)*
- [x] **D5. K3 / S1** Zeroize passwords and key bytes on close. Decide whether Lock clears in-memory keys; relabel the control if it does not. *(Verified: `keys.rs:95-104`, `VaultView.tsx:250` labeled "Lock vault".)*
- [x] **D6. K4** Bouncy Castle fixtures, then a read-only BKS / UBER / BCFKS decoder checked against `keytool`. BKS version 2 is read (fixture `tests/fixtures/sample.bks`, checked against keytool). UBER stays refused because the store cipher is Twofish. BCFKS stays refused; the file is still detected and the conversion command is unchanged. *(Verified: `keystore.rs:94-210`, `detect.rs:95-105`, `commands.rs:129-145`.)*
- [x] **D7. C14** Stop treating `.apk` as a JAR, or document and test the signature Android will not use. Leave CMS enveloping for its own project. *(Verified: `jar.rs:34-36`, `commands.rs:133`.)*

### Milestone E — hygiene and proof

- [x] **E1. S4** Optional TSA trust store. A timestamp is reported as verified only when that chain builds. *(Verified: `tsa.rs:82-320`.)*
- [ ] **E2. S5** Drop the `crypto-bigint` pin once the elliptic-curve crates allow it. Remove the `deny.toml` exception. Still blocked: p256/p384/p521 have not published a release on `elliptic-curve` 0.14, so the `deny.toml` exception stays.
- [x] **E3. S7** Diagnostics bundle with no secrets. *(Verified: `SettingsView.tsx:127-142`.)*
- [x] **E4.** rustfmt in one commit, then `cargo fmt --check` on CI. `src-tauri/rustfmt.toml` sets `max_width = 200` so the ASN.1 builders stay readable. The lint job runs `cargo fmt --check`.
- [x] **E5.** Speed up the keytool interop test with shared fixtures. *(Verified: `tests/interop.rs` parallelizes `keytool_keystores_open_in_xkeystore` across formats with `std::thread::scope`.)*
- [x] **E6.** Frontend tests for rename, save-as format guards, profile key usage, and renew's CA selection. *(Verified: 18 tests in `src/lib/lib.test.ts`.)*
- [ ] **E7.** Push the CI workflow and fix the first macOS and Windows breaks. The workflow now includes `cargo fmt --check`. It has not been pushed, so the macOS and Windows jobs are still unproven. Signing and notarization stay a release task.
- [x] **E8. S6** Remove MD5 from the default certificate view. *(Verified: `CertificateView.tsx`, `x509.rs`.)*

### Milestone F — fix review findings (2026-11-06)

Ordered High → Medium → Low. Full details, `file:line` pointers, repros, and acceptance criteria are in Section 7 below.

- [x] **F1. R1 (High)** Verify the TSA's CMS `SignerInfo` signature and `timeStamping` EKU in `tsa::verify_token` / `tsa::chain_trusted`, and parse `Accuracy.millis`/`micros` and `TSTInfo.extensions`.
- [x] **F2. R2 (High)** Fix `x509::validate_chain`: enforce `NameConstraints`, reject bare domain on `*.domain`, check IP SANs, verify self-signature on anchor leaves, enforce `pathLen` when leaf is a CA, and wire chain validation + embedded root anchors into `ScannerView.tsx`.
- [x] **F3. R3 (High)** Fix `keystore::detect_unsupported` salt-offset bug (`8 + salt_len`), distinguish BKS v2 from UBER v2, emit `-srcstoretype UBER` when appropriate, and detect BKS/BCFKS/UBER in `detect::examine` and `probe_file` by content.
- [x] **F4. R4 (High)** Preserve `entry.key_password` across `ops::rotate_key`, `ops::import_ca_reply`, and `entry::refresh`; handle distinct `key_password` on PKCS#12 save and BKS open; lowercase `key_passwords` map keys in `jks::decode`; fix `KeyPasswordDialog` copy.
- [x] **F5. R5 (Medium)** Unify `ops::rotate_key` and `ScannerView` renewal with the shared profile/extension logic so AIA, CRL DP, RSA `signature_hash`, `encipherOnly`/`decipherOnly`, `anyExtendedKeyUsage`, unknown-extension warnings, and CA ledger records are preserved.
- [x] **F6. R6 (Medium)** Add `"removeFromCRL" => Some(8)` to `x509::reason_code` and preserve full ISO-8601 revocation timestamps in `x509::parse_crl`.
- [x] **F7. R7 (Medium)** Wire `api.caLedger` and `api.caLedgerSetStatus` into `CaSigningView.tsx` (`CrlTool`), and persist the CRL number per CA instead of resetting to `1`.
- [x] **F8. R8 (Medium)** Fix `ops::resolve_usages` to fall back to `input.key_usage` / `input.extended_key_usage` before engine defaults when the CSR has no usages, and expose AIA (`ocsp_urls`, `ca_issuer_urls`) and intermediate CA `path_len` in the UI forms.
- [x] **F9. R9 (Medium)** In `cms::verify_with_trust`, enforce caller-selected signer certificate matching, check signer certificate validity (`not_before`/`not_after`), and verify `ATTR_CONTENT_TYPE` matches `eContentType`.
- [x] **F10. R10 (Medium)** Fix `keystore::save_with` mtime conflict check (`disk != opened`), return the new disk `mtime_ms` in `SaveResult`, and offer an Override prompt when quick `Save` (`Ctrl+S`) hits `changed-on-disk`.
- [x] **F11. R11 (Low)** Write sensitive private-key and secret-key exports with mode `0600` on Unix.
- [x] **F12. R12 (Low)** Deduplicate CA certificate bags by DER bytes in `pkcs12::encode_with_mac`.
- [x] **F13. R13 (Low)** Introduce a typed keystore error enum across IPC and ensure all parser error paths carry the classification kind.
- [x] **F14. R14 (Low)** Update stale capability copy in `SettingsView.tsx` and stop computing `md5_fingerprint` in `x509::parse_certificate`.

### Explicitly not on this list

- Writing BKS, UBER or BCFKS.
- PKCS#11, until the key model is "a handle that can sign" and SoftHSM is in CI.
- Post-quantum signing, until an external tool can check the signature.
- Making PBMAC1 the default write. Readers that are not OpenSSL 3.4+ would start failing. It stays opt-in (B2).
- Fetching CRLs and OCSP for every validation. Path building (C-e) comes first; network revocation is a separate design (where from, how long to cache, what to do offline).

---

## 7. Review findings (2026-11-06)

Findings from the 2026-11-06 full-tree code audit and scenario harness verification. Severity levels:
- **High**: wrong cryptographic bytes written, silent data/password loss, or false "verified/trusted" security verdict.
- **Medium**: broken or misleading feature behavior with a workaround, or incomplete implementation of a checked backlog item.
- **Low**: defense-in-depth, file hygiene, duplicate bags, or stale UI copy.

### R1. [High] Forged/unsigned RFC 3161 timestamp tokens report `valid: true` and `chain_trusted: Some(true)`, and valid `TSTInfo` tokens with `Accuracy.millis`/`micros` or `extensions` fail to parse

- **Where:** `src-tauri/src/tsa.rs:82-91`, `src-tauri/src/tsa.rs:180-215`, `src-tauri/src/tsa.rs:229-236`, `src-tauri/src/tsa.rs:275-282` (affects **E1 / S4**).
- **Symptom:**
  1. `tsa::describe_token` (`tsa.rs:209`) reads and discards `signerInfos` without verifying the TSA's CMS signature over the encapsulated `TSTInfo`.
  2. `tsa::chain_trusted` (`tsa.rs:275-282`) only runs `x509::validate_chain(leaf, &ts.certificates[1..], &anchors, None)` where `leaf` is `ts.certificates.first()`. It never verifies that any certificate in `ts.certificates` signed `signerInfos`, never matches `SignerInfo.sid` (assuming `ts.certificates[0]` is the signer leaf even though CMS `CertificateSet` is an unordered `SET OF`), never checks for critical `ExtendedKeyUsage: timeStamping` (`1.3.6.1.5.5.7.3.8`, required by RFC 3161 §2.3), and checks certificate validity at `now_ts()` rather than `genTime`. As a result, an unsigned or tampered CMS `SignedData` wrapping a `TSTInfo` with a matching `messageImprint` and a copy-pasted certificate chain is reported as `valid: true` and `chain_trusted: Some(true)`.
  3. `tsa::describe_token` (`tsa.rs:230-234`) only parses `seconds` (`INTEGER OPTIONAL`) inside `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] IMPLICIT INTEGER OPTIONAL, micros [1] IMPLICIT INTEGER OPTIONAL }` and omits the 10th field `extensions [1] IMPLICIT Extensions OPTIONAL` of `TSTInfo` (RFC 3161 §2.4.2). Tokens from public TSAs (such as DigiCert or Sectigo) or `openssl ts` that include `millis`, `micros`, or `extensions` fail with `"the timestamp token contains a malformed TSTInfo: ASN1Error { kind: Extra }"`.
- **Repro:** Construct a CMS `SignedData` with an empty `signerInfos` `SET {}`, a `TSTInfo` matching `SHA-256(signature)`, and an end-entity certificate in `certificates [0]`; call `tsa::verify_token` and `tsa::chain_trusted(&verified, &ca_pem)` — returns `Ok` and `Some(true)`. Construct a `TSTInfo` with `Accuracy { seconds: 1, millis: 500 }` — `tsa::verify_token` returns `Err("the timestamp token contains a malformed TSTInfo: ASN1Error { kind: Extra }")`.
- **Done when:** `tsa::verify_token` verifies the CMS `SignerInfo` signature over `TSTInfo` against the signer certificate identified by `SignerInfo.sid`, requires `id-kp-timeStamping` EKU on the TSA signer certificate, parses `Accuracy.millis` (`[0]`), `Accuracy.micros` (`[1]`), and `TSTInfo.extensions` (`[1]`), and `tsa::chain_trusted` validates the actual TSA signer's chain up to `anchors_pem`.

### R2. [High] `x509::validate_chain` ignores `NameConstraints`, accepts `*.example.com` for bare `example.com`, rejects IP SANs, skips self-signature on anchor leaves, and misses subordinate-CA `pathLen` on the leaf

- **Where:** `src-tauri/src/x509.rs:1168-1246`, `src-tauri/src/commands.rs:438-446`, `src/views/ScannerView.tsx:212-228` (affects **C-e / C12**).
- **Symptom:**
  1. Despite the doc comment at `x509.rs:1184` (`/// Name constraints are applied to DNS names on the leaf`) and `C12`, `validate_chain` never inspects `ParsedExtension::NameConstraints` (`permitted_subtrees` / `excluded_subtrees`).
  2. `host_matches` (`x509.rs:1171`) includes `host == rest`, so `*.example.com` matches bare `example.com` (violating RFC 6125 §6.4.3 / RFC 9525 and rejected by both `openssl verify -verify_hostname` and `rustls`).
  3. `san_matches_host` (`x509.rs:1174-1180`) only checks `dns:` SANs and ignores `ip:` SANs, so validating an IP literal hostname (`"127.0.0.1"`) against a certificate carrying `IP:127.0.0.1` always fails with `"the certificate is not valid for 127.0.0.1"`.
  4. When `leaf` is present in `anchors` (`x509.rs:1209`: `let mut reached = anchors.iter().any(|a| a.as_slice() == leaf)`), the loop exits before calling `issued_by`, so a self-signed trust anchor with a corrupted signature validates with no errors.
  5. When `leaf` itself is a subordinate CA (`is_ca == true`), `followed` starts at `0`, so an issuing CA with `path_len: Some(0)` is not flagged (`0 > 0` is `false`).
  6. `commands::validate_chain` (`commands.rs:442-443`) calls `.unwrap_or_default()` on `intermediates_pem` and `anchors_pem`, silently ignoring malformed PEM input.
  7. `ScannerView.tsx:212-228` only runs chain validation when the user manually clicks `"Validate chains"` (not in `findingsFor`), and builds `anchors` only from `e.certificate_chain[0]` of `TrustedCertificate` / CA entries, omitting self-signed root CAs at the end of a `KeyPair`'s `certificate_chain`.
- **Repro:** Call `x509::validate_chain` with (a) a `*.example.com` cert and `hostname: Some("example.com")` → returns `[]`; (b) an `IP:127.0.0.1` cert and `hostname: Some("127.0.0.1")` → returns `["the certificate is not valid for 127.0.0.1"]`; (c) a subordinate CA leaf under a `pathLen=0` root → returns `[]`; (d) a byte-corrupted self-signed root passed as both `leaf` and `anchors` → returns `[]`; (e) a leaf `evil.other.com` signed by a CA with critical `NameConstraints` permitting only `.allowed.example` → returns `[]`.
- **Done when:** `validate_chain` enforces DNS/IP `NameConstraints` (and rejects unhandled critical `NameConstraints`), requires a single non-empty leftmost label for `*.domain`, matches IP literal hostnames against `ip:` SANs, verifies self-signatures on self-signed anchors, counts CA leaves against parent `pathLenConstraint`, propagates PEM parse errors in `commands::validate_chain`, and wires chain validation into `ScannerView.tsx` including root anchors from full `KeyPair` chains.

### R3. [High] `keystore::detect_unsupported` reads random salt bytes as the iteration count (`sample.uber` fails as `unrecognized`), v2 UBER fails as `wrong-password`, and `detect::examine` misses BKS/BCFKS/UBER

- **Where:** `src-tauri/src/keystore.rs:94-146`, `src-tauri/src/keystore.rs:171-184`, `src-tauri/src/keystore.rs:317-325`, `src-tauri/src/commands.rs:129-138`, `src-tauri/src/detect.rs:95-97` (affects **D6 / K4**).
- **Symptom:**
  1. In Bouncy Castle BKS/UBER format (`bks.rs:114-124`), bytes `0..4` = `version`, `4..8` = `salt_len`, `8..8+salt_len` = random salt, and `8+salt_len..12+salt_len` = `iterations`. `keystore::detect_unsupported` (`keystore.rs:120`) reads `iterations` from `bytes[8..12]` (the first 4 bytes of the random salt!) instead of `bytes[8 + salt_len..12 + salt_len]`. The unit test `bcfks_is_told_apart_from_bks` (`keystore.rs:317-323`) passed only because it constructed a synthetic header `[version, salt_len, iterations, salt]` with `iterations` before `salt`. On the repository's own `tests/fixtures/sample.uber` fixture, `detect_unsupported` returns `None` and `keystore::decode` fails with `"unrecognized: not a recognised keystore (expected PKCS#12, JKS or JCEKS)"` instead of `"unsupported: this is a Bouncy Castle UBER keystore..."`.
  2. In BKS v2 vs UBER, `bks.rs` (`bks::decode`) only works for BKS v2 (`version == 2` with unencrypted outer entry stream), whereas UBER encrypts the entire store body after `salt` + `iterations` with Twofish (`PBEWithSHAAndTwofish-CBC`). If a file has `version == 2`, `salt_len == 20`, and a valid iteration count at `28..32` but an UBER encrypted payload (or non-standard entry tag `> 4` at `bytes[32]`), `looks_like_bks_v2` returns `true` and routes it into `bks::decode`, failing with `"wrong-password: BKS integrity check failed"`.
  3. `Unsupported::BksOrUber.store_type()` (`keystore.rs:95`) hardcodes `"BKS"`, producing `-srcstoretype BKS` even for UBER (`version == 1` or `.uber` files), which fails when pasted into `keytool`.
  4. `probe_file` (`commands.rs:135`) gates `detect_unsupported` on `.bks`/`.uber`/`.bcfks` file extensions (violating `keystore.rs:52` "never by file name alone"), and `detect::examine_der` (`detect.rs:95`) only calls `keystore::detect`, so Examine reports `kind: "unknown"` on `sample.bks`, `sample.bcfks`, and `sample.uber`.
- **Repro:** Call `keystore::detect_unsupported(&std::fs::read("src-tauri/tests/fixtures/sample.uber").unwrap())` → returns `None`; `keystore::decode` on `sample.uber` → returns `Err("unrecognized: ...")`; `detect::examine` on `sample.bks`, `sample.bcfks`, and `sample.uber` → all return `kind == "unknown"`.
- **Done when:** `detect_unsupported` reads `iterations` at `8 + salt_len..12 + salt_len`, distinguishes UBER (`version == 1` or non-BKS entry tag at `bytes[12 + salt_len]`) from BKS v1/v2 with `-srcstoretype UBER` vs `-srcstoretype BKS`, `looks_like_bks_v2` checks that `bytes[12 + salt_len]` is a valid BKS entry tag (`0..=4`), and both `probe_file` and `detect::examine` identify BKS v2, BKS v1, UBER, and BCFKS by content.

### R4. [High] Distinct per-key passwords (`key_password`) are silently dropped on PKCS#12 save, key rotation, CA reply import, entry refresh, and mixed-case JKS unlock

- **Where:** `src-tauri/src/ops.rs:335-338`, `src-tauri/src/ops.rs:471-474`, `src-tauri/src/entry.rs:225-236`, `src-tauri/src/pkcs12.rs:136, 459, 493`, `src-tauri/src/jks.rs:217, 239`, `src-tauri/src/bks.rs:168-178`, `src/components/KeystoreDialogs.tsx:441` (affects **B1 / C7**, **D4 / K3**).
- **Symptom:**
  1. `ops::rotate_key` (`ops.rs:471-474`), `ops::import_ca_reply` (`ops.rs:335-338`), and `entry::refresh` (`entry.rs:225-236`) construct a fresh `KeystoreEntry` and preserve `id` and `labels`, but leave `key_password: None`, silently resetting a key's distinct password to the store password on the next JKS/JCEKS save.
  2. `pkcs12::encode_with_mac` (`pkcs12.rs:459, 493`) ignores `entry.key_password` and encrypts every key bag with the store `password`, and `saveProblems` (`src/lib/keystore.ts:102-116`) does not warn that saving an entry with a custom `key_password` to PKCS#12 collapses its key password into the store password.
  3. `jks::decode` (`jks.rs:217, 239`) looks up `key_passwords.get(&alias)` after lowercasing `alias`, without lowercasing the keys of `key_passwords`. When a user types `MyKey=secret` in `OpenPasswordDialog` (`KeystoreDialogs.tsx:66`), `jks::decode` misses the key and leaves the entry locked. Also, if a supplied key password fails, `jks::decode` does not fall back to trying the store password.
  4. `bks::decode` (`bks.rs:168`) aborts the entire keystore open with `Err` if one `SEALED` entry has a separate key password (instead of returning a locked entry like `jks::decode`), and for unlocked sealed secret keys (`bks.rs:177`) forgets to set `e.key_password`.
  5. `KeyPasswordDialog` (`KeystoreDialogs.tsx:441`) still displays *"After unlocking, saving re-protects the key with the store password"*, contradicting `KeystoresView.tsx:257` and `jks::encode`.
- **Repro:** Set `entry.key_password = Some("secret-key-pw".into())` and call `ops::rotate_key`, `ops::import_ca_reply`, or `entry::refresh` → `key_password` is `None`. Encode the entry into JKS and call `jks::decode(&bytes, "store-pw", &HashMap::from([("My-Key".into(), "secret-key-pw".into())]))` → `entries[0].locked` is `true`.
- **Done when:** `rotate_key`, `import_ca_reply`, and `entry::refresh` preserve `entry.key_password`; `jks::decode` and `bks::decode` match `key_passwords` case-insensitively and handle locked entries consistently; `pkcs12::encode_with_mac` either uses `entry.key_password` (and `pkcs12::decode` accepts `key_passwords`) or `saveProblems` warns before collapsing `key_password`; and `KeyPasswordDialog` copy matches actual behavior.

### R5. [Medium] `ops::rotate_key` and `ScannerView` renewal drop AIA, CRL distribution points, RSA signature hash, `encipherOnly`/`decipherOnly`, `anyExtendedKeyUsage`, unknown extensions, and CA ledger records

- **Where:** `src-tauri/src/ops.rs:399-475`, `src-tauri/src/commands.rs:250-256`, `src/views/ScannerView.tsx:101-119` (affects **C-a / C11**, **C-c / C8**, **C-d / C9**).
- **Symptom:**
  1. `ops::rotate_key` (`ops.rs:451-462`) hardcodes `signature_hash: None` (downgrading RSA SHA-384/SHA-512 certificates to `SHA256withRSA`) and passes empty `crl_distribution_points: Vec::new()`, `ocsp_urls: Vec::new()`, and `ca_issuer_urls: Vec::new()` (stripping AIA and CRL DP extensions).
  2. `ops::rotate_key` (`ops.rs:423-448`) still uses its own display-label matching closures instead of a shared profile/extension helper, dropping `"Encipher Only"`, `"Decipher Only"`, and `"Any Extended Key Usage"`.
  3. Unknown extensions on the old certificate are silently discarded instead of being reported as not copied (`C11`).
  4. `commands::rotate_key` (`commands.rs:250-256`) does not call `record_issuance` when rotating with an open issuer CA.
  5. `ScannerView.tsx:101-119` (`renew`) also omits `crl_distribution_points`, `ocsp_urls`, `ca_issuer_urls`, and RSA `signature_hash` when renewing via `generateCsr` + `signCsr`.
- **Repro:** Generate an RSA key pair with `signature_hash: Some("SHA512")`, `ocsp_urls: ["http://ocsp.example.com"]`, and `crl_distribution_points: ["http://crl.example.com/root.crl"]`, then call `ops::rotate_key(&orig, "RSA", 2048, None, None)` → rotated certificate has `signature_algorithm == "SHA256withRSA"` and neither `Authority Information Access` nor `CRL Distribution Points`.
- **Done when:** `rotate_key` and `renew` preserve AIA, CRL DP, RSA signature hash, all KU/EKU values, surface a note when unknown extensions were not copied, and `commands::rotate_key` records CA issuance in the ledger.

### R6. [Medium] CRL builder rejects `"removeFromCRL"` and `x509::parse_crl` truncates revocation timestamps to `YYYY-MM-DD`

- **Where:** `src-tauri/src/x509.rs:569-595`, `src-tauri/src/x509.rs:1143-1150` (affects **C-c / C8**).
- **Symptom:**
  1. `x509::reason_name` (`x509.rs:592`) maps reason code `8 => "removeFromCRL"` and `CaSigningView.tsx:406` includes `"removeFromCRL"` in `CRL_REASONS`, but `x509::reason_code` (`x509.rs:569-582`) omits `"removeFromCRL" => Some(8)`. Selecting `"removeFromCRL"` in the UI or opening and extending a CRL that contains a `removeFromCRL` entry fails with `Err("unknown revocation reason 'removeFromCRL'")`.
  2. `x509::parse_crl` (`x509.rs:1147`) formats each entry's `revocation_date` with `fmt_date` (`%Y-%m-%d`) instead of an ISO-8601 timestamp (`%Y-%m-%dT%H:%M:%SZ`), so opening a CRL to extend it strips the time of day from all existing revocations.
- **Repro:** Call `ops::generate_crl(&ca, 30, 1, &[RevokedCertEntry { serial_number: "0102".into(), revocation_date: "2026-05-01T14:23:45Z".into(), reason: "removeFromCRL".into() }])` → returns `Err("unknown revocation reason 'removeFromCRL'")`. With `reason: "keyCompromise"`, `crl.revoked_entries[0].revocation_date` is `"2026-05-01"`.
- **Done when:** `x509::reason_code` maps `"removefromcrl" | "8" => Some(8)` and `x509::parse_crl` preserves the full UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) across round-trips.

### R7. [Medium] Private-CA issuance ledger (`ca_ledger`) is never wired into the UI, and CRL numbers are not persisted with the CA

- **Where:** `src/views/CaSigningView.tsx:408-454`, `src/lib/api.ts:103-105`, `src-tauri/src/commands.rs:344-403` (affects **C-c / C8**, **C-d / C9**).
- **Symptom:**
  1. `commands.rs` implements `ca_ledger` and `ca_ledger_set_status` and `src/lib/api.ts` exposes `api.caLedger` and `api.caLedgerSetStatus`, but neither function is called anywhere in `src/`. `CrlTool` (`CaSigningView.tsx:428-431`) only lists entries currently open in `keystores`, so certificates signed in `Sign CSR` and saved as `.pem` (never imported into a keystore) cannot be selected or searched in the CRL tool, and ledger records cannot be viewed or deleted.
  2. `CrlTool` (`CaSigningView.tsx:415, 422-426`) initializes `crlNumber` to `1` and resets it to `1` whenever the selected CA changes or the component remounts, rather than persisting the last CRL number with the CA ledger.
- **Repro:** Sign an external CSR in `CA & Signing → Sign CSR`, switch to `Issue CRL`, and check the `"Add a certificate issued by this CA…"` dropdown — the issued certificate is missing, and switching CAs resets `CRL number` to `1`.
- **Done when:** `CrlTool` loads issued certificates and the next CRL number from the CA's ledger (`api.caLedger`), updates ledger status when a serial is revoked, allows explicit deletion of ledger entries, and persists the incremented CRL number per CA.

### R8. [Medium] `ops::sign_csr` ignores caller `key_usage` / `extended_key_usage` when `copy_requested_usages` is `None`/`Some(true)` and the CSR has no usages, and UI forms omit AIA and intermediate `path_len` inputs

- **Where:** `src-tauri/src/ops.rs:307-319`, `src/components/AddEntryDialogs.tsx:156, 238`, `src/views/CaSigningView.tsx:190, 242, 300, 318-330` (affects **A6 / C2**, **C-c / C8**).
- **Symptom:**
  1. In `ops::resolve_usages` (`ops.rs:316-317`), when `copy` (`input.copy_requested_usages.unwrap_or(true)`) is `true` and the CSR carries no `keyUsage` or `extKeyUsage` extension (the default for `openssl req -new`), `resolve_usages` immediately falls back to `default_key_usage(false, algorithm)` and `default_extended_key_usage(false)` (`["serverAuth"]`), ignoring non-empty `input.key_usage` and `input.extended_key_usage` supplied by the caller.
  2. Neither `GenerateKeyPairDialog` (`AddEntryDialogs.tsx:238`) nor `SignCsrTool` (`CaSigningView.tsx:300`) provides inputs for Authority Information Access (`ocsp_urls`, `ca_issuer_urls`), and `SignCsrTool` (`CaSigningView.tsx:318-330`) has no `path_len` input when `"Issue a CA certificate (intermediate)"` is checked.
- **Repro:** Call `ops::sign_csr` on a CSR without extensions with `extended_key_usage: vec!["clientAuth".into()]` and `copy_requested_usages: None` → issued certificate receives `["TLS Web Server Authentication"]` instead of client auth.
- **Done when:** `ops::resolve_usages` uses `input.key_usage` / `input.extended_key_usage` when the CSR omits them before falling back to engine defaults, and `GenerateKeyPairDialog` and `SignCsrTool` expose AIA URLs (`ocsp_urls`, `ca_issuer_urls`) and CA `path_len`.

### R9. [Medium] `cms::verify_with_trust` ignores the caller-selected signer entry when certificates are embedded and does not check signer certificate validity or `contentType`

- **Where:** `src-tauri/src/cms.rs:346-445`, `src/views/CaSigningView.tsx:591, 616-617` (affects **C14**).
- **Symptom:**
  1. In `CaSigningView.tsx:616`, checking `"Use a keystore entry's certificate"` passes `signer.entry` to `api.cmsVerify`, which appends `entry`'s certificates to `extra_certs` *after* `parsed.certificates`. Because CMS signatures embed the signer certificate in `parsed.certificates` by default, `cms::verify_with_trust` matches the embedded certificate and reports `valid: true` even when the user selected a completely different keystore entry.
  2. `cms::verify_with_trust` only verifies the mathematical signature over `signedAttrs` / content; it never checks whether the signer certificate was expired (`not_after < now`) or not yet valid (`not_before > now`), and never checks that `ATTR_CONTENT_TYPE` (`1.2.840.113549.1.9.3`) inside `signedAttrs` matches `SignedData.encapContentInfo.eContentType` (required by RFC 5652 §5.3).
- **Repro:** Sign a payload with an expired key pair (`not_after = "2020-01-02"`), then call `cms::verify(&sig, None, &other_entry_certs)` → returns `valid: true, message: "Valid: 1 signature(s) verified and the content is intact."`.
- **Done when:** When a specific signer entry is supplied by the caller, `cms::verify_with_trust` requires the signer to match that entry's certificate, surfaces expired / not-yet-valid signer certificates in `CmsVerifyResult`, and verifies `ATTR_CONTENT_TYPE == eContentType` when `signedAttrs` is present.

### R10. [Medium] Keystore save conflict check (`keystore::save_with`) misses external edits within 1.5s or backdated replacements, and quick `Save` (`Ctrl+S`) has no Override flow

- **Where:** `src-tauri/src/keystore.rs:259-264`, `src-tauri/src/model.rs:274-279`, `src/state/store.tsx:528, 535-561` (affects **B2 / K1**).
- **Symptom:**
  1. `keystore::save_with` (`keystore.rs:260-261`) only rejects an overwrite when `disk > opened.saturating_add(1500)`. Any external edit within 1.5 seconds of opening, or any external file replacement with an older mtime (`cp -p`, `git checkout`, backup restore where `disk != opened` and `disk <= opened + 1500`), is silently overwritten.
  2. When `changed-on-disk` is returned during quick `Save` (`Ctrl+S` or the toolbar `Save` button, `store.tsx:535-561`), the error message says *"Save again and choose Override to replace it"*, but `store.save()` only shows an error toast and never opens `SaveDialog` (where the Override checkbox lives) or a confirmation dialog.
  3. `SaveResult` (`model.rs:274-279`) does not return the newly written file's disk `mtime_ms`, so `store.tsx:528` sets `source_mtime_ms: Date.now()` from the renderer clock instead of the filesystem's actual mtime.
- **Repro:** Open a keystore with `keystore::open`, overwrite the file on disk within 1.5s (or with an older mtime), and call `keystore::save_with(&opened, path, pw, fmt, SavePolicy::default())` → returns `Ok` and overwrites the external change.
- **Done when:** `SaveResult` returns the actual post-write filesystem `mtime_ms`, `save_with` flags any `disk != opened` when `!policy.force`, and `store.save()` prompts the user to Override when `changed-on-disk` occurs.

### R11. [Low] Unencrypted private-key and secret-key exports are written with default umask (`0644`) instead of `0600` on Unix

- **Where:** `src-tauri/src/util.rs:232-247`, `src-tauri/src/export.rs:94-112` (affects **S1 / S3 / C-f**).
- **Symptom:** `util::write_atomic` creates `.tmp` files via `std::fs::File::create`, inheriting the process umask (typically `0644` world-readable on macOS and Linux) even when exporting unencrypted private keys (`private_pkcs8_pem`, `private_traditional`, `private_jwk`) or raw secret keys (`secret_hex`, `secret_jwk`).
- **Repro:** Call `export::export_entry(&kp, "private_pkcs8_pem", path, None)` on macOS/Linux and inspect `std::fs::metadata(path).unwrap().permissions().mode() & 0o777` → `0o644`.
- **Done when:** Sensitive exports (and keystore files) are created with `0600` permissions (`OpenOptionsExt::mode(0o600)`) on Unix.

### R12. [Low] PKCS#12 writer still emits duplicate CA certificate bags when multiple entries share an issuing chain

- **Where:** `src-tauri/src/pkcs12.rs:467-473` (affects **K1**).
- **Symptom:** While `pkcs12::decode` deduplicates certificates on read, `pkcs12::encode_with_mac` (`pkcs12.rs:467-473`) writes every certificate in `entry.certificate_chain[1..]` for every `KeyPair` entry without deduplicating by DER bytes. Saving a PKCS#12 with 2 leaf key pairs issued by the same 2-certificate CA chain writes 6 certificate bags instead of 4.
- **Repro:** Encode two `KeyPair` entries sharing a 2-cert CA chain with `pkcs12::encode` and run `openssl pkcs12 -in dup.p12 -passin pass:pass123 -nokeys` → outputs 6 `BEGIN CERTIFICATE` blocks instead of 4.
- **Done when:** `pkcs12::encode_with_mac` deduplicates non-leaf CA certificate bags by DER bytes before writing `cert_bags`.

### R13. [Low] Keystore error classification relies on string prefixes instead of a typed error enum, and several decoder error paths omit prefixes

- **Where:** `src/lib/api.ts:38-47`, `src-tauri/src/keystore.rs:195`, `src-tauri/src/jks.rs:64, 198`, `src-tauri/src/bks.rs:101, 117`, `src-tauri/src/pkcs12.rs:116` (affects **B5 / S2**).
- **Symptom:** `S2` / `B5` specified a small error enum at the keystore boundary (`WrongPassword`, `Unrecognized`, `Unsupported`, `Invalid`). Instead, commands return `Result<T, String>` and `classifyError` (`src/lib/api.ts:38-47`) regex-matches string prefixes. Multiple parser errors (`jks::truncated`, `"not a JKS or JCEKS keystore"`, `"truncated BKS keystore"`, `"not a valid PKCS#12 file"`, `keystore::encode` `"a keystore password is required"`) omit the prefix and fall into `"other"`.
- **Repro:** Call `classifyError("truncated BKS keystore")` or `classifyError("not a valid PKCS#12 file: ...")` → returns `"other"` instead of `"invalid"` / `"unrecognized"`.
- **Done when:** Keystore commands serialize a typed error (or every decoder/encoder error path consistently constructs the typed error) and unit tests cover `classifyError` across all decoders.

### R14. [Low] Stale copy in `SettingsView.tsx` claims BKS and TSA timestamping are unsupported, and `x509::parse_certificate` still computes `md5_fingerprint`

- **Where:** `src/views/SettingsView.tsx:177, 186`, `src-tauri/src/x509.rs:881`, `src-tauri/src/model.rs:39` (affects **E1 / S4**, **D6 / K4**, **E8 / S6**).
- **Symptom:**
  1. `SettingsView.tsx:177` states *"Nothing is sent over the network except the TLS handshakes you start from Examine"* and line 186 states *"Not supported: Bouncy Castle BKS/BCFKS/UBER keystores, hardware tokens (PKCS#11), TSA timestamping"* on the same Settings page that configures RFC 3161 TSA timestamping and after BKS v2 read support was added.
  2. `x509::parse_certificate` (`x509.rs:881`) still computes `md5_fingerprint: colon_hex(&md5(der))` and serializes it on `CertificateInfo` (`model.rs:39`, `src/types/crypto.ts:52`) even though `S6` / `E8` removed MD5 from the UI.
- **Repro:** Open Settings → About xkeystore (`SettingsView.tsx:177, 186`).
- **Done when:** `SettingsView.tsx` accurately describes BKS v2 read-only support and optional RFC 3161 TSA requests, and `md5_fingerprint` is removed from `CertificateInfo` (or computed only on explicit demand).
