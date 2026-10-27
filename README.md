# xkeystore — Native Rust KeyStore Explorer

[![Tauri v2](https://img.shields.io/badge/Tauri-v2-blue?logo=tauri)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.99-orange?logo=rust)](https://rust-lang.org)
[![React](https://img.shields.io/badge/React-19-cyan?logo=react)](https://react.dev)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20Java%20%2F%20OpenSSL-success)](#)

**xkeystore** is a complete, zero-dependency, native Rust + Tauri desktop replacement for [KeyStore Explorer (`kaikramer/keystore-explorer`)](https://github.com/kaikramer/keystore-explorer), `keytool`, `jarsigner`, and `openssl`.

All cryptographic operations execute **directly inside the native Rust engine**—no external CLI commands to copy/run, no local Java Runtime Environment (JRE), and no OpenSSL binary required.

---

## ✨ Full KeyStore Explorer Feature Parity & Modern Enhancements

1. **Interactive Quick Start Bento Home (`Home` Tab):**
   - 6 interactive Bento cards replicating KeyStore Explorer's Quick Start screen (`Create a new KeyStore`, `Open an existing KeyStore`, `Open the Default KeyStore`, `Open the CA Certificates KeyStore`, `Examine a Certificate`, `Show the Help Pages`) with inline format selectors and store launchers.

2. **Certificate Workspaces (`Workspaces` Tab):**
   - Create logical multi-environment Workspaces (`Production`, `Staging`, `Development`, `Compliance`) and assign certificates, TLS key pairs, and CA roots across multiple KeyStores to a Workspace.

3. **KeyStore Sources & Multi-Format Management (`KeyStores` Tab):**
   - Create, open, inspect, edit, and convert in-place between **PKCS#12 (`.p12`)**, **JKS (`.jks` binary `0xFEEDFEED`)**, **JCEKS (`.jceks`)**, **BKS (`.bks`)**, **BCFKS (`.bcfks`)**, and **UBER (`.uber`)**.
   - Full Table & Card Grid views with instant search, Workspace assignment, label tagging, sorting (`A -> Z` / `Z -> A`), and integrated **Trust Hierarchy Graph View**.
   - Entry operations: **Cut**, **Copy**, **Paste**, **Rename Alias**, **Delete**, **Unlock / Lock**, **Undo / Redo** stack, **Save Native KeyStore Binary**, and **Export Inventory CSV**.

4. **Dashboard, Stats & KPI Telemetry (`Stats` Tab):**
   - Real-time KPI cards tracking Managed Entropy & Key Bits, Asymmetric Key Pairs, Symmetric Secret Keys, Trusted CAs, and Digital Signatures.
   - Live bar chart visualizing cryptographic key & operation distribution across RSA/DSA, ECDSA/Ed25519, AES/HMAC, and Post-Quantum (ML-DSA) assets.

5. **Key Pair, Certificate & Secret Key Generation (100% Native Rust):**
   - **Asymmetric Key Pairs + X.509 v3 Certificates:** RSA (1024–8192 bits), ECDSA (`secp256r1` P-256 / P-384), Ed25519, and Post-Quantum (NIST FIPS 204 `ML-DSA-65`, FIPS 203 `ML-KEM-768`, FIPS 205 `SLH-DSA`).
   - **Symmetric Secret Keys:** AES (128/192/256-bit), ChaCha20, HMAC-SHA256, HMAC-SHA512, Triple DES (`DESede`), and Blowfish.
   - **Multi-Format Export Directly to Disk (`~/Downloads/xkeystore_Exports/`):** X.509 (`.cer`/`.pem`), Certificate Chain Bundle, PKCS#7 (`.p7b`), PKI Path (`.pkipath`), Microsoft Authenticode SPC (`.spc`), PKCS#8 Private Key (`.key`), Microsoft PVK (`.pvk`), RFC 7517 JSON Web Key (`.jwk.json`), and OpenSSH Public Key (`.pub`).

6. **CA Authority & Digital Signing Studio (`CA & Sign` Tab):**
   - **Generate & Sign CSRs:** Create PKCS#10 and SPKAC requests and sign CSRs using any CA Key Pair in your KeyStore.
   - **Issue & Sign CRLs:** Generate signed X.509 v2 Certificate Revocation Lists with RFC 5280 revocation reasons.
   - **Sign & Verify JAR Archives:** Built-in Rust JAR signer generating `META-INF/MANIFEST.MF`, `META-INF/<ALIAS>.SF`, and cryptographic signature blocks without `jarsigner`.
   - **CMS / PKCS#7 File Signer & Verifier:** Sign and verify detached or attached payloads.
   - **JWT Token Signer:** Issue signed RS256, ES256, EdDSA, and HS256 JSON Web Tokens.
   - **Diffie-Hellman (PKCS#3 DH) Parameter Generator:** Generate 1024–4096 bit DH prime & generator sets.

7. **Examine SSL, Clipboard & Certificate Diff (`Examine` Tab):**
   - **Examine Live SSL/TLS Host:** Connect to any `host:port` (e.g., `github.com:443`), inspect the server certificate chain, and import certificates into your KeyStore with one click.
   - **Examine Clipboard & Auto-Detect File Type:** Automatically parse and fingerprint X.509 certificates, CSRs, CRLs, Private/Public keys, and JWTs.
   - **Compare Certificates:** Side-by-side diff of any two certificates highlighting differences.

8. **Security Posture & One-Click In-Place Key Rotation (`Security` Tab):**
   - Automatically flags weak keys (`RSA < 2048`) and rotates them in-place to `RSA-4096` or Post-Quantum `ML-DSA-65` with a single click.
