# CertForge (Next-Gen KeyStore Explorer)

[![Tauri v2](https://img.shields.io/badge/Tauri-v2-blue?logo=tauri)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.99-orange?logo=rust)](https://rust-lang.org)
[![React](https://img.shields.io/badge/React-19-cyan?logo=react)](https://react.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-v4-38bdf8?logo=tailwindcss)](https://tailwindcss.com)
[![Binary Size](https://img.shields.io/badge/Binary-4.5MB-green)](#)

**CertForge** is a modern, cross-platform, zero-dependency desktop cryptographic asset manager designed to replace legacy tools like KeyStore Explorer, `keytool`, and `openssl`. 

Designed with an ultra-clean, minimalist interface inspired by next-generation desktop styling, CertForge gives developers, DevOps engineers, and security analysts full visual control over their certificates, keystores, and trust chains without requiring a local Java Runtime Environment (JRE).

---

## ✨ Features

- **Format Parity & Keystore Management (Epic 1):**
  - Create, inspect, edit, and convert **JKS**, **PKCS#12** (`.p12`, `.pfx`), **BCFKS**, and **JCEKS** files.
  - Generates RSA (1024, 2048, 4096, 8192-bit), ECC (P-256, P-384), Ed25519, and Post-Quantum algorithms (NIST FIPS 204 ML-DSA-65 / Dilithium & FIPS 203 ML-KEM-768 / Kyber).
  - One-click format conversion between PEM, DER, P12, JKS, and PKCS#8.
  - X.509 Certificate and PKCS#10 CSR generation with custom Subject DNs and SANs (DNS & IP).

- **Next-Generation Visual UI/UX (Epic 2):**
  - **Visual Trust Graph:** Interactive node chain displaying Root CA &rarr; Intermediate CA &rarr; Leaf Certificate, with broken link and expiry diagnostics.
  - **Dynamic "Show CLI Command" Engine:** Generates exact copy-pasteable `openssl` or `keytool` commands for every action.
  - **Health & Security Scanner:** Live security audit flagging weak keys (RSA &lt; 2048), deprecated signature algorithms (SHA-1, MD5), and certificates expiring within 30 days.

- **Cloud & DevOps Workflows (Epic 3):**
  - **Cloud Key Vault Sync:** Export client-side keys directly to AWS KMS, Azure Key Vault, Google Secret Manager, and HashiCorp Vault.
  - **Automated ACME Client:** Let's Encrypt / ZeroSSL automated provisioning simulator supporting HTTP-01 and DNS-01 challenges.
  - **JWT Inspector:** Paste JSON Web Tokens, parse Header & Payload claims, and verify signatures client-side.

- **Expanded Cryptographic Scope (Epic 4):**
  - OpenSSH key parser and generator (`id_rsa`, `id_ed25519`, `authorized_keys`).

---

## 🚀 Getting Started

### Prerequisites

- [Rust & Cargo](https://rustup.rs) (v1.80+)
- [Node.js](https://nodejs.org) (v20+)
- [pnpm](https://pnpm.io)

### Development

```bash
# Clone the repository
git clone https://github.com/ajaykontham/xkeystore.git
cd xkeystore

# Install frontend dependencies
pnpm install

# Start Tauri development environment
pnpm tauri dev
```

### Production Build

```bash
# Compile standalone release binary
pnpm tauri build --no-bundle
```

The optimized release binary is located at:
`src-tauri/target/release/certforge` (standalone size: **~4.5 MB**).

---

## 🔒 Security Architecture

All cryptographic operations occur **strictly client-side in native Rust memory**. CertForge has zero telemetry, does not transmit private keys or keystore passwords over the network, and runs completely offline.
