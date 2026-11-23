# App readiness review (2026-11-09)

Full-tree review of Keystore Studio as a new desktop app: product coverage, design system,
engine quality, security posture, packaging and CI. Defects that were still open in code were
fixed in the same change set; everything else is recorded here so release decisions are explicit.

## Verdict

The app is feature-complete for a local keystore / X.509 workbench. Cryptographic defects from
[GAPS.md](../GAPS.md) milestones A–G are closed. Design rules in [DESIGN.md](../DESIGN.md) are
applied consistently (tokens, contrast, focus, shared tables). Remaining gaps are release
process and architectural trust boundaries, not missing product surfaces.

## What a new app needs — coverage

| Area | Status |
| --- | --- |
| Core workflows (open/edit/save PKCS#12, JKS, JCEKS; certs; convert; examine; CA/signing; audit; vault; workspaces) | Covered |
| Privacy / offline model | Documented; no accounts or telemetry |
| Help, About, diagnostics | Present in Settings |
| Themes (system / light / dark) | Present |
| Icons and installers (deb / dmg / msi) | Present; **unsigned** |
| License (MIT) | Present |
| Automated tests (unit, interop, robustness, fuzz smoke, headless UI, frontend) | Present |
| CI on Linux / macOS / Windows | Present; Windows + fuzz fixes in this PR |
| CONTRIBUTING / SECURITY / CHANGELOG | Not present (optional for v1) |
| Code signing / notarization | Not present (release blocker for macOS) |

## Fixes in this PR

1. **Crash:** BCFKS detection called yasna on untrusted bytes without `check_der_lengths`, aborting
   the process on a 69-byte indefinite-length BER input found by CI fuzz (`keystore` target).
2. **Windows interop:** openssl `-out /dev/null` → platform null device; PEM comparisons ignore CRLF.
3. **Error classification:** JKS `protected key too short` / `alias too long` now use the `invalid:` prefix.
4. **Docs:** README Limitations correctly state BKS v2 is read-only; GAPS/IMPROVEMENT updated for CI.
5. **Engine-only builds:** binary requires `tauri-app`, so `--no-default-features` builds the lib alone.

## Remaining accepted risks

| Severity | Item | Notes |
| --- | --- | --- |
| High (release) | Unsigned / un-notarized installers | Gatekeeper blocks unsigned `.dmg` |
| High (architecture) | Private keys in the webview + undo snapshots | Trusted-UI model; document for operators |
| Medium | Incomplete zeroize of key material | Vault/command passwords are zeroized; PKCS#8 buffers are not |
| Medium | `crypto-bigint` advisory still ignored | Blocked on elliptic-curve crate upgrades (`E2`) |
| Medium | No network CRL/OCSP fetch in path validation | Local anchors only; do not market as full PKI validation |
| Low | Dead `md5_fingerprint` field still on `CertificateInfo` | Always empty; safe to drop later |
| Low | No dedicated screen-reader pass | Contrast/focus/keyboard done; NVDA/VoiceOver unchecked |
| Low | Master key minimum length is 8 | Consider raising for a password vault product |

## Design

No material design-system violations found against DESIGN.md. Status uses glyphs plus color;
tables share column order; dialogs trap focus and restore it; dark theme is token-based without
`dark:` forks. Font choice (Inter) is intentional for this product.

## Recommendation

Ship a **developer / internal** build once CI is green on this branch. Hold a public macOS
release until signing and notarization secrets are wired. Treat the app as a powerful local
agent (filesystem + shell IPC), not a high-assurance HSM substitute.

## Update 2026-11-17 — format coverage

Keystores: PKCS#12, JKS, JCEKS, BKS, UBER and BCFKS all open, edit, save and convert. Keys:
OpenSSH, JWK, legacy OpenSSL PEM, scrypt and PBES1 PKCS#8 added. Certificates: PkiPath, Netscape
sequences and OpenSSL `TRUSTED CERTIFICATE` read; truststores can be built in any format. Settings
→ Tools covers every external tool the app mentions. Verified by 149 unit, 25 interop, 6
robustness, 77 frontend and 73 headless UI tests on macOS. Open: `cargo deny` reports three newer
advisories on existing dependencies (`chrono` unmaintained, two in `zip`), and the Bouncy Castle
keytool round trip has not run anywhere yet (no `bcprov.jar` on the development machine).
