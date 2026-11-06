# Fuzzing the xkeystore parsers

Written for: developers working on xkeystore.

Every parser here reads a file someone else produced. A user opens a keystore they were sent, or
drops a certificate on the window, and the bytes go straight into a decoder that does arithmetic on
lengths it was given. The unit and interop suites only ever feed those decoders well-formed input,
which is not what a parser gets wrong.

Rust's bounds checking means the likely failure is a panic rather than memory corruption — a crash
and lost work, not code execution — but that is still a bug a user hits by double-clicking the
wrong file.

## The two halves

| | `tests/robustness.rs` | `fuzz/` (here) |
|---|---|---|
| Toolchain | stable | nightly (libFuzzer needs sanitizer support) |
| Runs in CI | every push | 60s smoke per target |
| Input | fixed corpus + mutations of real files | coverage-guided exploration |
| Good at | keeping known bugs fixed | finding new ones |

Use both. A crash found here should be added to the corpus in `tests/robustness.rs` so the stable
suite keeps it fixed, then fixed in the parser.

## Running

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked

cd src-tauri

# One target, until you stop it.
cargo +nightly fuzz run examine

# A time-boxed run of each target.
for t in examine keystore x509 cms keys; do
  cargo +nightly fuzz run "$t" -- -max_total_time=300 -rss_limit_mb=4096
done

# Reproduce and minimise a crash.
cargo +nightly fuzz run examine fuzz/artifacts/examine/crash-<hash>
cargo +nightly fuzz tmin examine fuzz/artifacts/examine/crash-<hash>
```

A crash is written to `fuzz/artifacts/<target>/` and the input is replayable, so a fix can be
verified against the exact bytes.

## The targets

| Target | Covers | Why it matters |
|---|---|---|
| `examine` | `detect::examine` | The widest door: everything dropped on the window or picked in a dialog lands here, which then dispatches to every other parser. |
| `keystore` | PKCS#12, JKS, JCEKS | Password-based decryption, MAC verification, the Java serialization reader and nested safe contents. The most structurally complex code in the project. |
| `x509` | certificates, CSRs, CRLs, chain building | Parses DER from untrusted sources and renders distinguished names. |
| `cms` | PKCS#7 / CMS, RFC 3161 tokens | Signature verification, plus the timestamp token reader. |
| `keys` | PKCS#8, PKCS#1, SEC1, encrypted PKCS#8 | Reached whenever a user imports a key file. |

Each target feeds a password (`"fuzz"`) where one is accepted, so the decryption paths are
reachable. It is almost never the right password, which is the interesting case: wrong-password
handling must reject cleanly rather than panic.

Throughput differs a lot between targets, and that is expected: `examine` and `x509` manage
80k–285k inputs a minute, while `keystore`, `cms` and `keys` run far fewer because reaching a
decryption path means a 10 000-iteration PBKDF2 per input. Low counts there are the fuzzer doing
the expensive work, not stalling.

### What it has found

One crash so far, on the first run of `keys`: a 31-byte input aborted the process with "attempt to
add with overflow" inside `yasna`, reachable from `pbe::decrypt_pkcs8`. Fixed by
`util::check_der_lengths`; the input is now a named case in `tests/robustness.rs`. See
[IMPROVEMENT.md](../../IMPROVEMENT.md) for the full account.

## Why this links the engine without Tauri

The targets depend on the library with `default-features = false`, which drops the
`tauri-app` feature and with it `src/commands.rs`, Tauri, WebKit and the dialog plugin. Linking
that stack into an AddressSanitizer build fails outright, and none of it is needed to parse a file.

`profile.release` in `Cargo.toml` keeps optimizations on (fuzzing at `opt-level = 0` wastes most of
the execution budget) but turns on `debug-assertions` and `overflow-checks`, so an arithmetic
overflow is reported as a finding instead of silently wrapping.
