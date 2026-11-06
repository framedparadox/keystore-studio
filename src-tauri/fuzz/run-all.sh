#!/usr/bin/env bash
# Runs every fuzz target for a time box and fails on the first crash.
#
#   ./src-tauri/fuzz/run-all.sh          # 60 seconds per target (what CI does)
#   ./src-tauri/fuzz/run-all.sh 600      # 10 minutes per target
#
# Needs nightly Rust and cargo-fuzz:
#   rustup toolchain install nightly && cargo install cargo-fuzz --locked
set -euo pipefail

seconds="${1:-60}"
cd "$(dirname "$0")/.."

if ! cargo +nightly --version >/dev/null 2>&1; then
  echo "error: the nightly toolchain is required (rustup toolchain install nightly)" >&2
  exit 1
fi
if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "error: cargo-fuzz is required (cargo install cargo-fuzz --locked)" >&2
  exit 1
fi

status=0
for target in examine keystore x509 cms keys; do
  echo "::group::fuzz $target (${seconds}s)"
  if ! cargo +nightly fuzz run "$target" -- -max_total_time="$seconds" -rss_limit_mb=4096; then
    echo "FAILED: $target — see fuzz/artifacts/$target for the input" >&2
    status=1
  fi
  echo "::endgroup::"
done

if [ "$status" -ne 0 ]; then
  echo
  echo "A crash was found. Reproduce it with:" >&2
  echo "  cd src-tauri && cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>" >&2
  echo "Then add the input to tests/robustness.rs so the stable suite keeps it fixed." >&2
fi
exit "$status"
