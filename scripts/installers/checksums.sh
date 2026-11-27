#!/bin/bash
# Writes installers/SHA256SUMS for everything under installers/.
set -euo pipefail
cd "$(dirname "$0")/../../installers"
find . -type f ! -name SHA256SUMS ! -name .gitignore ! -name .DS_Store | sed 's|^\./||' | sort \
  | while IFS= read -r f; do shasum -a 256 "$f"; done > SHA256SUMS
echo "$(wc -l < SHA256SUMS | tr -d ' ') files listed in installers/SHA256SUMS"
