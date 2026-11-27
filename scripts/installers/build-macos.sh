#!/bin/bash
# Builds the macOS installers (.dmg, .pkg and a zipped .app) for universal, Apple silicon and Intel.
#
#   scripts/installers/build-macos.sh                          # all three
#   scripts/installers/build-macos.sh aarch64-apple-darwin     # one
#
# Without APPLE_SIGNING_IDENTITY the app is signed ad hoc, which Gatekeeper treats as an
# unidentified developer. Set it to a "Developer ID Application" identity (plus the notarization
# variables Tauri reads) to sign properly, and APPLE_INSTALLER_IDENTITY to a "Developer ID
# Installer" identity to sign the .pkg.
# Output: installers/macos/
set -euo pipefail
cd "$(dirname "$0")/../.."
targets=("$@")
# Universal goes first: it compiles both architectures, which the other two builds then reuse.
[ ${#targets[@]} -gt 0 ] || targets=(universal-apple-darwin aarch64-apple-darwin x86_64-apple-darwin)
out=installers/macos
export APPLE_SIGNING_IDENTITY="${APPLE_SIGNING_IDENTITY:--}"
version=$(node -p "require('./src-tauri/tauri.conf.json').version")
min_os=$(node -p "require('./src-tauri/tauri.conf.json').bundle.macOS.minimumSystemVersion")

make_pkg() { # <app> <hostArchitectures> <out.pkg>
  local work
  work=$(mktemp -d)
  mkdir -p "$work/root" "$work/resources"
  ditto "$1" "$work/root/Keystore Studio.app"
  # Not relocatable: otherwise Installer updates whichever copy of the app it finds on disk (such
  # as the one under target/) instead of installing into /Applications.
  pkgbuild --analyze --root "$work/root" "$work/components.plist" >/dev/null
  plutil -replace 0.BundleIsRelocatable -bool NO "$work/components.plist"
  # Recent macOS makes pkgbuild print "write: Permission denied" for its protected
  # com.apple.provenance attribute. The payload is complete regardless.
  pkgbuild --root "$work/root" --component-plist "$work/components.plist" \
    --identifier io.keystorestudio.desktop --version "$version" \
    --install-location /Applications "$work/component.pkg"
  cp LICENSE "$work/resources/LICENSE.txt"
  cat >"$work/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Keystore Studio</title>
  <license file="LICENSE.txt"/>
  <options customize="never" require-scripts="false" hostArchitectures="$2"/>
  <volume-check><allowed-os-versions><os-version min="$min_os"/></allowed-os-versions></volume-check>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" title="Keystore Studio"><pkg-ref id="io.keystorestudio.desktop"/></choice>
  <pkg-ref id="io.keystorestudio.desktop" version="$version">component.pkg</pkg-ref>
</installer-gui-script>
XML
  productbuild --distribution "$work/distribution.xml" --package-path "$work" \
    --resources "$work/resources" \
    ${APPLE_INSTALLER_IDENTITY:+--sign "$APPLE_INSTALLER_IDENTITY"} "$3"
  rm -rf "$work"
}

rustup target add aarch64-apple-darwin x86_64-apple-darwin
mkdir -p "$out"
echo '*' >installers/.gitignore

for target in "${targets[@]}"; do
  case $target in
    universal-apple-darwin) arch=universal hosts=arm64,x86_64 ;;
    aarch64-apple-darwin) arch=aarch64 hosts=arm64 ;;
    x86_64-apple-darwin) arch=x64 hosts=x86_64 ;;
    *) echo "unknown target: $target" >&2; exit 2 ;;
  esac
  echo "=== $target $(date '+%H:%M:%S')"
  pnpm tauri build --target "$target" --bundles app,dmg
  bundle="src-tauri/target/$target/release/bundle"
  app="$bundle/macos/Keystore Studio.app"
  name="Keystore Studio_${version}_${arch}"
  cp "$bundle/dmg/$name.dmg" "$out/"
  rm -f "$out/$name.app.zip"
  ditto -c -k --sequesterRsrc --keepParent "$app" "$out/$name.app.zip"
  make_pkg "$app" "$hosts" "$out/$name.pkg"
  echo "=== $target done $(date '+%H:%M:%S')"
done
scripts/installers/checksums.sh
