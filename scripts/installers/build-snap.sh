#!/bin/bash
# Builds the Snap package from the .deb that build-linux.sh produced, for the machine's own
# architecture only (see linux/snapcraft.yaml). snapd cannot run in a container, so this needs an
# Ubuntu 24.04 system, matching base core24:
#
#   macOS with Colima    scripts/installers/build-snap.sh    # builds inside the VM (arm64 on M-series)
#   Ubuntu 24.04         scripts/installers/build-snap.sh    # builds on the host, uses sudo
#
# For the x86_64 Snap, run it on an x86_64 machine or CI runner.
# Output: installers/linux/
set -euo pipefail
cd "$(dirname "$0")/../.."
out=installers/linux
version=$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' src-tauri/tauri.conf.json | head -1)

# Runs a command where snapcraft lives: in the Colima VM on macOS, locally on Linux.
if [ "$(uname)" = Darwin ]; then
  vm() { colima ssh -- "$@"; }
else
  vm() { "$@"; }
fi

arch=$(vm dpkg --print-architecture)
deb="$out/Keystore Studio_${version}_${arch}.deb"
[ -f "$deb" ] || { echo "missing $deb: run scripts/installers/build-linux.sh $arch first" >&2; exit 1; }

vm sudo sh -c 'command -v snapcraft >/dev/null 2>&1 || [ -x /snap/bin/snapcraft ] || {
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq snapd &&
  snap wait system seed.loaded && snap install snapcraft --classic; }'

echo "=== snap $arch $(date '+%H:%M:%S')"
stage=$(mktemp -d)
cp "$deb" "$stage/app.deb"
sed "s/\"VERSION\"/\"$version\"/" scripts/installers/linux/snapcraft.yaml >"$stage/snapcraft.yaml"
dir=/tmp/keystore-studio-snap
vm sudo rm -rf "$dir"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -cf - app.deb snapcraft.yaml |
  vm sh -c "mkdir -p $dir && tar -xf - -C $dir"
rm -rf "$stage"
vm sudo sh -c "cd $dir && PATH=\$PATH:/snap/bin snapcraft pack --destructive-mode"
vm sh -c "cat $dir/*.snap" >"$out/keystore-studio_${version}_${arch}.snap"
vm sudo rm -rf "$dir"
echo "=== snap $arch done $(date '+%H:%M:%S')"
scripts/installers/checksums.sh
