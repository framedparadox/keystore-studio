#!/bin/bash
# Runs inside the builder container. /work holds the staged sources and the prebuilt frontend
# (dist/); the installers are written to /out.
set -euo pipefail
cd /work

# AppImage tooling is itself shipped as AppImages, which cannot mount without FUSE in a container.
export CARGO_TARGET_DIR=/target APPIMAGE_EXTRACT_AND_RUN=1

bundle() { tauri build --bundles "$1" --config '{"build":{"beforeBuildCommand":null}}'; }

# Bundling stamps the package type into the binary and restores it only if the run succeeds. Left
# stamped, the next .deb and .rpm would carry the wrong type, so have Cargo link a clean one.
binary=/target/release/keystore-studio
if [ -f "$binary" ] && ! grep -aq __TAURI_BUNDLE_TYPE_VAR_UNK "$binary"; then
  rm -f "$binary" /target/release/deps/keystore_studio-*
fi

rm -rf /target/release/bundle
if ! bundle deb,rpm,appimage; then
  # Under emulation (amd64 on Apple silicon) the kernel cannot start an AppImage that carries the
  # "AI" magic bytes. Tauri clears them on linuxdeploy but not on the plugins linuxdeploy runs.
  # They only affect the build tools, never the AppImage being built.
  for tool in /root/.cache/tauri/*.AppImage; do
    dd if=/dev/zero of="$tool" bs=1 count=3 seek=8 conv=notrunc status=none
  done
  bundle appimage
fi

rm -rf /out && mkdir -p /out
cp /target/release/bundle/deb/*.deb /target/release/bundle/rpm/*.rpm \
   /target/release/bundle/appimage/*.AppImage /out/

# Portable archive: the same files as the .deb, installable on any distribution without root.
version=$(node -p "require('./src-tauri/tauri.conf.json').version")
name="keystore-studio-$version-linux-$(uname -m)"
rm -rf /tmp/debroot "/tmp/$name"
dpkg-deb -x /out/*.deb /tmp/debroot
mkdir -p "/tmp/$name"
cp -a /tmp/debroot/usr/bin /tmp/debroot/usr/share "/tmp/$name/"
install -m 644 LICENSE "/tmp/$name/LICENSE"
install -m 755 scripts/installers/linux/portable-install.sh "/tmp/$name/install.sh"
tar -C /tmp --owner=0 --group=0 -czf "/out/$name.tar.gz" "$name"

# Arch Linux package.
VERSION=$version NFPM_ARCH=$(dpkg --print-architecture) \
  nfpm package --config scripts/installers/linux/nfpm.yaml --packager archlinux --target /out/

# Flatpak bundle.
bash scripts/installers/linux/flatpak.sh /tmp/debroot "$(uname -m)" \
  "/out/Keystore Studio_${version}_$(uname -m).flatpak"

ls -l /out
