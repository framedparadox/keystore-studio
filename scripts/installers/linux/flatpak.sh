#!/bin/bash
# Packs an extracted .deb into a single-file Flatpak bundle:  flatpak.sh <debroot> <arch> <out.flatpak>
# It only repackages files, so the GNOME runtime is not needed to build; installing the bundle
# fetches it from Flathub. 51 is the last GNOME runtime with WebKitGTK 4.1.
set -euo pipefail
debroot=$1 arch=$2 out=$3
here=$(cd "$(dirname "$0")" && pwd)
id=io.keystorestudio.desktop
runtime_version=51

work=$(mktemp -d)
app=$work/app
mkdir -p "$app/files" # build-finish creates export/ and refuses a folder that already has one
cp -a "$debroot/usr/bin" "$debroot/usr/share" "$app/files/"

# Flatpak only exports desktop files and icons that are named after the application ID.
mv "$app"/files/share/applications/*.desktop "$app/files/share/applications/$id.desktop"
sed -i "s/^Icon=.*/Icon=$id/" "$app/files/share/applications/$id.desktop"
for icon in "$app"/files/share/icons/hicolor/*/apps/*.png; do
  mv "$icon" "$(dirname "$icon")/$id.png"
done
install -Dm644 "$here/$id.metainfo.xml" "$app/files/share/metainfo/$id.metainfo.xml"

printf '[Application]\nname=%s\nruntime=org.gnome.Platform/%s/%s\nsdk=org.gnome.Sdk/%s/%s\n' \
  "$id" "$arch" "$runtime_version" "$arch" "$runtime_version" > "$app/metadata"

# Home access so keystores can be opened by path (drag and drop, session restore, recent files).
flatpak build-finish "$app" --command=keystore-studio \
  --share=network --share=ipc --socket=wayland --socket=fallback-x11 --device=dri --filesystem=home
# The icon check normally runs under bwrap, which an unprivileged build container cannot start.
flatpak build-export --disable-sandbox --arch="$arch" "$work/repo" "$app" stable
flatpak build-bundle --arch="$arch" \
  --runtime-repo=https://dl.flathub.org/repo/flathub.flatpakrepo \
  "$work/repo" "$out" "$id" stable
rm -rf "$work"
