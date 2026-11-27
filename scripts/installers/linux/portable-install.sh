#!/bin/sh
# Installs Keystore Studio from this folder.
#   ./install.sh                          for the current user (~/.local)
#   sudo PREFIX=/usr/local ./install.sh   for every user
#   ./install.sh --uninstall              removes it again (use the same PREFIX)
# Needs WebKitGTK 4.1 from your distribution.
set -eu
cd "$(dirname "$0")"
PREFIX=${PREFIX:-"$HOME/.local"}

if [ "${1:-}" = "--uninstall" ]; then
  find bin share -type f | while IFS= read -r f; do rm -f "$PREFIX/$f"; done
  echo "Removed Keystore Studio from $PREFIX"
  exit 0
fi

find bin share -type f | while IFS= read -r f; do
  mode=644
  case $f in bin/*) mode=755 ;; esac
  mkdir -p "$PREFIX/$(dirname "$f")"
  install -m "$mode" "$f" "$PREFIX/$f"
done

# Desktop sessions do not always have ~/.local/bin on PATH, so point the launcher at the file.
for d in share/applications/*.desktop; do
  sed "s|^Exec=keystore-studio|Exec=\"$PREFIX/bin/keystore-studio\"|" "$d" > "$PREFIX/$d"
done
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$PREFIX/share/applications" >/dev/null 2>&1 || true
fi

echo "Installed Keystore Studio to $PREFIX"
missing=$(ldd "$PREFIX/bin/keystore-studio" 2>/dev/null | awk '/not found/ {print "  " $1}')
if [ -n "$missing" ]; then
  echo "These libraries are missing; install WebKitGTK 4.1 and GTK 3:"
  echo "$missing"
  echo "  Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-0 libgtk-3-0"
  echo "  Fedora:        sudo dnf install webkit2gtk4.1 gtk3"
  echo "  Arch:          sudo pacman -S webkit2gtk-4.1 gtk3"
fi
