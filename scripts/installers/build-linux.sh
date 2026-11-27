#!/bin/bash
# Builds the Linux installers with Docker: .deb, .rpm, .AppImage, portable .tar.gz, Arch package
# and Flatpak bundle.
#
#   scripts/installers/build-linux.sh            # arm64 and amd64
#   scripts/installers/build-linux.sh arm64      # one architecture
#
# On an Apple silicon Mac without Docker Desktop:
#   brew install colima docker docker-buildx
#   colima start --vm-type vz --vz-rosetta --cpus 6 --memory 5
# Output: installers/linux/
set -euo pipefail
cd "$(dirname "$0")/../.."
arches=("$@")
[ ${#arches[@]} -gt 0 ] || arches=(arm64 amd64)
out=installers/linux

# If the current Docker settings point somewhere that is not running (such as leftovers of Docker
# Desktop), talk to Colima through a temporary configuration. ~/.docker is not changed.
if ! docker info >/dev/null 2>&1 && [ -S "$HOME/.colima/default/docker.sock" ]; then
  DOCKER_CONFIG=$(mktemp -d)
  printf '{"cliPluginsExtraDirs":["%s/lib/docker/cli-plugins"]}\n' \
    "$(brew --prefix 2>/dev/null || echo /opt/homebrew)" >"$DOCKER_CONFIG/config.json"
  export DOCKER_CONFIG DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
fi
docker info >/dev/null || { echo "Docker is not running (on macOS: colima start)" >&2; exit 1; }

# The frontend is identical on every platform, so it is built once, here.
pnpm build

mkdir -p "$out"
echo '*' > installers/.gitignore
for arch in "${arches[@]}"; do
  echo "=== linux/$arch $(date '+%H:%M:%S')"
  image=keystore-studio-builder:$arch
  docker build --platform "linux/$arch" -t "$image" scripts/installers/linux
  container=$(docker create --platform "linux/$arch" \
    -v ks-cargo-registry:/opt/cargo/registry \
    -v "ks-target-$arch:/target" \
    -v "ks-tauri-cache-$arch:/root/.cache/tauri" \
    "$image" bash scripts/installers/linux/container-build.sh)
  trap 'docker rm -f "$container" >/dev/null' EXIT
  # The sources are copied in rather than mounted, so the build cannot change this checkout.
  COPYFILE_DISABLE=1 tar --no-xattrs \
    --exclude=src-tauri/target --exclude=src-tauri/fuzz --exclude=src-tauri/gen/schemas \
    -cf - package.json LICENSE dist src-tauri scripts/installers | docker cp - "$container:/work"
  docker start --attach "$container"
  docker cp "$container:/out/." "$out/"
  docker rm "$container" >/dev/null
  trap - EXIT
  echo "=== linux/$arch done $(date '+%H:%M:%S')"
done
scripts/installers/checksums.sh
