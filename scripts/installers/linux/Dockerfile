# Builder for the Linux installers, one image per architecture.
# Ubuntu 22.04 is the oldest distribution the README supports: a binary linked against its glibc
# (2.35) and WebKitGTK 4.1 also runs on newer systems.
FROM ubuntu:22.04

ARG NODE_VERSION=22.23.1
ARG RUST_VERSION=1.99.1
ARG TAURI_CLI_VERSION=2.12.4
ARG NFPM_VERSION=2.49.0

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl file pkg-config xz-utils \
      patchelf xdg-utils desktop-file-utils flatpak \
      libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
      librsvg2-dev libayatana-appindicator3-dev libssl-dev libxdo-dev \
 && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
  | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION"

# Node is only needed to run the Tauri CLI; the frontend is built on the host.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in amd64) a=x64 ;; arm64) a=arm64 ;; *) echo "unsupported architecture" >&2; exit 1 ;; esac; \
    f="node-v$NODE_VERSION-linux-$a.tar.xz"; cd /tmp; \
    curl -fsSLO "https://nodejs.org/dist/v$NODE_VERSION/$f"; \
    curl -fsSL "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt" | grep " $f\$" | sha256sum -c -; \
    mkdir -p /opt/node; tar -xJf "$f" -C /opt/node --strip-components=1; rm "$f"; \
    npm install -g --no-audit --no-fund "@tauri-apps/cli@$TAURI_CLI_VERSION"

# nfpm writes the Arch Linux package, which Tauri's bundler does not produce.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in amd64) a=x86_64 ;; arm64) a=arm64 ;; esac; \
    f="nfpm_${NFPM_VERSION}_Linux_$a.tar.gz"; cd /tmp; \
    u="https://github.com/goreleaser/nfpm/releases/download/v$NFPM_VERSION"; \
    curl -fsSLO "$u/$f"; curl -fsSL "$u/checksums.txt" | grep " $f\$" | sha256sum -c -; \
    tar -xzf "$f" -C /usr/local/bin nfpm; rm "$f"

WORKDIR /work
