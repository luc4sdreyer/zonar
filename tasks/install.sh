#!/bin/sh
# Download, verify, and install the latest zonar release.
#
# zonar is a supply-chain auditor, so it signs its releases and this installer
# verifies that signature before installing anything. The trust root is the
# public key committed to the repository (minisign.pub); its fingerprint is in
# the README. Read this script before piping it to a shell.
#
#   curl -fsSL https://raw.githubusercontent.com/luc4sdreyer/zonar/main/tasks/install.sh | sh
#
# Env:
#   ZONAR_BIN   install directory (default: $HOME/.local/bin)
set -eu

repo="luc4sdreyer/zonar"
base="https://github.com/${repo}/releases/latest/download"
pubkey_url="https://raw.githubusercontent.com/${repo}/main/minisign.pub"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Linux)
    case "$arch" in
      x86_64 | amd64) target="x86_64-linux-musl" ;;
      aarch64 | arm64) target="aarch64-linux-musl" ;;
      *) echo "zonar: unsupported architecture: $arch" >&2; exit 1 ;;
    esac ;;
  Darwin)
    case "$arch" in
      x86_64) target="x86_64-macos" ;;
      arm64) target="aarch64-macos" ;;
      *) echo "zonar: unsupported architecture: $arch" >&2; exit 1 ;;
    esac ;;
  *)
    echo "zonar: unsupported OS: $os (on Windows use install.ps1)" >&2
    exit 1 ;;
esac

archive="zonar-${target}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "zonar: downloading $archive"
curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/$archive.minisig" "$base/$archive.minisig"
curl -fsSL -o "$tmp/minisign.pub" "$pubkey_url"

if command -v minisign >/dev/null 2>&1; then
  echo "zonar: verifying signature"
  minisign -Vm "$tmp/$archive" -p "$tmp/minisign.pub"
else
  echo "zonar: WARNING - minisign is not installed; cannot verify the signature." >&2
  echo "       Install minisign (https://jedisct1.github.io/minisign/) and re-run," >&2
  echo "       or verify manually before trusting this binary." >&2
fi

tar -C "$tmp" -xzf "$tmp/$archive"
dest="${ZONAR_BIN:-$HOME/.local/bin}"
mkdir -p "$dest"
install -m 0755 "$tmp/zonar" "$dest/zonar"
echo "zonar: installed to $dest/zonar"
case ":$PATH:" in
  *":$dest:"*) ;;
  *) echo "zonar: note - $dest is not on your PATH" >&2 ;;
esac
