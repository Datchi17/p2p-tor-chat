#!/usr/bin/env bash
# Downloads the official Tor Expert Bundle for Windows into vendor/tor-windows/ and refuses to
# continue unless (1) the checksum file carries a valid signature from the Tor Browser signing
# key and (2) the archive matches that checksum.
#
# Usage: scripts/fetch-tor-windows.sh [version]
set -euo pipefail

VERSION="${1:-16.0.1}"
# Tor Browser Developers (signing key) — https://support.torproject.org/tbb/how-to-verify-signature/
KEY_FPR="EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
BASE="https://dist.torproject.org/torbrowser/${VERSION}"
FILE="tor-expert-bundle-windows-x86_64-${VERSION}.tar.gz"

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${root}/vendor/tor-windows"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/gnupg"
chmod 700 "$work/gnupg" 2>/dev/null || true   # not supported on Windows Git Bash

cd "$work"
echo "Downloading Tor Expert Bundle ${VERSION}…"
curl -sSfLO "${BASE}/${FILE}"
curl -sSfLO "${BASE}/sha256sums-signed-build.txt"
curl -sSfLO "${BASE}/sha256sums-signed-build.txt.asc"
curl -sSfL "https://keys.openpgp.org/vks/v1/by-fingerprint/${KEY_FPR}" -o signing-key.asc

gpg --homedir "$work/gnupg" --quiet --import signing-key.asc
# Require a good signature made by (a subkey of) exactly this primary key.
status="$(gpg --homedir "$work/gnupg" --status-fd 1 --verify sha256sums-signed-build.txt.asc sha256sums-signed-build.txt 2>/dev/null || true)"
if ! grep -q "^\[GNUPG:\] VALIDSIG .* ${KEY_FPR}$" <<<"$status"; then
  echo "ERROR: signature on sha256sums-signed-build.txt is not valid for ${KEY_FPR}" >&2
  exit 1
fi
echo "Signature OK (Tor Browser Developers, ${KEY_FPR})."

expected="$(grep " ${FILE}\$" sha256sums-signed-build.txt | awk '{print $1}')"
actual="$(sha256sum "${FILE}" | awk '{print $1}')"
if [[ -z "$expected" || "$expected" != "$actual" ]]; then
  echo "ERROR: checksum mismatch for ${FILE}" >&2
  exit 1
fi
echo "Checksum OK (${actual})."

rm -rf "$out"
mkdir -p "$out"
tar -xzf "${FILE}" -C "$out" tor
echo "${VERSION} ${actual}" > "$out/VERSION"
echo "Installed to ${out}/tor"
