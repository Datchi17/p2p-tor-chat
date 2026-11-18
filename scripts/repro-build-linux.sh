#!/usr/bin/env bash
# Builds the Linux .deb inside the pinned container from a clean `git archive` of a commit,
# then prints SHA-256 of the .deb and of the app binary inside it. Run the same commit on
# Kali and in CI: the app binary hashes should be identical.
#
# Usage: scripts/repro-build-linux.sh [commit]   (default: HEAD)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
commit="$(git -C "$root" rev-parse "${1:-HEAD}")"
epoch="$(git -C "$root" log -1 --format=%ct "$commit")"
out="$root/dist-repro/$commit"
image=p2pchat-linux-builder:1

docker build -q -t "$image" -f "$root/build/Dockerfile.linux" "$root/build" >/dev/null
rm -rf "$out" && mkdir -p "$out"

git -C "$root" archive --format=tar "$commit" | docker run -i --rm \
  -e SOURCE_DATE_EPOCH="$epoch" \
  -e CARGO_INCREMENTAL=0 \
  -e RUSTFLAGS="--remap-path-prefix=/build=/build --remap-path-prefix=/opt/cargo=/cargo" \
  -v "$out:/out" \
  "$image" bash -euo pipefail -c '
    tar -x -C /build
    npm ci --prefix ui --no-audit --no-fund >/dev/null
    ./ui/node_modules/.bin/tauri build --bundles deb -- --locked >/out/build.log 2>&1 || { tail -40 /out/build.log; exit 1; }
    deb=$(ls target/release/bundle/deb/*.deb)
    cp "$deb" /out/
    mkdir -p /tmp/x && dpkg-deb -x "$deb" /tmp/x
    cp /tmp/x/usr/bin/p2p-chat /out/p2p-chat.bin
    chown -R '"$(id -u):$(id -g)"' /out
  '

cd "$out"
{
  echo "commit $commit"
  sha256sum p2p-chat.bin | sed "s|p2p-chat.bin|usr/bin/p2p-chat (app binary)|"
  sha256sum ./*.deb
} | tee REPRO-SHA256SUMS.txt
