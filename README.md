# P2P Chat

A serverless, end-to-end encrypted desktop messenger for two people, running over Tor.

- **No server.** Each app is its own Tor onion service; only your paired friend can reach it.
- **Signal protocol.** Signal's own `libsignal`: post-quantum PQXDH (X25519 + Kyber-1024),
  the Double Ratchet, and the SPQR post-quantum ratchet.
- **Mutual authentication.** Every connection runs a Noise IK handshake with keys pinned at
  pairing; a 60-digit safety number compared on a call rules out MITM.
- **Anonymous.** Neither side learns the other's IP; observers see only Tor.
- **No logs, no phoning home.** There is no server to log anything. The app writes no logs,
  its window keeps no web cache or storage on disk, notifications show no text, and it has no
  update checks or telemetry. On Linux it contacts nothing but your own Tor. On Windows, the
  built-in web engine (Microsoft WebView2) is started with its own downloads turned off and
  pointed at a dead proxy, so it can't go online either (WINDOWS_TEST.md check 29b).
- **Encrypted at rest.** SQLCipher database, key derived with Argon2id (256 MiB) from your
  passphrase. Panic wipe included.
- **Works offline.** Messages wait (encrypted) in your outbox and are delivered when you're
  both online. Delivery and read receipts, file sending (≤ 64 MB, encrypted, integrity-checked),
  disappearing messages (1 week by default, counted from receipt).
- **Kali/Linux and Windows** from one codebase (Tauri 2 + Rust + SolidJS).

Read [docs/USER_GUIDE.md](docs/USER_GUIDE.md) to get started and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for exactly what is and isn't protected.

## Layout

```
crates/
  p2p-vault/      Argon2id + SQLCipher encrypted storage, crash-safe passphrase change, wipe
  p2p-transport/  Private Tor process + control protocol, onion services, Noise IK channel
  p2p-proto/      Protobuf wire formats, size-bucket padding
  p2p-signal/     libsignal integration (PQXDH, ratchet, prekeys, safety numbers)
  p2p-core/       App logic: pairing, peer protocol, outbox, receipts, disappearing messages
src-tauri/        Desktop shell: fixed command list, strict CSP, deny-by-default permissions
ui/               SolidJS interface (renders only; never sees keys)
scripts/          fetch-tor-windows.sh — downloads and GPG-verifies Tor for Windows builds
```

## Build

Requirements: Rust (stable), Node.js 20+, `protoc`, and on Linux:

```bash
sudo apt install libwebkit2gtk-4.1-dev librsvg2-dev libayatana-appindicator3-dev \
  libxdo-dev libssl-dev build-essential protobuf-compiler tor
```

```bash
npm ci --prefix ui
cargo test --workspace --exclude p2p-chat          # unit + robustness tests
npx --prefix ui tauri build --bundles deb,appimage  # Linux
# Windows: bash scripts/fetch-tor-windows.sh && npx --prefix ui tauri build --bundles msi,nsis
```

Outputs land in `target/release/bundle/`. Or push a `v*` tag and let
`.github/workflows/build.yml` build both platforms with SHA-256 checksums.

Run two instances on one machine for testing:

```bash
P2PCHAT_DATA_DIR=/tmp/alice target/release/p2p-chat &
P2PCHAT_DATA_DIR=/tmp/bob   target/release/p2p-chat &
```

Live network tests (real Tor, a few minutes each):

```bash
cargo test -p p2p-transport --test tor_live -- --ignored --nocapture
cargo test -p p2p-core --test e2e_live -- --ignored --nocapture
```

## Contributing and security reports

Bug reports and ideas are welcome as issues. Code from outside contributors is **not merged**:
for a security tool, a patient attacker could earn trust over months and slip something in.
Good ideas are re-implemented and reviewed by the maintainer instead. See
[CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability? Report it privately: see
[SECURITY.md](SECURITY.md).

Development history before 2026-11-18 is kept in a private archive; commit references in the
docs written before that date (for example in TRIAL_PLAN.md) point there.

## License

AGPL-3.0-only (as the original project and libsignal).
