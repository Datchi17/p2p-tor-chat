# Independent review — scope for a reviewer

Thank you for looking. Everything in this repository was written by an AI assistant
(Claude) in one session and tested by the same assistant. Your job is to find what it
missed. **Please assume nothing here is correct because a test says so.**

## What is NOT ours (out of scope unless misused)

libsignal-protocol v0.105.2 (Signal), Tor, `snow` (Noise), SQLCipher, `argon2`, Tauri.
Check **how we use them**, not the libraries themselves.

## What to review, highest risk first (~4,800 lines of Rust)

| Area | File(s) | Questions |
|---|---|---|
| Peer protocol state machine | `crates/p2p-core/src/peer.rs` | Can a paired-but-malicious peer, or a desync, make us skip verification, reuse keys, accept replays, lose messages silently, or loop? Initiator/responder role, re-handshake limits, ack handling. |
| Signal integration | `crates/p2p-signal/src/lib.rs` | Are libsignal store traits implemented correctly? Identity pinning (`save_identity`/`is_trusted_identity`), prekey erasure, Kyber "one-time" handling, the decrypt savepoint/rollback, session usability checks. |
| Verification gate | `crates/p2p-core/src/lib.rs` (`verify_contact`, `send_text`) | Can anything send to an unverified contact? Is the typed-groups check sound? |
| Pairing codes | `crates/p2p-core/src/pairing.rs` | Parsing hostile input, signature domain separation, what an attacker who swaps a code can and can't do. |
| Noise channel | `crates/p2p-transport/src/noise.rs` | IK usage, prologue, framing, nonce handling across the split reader/writer, rejection of unknown initiators. |
| Tor control | `crates/p2p-transport/src/tor.rs` | Command injection, key material in memory/logs, `ADD_ONION` client auth, process lifetime. |
| Network supervisor | `crates/p2p-core/src/net.rs` | Connection tie-break, DoS limits, anything listening beyond loopback. |
| Vault | `crates/p2p-vault/src/lib.rs` | Argon2id/SQLCipher keying, passphrase change crash safety, header tampering, wipe. |
| Shell + UI | `src-tauri/`, `ui/src/` | CSP, Tauri capability/command exposure, any HTML injection path. |

## How to run it

See README.md → Build. Unit tests: `cargo test --workspace --exclude p2p-chat`.
Live over real Tor: `cargo test -p p2p-core --test e2e_live -- --ignored --nocapture`.
Two GUI instances on one machine: `P2PCHAT_DATA_DIR=/tmp/a p2p-chat` and `…/tmp/b…`.

## Reporting

Open a private issue in this repository (or tell the owner directly). Severity guide: anything
that reveals message content, lets someone impersonate a contact, or bypasses verification is
critical.
