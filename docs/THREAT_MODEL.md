# Threat model

What P2P Chat protects against, how, and — just as important — what it does not.

## Design summary

| Layer | Mechanism | Library |
|---|---|---|
| Message encryption | Signal protocol: PQXDH (X25519 + Kyber-1024) session setup, Double Ratchet, SPQR post-quantum ratchet | `libsignal-protocol` v0.105.2 (Signal's own) |
| Peer authentication | Noise `IK_25519_ChaChaPoly_BLAKE2s`; both static keys pinned at pairing | `snow` |
| Transport & anonymity | Tor v3 onion services with client authorization | Tor 0.4.8+ (system on Linux, signed Expert Bundle on Windows) |
| Storage | SQLCipher (AES-256, HMAC-SHA512 per page), key = Argon2id(passphrase; 256 MiB, t=3, p=4) | `rusqlite` + bundled SQLCipher, `argon2` |
| Traffic shape | Frames padded to 512 / 2 KiB / 8 KiB / 32 KiB / 64 KiB; content padded to 160-byte blocks | — |

There is **no server**. Each app is its own onion service; only the two paired apps can
reach each other.

## Keys

| Key | Where it lives | Purpose |
|---|---|---|
| Signal identity (Curve25519) | vault | Safety number; signs prekeys and pairing code |
| Signed prekey | vault, rotated every 7 days, old ones erased after 30 | PQXDH |
| One-time EC + Kyber prekeys | vault, created per session setup, **erased when used** | Forward secrecy of session setup |
| Noise static (X25519) | vault | Proves which device is on the other end of every connection |
| Onion service key (Ed25519) | vault; handed to Tor in memory via `ADD_ONION`, never written by Tor | Your `.onion` address |
| Tor client-auth key (X25519) | vault; handed to Tor in memory | Lets you reach your friend's (locked) onion service |
| Vault key | RAM only while unlocked; wiped on lock | Decrypts the database |

## Protected ✅

| Adversary | Why they fail |
|---|---|
| ISP, Wi-Fi operator, national network monitoring | They see Tor traffic only: no content, no peer, no destination |
| Anyone trying to learn your IP | Onion services hide both ends |
| A random internet attacker | With client authorization they can't even fetch your onion descriptor (tested live: a third Tor client is refused) |
| Someone who learns your `.onion` address | Same: client authorization + Noise reject them before any app data |
| Someone who intercepts or swaps the pairing codes | The 60-digit safety number, compared on a live call, won't match. Verifying requires typing two random groups read aloud from the friend's screen, so a mismatch can't be skimmed past. Sending is disabled until verified |
| Key substitution / MITM later on | Identity, Noise and onion keys are pinned at pairing; a different identity key is refused and raises a security warning |
| Recorded traffic + a future quantum computer | Kyber-1024 in PQXDH and the SPQR ratchet |
| Theft of your keys at some later date | Forward secrecy: message keys are erased after use; one-time prekeys erased after use |
| A one-off compromise of session state | Break-in recovery: fresh DH (and PQ) secrets on every round trip |
| Replay of old messages | Message keys are single-use; content IDs de-duplicated |
| Forged / bit-flipped messages | Rejected without changing session state (tested exhaustively on every byte) |
| Stolen laptop while the app is locked or closed | Only the SQLCipher file; brute-forcing a strong passphrase through Argon2id is infeasible |
| Code injection through the UI (XSS) | Messages are rendered as text only; strict CSP (`script-src 'self'`, no inline, no eval); UI has no keys; Tauri commands are deny-by-default |
| Malicious update | No auto-updater; no code is downloaded at runtime |
| Malicious or altered files | Files only from verified contacts; each chunk is Signal-authenticated and the whole file SHA-256-checked; names stripped of paths and invisible/bidi characters (no "invoice‮fdp.exe" tricks); files are never opened automatically; on Windows saved files carry the "downloaded from the internet" mark so SmartScreen warns before running them; at most 8 incoming transfers of ≤ 64 MB per contact |
| Server compromise / subpoena | There is no server |
| Activity records on your own computer | Release builds write no logs (Linux desktops would otherwise save an app's error output, with timestamps, in `~/.xsession-errors` / the journal); Tor's log is kept in memory only; notifications only flash the taskbar, with no name or text; the window's web view runs in private mode (no cache or web storage on disk); spell check and autocorrect are off in the fields that hold private text. No update checks, no telemetry. On Windows, the WebView2 engine would otherwise download its own components (DRM module, filter lists, certificate data) from Microsoft outside Tor; it is started with component updates and background networking off and a dead proxy (`socks5://127.0.0.1:9`), so nothing it tries can connect (checked by WINDOWS_TEST.md 29b) |

## NOT protected ⚠️

| Risk | Notes / mitigation |
|---|---|
| Malware or a keylogger on either computer while the app is unlocked | Nothing on the same machine can be defended against. Keep the OS updated; don't run untrusted software; use full-disk encryption (LUKS / BitLocker) |
| Your friend copying or screenshotting messages | Disappearing messages limit how long they are kept by the app, not what a person does |
| A weak passphrase | Use 6+ random words. The app requires ≥ 12 characters |
| A global adversary watching both your and your friend's internet connections at the same time | Tor does not fully defeat end-to-end timing correlation. Padding helps a little; it is not cover traffic |
| Being seen *using Tor* | Use a bridge (Settings → Tor bridges) if that matters where you are |
| Bugs in this app's own integration code | The crypto comes from audited projects, but this app's glue code has **not** been independently audited. It was written and tested by the same AI assistant in one session — its tests check the failures it thought of. See REVIEW.md |
| Physical coercion | Panic wipe ("Destroy everything"); disappearing messages |
| A file that is itself malware (e.g. your friend's PC is infected) | The app can't tell a harmful file from a good one. Only open files you expected; files saved with "Save…" stay on disk until you delete them |
| Messages in RAM while unlocked | Keys and plaintext are in process memory while the app runs. The idle screen lock hides the UI but keeps keys loaded so you stay reachable; 🔒 (full lock) wipes them and goes offline |
| SSD / copy-on-write filesystems | Deleted data may survive in flash blocks. It stays encrypted under the vault key; SQLite `secure_delete` is on |
| Both apps must be running to deliver | By design (no server). Messages wait encrypted in the sender's outbox for up to 30 days. Repeatedly coming online together is itself a pattern a Tor-level observer could correlate |
| **A swapped or trojaned installer** | The safety number protects keys, not the program: a fake app would show the "right" digits. Mitigation: read the installer's SHA-256 aloud on the verification call (USER_GUIDE rule 1). There is no code-signing certificate. The Linux app binary is reproducible (CI and Kali build identical bytes); the Windows build is not yet |
| **Updates and maintenance** | No auto-updater (deliberately). Tor and libsignal must be updated by a person; the weekly `maintenance` workflow flags new releases and vulnerable dependencies. Every update repeats the fingerprint-on-a-call step. See UPDATES.md |
| **Social engineering around re-pairing** | "I reinstalled, here's my new code" is the classic attack. A new code is always a new, unverified contact; re-verify on a live call (USER_GUIDE rule 2) |
| **Windows copying data outside the vault** | Recall/screenshots (mitigated: the window is marked content-protected), pagefile/hibernation/crash dumps (mitigation: BitLocker; a crash dump of the window could hold message fragments), clipboard history and its cloud sync if you copy a message (mitigation: Settings → System → Clipboard → off), Defender sample uploads (mitigation: turn off automatic submission). On Linux, plaintext-on-disk checks found nothing outside the vault; on Windows, FRIEND_WINDOWS_TEST check 19 searches the app's folders, Temp, crash dumps and the notification database for a test word |
| **Traces that the app was used (Windows)** | The WebView2 folder `%LOCALAPPDATA%\org.p2pchat.desktop` holds no messages (leftover-text search: 0 hits) but survives "Destroy everything" and uninstalling, because WebView2 keeps it open while the app runs. Delete it by hand after uninstalling. The WebView2 runtime itself is part of Windows and is updated by Microsoft like the rest of the system |
| **The AI session that built this** | The design, code and threat model were produced in a cloud AI conversation, which may be retained by the provider. Nothing secret (keys, messages) was ever in it, but the full design is |

## Verifying the design yourself

- `cargo test --workspace --exclude p2p-chat` — 59 unit and robustness tests.
- `cargo test -p p2p-transport --test tor_live -- --ignored` — onion service + client auth on the real Tor network (an unauthorized client is refused).
- `cargo test -p p2p-core --test e2e_live -- --ignored` — two complete apps chatting over Tor: delivery, read receipts, disappearing messages, offline delivery, a 120-message backlog, a file transfer.
- `cargo audit` — dependency vulnerability scan.
