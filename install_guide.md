# Install guide — current versions

Both of you install the versions below, then do the installer test from
[docs/FRIEND_WINDOWS_TEST.md](docs/FRIEND_WINDOWS_TEST.md) **together on a live voice or video
call**, starting with the fingerprint check.

All builds come from commit **`a1e9558`** (2026-11-18). New in this version:

- **Received files can be saved again.** In every build since `a6145cd`, a file showed only
  as a grey line with no **Save…** button (found in the Windows test).
- A text sent during a file transfer no longer waits behind the file (27 s before, now a few
  seconds).
- On Windows, the window's browser engine (WebView2) can no longer go online by itself.
- **Changing your passphrase can no longer lose your vault.** If the change failed halfway,
  anything saved afterwards made the whole vault unreadable; now it safely keeps the old one.

Also new today (`c3464dd`, nothing left on your computer):

- The app writes **no logs**. On Linux, its error output used to go to `~/.xsession-errors`
  with timestamps, which is a record of when you chatted.
- The window runs in **private mode**: no web cache or web storage on disk.
- Spell check and autocorrect are off in the message box and other private fields.
- A yellow **reminder when your version is 90 days old**. The app still never goes online to
  check.
- Your existing vault, contacts and messages open unchanged.

Also included, from the security update (`7025610`, 2026-11-14): SQLCipher 4.20 / SQLite
3.54.1, fixes in `ctutils` and `tokio`, and Tor **16.0.1** in the Windows installer.

And from the update before (`a6145cd`, 2026-10-22):

- **File sending** (📎, up to 64 MB, end-to-end encrypted, integrity-checked, only from
  verified contacts).
- **Disappearing messages on by default: 1 week**, counted from when a message is
  **received** (on the sender's side: from delivery). Existing contacts that had it off are
  switched to 1 week.

It also contains everything from before: the PR #1 fixes and the outbox fix for backlogs
larger than 100 messages.

> **Both of you should update.** Versions before `a6145cd` silently drop received files while
> the sender sees ✓ delivered.

> ⚠️ Still a **trial**: send only throwaway messages until every item in
> [docs/TRIAL_PLAN.md](docs/TRIAL_PLAN.md) is done.

## Versions

| | Kali (Datchi17) | Windows (friend) |
|---|---|---|
| File | `P2P Chat_0.1.0_amd64.deb` | `P2P Chat_0.1.0_x64_en-US.msi` |
| Where | built locally with `scripts/repro-build-linux.sh a1e9558`, or the **p2p-chat-linux-reproducible** download of the build run below | the **p2p-chat-Windows** download of the build run below → `msi\` folder |
| Build run | https://github.com/Datchi17/p2p-tor-chat/actions/runs/44377699782 | same |
| Fingerprint (SHA-256) | app binary inside the .deb: `11ef2fc221356c97729a7026eea1e4d6e173bfb528d4aba2b6ed2ac114f6f22b` (identical on Kali and GitHub — reproducible build) | installer: `4e11d13a0d5fe92b5e69724cb4af5889baab9d4c7a00ec7619da3411de3b1194` |

> **Important:** the fingerprints written here are for reference only. Anyone who can change
> this repository could change this file too. What counts is the fingerprint **Datchi17 reads
> aloud on the call** from the copy downloaded on Kali, compared character by character with
> what the friend's own PC computes.

GitHub keeps build downloads for 90 days (until about 2027-02-16).

If you already have an older `~/p2p-win` folder, delete it first (`rm -rf ~/p2p-win`), or the
download mixes old and new files.

## Kali (Datchi17)

Close the app first. Your vault, contacts and messages are kept.

```bash
cp ~/p2p-tor-chat/dist-repro/a1e9558a21fa144c07215578760cf97867943b89/"P2P Chat_0.1.0_amd64.deb" /tmp/p2p-chat.deb
sudo apt install --reinstall /tmp/p2p-chat.deb
```

Before the call, download the Windows installer on Kali and compute the fingerprint you will
read aloud:

```bash
gh run download 44377699782 --repo Datchi17/p2p-tor-chat -n p2p-chat-Windows -D ~/p2p-win
sha256sum ~/p2p-win/msi/*.msi
```

It must print `4e11d13a…de3b1194` (the full value above). If it doesn't, stop.

## Windows (your own PC first, then your friend)

Test it yourself first with [docs/WINDOWS_TEST.md](docs/WINDOWS_TEST.md). On a dual-boot PC,
run two copies of the app on Windows (its step 10a), since Kali is off while Windows runs.

Your friend follows [docs/FRIEND_WINDOWS_TEST.md](docs/FRIEND_WINDOWS_TEST.md), using **build run
44377699782** in step 1 (not just "the newest run": every Windows build has a different
fingerprint).

## On the call, in this order

1. **Fingerprint** — friend runs `Get-FileHash` (guide step 2); Datchi17 reads the value from
   Kali; compare every character. Different → stop, delete the file.
2. **Install and create the vault** (guide steps 3–4).
3. **Pair and verify** — compare all 12 safety-number groups, then type the two highlighted
   groups as the other person reads them (guide step 5).
4. **Test checklist** (guide step 6), with throwaway messages and throwaway files only
   (items 10–15 cover the 1-week timer and file sending; item 19 is the new leftover-text
   search).
5. Friend sends the filled-in checklist to Datchi17; record the result in
   [docs/TRIAL_PLAN.md](docs/TRIAL_PLAN.md).
