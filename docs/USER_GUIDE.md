# User guide

For you and your friend. Setup takes about 20 minutes, once, and needs **one live voice or
video call** where you both recognize each other.

> **Status:** this app has not had an independent security review yet. Until the checklist in
> [TRIAL_PLAN.md](TRIAL_PLAN.md) is complete, use it only for things you wouldn't mind leaking,
> and keep sensitive conversations on Signal (or another audited messenger you have checked).

## The two rules that keep you safe

1. **The installer's fingerprint is read aloud on a live call.** Before anyone installs a new
   version, the person who built it reads the installer's SHA-256 aloud on a voice/video call,
   and the other compares every character. A fingerprint sent by email or chat doesn't count:
   whoever could swap the file could swap that message too. (The safety number protects your
   *keys*; this protects the *program*.)
2. **Every new pairing code means a new live call.** If your friend says "I reinstalled, here's
   my new code", you re-verify on a live call before sending anything. Never accept a new code
   by text alone. The app enforces this: a new code is a new, unverified contact.

## 1. Install

### Kali / Debian / Ubuntu

```bash
sha256sum p2p-chat_0.1.0_amd64.deb       # compare on the call (rule 1)
cp p2p-chat_0.1.0_amd64.deb /tmp/ && sudo apt install /tmp/p2p-chat_0.1.0_amd64.deb   # also installs `tor`
```

Run the app as your normal user, **not root**. Kali is designed as a pentesting system; for
the most sensitive use, prefer a separate, minimal user account or OS install that doesn't run
attack tools or untrusted code.

### Windows 10/11

1. In PowerShell: `Get-FileHash .\P2P.Chat_0.1.0_x64_en-US.msi` — compare every character with
   the fingerprint read aloud on the call (rule 1). If anything differs, **delete the file**.
2. Run it. SmartScreen will say "Windows protected your PC" because the installer is not
   signed by a paid certificate. **Only if the fingerprint matched:** More info → Run anyway.
   This is the *only* warning to click through; never make a habit of it for anything else.
3. If Defender flags `tor.exe`: it's the official Tor, checked by the build against the Tor
   Project's signature. Allow it only for this app's install folder.
4. If the Firewall asks: **no inbound access is needed**.

**Windows privacy settings worth changing** (Windows can copy what's on screen or in memory
outside the app's encrypted database):

- **Recall** (Copilot+ PCs): turn it off — Settings → Privacy & security → Recall & snapshots.
  (The app also marks its window as protected, which excludes it from Recall and screenshots.)
- **BitLocker / Device encryption**: turn it on, so the pagefile, hibernation file and crash
  dumps are encrypted too.
- **Automatic sample submission** in Defender: consider turning it off so flagged files aren't
  uploaded.

## 2. Create your vault

Enter your name and a passphrase of **6 or more random words chosen with dice** (search
"Diceware"). Never reuse a phrase you've seen anywhere, including in this guide. If you forget
it, nothing can be recovered.

The status bar shows "Connecting to Tor…" — the first time can take a minute.

## 3. Pair

1. **+ Pair with a friend** → **Copy my code**, send it to your friend any way you like (it
   contains only public keys).
2. Paste your friend's code → **Add contact**. They do the same with yours.

## 4. Verify — on a live call

1. Call by **voice or video**. You must recognize each other.
2. Both open **Verify**. Read all 12 groups to each other and compare every digit.
3. The app highlights two random groups. Your friend reads those from **their** screen; you
   type what you hear. If an impostor sat in the middle, the digits on your friend's screen
   would differ and the app refuses.
4. Your friend does the same on their side.
5. If anything differs: don't verify. Delete the contact and pair again through a different
   channel.

## 5. Chat

- Green dot = you're both online right now. If your friend is offline, messages wait (🕓) and
  go out when you're both online. ✓ delivered, ✓✓ read (if read receipts are on).
- ⏱ in the chat header: disappearing messages. **On by default: 1 week.** The countdown
  starts when a message is **received** (on your side: when it's delivered), so a message
  that waits in the outbox while your friend is offline doesn't lose its time. Hover the ⏱ on
  a message to see when it disappears. Each side's timer applies to the messages it sends.
- 📎 next to the message box: **send a file** (up to 64 MB). It travels end-to-end encrypted in
  chunks, after any text messages already waiting, and shows "sending… N %" until delivered.
  Files are accepted only from **verified** contacts and are integrity-checked (SHA-256)
  before **Save…** appears. The app never opens files itself. Only open files you expected:
  a file can contain malware even when it's from your friend's (possibly infected) computer.
  Received files are kept inside the encrypted vault and disappear with their message; a copy
  you save to disk with **Save…** is outside the app's control.
- The first connection after starting can take 1–2 minutes.

## Locking, losing a device, wiping

- **🔒** = full lock: keys are wiped from memory and you go offline. The automatic screen lock
  only hides the app; you stay reachable.
- **Lost or stolen computer:** tell your friend on a live call. They delete your contact. You
  install fresh, create a new vault, and pair + verify again (rule 2).
- **Destroy everything** (Settings, or on the unlock screen) wipes all keys and messages. On
  Windows, after uninstalling, also delete `%LOCALAPPDATA%\org.p2pchat.desktop`: it holds no
  messages, only the window's browser-engine files, but it shows the app was used.

## Updates

See [UPDATES.md](UPDATES.md). In short: one named person builds, the fingerprint is read
aloud on a call, nobody installs a version that arrives with "urgent, install this now".

The app never checks for updates online (that would mean contacting a server). Instead, when
your version is **90 days old** it shows a yellow reminder: get the newest installer from the
person who builds it, and check its fingerprint on a call.

## What the app keeps on your computer

Only the encrypted vault, and Tor's own network data (public relay lists and which entry
relays it uses; no messages or contacts). It writes **no logs**: on Linux, a program's error
output would otherwise end up in `~/.xsession-errors` or the system journal with timestamps,
which is a record of when you chatted. Notifications only flash the taskbar; they never
contain names or text. Spell check and autocorrect are off in the message box, so Windows'
typing features don't learn what you write.

For troubleshooting only, start it from a terminal with logging on, and delete the output
afterwards:

```bash
P2PCHAT_LOG=warn p2p-chat
```

For Tor connection problems, **Settings → Show Tor log** is enough (it's kept in memory only).
