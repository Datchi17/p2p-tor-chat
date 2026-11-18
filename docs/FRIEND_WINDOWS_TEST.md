# P2P Chat — Windows test guide

Hi! This guide walks you through installing and testing **P2P Chat** on Windows, and
chatting with Datchi (who sent you this) over Tor. It takes about **45 minutes**, including a
**voice or video call** with Datchi for two short security steps.

> ⚠️ **This is a test.** The app has not had an independent security review yet. During the
> test, send **only throwaway messages** ("test 1", "hello", emoji…). Keep anything private
> on your usual secure messenger until Datchi tells you the trial is over.

## Which version to test

| | |
|---|---|
| Build | **run 44349921184** — https://github.com/Datchi17/p2p-tor-chat/actions/runs/44349921184 |
| Source | commit `8cf17ad` (2026-11-18) |
| Installer | `P2P Chat_0.1.0_x64_en-US.msi` (fingerprint: **only from Datchi, read aloud on the call** — step 2) |

**New in this version:**
- 📎 **Send files** (photos, PDFs…, up to 64 MB) — only to a verified contact.
- ⏱ **Disappearing messages default to 1 week**, counted from when the message **arrives**
  (not from when it was sent).
- Security updates: encrypted database (SQLCipher 4.20 / SQLite 3.54.1), bundled **Tor 16.0.1**,
  and fixes in two internal libraries.
- 🧹 **Nothing left on your PC**: the app writes no logs, its window runs in private mode
  (no web cache or storage on disk), and spell check is off in the message box. Check 19
  verifies this on your PC.
- A yellow reminder when your version is 90 days old (the app never goes online to check).
- Fixed after Datchi's own Windows test: received files can be saved (**Save…** was missing),
  a text sent during a file transfer no longer waits behind it, and the window's browser
  engine (WebView2) can no longer go online by itself, and a failed passphrase change can
  no longer make the vault unreadable.

> Already installed an older test version? See **"Updating from an older version"** at the end.

---

## What you need

- A Windows 10 or 11 PC (64-bit), with an internet connection.
- A free GitHub account (GitHub only lets signed-in users download builds). The repository
  **Datchi17/p2p-tor-chat** is public: no invitation needed.
- About 300 MB of free disk space.
- A voice or video call with Datchi (Signal, WhatsApp call, phone… anything where you
  recognize each other's voice). You'll need it for **step 2** and **step 5**.

## What P2P Chat is, in one paragraph

Each copy of the app runs its own private Tor connection and becomes a hidden ".onion"
address that **only you two** can reach. There is no server: messages go directly from
Datchi's computer to yours through the Tor network, encrypted with the Signal protocol.
Nobody (not your internet provider, not Tor, not GitHub) can read them or see your IP
address. Because there's no server, **a message is delivered only while both apps are open**;
until then it waits on the sender's computer.

---

## Step 1 — Download the installer from GitHub

You only need **one file**: the `.msi` installer.

1. Go to **https://github.com/Datchi17/p2p-tor-chat/actions/workflows/build.yml**
   (sign in to GitHub first).
2. Open the run named in **"Which version to test"** above (direct link:
   https://github.com/Datchi17/p2p-tor-chat/actions/runs/44349921184). It has a green ✓.
   If Datchi tells you a newer run, use that one instead.
3. Scroll down to **Artifacts** and click **`p2p-chat-Windows`**. A zip file downloads.
4. Open the zip. Inside you'll find:

   | File in the zip | Do you need it? |
   |---|---|
   | `msi\P2P Chat_0.1.0_x64_en-US.msi` | ✅ **Yes — this is the installer** |
   | `nsis\P2P Chat_0.1.0_x64-setup.exe` | ❌ No (alternative installer, same app) |
   | `SHA256SUMS-Windows.txt` | ❌ Don't rely on it (see step 2) |

5. Extract the `.msi` to your **Downloads** folder.

You don't need anything else from the repository (no source code, no tools).

---

## Step 2 — Check the installer's fingerprint (on the call with Datchi) 🔒

This makes sure the file you downloaded is exactly the one Datchi built — not a fake one
swapped in along the way. The fingerprint file inside the same zip doesn't prove anything
(whoever could swap the installer could swap that file too), so **Datchi reads it aloud**.

1. Press **Start**, type **PowerShell**, open **Windows PowerShell**.
2. Run (copy-paste):

   ```powershell
   cd $HOME\Downloads
   Get-FileHash ".\P2P Chat_0.1.0_x64_en-US.msi" -Algorithm SHA256
   ```

3. You get a long line of 64 letters and digits after `Hash`.
4. **On the call**, Datchi reads their fingerprint aloud. Compare **every character**, in
   groups of 4 if it helps.
5. ✅ Identical → continue. ❌ **Any difference → stop**, delete the file, tell Datchi.

---

## Step 3 — Install

1. Double-click the `.msi`.
2. Windows SmartScreen will probably show **"Windows protected your PC"**. That's because the
   installer isn't signed with a paid certificate — **not** because something is wrong.
   Since the fingerprint matched in step 2: click **More info → Run anyway**.
   (This is the only time you should do that. Don't make it a habit for other files.)
3. Follow the installer (Next → Install → Finish). It installs to
   `C:\Program Files\P2P Chat\`.
4. If **Windows Defender** warns about `tor.exe`: that's the official Tor program, version 16.0.1 (the build
   checks it against the Tor Project's digital signature). Allow it. Tell Datchi it happened.
5. If the **Windows Firewall** asks for permission: click **Cancel** (don't allow). The app
   only makes outgoing connections and must work without it — that's part of the test.

**Recommended Windows privacy settings** (optional for the test, important for real use):

- **Recall** (only on "Copilot+ PC" laptops): Settings → Privacy & security → **Recall &
  snapshots** → off.
- **Device encryption / BitLocker**: Settings → Privacy & security → **Device encryption** →
  on (protects anything Windows writes to disk, like the page file).

---

## Step 4 — First start: create your vault

1. Start **P2P Chat** from the Start menu.
2. Enter your **name** (Datchi will see it) and a **passphrase**.
   - For this test you can use any **6 random words** (at least 12 characters).
   - For real use later: choose 6 random words with dice ("Diceware"), never reuse one you've
     seen anywhere. **If you forget it, nothing can be recovered — not even by Datchi.**
3. Click **Create vault**. It takes a second (it's deliberately slow, to resist guessing).
4. At the bottom, the status bar shows **"🧅 Connecting to Tor… N%"**, then
   **"🧅 Tor connected"**. The first time can take **1–3 minutes**.

---

## Step 5 — Pair and verify with Datchi (on the call) 🔒

### 5a. Exchange pairing codes

1. Click **+ Pair with a friend**.
2. Click **Copy my code** and send it to Datchi (email, chat — any way; it contains only
   public information, so that's fine).
3. Datchi sends you theirs. Paste it under **2. Paste your friend's code** → **Add contact**.

### 5b. Verify the safety number

This is what proves nobody swapped the codes on the way. **Do it on the live call.**

1. The **Verify** screen opens with **12 groups of 5 digits**. Datchi has the same screen.
2. Read all 12 groups to each other. They must be **identical** on both screens.
3. Two groups are highlighted on your screen. Ask Datchi to read **those two groups from
   their screen**, and type what you hear into the two boxes. Click **✅ Verify**.
4. Datchi does the same with the groups highlighted on their screen.
5. If the app says the digits **don't match**: don't continue. Delete the contact (⋮ menu →
   Delete) and tell Datchi; you'll redo pairing another way.

When verified, Datchi's name shows **✅ verified** and you can type messages.

---

## Step 6 — Test checklist

Do these with Datchi (you can stay on the call or switch to text on your usual messenger).
Write **✅ / ❌ and a short note** for each, and send the list to Datchi at the end.

### Messaging
| # | Test | Result |
|---|---|---|
| 1 | Datchi sends you a message → it appears on your screen | |
| 2 | You send one back → it reaches Datchi; you see **✓** (delivered) next to it | |
| 3 | Send `مرحبا 👋 тест 你好` → arrives exactly the same on the other side | |
| 4 | The green dot next to Datchi's name shows when you're both online | |

### Offline delivery
| # | Test | Result |
|---|---|---|
| 5 | Click **🔒** (top left) — the app locks and goes offline | |
| 6 | Datchi sends you a message while you're locked (they'll see 🕓 queued) | |
| 7 | Unlock with your passphrase → that message arrives within ~2 minutes | |
| 8 | Close P2P Chat completely. Open **Task Manager** (Ctrl+Shift+Esc) → no **tor.exe** left running | |
| 9 | Restart Windows, open the app, unlock → your earlier messages are still there, and messaging works | |

### Disappearing messages
| # | Test | Result |
|---|---|---|
| 10 | The **⏱** in the chat header shows **1 week** (the default). Hover the ⏱ on a received message → "Disappears in 7 days" | |
| 11 | Set ⏱ to **5 minutes**. Send a message. About 5 minutes after it **arrives**, it disappears on **both** screens | |
| 12 | Set ⏱ back to **1 week** | |

### Files
| # | Test | Result |
|---|---|---|
| 13 | Click **📎**, choose a small photo or PDF → it shows "sending… %" then **✓**; Datchi gets it and clicks **Save…** → it opens fine on Kali | |
| 14 | Datchi sends you a file → click **Save…**, save it to Downloads → it opens correctly | |
| 15 | Send a file of about **20 MB** → it arrives completely (it may take a few minutes over Tor); a text sent meanwhile arrives before the file finishes | |

### Privacy checks
| # | Test | Result |
|---|---|---|
| 16 | Press **Win + Shift + S** and try to screenshot the P2P Chat window → the window should appear **black or empty** in the screenshot | |
| 17 | Press **Win + R**, type `%APPDATA%\org.p2pchat.desktop\vault` → Enter. Right-click `vault.db` → Open with → **Notepad**. You should see only gibberish: **no message text, and it must NOT start with** `SQLite format 3`. Close Notepad without saving | |
| 18 | Wrong passphrase: lock (🔒), type a wrong passphrase → refused with an error | |
| 19 | **Leftover-text search** (steps below) → it prints `Self-test OK.` and `Files containing the test word: 0` | |

**How to do check 19.** It proves that no message text is left on your disk outside the
encrypted vault: not in the app's folders, Temp, crash dumps or the notification database.

1. Send Datchi a message containing the made-up word `zebra7canary`, and ask Datchi to send
   one back with the same word. Make sure both show on your screen.
2. Lock (🔒), then close P2P Chat completely, so that its files are no longer in use.
3. Open **Windows PowerShell**, paste this whole block, and press Enter. It only reads
   files; it takes from a few seconds to a few minutes:

   ```powershell
   $word = "zebra7canary"
   $probe = Join-Path $env:TEMP "p2p-check-selftest.txt"
   [IO.File]::WriteAllText($probe, "self-test $word")
   $l1 = [Text.Encoding]::GetEncoding(28591)
   $pats = @([Text.Encoding]::UTF8, [Text.Encoding]::Unicode | ForEach-Object { $l1.GetString($_.GetBytes($word)) })
   $dirs = "$env:LOCALAPPDATA\org.p2pchat.desktop", "$env:APPDATA\org.p2pchat.desktop", "$env:TEMP",
           "$env:LOCALAPPDATA\CrashDumps", "$env:LOCALAPPDATA\Microsoft\Windows\WER",
           "$env:LOCALAPPDATA\Microsoft\Windows\Notifications"
   $found = 0; $checked = 0; $skipped = 0; $selftest = $false
   Get-ChildItem $dirs -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object Length -lt 300MB | ForEach-Object {
     try {
       $f = [IO.File]::Open($_.FullName, 'Open', 'Read', 'ReadWrite, Delete')
       try { $ms = New-Object IO.MemoryStream; $f.CopyTo($ms) } finally { $f.Close() }
       $s = $l1.GetString($ms.ToArray()); $checked++
       foreach ($p in $pats) {
         if ($s.Contains($p)) {
           if ($_.Name -eq "p2p-check-selftest.txt") { $selftest = $true } else { "FOUND IN: " + $_.FullName; $found++ }
           break
         }
       }
     } catch { $skipped++ }
   }
   Remove-Item $probe
   if ($selftest) { "Self-test OK." } else { "SELF-TEST FAILED - the check itself did not work, tell Datchi." }
   "Checked $checked files ($skipped could not be read). Files containing the test word: $found"
   ```

4. ✅ `Self-test OK.` and `Files containing the test word: 0` → pass.
   ❌ Any `FOUND IN:` line → send Datchi the file paths shown (not the files).

### Things to note if they happen
- Did SmartScreen, Defender or the Firewall show anything? What exactly?
- Did any black console window pop up?
- How long did "Connecting to Tor" take the first time?
- Anything confusing, slow, or broken — even small things.

---

## Step 7 — Finish the test

When you're done (or if Datchi asks you to start over):

1. **Settings (⚙) → Destroy everything → Yes** — deletes all keys and messages of the test.
2. Uninstall: Settings → Apps → Installed apps → **P2P Chat** → Uninstall.
3. Press **Win + R**, type `%LOCALAPPDATA%` → Enter, and delete the folder
   `org.p2pchat.desktop`. It holds no messages, only the window's browser-engine files,
   but Windows can't remove it while the app runs, so it would otherwise show that P2P Chat
   was used. Do the same in `%APPDATA%` if a folder of that name is still there.
4. Send your checklist results to Datchi.

---

## Updating from an older version

If you already have an older P2P Chat test version installed:

1. Close P2P Chat (lock 🔒, then close the window).
2. Download the new `.msi` (step 1) and **check its fingerprint on a call** (step 2) —
   an update is a new installer, so this is required every time.
3. Double-click it — it replaces the old version. **Don't uninstall first** and **don't use
   "Destroy everything"**: your vault, contacts and messages are kept.
4. Open the app and unlock with your usual passphrase. Datchi stays ✅ verified — no new
   pairing needed.
5. Check: **⏱** in the chat header. Contacts that had no timer are now set to **1 week**.
   Then do the **Files** tests (13–15).

---

## Troubleshooting

| Problem | What to do |
|---|---|
| Stuck on "Connecting to Tor…" for more than 5 minutes | Check your internet. Some networks (offices, some countries) block Tor: get bridges at **https://bridges.torproject.org** → paste them in **Settings → Tor bridges** → Save (Tor restarts). Send Datchi the text from **Settings → Show Tor log**. |
| Datchi stays offline (grey dot) although both apps are open | Normal for the first **1–2 minutes** after starting (Tor is publishing your hidden address). Wait. If it lasts more than 5 minutes, restart both apps. |
| "the pairing code is damaged or was tampered with" | The code was cut or changed while copying. Copy it again **completely** (it starts with `p2pchat1:`). |
| "verify this contact's safety number before sending messages" | You haven't done step 5b yet. |
| Messages show 🕓 for a long time | Delivery only happens while **both** apps are open and unlocked. |
| "Smart App Control blocked an app" with no **Run anyway** | Smart App Control (Windows 11) blocks every installer without a paid signature. It can only be turned off, not bypassed for one file, and turning it back on later may require reinstalling Windows. Don't change it just for this test: tell Datchi. |
| Forgot your passphrase | Nothing can recover it. On the unlock screen: **Forgot passphrase / destroy everything**, then start again from step 4 and re-pair. |

---

## The two safety rules (for after the test, too)

1. **A new installer = fingerprint read aloud on a call** (step 2), every time — including
   updates. Never install a version that arrives with "urgent, install this now".
2. **A new pairing code = a new live call** (step 5b). If someone says "I reinstalled, here's
   my new code" by text only, don't accept it until you've verified on a call.

Thanks for testing! 🙏
