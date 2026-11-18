# Windows test report — 2026-11-18

Hand-off from the Claude Code session that ran `docs/WINDOWS_TEST.md` on Windows, for the Kali
session (which did not see any of this). Everything below was done on the dual-boot PC while
Kali was off. Read this together with PR #2 (branch `fix/file-bubble`).

## TL;DR

- **All 32 checks of WINDOWS_TEST.md pass, but only with a fix**: on the build you prepared
  (run 44215249839), **received files could not be saved** (checks 19–21). Cause: one line in
  `ui/src/components/Chat.tsx`; fixed in **2ceedc4**, built as **run 44325493264**, re-tested:
  files work, and installing it over the old version keeps vault, contacts and verification.
- **Nothing is merged.** The fix, the doc updates and this report are on branch
  `fix/file-bubble`, PR **#2** (https://github.com/Datchi17/p2p-tor-chat/pull/2).
- **FRIEND_WINDOWS_TEST.md and install_guide.md still name run 44215249839**, which has the
  file bug. The friend must not test that build. Needs: merge → new build from `main` →
  update both docs with its fingerprints (checked from Kali).
- **Open findings** (not fixed, decisions for you): text delayed 27 s during a file transfer;
  WebView2 profile folder (`EBWebView`, ~70 MB) survives "Destroy everything" and uninstall;
  WebView2 fetches its own components from Microsoft outside Tor.

## 1. Setup

| | |
|---|---|
| PC | Same dual-boot PC, Windows 11 Home 10.0.26200, x64 |
| Mode | Two copies of the app on one Windows (WINDOWS_TEST.md step 10a): copy A "Win-Test" (default data dir), copy B "Win-Test-2" (`P2PCHAT_DATA_DIR=%LOCALAPPDATA%\org.p2pchat.desktop\second`) |
| Repo | Cloned from GitHub to `%USERPROFILE%\p2p-chat` (main at 7437ec8) |
| Git identity on Windows | Already set to the no-reply address before anything was committed |
| GitHub CLI | Installed on Windows (winget) and signed in, to download artifacts and push; still signed in at the end |
| Clock | 4–6 s off internet time each time it was checked (fine for Tor). Note: Windows Time had never synced ("Local CMOS Clock") |
| Smart App Control | Off on this PC (so SmartScreen offered "Run anyway") |

### Builds

| Build | Source | MSI SHA-256 | Checked against |
|---|---|---|---|
| run 44215249839 | c3464dd (main's code; 7437ec8 adds only docs) | `5682193437ad7d631695a7525c06107469952f3238a5cf667f5949e3b86bb508` | The fingerprint written down on Kali ✅ |
| run 44325493264 | **2ceedc4** (fix) | `9b1d9bb76e8d98fc82b493e2483c8f3d31e8f5bbe9bb025b5495a0e540e46728` | The zip's SHA256SUMS and the Windows job's build log (both GitHub). **Not yet checked from Kali** |

## 2. How the tests were run (read this before trusting the results)

The user asked Claude to do the tests itself, so the user clicked only what Windows reserves
for a human: SmartScreen "Run anyway", the installer wizard, UAC "Yes", and the reboot.
Everything else was automated from PowerShell 7 against the **real installed app**:

- **App windows**: Windows UI Automation (the screen-reader interface), which reads the
  WebView2 page's accessibility tree and presses its real buttons. It is not blocked by the
  window's content protection.
- **Text entry**: UIA `ValuePattern.SetValue`, which fires the page's `input` events. After
  the windows had been minimized and restored, SetValue stopped taking effect (the field
  stayed empty, Send stayed disabled) while real keystrokes still worked, so text was then
  typed with `SendKeys`, only after checking the target window was in front and focus was
  on the target field. **Seen as an automation quirk; no user-facing effect observed.**
- **⏱ timer select**: its drop-down closes as soon as the window loses activation, so it was
  set with the keyboard (Shift+Tab to the select, then "5" / "1").
- **Native file dialogs** ("Send a file", "Save file"): classic Win32 controls, driven with
  `WM_SETTEXT` on the file-name box and `BM_CLICK` on Open/Save.
- **Pairing codes**: "Copy my code" clicked, clipboard read back and compared with the code
  shown, then put into the other window's paste box.
- **Safety number**: the 12 groups read from both windows; the requested groups typed from
  the *other* window's screen (the equivalent of reading them aloud).
- **Screenshot check**: GDI screen capture plus `GetWindowDisplayAffinity`, not Win+Shift+S.
- **Leftover-text search**: the exact PowerShell block of FRIEND_WINDOWS_TEST.md check 19.
  The test word was only ever assembled at runtime (`"zebra7" + "canary"`) and never printed
  or written, because the search also scans `%TEMP%`, where Claude's scratch files live.
- **Uninstall**: `msiexec /x {ProductCode} /passive` (same MSI uninstall as Settings → Apps,
  but not through the Settings UI).

What automation can't judge: whether texts and layout are clear to a person, the red colour
of warnings, how things look. The friend's test still covers the human side.

## 3. Results, check by check (WINDOWS_TEST.md numbering)

| # | Result | Details |
|---|---|---|
| 3 | ✅ | Fingerprint of run 44215249839 = the one written down on Kali |
| 4 | ✅ | SmartScreen: "Windows protected your PC — Microsoft Defender SmartScreen prevented an unrecognized app from starting… App: P2P Chat_0.1.0_x64_en-US.msi, Publisher: Unknown publisher" → More info → Run anyway |
| 5 | ✅ | "Installation completed successfully"; Start menu entry `P2P Chat`. Installed: `p2p-chat.exe`, `tor\tor.exe`, `tor\tor-gencert.exe`, `tor\pluggable_transports\{lyrebird.exe, conjure-client.exe, pt_config.json, README.CONJURE.md}`, uninstall shortcut |
| 6 | ✅ | No Defender detection, no Defender events |
| 7 | ✅ | No firewall rule created for the app or tor.exe; the user reported no prompt |
| 8 | ✅ | Vault created in ~1 s (passphrase-strength hint showed "Strong") |
| 9 | ✅ | "🧅 Tor connected": copy A 35 s, copy B 52 s |
| 10 | ✅ | No console window. tor.exe has a hidden conhost (CREATE_NO_WINDOW); no visible window for it |
| 10a | ✅ | The second copy opens normally, no blank window. Both copies share the WebView2 folder `%LOCALAPPDATA%\org.p2pchat.desktop\EBWebView` without trouble (the UI uses no browser storage) |
| 11 | ✅ | "Copy my code" puts exactly the shown code on the clipboard (codes of 340/343 chars, `p2pchat1:` prefix); each side accepted the other's |
| 12 | ✅ | Same 12 groups on both sides |
| 13 | ✅ | One wrong digit → "those digits don't match. Do NOT verify: compare again, and if they still differ, delete this contact and pair again" |
| 14 | ✅ | ✅ verified on both sides |
| 15–16 | ✅ | Both "🟢 reachable now" ~1½–2 min after Tor connected (onion publication); messages arrive in 0.4–0.9 s; ✓ on the sender |
| 17 | ✅ | `مرحبا 👋 тест 你好` (and a variant) arrives exactly identical both ways |
| 18 | ✅ | Default ⏱ 1 week ("Disappears in 7 days"). Set to 5 min on A → B followed by itself; system lines "You set…" / "Your contact set disappearing messages to 5 minutes." Messages ("Disappears in 5 min") vanished on both sides ~5 min 37 s after arrival; 1-week messages untouched. Set back to 1 week |
| 19 | ❌ → ✅ | **Run 44215249839: bug** (section 4). With 2ceedc4: "sending… 0%" → ✓; receiver bubble "📄 test-photo.png (6 KB)", warning "Only open files you expected. Files can contain malware.", Save… → saved file byte-identical (SHA-256) |
| 20 | ❌ → ✅ | With 2ceedc4: 20 MB (random bytes) arrived byte-identical after ~5 min 40 s. A text sent when the file was at 6% arrived first (file at 14%) — **but took 27 s** (finding 5.1) |
| 21 | ❌ → ✅ | With 2ceedc4: saved file has `Zone.Identifier` `[ZoneTransfer] ZoneId=3` (Properties shows "Unblock") |
| 22 | ✅ | 🔒 → A's tor.exe stops; B shows "⚪ offline — messages will wait" after 3 s |
| 23 | ✅ | Message to the locked side shows 🕓 |
| 24 | ✅ | After unlock, the queued message arrived 15 s later; ✓ on the sender |
| 25 | ✅ | After closing both windows: no tor.exe and no p2p-chat.exe within 0.5 s; WebView2 helper processes gone a few seconds later |
| 26 | ✅ | Reboot; copy A started from the Start menu, B from PowerShell; unlock screen; history, ✅ verified and timer kept; reachable within seconds; messages 0.5 s both ways |
| 27 | ✅ | `GetWindowDisplayAffinity` = 0x11 (`WDA_EXCLUDEFROMCAPTURE`) on both windows: in a screen capture the windows are **missing** (what's behind shows), not black. Doc wording updated (dc312dc) |
| 28 | ✅ | Both `vault.db` start with random bytes, no "SQLite format 3"; no sent message text or contact name in any file of either vault folder (`vault.db`, `vault.json`, `vault.lock`) |
| 29 | ✅ | "Self-test OK.", "Checked 10746 files (1 could not be read). Files containing the test word: 0". The unreadable file was `%LOCALAPPDATA%\Microsoft\Windows\Notifications\WPNPRMRY.tmp`, locked by Windows' notification service (the app shows no toasts) |
| 30 | ✅ | Settings → Destroy everything… → Yes: both copies back to the setup screen, vault folders empty, tor.exe stopped. **But** `EBWebView` remains (finding 5.2) |
| 31 | ✅ | Uninstall OK: Program Files folder, Start menu entry and Programs entry gone. Then deleted `%APPDATA%\org.p2pchat.desktop` (only an empty vault folder) and `%LOCALAPPDATA%\org.p2pchat.desktop` (252 files, the EBWebView profile) |
| 32 | n/a | Kali wasn't the other side |
| Update | ✅ | Run 44325493264 installed **over** run 44215249839 (same version 0.1.0, after lock + close): one Programs entry, both copies opened on the unlock screen, same passphrases, history, ✅ verified and ⏱ kept, no re-pairing |

## 4. The bug that was fixed (2ceedc4)

**Symptom** (both sides, run 44215249839): after 📎 → pick a file, the chat showed only a grey
centred line `test-photo.png · 02:20 PM` — no 📄 bubble, no "sending… %", no ✓, and on the
receiving side no **Save…** button. The received file could not be saved.

**Cause**: `ui/src/components/Chat.tsx` (line 235) rendered a bubble only when
`m.kind === 'text'`. The core returns file messages with `kind: "file"` (`db.rs`), so they
fell into the `<Show>` fallback, the system line (`{m.body} · {time}`). The file UI (📄, size,
progress, Save…) was added in a6145cd **inside** the text branch, while the outer condition
dates from 3d485d9. So it never rendered, on any platform. Core tests (`tests.rs`) cover file
transfer but not the UI, which is why nothing failed.

**Fix**: `when={m.kind === 'text'}` → `when={m.kind !== 'system'}` (only kinds are text, file,
system). `tsc --noEmit && vite build` passes locally (Node 24). Built by CI as run
44325493264 and re-tested on Windows (checks 19–21 and the update path pass).

Side effect seen on the old build: a file sent while ⏱ was 5 minutes disappeared like any
message (expected).

## 5. Open findings (not fixed — your decision)

### 5.1 Text delayed during a file transfer
20 MB between the two copies (two onion services on one PC) took ~5 min 40 s (~60 KB/s). A text
sent when the file was at 6% did arrive before the file finished (at 14%) — so check 20
passes — but took **27.4 s** instead of < 1 s. Not investigated; presumably the text waits
behind file chunks already queued on the same connection. Worth a look in
`crates/p2p-core/src/peer.rs` (outbox batching / priorities) if it matters.

### 5.2 `EBWebView` survives "Destroy everything" and uninstall
Despite `"incognito": true`, WebView2 creates its user data folder
`%LOCALAPPDATA%\org.p2pchat.desktop\EBWebView` (~70 MB, ~250 files: `Default\` profile ~0.9 MB,
`component_crx_cache`, `WidevineCdm`, `Subresource Filter`, `GrShaderCache`, `ShaderCache`,
`CertificateRevocation`, `PKIMetadata`, `Variations*`, `Local State`, …). It held **no message
text** (check 29: 0 hits), but it remains after "Destroy everything" and after MSI uninstall,
so it shows the app was installed and used. Only WINDOWS_TEST.md step 31 (manual delete)
removes it; FRIEND_WINDOWS_TEST.md step 7 does not mention it. Options: document it in the
friend guide, delete it on wipe/next start, and/or check what the uninstaller can remove.

### 5.3 WebView2 fetches components from Microsoft, outside Tor
Inferred from the files above (Widevine CDM, subresource filter lists, certificate revocation
data, variations seed) appearing in the app's own WebView2 folder: the WebView2 runtime
downloads these by itself, over the normal internet connection, not through Tor. **Network
traffic was not captured**, so endpoints and timing are unverified. It reveals no message
content, but it is network activity THREAT_MODEL.md doesn't mention. Possible directions
(unverified): WebView2 browser arguments that disable component updates, set through Tauri's
additional browser args, then re-check which folders still appear.

### 5.4 Friend guide still names the buggy build
FRIEND_WINDOWS_TEST.md ("Which version to test", run 44215249839) and install_guide.md list
the build with the file bug, so the friend's file checks 13–15 would fail. Needs a new build
from `main` after merging PR #2, and its fingerprints read from Kali.

## 6. Smaller observations (no action needed unless you want)

- The app started by itself at the end of both installs (launched by the installer; its
  process token was checked: **not** elevated). Whether the last wizard page has a "Launch"
  checkbox wasn't recorded.
- If the friend's PC has **Smart App Control** on, Windows blocks unsigned installers with no
  "Run anyway". Could be worth a line in FRIEND_WINDOWS_TEST.md's troubleshooting.
- The MSI also ships `tor-gencert.exe` (only for Tor directory authorities) and
  `conjure-client.exe`; the app only looks for `tor.exe` and `lyrebird.exe` (`main.rs`
  `tor_binary`/`pt_binary`). Not tested; unused files could be dropped from the bundle.
- The inactivity screen lock (default 10 min) never triggered during the run, so it was not
  tested on Windows. (Keyboard input during the run kept resetting its timer.)
- Starting the MSI from a script with `explorer.exe <msi>` produced an invisible SmartScreen
  prompt; double-clicking it in File Explorer worked. Tooling only, not an app issue.

## 7. What changed in the repository

All on branch **`fix/file-bubble`** (based on main 7437ec8), PR **#2**, not merged:

| Commit | Change |
|---|---|
| 2ceedc4 | `ui/src/components/Chat.tsx`: the one-line fix (section 4) |
| dc312dc | `docs/TRIAL_PLAN.md`: item a (own Windows PC) ticked with notes; log rows for the bug and findings 5.1–5.4. `docs/WINDOWS_TEST.md` check 27: "black/blank, or missing from the screenshot" |
| (this commit) | This report |

All commits use the GitHub no-reply address. Nothing else was changed in the repo; no change
to `main`, tags, releases or workflow files. One extra workflow run: build of `fix/file-bubble`
(run 44325493264, `workflow_dispatch`).

To get it on Kali: `git fetch && git switch fix/file-bubble` (or `gh pr checkout 2`); after
merging, `git switch main && git pull`.

## 8. State of the Windows side at the end

- P2P Chat uninstalled; both test vaults destroyed; app data folders deleted; throwaway
  passphrases and test files deleted.
- Still present: the downloaded build zips in Downloads (`p2p-chat-Windows\` = run
  44215249839 with the bug, `p2p-chat-update\` = run 44325493264) and the copied old MSI;
  the repo clone `%USERPROFILE%\p2p-chat` (with `ui/node_modules`, `ui/dist` from the local
  build, both git-ignored); GitHub CLI signed in (`gh auth logout` when done).

## 9. Suggested next steps (Kali)

1. Review and merge PR #2.
2. Compare run 44325493264's MSI fingerprint (above) from Kali, or skip it and build `main`.
3. Build from `main` (tag `v*` or workflow_dispatch), write down the fingerprints on Kali,
   and update FRIEND_WINDOWS_TEST.md + install_guide.md (finding 5.4).
4. Decide on findings 5.1–5.3 (and whether the friend guide should mention 5.2 and Smart App
   Control).
5. Then the friend's test (TRIAL_PLAN item a, second row).
