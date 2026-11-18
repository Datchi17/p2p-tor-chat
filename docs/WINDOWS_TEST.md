# Windows test checklist (TRIAL_PLAN item a)

Do this on **your own Windows 10/11 PC** before your friend installs anything. You play
both people, with throwaway test messages only. Tick each box; write down anything odd in
TRIAL_PLAN.md's log.

**Who is "the other side"?**
- If Kali runs on **another computer** at the same time: Kali is the other side.
- On a **dual-boot PC** (Kali is off while Windows runs): run **two copies of the app on
  Windows** (step 10a). Wherever this list says "the other side", use the second copy.

## 0. Get the installer

1. ☐ **While still on Kali** (or on your phone), write down the `.msi` fingerprint of the
   build you'll test, from the GitHub build run. Don't rely only on reading it later from the
   same page you download from.
2. On Windows, sign in to GitHub → **Datchi17/p2p-tor-chat → Actions → build** → open that run →
   download the **p2p-chat-Windows** artifact. Extract the `.msi` to Downloads.
3. ☐ In PowerShell: `Get-FileHash "$HOME\Downloads\P2P Chat_0.1.0_x64_en-US.msi"` — the
   hash equals the fingerprint you wrote down.

## 1. Install

4. ☐ Run the `.msi`. SmartScreen warns → More info → Run anyway (only because step 3 matched).
5. ☐ Installs without errors; "P2P Chat" appears in the Start menu.
6. ☐ If Defender flags `tor.exe`: note it in the log (it's expected to happen sometimes).
7. ☐ If the Firewall asks: choose **Cancel / don't allow**. The app must still work, since
   Tor only connects outward. Note which you saw.

## 2. First run

**Dual boot:** check the clock first. Kali keeps the PC clock in UTC and Windows reads it as
local time, so after switching, Windows' clock can be off by your time-zone offset, and Tor
won't connect with a wrong clock. Settings → Time & language → Date & time → **Sync now**.

8. ☐ Create a vault (name "Win-Test", any 6-word passphrase you'll throw away).
9. ☐ Status bar reaches "🧅 Tor connected" (may take a minute or two).
10. ☐ No black console window pops up.

**10a. Dual boot: start a second copy.** In PowerShell (it keeps its own vault and Tor in
the folder named on the first line):

```powershell
$env:P2PCHAT_DATA_DIR = "$env:LOCALAPPDATA\org.p2pchat.desktop\second"
& "C:\Program Files\P2P Chat\p2p-chat.exe"
```

A second window opens. Create a vault named "Win-Test-2". Both windows have the same title:
put them side by side.

## 3. Pair and verify

11. ☐ Exchange codes between the two sides (**Copy my code** → paste into the other side's
    **Paste your friend's code**).
12. ☐ Both show the **same 12 groups**.
13. ☐ Typing **wrong** digits for the requested groups is refused with a red warning.
14. ☐ Typing the right digits verifies on both sides.

## 4. Messaging

15. ☐ A message from the other side arrives; ✓ appears on the sender.
16. ☐ A message to the other side arrives; ✓ appears on Windows.
17. ☐ Emoji and non-English text (e.g. `مرحبا 👋 тест`) arrive intact both ways.
18. ☐ ⏱ shows **1 week** by default. Set it to 5 minutes; a message disappears on both sides
    about 5 minutes after it arrives. Set it back to 1 week.

## 5. Files (never yet clicked through on Windows)

19. ☐ 📎 → pick a small photo or PDF → "sending… %" then ✓. The other side clicks **Save…**
    → the saved file opens correctly.
20. ☐ A file of about **20 MB** arrives completely; a text sent meanwhile arrives first, within
    about 10 seconds (it took 27 s before the fix of 2026-11-18).
21. ☐ Right-click a saved file → Properties: it says it came from another computer
    ("Unblock" checkbox), so SmartScreen will warn before running it.

## 6. Offline and restart

22. ☐ Click 🔒 (full lock) on one side. The other side shows it ⚪ offline.
23. ☐ Send to the locked side → shows 🕓 queued.
24. ☐ Unlock → the queued message arrives within ~2 minutes; ✓ appears.
25. ☐ Close every P2P Chat window, then check Task Manager: **no `tor.exe` left running**.
26. ☐ Reboot Windows, start the app (and the second copy), unlock → history is still there;
    messaging still works.

## 7. Privacy checks on Windows

27. ☐ Press Win+Shift+S and try to screenshot the app window → it appears **black/blank**, or
    is **missing** from the screenshot so you see what's behind it (the window is marked
    content-protected; current Windows 10/11 leave it out of captures entirely).
28. ☐ `%APPDATA%\org.p2pchat.desktop\vault\vault.db` exists; open it in Notepad → unreadable
    gibberish, no message text, no "SQLite format 3" at the start.
29. ☐ **Leftover-text search:** do check 19 of FRIEND_WINDOWS_TEST.md (send `zebra7canary`
    both ways, lock and close every window, paste the PowerShell block). Result:
    `Self-test OK.` and `Files containing the test word: 0`. The second copy's folder is
    inside one of the searched folders, so it's checked too.
29b. ☐ **The browser engine stays offline.** Start from a clean state (no
    `%LOCALAPPDATA%\org.p2pchat.desktop\EBWebView` left from an older version), chat and send
    a file, then with the app still open paste this in PowerShell. It must print
    `Internet connections from them: 0` and `Downloaded component folders: 0`:

    ```powershell
    $all = Get-CimInstance Win32_Process
    $ids = @($all | Where-Object Name -eq 'p2p-chat.exe' | ForEach-Object ProcessId)
    do {
      $n = $ids.Count
      $ids = @(@($ids) + @($all | Where-Object { $ids -contains $_.ParentProcessId -and $_.Name -eq 'msedgewebview2.exe' } | ForEach-Object ProcessId) | Select-Object -Unique)
    } while ($ids.Count -gt $n)
    $web = @($all | Where-Object { $ids -contains $_.ProcessId -and $_.Name -eq 'msedgewebview2.exe' } | ForEach-Object ProcessId)
    $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $web -contains $_.OwningProcess -and $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0$|::$)' })
    "WebView2 processes of P2P Chat: $($web.Count). Internet connections from them: $($conns.Count)"
    $conns | Format-Table RemoteAddress, RemotePort, State
    $dir = "$env:LOCALAPPDATA\org.p2pchat.desktop\EBWebView"
    $dl = @(Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue | Where-Object Name -in 'WidevineCdm', 'Subresource Filter', 'CertificateRevocation', 'PKIMetadata', 'component_crx_cache')
    "Downloaded component folders: $($dl.Count) $($dl.Name -join ', ')"
    ```

30. ☐ Settings → **Destroy everything** → the app returns to the setup screen and the `vault`
    folder is empty. Do it in both copies.

## 8. Clean up

31. ☐ Uninstall via Settings → Apps. Delete `%APPDATA%\org.p2pchat.desktop` and
    `%LOCALAPPDATA%\org.p2pchat.desktop` (the WebView2 folder always remains; it holds no
    messages).
32. ☐ If Kali was the other side: delete the "Win-Test" contact there.

**Result:** all boxes ticked → item **a** (your own Windows PC) is done. The friend's test is
still needed: their own PC, antivirus and network, and the pairing ritual between two real
people on a call (FRIEND_WINDOWS_TEST.md).
