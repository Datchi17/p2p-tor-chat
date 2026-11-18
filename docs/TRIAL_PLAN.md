# Before trusting it with real conversations

Until **every** box is ticked, keep sensitive conversations on Signal (or another audited
messenger whose current audit and maintenance status you checked yourselves).

| # | Item | Status | Notes |
|---|---|---|---|
| a | Windows build compiled by CI | ☑ | run 39475533697 (2026-10-20) |
| a | Automated: two full app cores chat over real Tor on a Windows CI machine | ☑ | delivery, receipts, disappearing, offline — all passed |
| a | Tested on a spare Windows PC: install, pair with Kali, offline delivery, restart, lock/unlock | ☑ | WINDOWS_TEST.md, 2026-11-18 on the dual-boot PC with two copies (step 10a). All checks pass with fix 2ceedc4 (run 44325493264), including installing it over the old version; file checks 19–21 failed on run 44215249839 (log below) |
| a | Tested on the friend's own PC | ☐ | |
| b | Installer fingerprint read aloud on the verification call (every install and update) | ☐ | USER_GUIDE.md, rule 1 |
| c | CI actions pinned to commits; Kali rebuild compared with CI | ☑ pinned / ☑ Linux binary identical | commit a35088a: app binary 1263c869…b26d08e on both. Windows installer is not yet reproducible |
| d | Strict re-pairing rule agreed; app enforces typed safety-number groups | ☑ enforced / ☐ agreed | USER_GUIDE.md, rule 2 |
| e | Independent human review of the glue code | ☐ | REVIEW.md gives the scope. Note: SECURITY_AUDIT_REPORT.md (2026-10-21) is a second **AI** review — useful (found 2 real bugs, fixed in PR #1) but it does not replace a human reviewer |
| f | One month of side-by-side use with nothing real in it | ☐ | log below |
| g | Update owner named (Datchi17); friend agrees to this setup | ☑ owner / ☐ friend agreed | UPDATES.md |

## Month trial log (item f)

Use the app daily for unimportant chat while real conversations stay elsewhere. Note anything
odd — even small: a message that never arrived, a duplicate, a security warning, a crash,
Tor that wouldn't connect, the app being slow to show "reachable".

| Date | Who | What happened | Resolved? |
|---|---|---|---|
| 2026-10-21 | friend | Built from source on Windows 11, AI-assisted code review (SECURITY_AUDIT_REPORT.md); fixed read receipts to unverified contacts and a false "too fast" alarm on large backlogs | ✅ PR #1 |
| 2026-10-22 | Datchi17 | New live test (120-message backlog) found outboxes > 100 messages stalled after the first batch; fixed (next batch sent when a batch is fully acked) | ✅ |
| 2026-11-18 | Datchi17 | Windows test (WINDOWS_TEST.md) of run 44215249839: files could not be received. A file showed only as a grey system line (name · time), with no progress, ✓ or Save… button: Chat.tsx drew bubbles only for `kind === 'text'` (all platforms, since a6145cd) | ✅ 2ceedc4 (run 44325493264, MSI `9b1d9bb7…40e46728`): photo and 20 MB file arrive identical, Save… adds the "came from another computer" mark |
| 2026-11-18 | Datchi17 | FRIEND_WINDOWS_TEST.md still points to run 44215249839, which has the file bug: point it to a build with the fix before the friend's test | ✅ new build from main, both guides updated |
| 2026-11-18 | Datchi17 | A text sent during a 20 MB file transfer arrived before the file finished, but took 27 s instead of < 1 s (the 20 MB took ~5½ min) | ✅ fixed in code: at most 6 file chunks in flight; live Tor test: a text overtakes a 2 MB file. Re-check WINDOWS_TEST 20 on Windows |
| 2026-11-18 | Datchi17 | "Destroy everything" and uninstalling leave `%LOCALAPPDATA%\org.p2pchat.desktop\EBWebView` (~70 MB of WebView2 profile and components). No message text in it (leftover-text search: 0), but it shows the app was used; only the manual delete in WINDOWS_TEST.md step 31 removes it | ✅ documented (FRIEND_WINDOWS_TEST step 7, USER_GUIDE, THREAT_MODEL); it can't be deleted while WebView2 runs |
| 2026-11-18 | Datchi17 | WebView2 downloads its own components (Widevine, subresource filter, certificate revocation lists) from Microsoft, outside Tor. Not mentioned in THREAT_MODEL.md | ✅ mitigated: WebView2 starts with component updates and background networking off and a dead proxy; README/THREAT_MODEL corrected. Re-check WINDOWS_TEST 29b on Windows |
| 2026-11-18 | Datchi17 | CI build of 3cdcb09 failed once in the vault's change-passphrase test (SQLCipher rekey error; not reproducible in 860 local runs). Investigating it found a real bug: after a failed rekey SQLCipher keeps writing with the new key, so anything saved afterwards made the whole vault unreadable | ✅ fixed: reconnect with the old key and retry once; new test forces a failed rekey and checks the vault still opens with all data |
| | | Still to do: the installer test on the friend's PC (FRIEND_WINDOWS_TEST.md) | ☐ |

**Pass criteria:** no undelivered or duplicated messages that weren't explained, no unexpected
security warnings, no crashes that lost data, both of you still willing to use it.
