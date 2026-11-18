# Roadmap

The goal is three statements that are literally true and that anyone can check, without
having to trust the person who builds the app:

1. **Zero access.** Keys are created on each device and never leave it; there is no server
   where messages could pass.
2. **Nobody in the middle.** No servers, accounts or phone numbers; apps talk directly over
   Tor; there is no switch to read, block or shut down a conversation. The only thing the
   maintainer controls is the app itself, so every release must be checkable.
3. **No logs.** No infrastructure to log anything; the app keeps no logs on the device;
   messages disappear on the chosen timer.

"Absolute security" is not one of them: no software can promise it. THREAT_MODEL.md lists
what is and isn't protected.

## Decisions (2026-11-18)

| Question | Decision |
|---|---|
| Who it's for | The maintainer and friends for now; maybe public later |
| Disappearing messages | Stay at **1 week**, counted from receipt; no memory-only mode |
| Budget | None: only free tools and services |
| Public repository | Wanted, but not yet: see "Before going public" |

## Phase A: nothing left on the device (done)

- Release builds write no logs (`P2PCHAT_LOG` turns them on for troubleshooting).
- The web view runs in private mode: no web cache or storage on disk.
- Spell check and autocorrect are off in fields that hold private text.
- A "this version is N days old" reminder after 90 days, computed from the build date, with no
  network access.
- Windows leftover-text search (FRIEND_WINDOWS_TEST check 19).

## Phase B: checkable by others (needs the public repository)

| Step | Free tool |
|---|---|
| Public source code (licence is already AGPL-3.0) | GitHub |
| Windows app binary rebuildable byte for byte, like Linux | Fixed paths and timestamps, possibly a Linux cross-build |
| Signed releases in a public log | Sigstore (GitHub artifact attestations are free for public repos) or minisign |
| Account protection | Passkey or authenticator-app 2FA on GitHub, signed commits |
| Rules on `main` | GitHub rulesets (free for public repos): no force-push, no deletion, changes only through reviewed pull requests |
| Strangers' pull requests can't run CI without approval | Actions setting "Require approval for all external contributors" |
| Private vulnerability reports | GitHub private vulnerability reporting |

## Phase C: hardening without a budget

- Fuzz everything that reads network input (pairing code, frames, file chunks) with `cargo-fuzz`.
- Dependency policy with `cargo-deny`, and `cargo-mutants` to find code the tests don't really check.
- Censorship resistance: bundle Snowflake and the built-in bridges.
- If public use grows: apply for a free audit (OTF Red Team Lab, NLnet NGI Zero) and free code
  signing (SignPath Foundation). All three require public source.

## Before going public

1. Decide what to do with the names and email addresses in the commit history (they become
   public with the repository).
2. Remove write access that is no longer needed: a public repo's builds can be downloaded
   by anyone with a GitHub account.
3. Add CONTRIBUTING.md (outside code is not merged; ideas and bug reports are welcome) and
   SECURITY.md (how to report a vulnerability privately).
4. Flip the visibility, then apply the Phase B settings the same day.
