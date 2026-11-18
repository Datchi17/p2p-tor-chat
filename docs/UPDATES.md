# Updates and ownership

A secure tool that nobody maintains decays: Tor versions get dropped from the network,
libraries get security fixes, and every new installer is a chance to slip in a fake one.

## Who owns what — fill this in together

| Role | Person | Agreed on |
|---|---|---|
| **Update owner** (builds releases, watches for fixes) | Datchi17 (repository owner) | 2026-10-20 |
| **Second checker** (confirms fingerprints, can veto a release) | the friend — **pending their agreement** | ____ |

Both of you must agree to this file before relying on the app (checklist item **g** in
[TRIAL_PLAN.md](TRIAL_PLAN.md)).

## What triggers an update

The `maintenance` workflow runs every Monday on GitHub and turns **red** (GitHub emails the
repository owner) when:

- `cargo audit` finds a vulnerability in any Rust dependency;
- a newer Tor Expert Bundle than the pinned one exists (Windows build);
- a newer libsignal release than the pinned one exists (and is newer than the last release
  reviewed and skipped, below).

The Linux app uses Kali's own `tor` package, so `sudo apt update && sudo apt upgrade` keeps
Tor current there.

## How a release is made

1. The update owner bumps the pinned version(s), runs `cargo test --workspace --exclude p2p-chat`
   and the live tests, and pushes a tag `vX.Y.Z`.
2. GitHub Actions builds the `.deb` and `.msi` with pinned tools and publishes `SHA256SUMS`.
3. The update owner also builds the Linux `.deb` locally on Kali and compares. (A bit-for-bit
   match is not guaranteed yet — see "Reproducibility" below.)
4. **On a live call**, the update owner reads the fingerprint of the installer the friend will
   use; the friend compares with `Get-FileHash` / `sha256sum` before installing.
5. If anything doesn't match, nobody installs. No exceptions for "urgent" updates.

## Reviewed and skipped

| Date | What | Decision and why |
|---|---|---|
| 2026-11-14 | libsignal v0.106.0 – v0.108.0 (pinned: v0.105.2) | **Stay on v0.105.2.** No security fix applies to v0.105.2. These releases add *Tahini*, a rewrite of session management (~3,000 lines, first shipped in v0.106.0 on 2026-10-23); v0.108.0's "reject PreKey messages carrying our own base key" fixes the new Tahini code. Wire format and stored sessions stay compatible, so upgrading later is safe. Re-evaluate once Tahini has had a few weeks of fixes. The weekly check accepts up to v0.108.0 (`reviewed=` in `.github/workflows/maintenance.yml`) and alerts on anything newer. |

## Red flags — stop and call

- An update arriving with pressure ("install this now, it's urgent").
- A fingerprint sent only by text/email.
- A new pairing code without a call.
- The app suddenly asking you to verify an existing contact again.

## Reproducibility

**Linux: reproducible.** `scripts/repro-build-linux.sh <commit>` builds inside a pinned
container (`build/Dockerfile.linux`: base image by digest, Debian packages from a dated
snapshot, Rust/Node/protoc by checksum). The CI job `linux-reproducible` runs the same script.
For commit `a35088a` the **app binary** was byte-identical on Kali and on GitHub
(`1263c869…b26d08e`). The `.deb` wrapper itself still differs (packaging metadata), so compare
the app-binary line of `REPRO-SHA256SUMS.txt`, not the `.deb` line.

**Windows: not reproducible yet.** Every CI run produces a different `.msi`, so the
fingerprint you read aloud is tied to one specific run. Making the Windows build reproducible
is an open item.
