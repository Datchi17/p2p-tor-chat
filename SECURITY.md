# Security policy

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository. Only the maintainer sees the report.

Helpful details: what an attacker can do, the steps to reproduce, the version (commit or build
run) and the OS.

You'll get an answer as soon as possible. This is a small, unfunded project, so please allow a
few days. Fixed issues are described in the release notes once users have had time to update.

## Supported versions

Only the newest build. The app never updates itself and never checks online: it shows a
reminder when it is 90 days old.

## What is in scope

Everything in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) listed as protected. The "NOT
protected" list there (for example malware on your own computer) is known and documented.
