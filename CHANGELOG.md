# Changelog

## 0.2.0 — development candidate

- Tabbed Qt6 GUI, organized menus, Turkish/English UI and five embedded lock icons.
- Rust CLI/core and per-user ECP agent with versioned process events.
- SFTP transfers, SSH-carried ECP control, signed upload receipts and HTTPS retrieval.
- Signing-key password change/export, trust management and authenticated content preview.
- GPL-3.0-only project license; historical MIT notice retained.
- Offline license viewer and 35 vendored Rust dependency source trees.
- Fixes for agent locking, upload finalization recovery, receipt binding,
  cancellation, safe local transfer files and package document ownership.

Validation recorded on Ubuntu 24.04 amd64: 14 Rust tests, 18 CLI integration tests,
GUI smoke checks and six benchmark roundtrips. These do not establish Debian 13
or live SSH/SFTP compatibility. See docs/DEBUG_REPORT_TR.md.

## 0.2.0-1 — packaging revision

The application version remains 0.2.0. A combined Debian package includes GUI,
CLI and agent. This repository adds a repeatable `package-single-deb.sh` script.
The source preparation adds contribution/security guides, issue/PR templates and
CI definitions. These new GitHub workflows have not yet executed on GitHub.
