# ESCrypter 0.2.0 development candidate

Built and debugged on Ubuntu 24.04 amd64. Current checks and limitations are in
DEBUG_REPORT_TR.md. Debian 13 and real SSH/SFTP validation remain pending.
This GitHub bundle includes source and vendored dependencies; .deb files are generated separately.

Implemented source modules:
- Rust library extracted from CLI; versioned JSON worker events; key-password,
  public-key, package-info and authenticated contents-preview operations.
- Qt QMainWindow menus, movable/closable tabs, local workspaces, server tabs,
  global local-job queue, transfer view, hidden technical details.
- Five embedded SVG lock variants rendered using QtSvg for app/window/actions.
- Password dialog/generator, signing key selection/export/change, trust store,
  themes, languages, job history, redacted diagnostic export, marked work cleanup.
- GPLv3 code licensing plus historical MIT notice; offline license inventory
  viewer, build-time Cargo/distro full-text inventory generation.
- OpenSSH stdio ECP bridge, per-account daemon, Unix peer authentication, durable
  job IDs/events, bounded jobs/connections/history, cancellation, resource limits.
- Remote listing, jobs, progress events, resource summary, encryption/decryption,
  recovery, verification, info and password-change submissions.
- libcurl SFTP queue, speed limit, host-key verification, ECP staging/finalization,
  verified-prefix resume, downloads, Ed25519 receipt verification/storage.
- Local encrypt-then-upload action; independent wget HTTPS retrieval.
- Desktop/core split packaging and user-systemd unit.

Known scope limits to retain honestly:
- The GUI still displays some diagnostic statuses and advanced strings in English;
  changing language live updates menus, while tabs need reopening for all labels.
- No automatic retries for remote job submission; reconnect + list jobs prevents
  blindly starting duplicates. Protocol-level ID replay is supported.
- Agent enforces per-file/worker/reservation limits, not aggregate filesystem quota.
- Remote signing keys are provisioned separately; no remote private-key upload wizard.
- Local encrypted workflow uploads and ECP checks transport digest; full archive
  verification is a separate selectable remote job, not an automatic universal claim.
- Agent filesystem policy assumes account-private roots; hardened openat2-based
  traversal against same-account races remains a review item.
- Remote content-name preview and general pause/resume of crypto jobs are omitted.
- Cleanup covers marked local work directories, not unattended server upload retention.
- This is a development candidate, not an independently audited production release.
- License catalog is generated from resolved dependencies (`draft: false`).
