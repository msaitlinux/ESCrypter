# GitHub bundle preparation — 2026-10-26

Based on the delivered 0.2.0 debugged source candidate. Rust and Qt application
sources are unchanged byte-for-byte. Added README/project guides, issue/PR
forms, editor/Git settings, Actions/Dependabot definitions and a combined-package
script. The license collector now resolves the installed GNU C++ major version
instead of hard-coding 13.

Checks performed for this preparation:
- All five YAML files parsed; matrix contains Ubuntu 24.04 and Debian 13 jobs.
- Shell syntax checked; license collector Python syntax checked.
- Combined Debian package script executed with existing compiled candidate
  binaries; verified GUI/core/agent inclusion and no separate core dependency.
- Git staging includes .github, .cargo, source, lockfile and vendored dependencies.
- ZIP contains no build trees, .git database or compiled .deb files.

Application tests were not rerun for this documentation/packaging preparation.
Previous results are explicitly archived under docs/validation. GitHub workflows
have not yet run; real Debian 13 and SSH/SFTP validation are still pending.
No repository or release has been published by creating this ZIP.
