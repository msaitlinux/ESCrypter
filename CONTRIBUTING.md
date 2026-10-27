# Contributing

ESCrypter is a development candidate. Discuss archive-format changes in an issue
before implementation. Keep changes focused and add regression coverage for
security-sensitive behavior. Never use real passwords or confidential files in
issues, fixtures, screenshots or logs.

1. Fork the repository and create a branch.
2. Install the build dependencies listed in README.md.
3. Run `bash tests/run-checks.sh`.
4. On a host permitting Unix sockets, run
   `python3 tests/ecp_integration.py target/release`.
5. Describe the change, tests actually run, and remaining limitations in your PR.

Preserve archive compatibility, no-overwrite behavior and original input files.
Changing a protocol, cryptographic parameter or key format needs explicit review
and migration documentation. Use established crypto libraries; do not introduce
custom encryption primitives. Do not edit vendored dependencies casually: update
the lockfile, source snapshots and notices together and verify offline builds.

Project contributions are under GPL-3.0-only; retain existing notices and the
licenses of third-party files. No CLA or copyright assignment is required here.
See SECURITY.md for vulnerability reports.
