# Original validation plan — current results in DEBUG_REPORT_TR.md

1. Compile Rust library/CLI/agent and C++ Qt GUI against Debian 13 dependencies.
   Resolve compiler/API errors; run formatters and static analysis.
2. Adapt inherited integration harness to versioned events. Re-run previous crypto,
   roundtrip, mutation, limits, cancellation and overwrite tests against 0.2.
3. Fuzz ECP frame/parser/paths, malformed XML, TAR/XZ resource bounds, duplicate IDs,
   early EOF, final tags, untrusted signers and adversarial multi-part layouts.
4. Exercise per-user agent, UID checks, duplicate agent locking, SSH reconnect,
   worker crash, reboot-interrupted states, secret redaction and child cancellation.
5. Run an isolated SSH/SFTP server fixture; compare libcurl and OpenSSH known_hosts
   identities, unknown/changed keys, encrypted keys through ssh-agent, IPv6 hosts.
6. Test upload/download from 0 bytes through >4 GiB, verified-prefix resume, short
   writes, disconnect during finalize, output collisions, receipt replay/signature,
   changed local inputs, exhausted quota and stale reservation cleanup.
7. Review path TOCTOU, extraction symlinks, permissions, temporary folder ownership,
   state tampering, daemon shutdown ordering and durable state failure handling.
8. Click through every menu/tab/dialog in TR/EN, dark/light/system, HiDPI, keyboard
   navigation, screen reader labels, long paths, context switching and tab close.
9. Review async callback lifetimes, pending digest/transfer cancellation, close while
   wget or SSH is active, transfer-queue cancellation status, file descriptor leaks.
10. Resolve all dependency license notices, GPLv3 compatibility and obligations;
    test license viewer offline; include source and notices with binaries.
11. Build/install/remove desktop/core .deb on clean Debian 13; test .esc association,
    taskbar/launcher icons, Wayland/X11 and user service. ARM64 separately.
12. Benchmark bounded RAM/CPU/disk usage and revise progress/ETA estimates. Publish
    actual results and limitations; do not reuse 0.1 claims for the new release.

Until this stage finishes, use copies of non-critical files only. No independent
security audit has been completed.
