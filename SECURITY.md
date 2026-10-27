# Security policy

## Status

0.2.0 is a development candidate, not an independently audited production release.
No release is currently designated as a security-supported stable release.
See docs/DEBUG_REPORT_TR.md for actual validation scope and known limitations.

## Reporting a vulnerability

Do not disclose secrets or exploitable vulnerability details in a public issue.
Use GitHub's **Security → Report a vulnerability** when enabled for this repository.
If it is unavailable, open an issue requesting a private reporting channel without
including exploit details. No private contact address or response-time promise is
invented by this template. The repository owner should enable private vulnerability
reporting before public release.

Include the affected version, OS, reproduction using synthetic data, observed
impact, and suggested mitigation. Do not upload private keys, recovery keys,
passwords, personal archives, or third-party data.

## Trust boundaries

- Archive encryption does not protect a compromised endpoint.
- A valid signature requires independently established signer trust.
- Splitting into 100 pieces is format organization, not added cryptographic strength.
- Remote processing exposes plaintext and passwords to the server account.
- ECP is carried over SSH; its filesystem policy is not a sandbox against a
  malicious process sharing the same Unix account.
- Working directories may retain plaintext after an abrupt termination.
- Real SSH/SFTP, Debian 13 installation and systemd lifecycle validation are pending.
