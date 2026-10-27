# ECP/1 — implementation contract (0.2.0 source draft)

ECP is ESCrypter Communication Protocol. It transports structured operations and
state, not pixels. Cryptographic transport is OpenSSH; ECP invents no cipher.

## Deployment / identity

One agent per Unix account. `escrypter-agent --serve` listens on
`$XDG_RUNTIME_DIR/escrypter/agent.sock` (0700 directory, 0600 socket). SO_PEERCRED
must match the agent UID. A lifetime flock prevents concurrent agent instances.
The SSH client runs the fixed command `escrypter-agent --bridge`; user-controlled
paths or operations are never concatenated into this command. The bridge copies
stdio to the Unix socket. No ECP public TCP listener exists.

GUI SSH: BatchMode=yes, StrictHostKeyChecking=yes, user-selected known_hosts,
no global known_hosts, no user SSH config, public key/agent authentication.
libcurl SFTP uses the same host, account and known_hosts policy. Provision host
keys through a trusted channel before connecting. Host-key changes fail closed.

The Unix account is the isolation boundary. Root and other processes using the
same Unix account are trusted. Path restrictions are policy, not an OS sandbox
against malicious concurrent symlink/path manipulation by the same account.
Separate accounts and filesystem quotas are recommended for separate tenants.

## Framing

Each frame: 4-byte unsigned big-endian length + UTF-8 JSON object. Length must
be 1..262144. A session accepts up to 16 concurrent local peer connections.
Server idle read timeout: 300 seconds; write timeout: 30 seconds. Desktop request
timeout: 120 seconds; a timeout never means an already-submitted job was cancelled.

Request: `{ "v":1, "id":"request-uuid", "method":"hello", ... }`.
Response: `{ "v":1, "id":"request-uuid", "ok":true, "result":{...} }` or
`{ "v":1, "id":"request-uuid", "ok":false, "error":{"code":...,"message":...} }`.
No arbitrary command execution method is provided. Method arguments are validated
server-side. Unknown methods/versions are rejected.

## Methods

- hello: protocol/app versions, capabilities, canonical data root, job/memory/file
  limits, receipt public key.
- list: relative directory path (empty = data root), numeric offset; 100 entries
  per response, next offset or null. Links are labelled and cannot be followed.
- hash: regular relative file path, optional prefix_bytes. SHA-256, full file size.
- submit: job_id, spec, secrets array. Spec operations: encrypt, decrypt, recover,
  verify, info, rekey. Paths are relative to configured data/key roots. Encryption
  inputs are 1..256 paths. Remote recovery-slot creation is not exposed yet;
  existing recovery slots can be used by recover.
- jobs: persisted job summaries and server free disk/concurrency counts.
- events: job_id, after sequence; at most 64 events per response; gap flag when
  earlier events expired. Last 512 events retained per job.
- cancel: requests SIGTERM only for a tracked, still-running child.
- forget: removes a completed job's history; never removes output files.
- upload_prepare: upload_id, path, size, sha256. Reserves a unique staging path,
  returns path/offset/prefix SHA-256. Replayed IDs must match content/destination.
- upload_finish: upload_id. Checks size/SHA-256, fsyncs, uses
  renameat2(RENAME_NOREPLACE), issues a signed receipt.

Submit returns an existing job on an identical ID/spec retry and rejects the same
ID with another spec. Secrets do not participate in the persisted request hash.
Job metadata and bounded event history persist; secrets are passed only through
worker stdin and are not intentionally written to job state or argv. Serde/Qt
string copies mean complete memory erasure cannot be guaranteed.

## Job lifetime

starting -> running -> completed / failed. After agent restart, starting/running
records become interrupted. Disconnected SSH clients do not own worker lifetime.
A user-systemd unit owns the daemon and workers. Login session shutdown can stop
a user service unless an administrator has enabled user lingering. A machine
restart does not resume an encryption operation. Transfers can resume after
verified prefix matching; encryption restarts from the beginning.

Limits: simultaneous workers, RLIMIT_AS, RLIMIT_FSIZE, no core dumps, bounded
history. max_upload_bytes bounds outstanding upload reservations, not total
on-disk data usage. Use filesystem quotas for total storage enforcement. Failed
or abandoned upload reservations are retained; administration/retention tooling
must be finalized in the debug phase before long-term unattended use.

## Signed receipts

Agent owns a separate Ed25519 receipt key under private state permissions.
Receipt key is not the user's archive-signing key and never decrypts archives.
Receipt JSON payload contains v, upload_id, SHA-256, byte count, received_at.
Signature input is the 21 bytes `ESCrypter receipt v1\0` followed by the exact
payload bytes. Response gives payload_hex, signature (hex) and public_key (hex).
Desktop compares the key with the SSH-authenticated hello key and verifies the
signature, then stores the receipt locally. This records receipt of bytes; it
is not a promise of permanent storage or a substitute for archive verification.

## Confidentiality modes

Local encrypt -> upload: server receives encrypted bytes, not archive password.
Remote processing: server necessarily receives needed secrets and may access
plaintext. GUI requires an explicit acknowledgement before remote operations
that decrypt or create data. A TLS tunnel or SSH connection does not hide secrets
from the server performing the operation.

## Transport-only SFTP

A server without ECP can transfer files using absolute SFTP paths. Upload uses a
unique staging filename followed by SFTP rename; exact no-overwrite behavior
must be validated against target SSH/SFTP implementations. It has no ECP digest
receipt or checked-upload-resume semantics. Download without ECP restarts from
zero and requires independent package signature verification.
