# ESCrypter format v1 (0.1.0)

This format is application-specific; implementers must validate every bound.
All integers in XML are decimal ASCII, except fields documented as hexadecimal.
The XML subset has a single `<escrypter>` root, exact ordered fields, no whitespace,
attributes, entities, declarations, namespaces or DTDs. Metadata records are
limited to 1 MiB. Hex is lowercase on output. Algorithms are fixed by version.

## Outer archive

Uncompressed USTAR-compatible TAR, filename suffix `.esc`, >=4,000,000 bytes.
100 regular file entries with names `escs/esc{10,20,...,100}/NNNN.esc`, 10 per
folder, NNNN from 1000 through 9999, globally unique within the package. All paths
are relative. The outer TAR additionally has:

- files/manifest.xml
- files/signer.pub (32 raw bytes)
- files/signature.ed25519 (64 raw bytes)
- optionally files/recovery.xml

Reject duplicates, unexpected entry names/types, incorrect part counts, missing
metadata, invalid signatures, and nonzero trailing TAR data. Physical entry
order is shuffled. The directory tree is implicit in regular member paths.

## Signature

Exclude only files/signature.ed25519. Sort names lexicographically in a BTreeMap.
Compute SHA-512 of:

1. ASCII `ESCrypter content signature v1` followed by NUL.
2. Number of included files as u32 little endian.
3. For each: UTF-8 name byte count (u32 LE), name bytes, size (u64 LE), SHA-256
   of the complete content (32 raw bytes).

Ed25519 signs this 64-byte digest using libsodium crypto_sign_detached. This is
Ed25519 on an application-domain-separated digest, not Ed25519ph. The public key
is covered by the transcript. Trust pin is lowercase SHA-256 of the public key.
TAR headers, padding, and physical order are not authenticated by this signature.

## Password envelope

Exact fields: version=1, memory=65536, iterations=3, salt (16 bytes hex), nonce
(24 bytes hex), ciphertext (hex, includes 16-byte AEAD tag).
Argon2id v1.3 via libsodium crypto_pwhash, alg=2, opslimit=3, memlimit=67108864,
32-byte output key (libsodium uses one lane). Arbitrary KDF parameters are rejected.
No Unicode normalization: password is UTF-8, trailing CR/LF removed by the CLI.

AEAD: XChaCha20-Poly1305-IETF, random nonce. Associated data is exact ASCII:
`ESCrypter/{context}/v1/argon2id13/m65536/t3/p1/{salt_hex}`.
Context is `manifest` or `signing-key`; never interchange these contexts.

Manifest plaintext exact fields:
- version=1
- key: random 32-byte stream key, hex
- compressed: true XZ byte length, decimal
- cipherbytes: combined encrypted stream byte length, decimal
- unpacked: sum of regular file sizes in inner TAR, decimal
- order: UTF-8 newline-separated list of all 100 part paths, hex encoded

Manifest contains the data key and all ordering/length information. File names
and modification timestamps are contained in the encrypted inner TAR. No
external signing key is required to decrypt.

## Data stream

Inner GNU TAR with regular files/directories -> XZ -> libsodium secretstream
XChaCha20-Poly1305. The encrypted stream starts with the 24-byte secretstream
header. Each record: u32 LE ciphertext length, ciphertext. Maximum plaintext
record is 1 MiB; minimum ciphertext 17, maximum 1 MiB+17. TAG_MESSAGE=0 for data
and padding, TAG_FINAL=3 for an empty final record. No additional authenticated
data is used for stream records. All records must authenticate in order. Require
FINAL; reject truncated, reordered or trailing records.

After XZ completes, remember compressed length. Add encrypted CSPRNG random
padding records of 65536 bytes until current stream reaches >=4,000,000 bytes;
then add FINAL. Decryption delivers exactly `compressed` plaintext bytes to XZ,
authenticates but discards padding and requires FINAL. This conservative rule
makes the completed outer archive slightly larger than 4 MB.

Split complete ciphertext into 100 balanced consecutive byte ranges; the first
L mod 100 parts have floor(L/100)+1 bytes. Randomly assign part paths, and store
the true ordered paths in the protected manifest. No per-part plaintext headers.
No redundancy; every data part is required.

## Signing key / recovery

Signing key file: password envelope with context signing-key. Plaintext fields:
public (32 bytes hex), secret (64-byte libsodium Ed25519 secret key, hex).
Generated keys are checked by signing/verifying a fixed key-check message.
The signing private key is never intentionally placed in an archive.

Optional files/recovery.xml exact fields: nonce (24 bytes hex), ciphertext.
The same manifest plaintext is AEAD encrypted with an independent random 32-byte
recovery key, associated data `ESCrypter/recovery/v1`. The recovery key is saved
outside the archive as 64 hex characters plus newline, with private permissions.

## Extraction

Verify content signature first. Validate pinned identity if supplied. Unlock
manifest, validate exactly 100 unique paths and total cipher length, check free
space. Decrypt with bounded records and an XZ decoder memory limit of 256 MiB.
Reject absolute paths, `..`, links, special files, duplicate inner paths, >1M
entries and file totals exceeding the manifest. Extract to a private sibling
staging folder, require full stream authentication, then atomically publish using
Linux renameat2(RENAME_NOREPLACE). No overwrite. Source files remain untouched.
