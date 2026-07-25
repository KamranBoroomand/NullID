# Password Storage Hashing in NullID

NullID's password storage hashing tools are for storing a verifier for a user password. They are not a substitute for encryption, and they are not the same thing as integrity hashing.

## What It Is

- Integrity hashing answers: "Did this file or text change?"
- Password storage hashing answers: "Does this candidate password match the stored verifier?"
- Encryption answers: "Can an authorized recipient recover the plaintext later?"

If you need to recover the original data later, use encryption. If you need to store a verifier for a human password without storing the password itself, use password storage hashing.

## Why It Is One-Way

NullID stores a password hash record, not ciphertext. The record contains:

- the algorithm
- the salt
- the cost settings
- the derived hash

That record is designed for recomputation and comparison. It is not designed to be decrypted, and there is no "original password" hidden inside the record to recover later.

This matters because password storage is about safely checking guesses, not about preserving a reversible copy of the password.

## Why Hashes Are Not Reversible

A password hash record is produced by running the password through a one-way derivation function. NullID intentionally uses algorithms that are suitable for verification, not for later recovery:

- `Argon2id` is preferred when available because it is memory-hard and slows large-scale guessing better than plain fast digests.
- `PBKDF2-SHA256` is the compatibility fallback when `Argon2id` is unavailable.
- `SHA-256` and `SHA-512` remain in the tool only for legacy migration/testing cases. They are fast digests and should not be chosen for new password storage.

NullID does not offer a "decrypt password hash" action because password hashes are not ciphertext.

## How Salt Works

NullID generates a random salt for each password hash record. The salt is stored in the record on purpose.

Salt does two important things:

1. Two identical passwords should produce different stored records.
2. Attackers cannot reuse one precomputed digest table for every account.

The salt is not a secret. The security comes from combining that salt with a slow password KDF and the password itself.

## How Verification Works

Verification is recomputation, not decryption:

1. Read the stored record.
2. Parse the algorithm, salt, and cost settings from the record.
3. Recompute the derived hash from the candidate password.
4. Compare the recomputed bytes to the stored bytes.

If they match, the password is correct. If they do not match, the password is wrong.

## Choosing `Argon2id` vs `PBKDF2-SHA256`

Choose `Argon2id` when:

- the browser/runtime supports it
- you want the preferred option for new password storage
- you want a memory-hard KDF

Choose `PBKDF2-SHA256` when:

- the runtime does not support `Argon2id`
- you need the compatibility fallback across older browsers/runtimes
- you are integrating with an environment that already expects PBKDF2-style records

Choose legacy `SHA-256` / `SHA-512` only when:

- you are migrating older records
- you need to reproduce a legacy verifier format before replacing it

Do not choose fast SHA digests for new password storage records.

## Runtime Support

`Argon2id` availability is runtime-dependent.

- In the browser UI, NullID detects support and shows a warning when the current runtime cannot generate or verify `Argon2id` records.
- In the CLI, `pw-hash` / `pw-verify` attempt to use the runtime's WebCrypto `Argon2id` support. If it is unavailable, the command fails clearly and `PBKDF2-SHA256` remains available.

Because of that variability, `PBKDF2-SHA256` is documented as the compatibility fallback.

## Record Format and Interoperability

NullID emits self-contained text records.

Examples:

```text
$argon2id$v=19$m=65536,t=3,p=1$<salt>$<digest>
$pbkdf2-sha256$i=600000$<salt>$<digest>
$sha512$s=<salt>$<digest>
```

Notes:

- NullID emits URL-safe base64 fields without padding.
- The parser accepts both URL-safe and standard base64 field encodings when importing/verifying records.
- Imported records are only accepted when their salt length, digest length, and cost parameters stay within NullID's supported bounds. NullID rejects malformed or resource-heavy records instead of guessing through them.
- `Argon2id` output is PHC-like, but NullID does not promise that every external Argon2/PHC consumer will accept the record unchanged.
- `PBKDF2-SHA256` and legacy SHA records are NullID-defined formats and should be treated as NullID-specific unless you deliberately add matching parser support elsewhere.

If you need interoperability with another password system, verify that system's exact record syntax before assuming the strings are drop-in compatible.

## What To Store

Store the full record string.

In the browser UI, paste that full record back into the `Password hash record` field when you verify later. In the CLI, pass it with `--record`, `--record-file`, or `--record-stdin`.

Do not store only:

- the digest
- the salt
- the algorithm name

You need the entire record so the verifier has the algorithm, salt, and cost settings required to recompute the same value later.

## CLI Examples

Prefer environment variables or stdin over inline shell arguments when password exposure in shell history matters.

Generate a PBKDF2 record:

```bash
NULLID_PASSWORD='correct horse battery staple' npm run cli -- pw-hash --password-env NULLID_PASSWORD --algo pbkdf2-sha256
```

Generate an Argon2id record when supported:

```bash
NULLID_PASSWORD='correct horse battery staple' npm run cli -- pw-hash --password-env NULLID_PASSWORD --algo argon2id
```

Verify a stored record:

```bash
NULLID_PASSWORD='correct horse battery staple' npm run cli -- pw-verify --record '$pbkdf2-sha256$i=600000$...' --password-env NULLID_PASSWORD
```

## Practical Guidance

- Use `Hash & Verify` / CLI `hash` for artifact integrity, not password storage.
- Use `Password Storage Hashing` / CLI `pw-hash` + `pw-verify` for login/verifier workflows.
- Use `Encrypt / Decrypt`, `Secure Notes`, or CLI `enc` / `dec` for reversible secrecy.
