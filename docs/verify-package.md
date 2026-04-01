# Verify Package

`Verify Package` is NullID's first receiver-side verification flow. It opens supported local artifacts and explains, in plain terms, what NullID checked, what trust basis was available, and what remains unproven.

## Supported Artifact Types

This step supports:

- `nullid-workflow-package`
- `nullid-safe-share` bundles
- `sanitize-policy-pack`
- profile snapshots
- vault snapshots
- `NULLID:ENC:1` envelopes as inspectable containers, with optional local decryption

That means current Safe Share Assistant exports and sanitize compatibility bundles both land in the same receiver flow.
Incident Workflow exports also land in the same receiver flow because they use the same shared workflow package contract.

## App Workflow

In the app:

1. Open `Verify Package`.
2. Paste a JSON artifact or `NULLID:ENC:1` envelope, or load a local file.
3. If the artifact is encrypted, provide the envelope passphrase to inspect the inner payload.
4. If the artifact carries shared-secret HMAC metadata for verification-aware flows such as policy/profile/vault snapshots, provide the verification passphrase to check that claim.
5. Review:
   - artifact type
   - verification result
   - trust basis
   - package-declared workflow metadata such as purpose, audience, included artifacts, preserved context, and receiver-verification limits when present
   - verified checks
   - not verified checks
   - warnings and limitations
   - included artifacts and any descriptive transform/policy metadata when present

For schema-2 `nullid-safe-share` bundles, the app now makes it explicit that verification is based on the embedded workflow package. Duplicated outer wrapper fields are not automatically trusted.

All verification stays local. NullID does not upload the artifact or call a backend.

## CLI Workflow

Use `package-inspect`:

```bash
npm run cli -- package-inspect ./received-artifact.json
npm run cli -- package-inspect ./received-artifact.nullid --pass-env NULLID_PASSPHRASE
npm run cli -- package-inspect ./signed-policy.json --verify-pass-env NULLID_VERIFY_PASSPHRASE
```

The CLI prints structured JSON describing:

- artifact type
- verification state
- trust basis
- verified and unverified checks
- warnings and failures
- included artifacts, summary facts, and any package-declared workflow metadata the verifier exposes separately from integrity-checked results

## Trust Labels

NullID keeps these labels intentionally conservative.

- `Unsigned`: the artifact structure was understood, but there is no signature or shared-secret verification proving who produced it.
- `Integrity checked`: NullID verified self-consistency, such as payload hashes, manifest counts, or embedded integrity metadata. This detects some tampering, but it still does not prove sender identity.
- For workflow packages and schema-2 safe-share bundles, `Integrity checked` refers to manifest/hash self-consistency for the embedded workflow package artifacts, not to package-level signatures or authenticated top-level metadata.
- `HMAC verified`: a shared-secret HMAC check succeeded. This proves tamper detection for parties that already share the same secret. It does not provide public-key identity or independent proof of who sent the package.
- `Verification required`: the artifact includes shared-secret verification metadata, but NullID needs the verification passphrase before it can check that claim.
- `Mismatch`: integrity metadata or shared-secret verification did not match. The artifact may be incomplete, tampered, corrupted, or paired with the wrong secret.
- `Invalid`: NullID recognized the artifact family, but the structure or metadata was not valid enough to trust.
- `Malformed`: the input could not be parsed as supported JSON or as a `NULLID:ENC:1` envelope.
- `Unsupported`: the payload decoded successfully, but it is not one of the artifact types this verification surface currently understands.

## What NullID Can Prove

NullID can currently prove or check:

- local parsing and schema recognition
- embedded integrity metadata consistency
- manifest self-consistency for included artifacts
- successful shared-secret HMAC verification when the receiver already knows the secret
- envelope metadata parsing without decryption
- envelope decryption success when the passphrase is provided
- for schema-2 safe-share bundles, that verification is being derived from the embedded workflow package rather than the duplicated outer wrapper fields
- that a package carries workflow metadata when the producer recorded it

## What NullID Cannot Prove

NullID does not currently prove:

- public-key sender identity
- package-level workflow signatures, because the workflow contract does not currently carry a verifiable signature payload
- that top-level workflow metadata such as summary/report/policy/preset/warnings/limitations is authenticated, unless that same content is also represented inside hashed artifacts
- that duplicated schema-2 safe-share outer wrapper fields match the embedded workflow package
- that the inner workflow JSON was encrypted; only an outer `NULLID:ENC:1` envelope proves encrypted file transport
- third-party timestamp authority
- that omitted or referenced files are safe, complete, or unchanged
- that sanitized output is appropriate for every downstream recipient or policy context
- trust beyond what the artifact's local metadata and provided shared secrets can justify

## UI vs CLI

The app and CLI use the same underlying trust semantics.

- The app is better for interactive inspection of facts, warnings, transforms, and included entries.
- The CLI is better for automation, scripting, and local handoff checks in terminal workflows.
- Both stay offline and local-first.
- Both distinguish unsigned, integrity-checked, shared-secret verified, mismatch, invalid, malformed, and unsupported states.
