# NullID Threat Model

## Scope

- Browser app: React, WebCrypto, IndexedDB/localStorage, service worker, and static assets.
- Local CLI: `scripts/nullid-local.mjs` for supported offline automation workflows.
- Build and release outputs: `dist/`, `deploy-manifest.json`, `SHA256SUMS`, CycloneDX SBOM, and release archive packaging.
- Optional experimental desktop packaging bootstrap under `desktop/tauri/`; no supported native desktop distribution is currently shipped.

## Security Objectives

- Keep sensitive processing local to user-controlled runtime.
- Prevent accidental runtime network exfiltration.
- Preserve confidentiality and integrity of encrypted artifacts and vault data.
- Make import/verification behavior fail closed for malformed or tampered artifacts.
- Keep release artifacts reproducible enough to verify with manifests, checksums, and SBOM data.

## Assets

- Plaintext user inputs: logs, snippets, notes, files, passwords, passphrases, and metadata.
- Derived encryption keys, KDF salts, IVs, and vault canary data.
- Vault ciphertext and non-secret vault record metadata.
- Policy packs, profile snapshots, vault snapshots, safe-share bundles, workflow packages, and release artifacts.
- Dependency and build metadata used for release verification.

## Trust Boundaries

- Browser sandbox, service worker cache, clipboard, localStorage, IndexedDB, and WebAuthn APIs.
- Local filesystem inputs and outputs used by the CLI.
- Static hosting layer that serves security headers and deployment paths.
- CI and local release environments that run dependency install, build, signing, and packaging commands.

## Threats And Controls

1. Runtime network exfiltration.
   - Control: `npm run lint:network` scans runtime source and public assets for disallowed network primitives and external URL usage.

2. Envelope tamper or metadata substitution.
   - Control: new exports use `NULLID:ENC:2`, AES-GCM, PBKDF2, strict Base64URL parsing, and AAD over canonicalized header metadata. Legacy `NULLID:ENC:1` envelopes remain decryptable, but their filename/MIME metadata is treated as unauthenticated.

3. Weak passphrase or KDF choices.
   - Control: profile-driven KDF settings (`compat`, `strong`, `paranoid`), explicit iteration bounds, and weak-choice warnings. Password storage hashing prefers Argon2id when available and uses PBKDF2-SHA256 as the compatibility fallback.

4. Malformed import or storage records.
   - Control: strict canonical JSON, fixed digest/signature lengths, bounded file/text input helpers, conservative storage parsing, and tests for corrupt fallback vault records.
   - Vault note imports accept canonical note version 3 and snapshot schema 2 only. Unsupported v1, v2, unversioned, schema-less, and obsolete fallback-key vault data is ignored during normal reads and imports.

5. Data residue in clipboard or local state.
   - Control: best-effort clipboard auto-clear, in-app auto-clear timers, local vault lock behavior, and explicit warnings about localStorage fallback visibility.

6. Vault unlock brute force.
   - Control: optional local rate limiting, human-check challenges after repeated failures, and optional local WebAuthn MFA after passphrase validation.

7. Build or release artifact substitution.
   - Control: deterministic build metadata, `deploy-manifest.json`, `SHA256SUMS`, CycloneDX SBOM, release archive verification, release checksums, and reproducibility checks.

8. Dependency visibility gaps.
   - Control: lockfile-based `npm ci`, `npm audit --audit-level=high`, and CycloneDX SBOM generation in `dist/sbom.json`.

## Out Of Scope

- Memory extraction, malware, malicious browser extensions, or compromised local accounts.
- Public-key identity for workflow packages.
- Server-side session enforcement in the static app.
- Formal cryptographic certification or third-party security audit claims.

## Residual Risks

- Clipboard history managers may retain copied values outside NullID control.
- PBKDF2 is CPU-hard, not memory-hard; high-risk deployments may require additional controls.
- Static hosts differ in header support; the real deployed host must be verified separately.
- Browser media parsers and WebCrypto capabilities vary by runtime.
- Local WebAuthn MFA is device-bound and not a recovery system.

## Required Release Checks

- Keep this document aligned with behavior before release approval.
- Run the validation matrix in `docs/release-readiness.md`.
- Verify release archive contents and checksums with `npm run release:verify`.
- Record any skipped or external-only deployment checks in the release evidence.
