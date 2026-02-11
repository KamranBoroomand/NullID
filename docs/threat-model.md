# NullID Threat Model (Working Draft)

## Scope
- NullID browser app (React + WebCrypto + IndexedDB/localStorage).
- NullID local CLI (`scripts/nullid-local.mjs`).
- Build/release artifact generation (`dist`, `SHA256SUMS`, manifest, SBOM).

## Security Objectives
- Keep sensitive processing local to user-controlled runtime.
- Prevent accidental leakage through network calls.
- Preserve integrity of encrypted and exported artifacts.
- Maintain deterministic build integrity for release verification.

## Assets
- Plaintext user inputs (logs, notes, files, secrets).
- Encryption passphrases and derived keys.
- Vault note ciphertext + metadata.
- Policy packs and safe-share bundles.
- Build artifacts and checksums.

## Trust Boundaries
- Browser sandbox and storage APIs.
- Local filesystem for CLI inputs/outputs.
- Clipboard integration (best effort hygiene only).
- Build pipeline and CI runner environment.

## Threats and Controls
1. Passive network exfiltration from runtime code.
- Control: offline policy lint scans for disallowed network primitives in `src/`.

2. Envelope tamper or corruption.
- Control: AES-GCM authenticated encryption with AAD-bound envelope format (`NULLID:ENC:1`).

3. Weak passphrase/KDF choices.
- Control: default PBKDF2 profile plus stronger selectable profiles (`strong`, `paranoid`), explicit user-controlled tradeoff.

4. Data residue in clipboard/state.
- Control: clipboard auto-clear and in-app auto-clear timers (best effort).

5. Build artifact substitution.
- Control: deterministic manifest + `SHA256SUMS` verification and matrix reproducibility checks.

6. Dependency visibility gaps.
- Control: deterministic lockfile-derived SBOM in `dist/sbom.json`.

## Out of Scope
- Memory extraction from compromised host OS.
- Malicious browser extensions or compromised local user account.
- Formal cryptographic certification claims.

## Residual Risks
- Clipboard history managers may retain copies.
- PBKDF2 remains CPU-hard but not memory-hard; high-risk deployments may require additional controls.
- Browser codec/parser behavior varies by platform and may reject or transform edge media.

## Next Hardening Steps
- Keep release signing + provenance workflow healthy (`.github/workflows/release-signed.yml`).
- Maintain adversarial regression corpus coverage as formats/rules expand.
- Require `docs/release-security-checklist.md` completion before release tag publication.
