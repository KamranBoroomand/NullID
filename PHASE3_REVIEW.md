# Phase 3 Review

Date: 2026-03-16

Follow-up:
Phase 4 addressed the main architectural follow-ups from this review: shared snapshot HMAC logic is now centralized, vault localStorage namespaces are split with migration coverage, and the visual vault baselines were rerun intentionally. See [`PHASE4_STABILIZATION.md`](./PHASE4_STABILIZATION.md).

## Audited Areas

- Vault encryption, note storage, snapshot export/import, and localStorage fallback behavior
- Encrypted envelope parsing/import validation
- Locking/session behavior, idle timer semantics, panic lock messaging, and session-cookie signaling
- WebAuthn MFA setup/verification assumptions and recovery boundaries
- Profile export/import scope and interaction with vault fallback storage
- Self-test claims, runtime diagnostics wording, and exported-report semantics
- Guide/README/help consistency for trust-sensitive features
- Cross-runtime/shared security-logic cleanup opportunities

## Confirmed Strengths

- Core product direction remains consistent: local-first, browser-native, no runtime network dependency for core workflows.
- Vault note contents are still encrypted with AES-GCM and only decrypted after unlock.
- The app already had good defensive foundations in place: canary verification, unlock hardening controls, panic lock, export integrity metadata, and explicit fallback detection.
- Phase 1 and 2 work on password-storage hashing held up well and gave phase 3 a solid baseline for format-validation hardening.

## Critical Issues

### C1. Profile snapshots could accidentally include fallback vault data

Status:
Fixed.

Details:

- `collectProfile()` previously swept up all `nullid:*` localStorage keys.
- When the vault was using localStorage fallback, that included `nullid:vault:{store}:*` records that behave like the vault database, not preferences.
- This contradicted the product explanation and made profile snapshots broader than users were told.

Applied fix:

- Excluded fallback vault-store keys on both profile export and profile import.
- Added tests to prevent that scope bug from returning.

### C2. Vault/envelope import validation allowed too much malformed metadata through

Status:
Fixed.

Details:

- Vault snapshot normalization previously only checked a few string lengths and a low minimum iteration count.
- Encrypted envelope decrypt previously clamped imported KDF iterations instead of rejecting out-of-range values explicitly.
- Both behaviors made malformed or hostile imports fail later than necessary.

Applied fix:

- Added strict decode validation for imported salts, IVs, and ciphertext.
- Added explicit iteration upper-bound checks and unsupported-hash rejection.
- Added regression tests for malformed records and imported envelopes.

### C3. Several trust-facing phrases could create false confidence

Status:
Mostly fixed.

Details:

- "Signed" export language read like identity signing, but the implementation uses shared-passphrase HMAC metadata.
- Session-cookie wording did not make it clear enough that the cookie is browser-visible and not an auth boundary.
- WebAuthn MFA wording did not say clearly enough that the feature is local/device-bound and not a recovery path.
- Self-test wording risked sounding like a security assessment rather than a runtime diagnostic.

Applied fix:

- Tightened README, guide, profile dialog, vault dialog, and Self-test copy.
- Added explicit HMAC, session-hint, and recovery-boundary explanations.

## Medium Issues

### M1. HMAC export/import behavior is still duplicated

- Profiles, vault snapshots, and policy packs each carry their own payload hashing, metadata validation, and verification flow.
- The semantics are now explained more consistently than before, but the implementations are still separate.

### M2. Vault fallback storage still shares a root namespace with vault preferences

- The bug from C1 is fixed, but the namespace design still makes confusion easier than it should be.
- This is now a documented architectural risk rather than a silent behavior mismatch.

### M3. Self-test still cannot prove deployed host/edge security headers

- The UI/docs now say this clearly.
- The current behavior is fine as long as it stays described as a local page/runtime diagnostic.

## Low Issues

### L1. Some runtime strings are still not localized

- Phase 3 covered the new trust-sensitive phrases it introduced.
- Older raw English strings remain in surrounding operational copy.

### L2. Full visual regression was not rerun

- Focused Playwright behavior checks passed.
- The broader visual matrix still needs a deliberate rerun if these UI copy changes are accepted.

## Fixes Applied In This Phase

- Added shared strict base64/base64url decode validation and reused it across security-sensitive parsers.
- Hardened envelope parsing to reject invalid imported KDF and AES-GCM metadata explicitly.
- Hardened vault snapshot import and vault-meta normalization.
- Excluded fallback vault-store records from profile export/import.
- Clarified session-cookie, HMAC-signing, WebAuthn MFA, localStorage fallback, and Self-test semantics in UI/help/docs.
- Added guide-coverage regression tests and a focused Self-test Playwright regression.

## Unresolved Risks

- Shared-passphrase HMAC logic remains parallel across profile, vault, and policy-pack code.
- The `nullid:vault:*` prefix still carries both preferences and fallback data.
- WebAuthn remains minimal local gating only; any future product messaging must keep that boundary explicit.
- Self-test still cannot assert real host/edge response headers from within the current client-only model.

## Recommended Next Refactors

1. Extract a common HMAC snapshot helper for profile, vault, and policy-pack export/import paths.
2. Split vault preference keys from fallback-store keys at the storage-prefix level.
3. Consider a shared trust-copy/constants layer for security-sensitive warnings that currently live in multiple UI modules.
4. If product scope grows, separate Self-test into local-runtime probes versus deployment verification.

## Recommended Future Tests

1. Add unit coverage for encrypted vault import failure paths that combine invalid envelope metadata with otherwise valid vault JSON.
2. Add browser tests around vault export dialogs that check the HMAC/session/MFA explanatory copy remains present.
3. Add tests for profile import/export compatibility when localStorage already contains both vault preferences and fallback store records.
4. Run the full Playwright visual suite and refresh only approved snapshots for Vault and Self-test.
