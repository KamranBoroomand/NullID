# NullID Audit

Date: 2026-03-16

## Summary

Phases 1-3 addressed the largest trust, parsing, and product-scope mismatches across password hashing, vault handling, import validation, and user-facing guarantees.

Phase 4 finished the narrow architectural cleanup that remained:

- centralized profile/policy/vault snapshot HMAC logic behind one shared helper
- split vault localStorage namespaces into explicit preference and fallback-data prefixes with migration coverage
- reran the desktop and mobile visual snapshot suites, refreshing only the intentional vault baselines
- localized the most trust-sensitive vault/policy/self-test copy added or tightened during the audit

NullID is now materially less drift-prone in its snapshot integrity flows and easier to reason about in localStorage. The main remaining risks are older raw English runtime strings outside the touched surfaces, the still-separate browser/CLI password-hash executable logic, and Self-test’s intentionally limited ability to comment on deployed host/edge security.

## Critical Issues

### C1. Trust-sensitive UI and docs were stronger than the implementation in a few key places

Impact:
Users could overestimate what some protections actually mean, especially around session cookies, WebAuthn MFA, Self-test, and "signed" exports.

Status:
Fixed for the audited surfaces.

What changed:

- Clarified that in-app session-cookie signaling is a browser-visible presence hint, not a server-side auth boundary.
- Clarified that WebAuthn MFA is a local/device-bound unlock step, not an account or recovery system.
- Clarified that NullID "signed" profile/policy/vault exports are shared-passphrase HMAC metadata checks, not public-key identity signatures.
- Clarified that Self-test is a local runtime diagnostic, not a security certification, and that its runtime score is not a security rating.
- Added localization coverage for the highest-signal vault/policy/self-test trust copy so those clarifications are not English-only.

### C2. Profile export/import scope mismatched the documented behavior

Impact:
When the vault fell back to localStorage, profile snapshots could include vault blobs and vault-store metadata even though the docs described profiles as preferences-only snapshots.

Status:
Fixed, with namespace cleanup completed in phase 4.

What changed:

- Profile export/import excludes legacy fallback vault records under `nullid:vault:{store}:*`.
- Profile export/import also excludes the new fallback vault namespace under `nullid:vault:data:{store}:*`.
- Vault preferences now live under `nullid:vault:pref:*`, making the separation between settings and fallback data explicit.
- README and Guide text now reflect the new namespace split and legacy-migration behavior.

### C3. Imported vault snapshots and encrypted envelopes did not validate enough before use

Impact:
Malformed or hostile imports could reach later runtime failures, and oversized KDF settings could be accepted too deep into the flow.

Status:
Fixed for the reviewed paths.

What changed:

- Added shared strict base64/base64url decoding for imported crypto fields.
- Vault snapshot import validates salt encoding/length, iteration upper bounds, AES-GCM IV length, and ciphertext encoding/length before use.
- Encrypted envelope parsing rejects invalid KDF iterations, unsupported hash labels, invalid salt/IV encodings, and malformed ciphertext before attempting decrypt.

## Medium Issues

### M1. Shared-passphrase HMAC export logic could drift across product areas

Impact:
Profiles, policy packs, and vault snapshots all used similar integrity/signature metadata rules. Parallel implementations invited format and validation drift.

Status:
Fixed in phase 4.

What changed:

- Added [`src/utils/snapshotIntegrity.ts`](./src/utils/snapshotIntegrity.ts) as the shared snapshot helper for canonical hashing, HMAC generation/verification, algorithm labeling, key-hint normalization, and error classification.
- Refactored profile, policy-pack, and vault export/import flows to use that shared helper while preserving the existing `HMAC-SHA-256` metadata format.
- Added helper-level regression tests plus end-to-end profile/policy/vault integrity tests to prove the shared path stays deterministic.

### M2. Vault fallback storage shared a confusing root namespace with vault preferences

Impact:
The old `nullid:vault:*` model mixed preferences with localStorage fallback records, which made export-scope reasoning and maintenance harder than necessary.

Status:
Fixed in phase 4.

What changed:

- Added [`src/utils/vaultStorageKeys.ts`](./src/utils/vaultStorageKeys.ts) to define explicit `nullid:vault:pref:*` and `nullid:vault:data:{store}:*` namespaces.
- Added migration-aware localStorage reads/writes so legacy fallback records under `nullid:vault:{store}:*` continue to load and are rewritten into the new `data:` namespace.
- Added migration-aware persistent-state support so existing vault preferences move into `pref:` keys without user intervention.
- Added namespace tests to verify migration, exclusion from profile snapshots, and key classification.

### M3. Self-test remains intentionally limited to local runtime observation

Impact:
The Self-test panel can help diagnose local capability problems, but it still cannot prove deployed headers, origin policy, or external hosting guarantees.

Status:
Clarified, not expanded.

What changed:

- Kept the CSP/referrer probe scoped to page-visible markers.
- Kept in-view and guide disclaimers aligned with that limitation.

## Low-Priority Issues

### L1. Browser and CLI still do not share one full executable security-logic layer

Impact:
Password-hash drift risk is lower than before, but browser and CLI implementations are still parallel at the executable level.

Status:
Partially mitigated.

### L2. Full visual regression coverage had not been rerun after trust-copy changes

Impact:
Copy changes in Vault and adjacent trust flows could have introduced unnoticed UI regressions.

Status:
Fixed in phase 4.

What changed:

- Ran the desktop visual suite.
- Ran the mobile visual snapshot checks.
- Refreshed only the intentional vault baselines after reviewing the changed copy surfaces.

### L3. Some older runtime strings still bypass localization

Impact:
The highest-risk trust copy is now covered more consistently, but older operational/toast strings remain English-only in parts of the app.

Status:
Improved, not complete.

## What Was Fixed

- Added a shared snapshot integrity helper for canonical hashing, HMAC signing, verification, algorithm labeling, key-hint normalization, and error classification.
- Refactored profile, policy-pack, and vault snapshot export/import paths to use the shared helper without changing the wire format.
- Split vault preference keys into `nullid:vault:pref:*`.
- Split localStorage fallback vault data into `nullid:vault:data:{store}:*`.
- Added transparent migration for legacy preference keys and legacy fallback vault records.
- Updated profile export/import filtering so both legacy and new fallback vault storage classes are excluded.
- Localized trust-sensitive vault, policy, and self-test copy introduced or tightened during recent phases.
- Updated README and Guide text to reflect the new namespace split and legacy migration behavior.
- Added deterministic helper tests and namespace migration tests.
- Reran the visual regression suites and refreshed only the intentional vault snapshots.

## What Remains

- Browser and CLI password-hash logic still share spec/tests more than executable code.
- Older non-critical runtime strings and some operational toasts remain English-only.
- Self-test still cannot authoritatively verify deployed headers or hosting controls from the current local-only model.

## Recommendations

1. Build a truly shared browser/CLI password-hash runtime module so drift protection no longer depends primarily on spec/tests.
2. Continue the localization pass on older operational strings, especially toasts and error messages around vault/session/self-test flows.
3. If product scope expands, separate Self-test into local runtime probes versus deployment/header verification.
4. Keep the new snapshot-integrity and storage-namespace tests green in CI; they are the main low-maintenance guardrails against regression here.

## Validation Performed

- `npm run i18n:check`
- `npm run typecheck`
- `npm test`
- `npm run test:visual`
- `env PW_REUSE_SERVER=1 npx playwright test tests/e2e/app.spec.ts -g "mobile visual snapshot"`
