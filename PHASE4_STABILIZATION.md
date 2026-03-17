# Phase 4 Stabilization

Date: 2026-03-16

## Scope

Phase 4 focused on architectural cleanup and regression hardening rather than new features. The goals were to reduce future drift, make vault storage boundaries easier to reason about, add high-signal compatibility tests, and rerun the visual baseline work that earlier phases deferred.

## Refactors Completed

- Added [`src/utils/snapshotIntegrity.ts`](./src/utils/snapshotIntegrity.ts) as the shared helper for:
  - canonical payload hashing via the existing stable serializer
  - HMAC generation and verification
  - algorithm labeling (`HMAC-SHA-256`)
  - key-hint normalization
  - integrity/signature error classification
- Refactored:
  - [`src/utils/profile.ts`](./src/utils/profile.ts)
  - [`src/utils/policyPack.ts`](./src/utils/policyPack.ts)
  - [`src/utils/vault.ts`](./src/utils/vault.ts)
  so profile, policy-pack, and vault snapshot flows all use the shared helper.
- Added [`src/utils/vaultStorageKeys.ts`](./src/utils/vaultStorageKeys.ts) to centralize vault localStorage key construction and legacy/new namespace recognition.
- Extended [`src/hooks/usePersistentState.ts`](./src/hooks/usePersistentState.ts) with low-risk legacy-key migration support so vault preferences can move cleanly without a larger state-management rewrite.

## Storage Namespace Changes

- Vault preferences/settings now live under:
  - `nullid:vault:pref:*`
- localStorage fallback vault records now live under:
  - `nullid:vault:data:notes:*`
  - `nullid:vault:data:meta:*`
  - `nullid:vault:data:canary:*`
  - `nullid:vault:data:selftest:*`
- Legacy fallback data keys under `nullid:vault:{store}:*` remain readable for compatibility and are migrated locally on access.

## Migration Notes

- Vault preference keys are migrated on first read/write through the persistent-state helper.
- localStorage fallback data is migrated opportunistically:
  - `getValue(...)` and `getAllValues(...)` read the new namespace first
  - if only a legacy fallback key exists, the record is rewritten into `nullid:vault:data:*`
  - legacy fallback keys are removed after successful migration
- Profile export/import excludes both:
  - the new fallback namespace
  - older legacy fallback records that may still exist before migration
- Legacy profile snapshots and legacy vault snapshots remain importable.

## Tests Added

- [`src/__tests__/snapshotIntegrity.test.ts`](./src/__tests__/snapshotIntegrity.test.ts)
  - verifies deterministic/canonical integrity packs for profile, policy, and vault payload shapes
  - verifies integrity/verification error classification
- [`src/__tests__/vaultStorageNamespaces.test.ts`](./src/__tests__/vaultStorageNamespaces.test.ts)
  - verifies vault preference migration into `pref:`
  - verifies fallback blob migration into `data:`
  - verifies profile snapshots exclude fallback storage in both legacy and new namespaces
  - verifies namespace classification stays aligned
- Existing profile/policy/vault tests continue to validate end-to-end signing/import compatibility.

## Visual Review

- Ran the desktop visual suite with [`tests/e2e/visual-regression.spec.ts`](./tests/e2e/visual-regression.spec.ts).
- Ran the mobile visual snapshots in [`tests/e2e/app.spec.ts`](./tests/e2e/app.spec.ts).
- Only vault snapshots changed intentionally:
  - [`tests/e2e/visual-regression.spec.ts-snapshots/desktop-vault-light-darwin.png`](./tests/e2e/visual-regression.spec.ts-snapshots/desktop-vault-light-darwin.png)
  - [`tests/e2e/visual-regression.spec.ts-snapshots/desktop-vault-dark-darwin.png`](./tests/e2e/visual-regression.spec.ts-snapshots/desktop-vault-dark-darwin.png)
  - [`tests/e2e/app.spec.ts-snapshots/mobile-vault-darwin.png`](./tests/e2e/app.spec.ts-snapshots/mobile-vault-darwin.png)
- The snapshot drift matched the intentional vault trust/MFA copy tightening rather than a layout accident, so those baselines were refreshed.

## Localization Cleanup

- Localized the highest-signal trust-sensitive copy added or tightened during recent phases:
  - vault HMAC export/import explanations
  - vault session-cookie explanation
  - vault MFA boundary/back-up warning
  - policy-pack verification prompts
  - self-test overview copy
- This was intentionally scoped; broader operational/toast-string coverage is still incomplete.

## Compatibility Considerations

- Snapshot HMAC format is unchanged:
  - same payload hashing inputs
  - same `HMAC-SHA-256` label
  - same signature field shape
- Stored user data remains backward-compatible where practical:
  - legacy fallback vault keys still load
  - legacy profile and vault payloads still import
  - profile import still ignores vault fallback storage classes rather than widening scope
- Phase 4 does not add stronger guarantees than the app enforces:
  - HMAC metadata still provides shared-secret integrity/authenticity checking, not identity signing
  - Self-test remains a local runtime probe, not deployment verification
  - WebAuthn MFA remains local/browser-device-bound only

## Remaining Risks

- Browser and CLI password-hash logic still do not share one executable module.
- Some older runtime strings remain English-only outside the touched trust-sensitive surfaces.
- Self-test still cannot authoritatively verify deployed host/edge response headers.

## Recommended Future Work

1. Build a shared browser/CLI password-hash runtime module to remove the remaining executable drift seam.
2. Continue the localization pass on older vault/session/self-test toasts and operational errors.
3. If product scope grows, split Self-test into local-runtime checks versus deployment/header verification.
4. Keep the new snapshot-integrity and namespace tests in CI as permanent guardrails against format/storage drift.

## Validation Performed

- `npm run i18n:check`
- `npm run typecheck`
- `npm test`
- `npm run test:visual`
- `env PW_REUSE_SERVER=1 npx playwright test tests/e2e/app.spec.ts -g "mobile visual snapshot"`
