# Hardening Notes

Date: 2026-03-16

## Architectural Risks

- Password storage hashing still has two runtime implementations: browser TypeScript in [`src/utils/passwordHashing.ts`](./src/utils/passwordHashing.ts) and Node CLI logic in [`scripts/nullid-local.mjs`](./scripts/nullid-local.mjs). Phase 2 added a shared spec file plus drift tests, but the executable logic is still duplicated.
- The current split exists partly because the browser app, Node CLI, and `build-test/` compile path do not share a clean cross-runtime source module yet. A true shared module will likely require either:
  - a shared JS runtime module plus TypeScript declarations
  - or a small build step that emits both browser- and CLI-consumable artifacts

## Drift Risks

- Warning strings, bounds, and record formats are now constrained by [`src/utils/passwordHashingSpec.json`](./src/utils/passwordHashingSpec.json), but only the CLI consumes that file directly today.
- The browser utility is protected by tests that compare exported limits/messages to the shared spec, but a future change can still bypass that if tests are not kept green in CI.
- README, built-in guide, and CLI help now describe the same `pw-hash` / `pw-verify` scope, but there is no automated repo check that enforces that alignment.

## Test Gaps

- Full visual regression was not rerun after the password-hash panel copy/field behavior change.
- Argon2id availability is runtime-dependent, so CI coverage still depends on what the host runtime exposes. The repo handles both supported and unsupported paths, but not every environment will exercise both.
- There is still no end-to-end coverage for importing external non-NullID password-hash records beyond the current accepted formats and bounds.

## Documentation Gaps

- Third-party interoperability remains intentionally conservative. The docs now say "PHC-like" for Argon2id and "NullID-defined" for PBKDF2/legacy SHA, but there is still no import/export compatibility matrix.
- Older runtime strings in some modules remain English-only or inconsistently localized. Phase 2 covered the new password-hash strings and new guide phrases, not the entire app surface.
- `Self-test` now has guide coverage, but its own in-view explanatory copy is still more implementation-oriented than the rest of the app.

## Generated Output Notes

- `build-test/` is a tracked generated tree. `npm test` recompiles TypeScript sources/tests into that directory before running Node tests.
- The `build-test` changes in this phase are intentional because they mirror source/test changes that were validated locally.

## Recommended Next Refactors

1. Build a single cross-runtime password-hash module or generation flow so browser and CLI stop carrying parallel parser/formatter logic.
2. Add a docs/help consistency script that checks README command lists, CLI help text, and guide coverage for core modules.
3. Add one or two compatibility fixtures for clearly documented imported-record cases so future interoperability decisions happen intentionally.
4. Run the full visual regression suite and refresh snapshots only after product approval of the password-hash panel updates.
