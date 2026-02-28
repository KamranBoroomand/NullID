# NullID Release Readiness

Last updated: 2026-02-28

This document tracks what is already at release-candidate quality and what is still missing before a production GA cut.

## Current Baseline (Done)

- Design and UX:
  - Destructive wipe flow now requires explicit confirmation (`WIPE`) and shows backup/export guidance.
  - Redaction preview style token mismatch fixed (`--border-subtle`).
  - Testimonial-style guide copy removed and replaced with operational guidance.
- Data and detection coverage:
  - Added built-in sanitization/redaction for GitHub tokens, Slack tokens, and private key blocks.
  - Synced browser + CLI rule coverage and policy defaults (`nullid.policy.json`).
  - Added regression tests for new token/key-block masking.
- Docs and project information:
  - Added `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`.
  - Added GitHub issue templates and PR template.
  - README updated for current scripts, release references, and governance links.
- Internationalization:
  - Added missing FA/RU strings for new and high-impact UI text.
  - Added `npm run i18n:check` and integrated it into CI/workflows.
- Security and release checks:
  - Replaced regex-only offline-policy lint with AST-based source scanning.
  - Hardened security-header audit to strict directive/value checks.
  - Visual snapshots updated for intentional UI changes.

## Quality Gate Status

Latest local validation run (`npm run validate`) passed end-to-end on 2026-02-28:

- `typecheck` passed
- `i18n:check` passed
- `lint` passed
- `test` passed (62/62)
- `e2e` passed (18/18)
- `build` passed
- `verify:build` passed

## Remaining Gaps Before Production GA

These are the highest-value missing items that should still be completed for full production readiness.

### P0 (Release-Blocking)

- Final host validation:
  - Verify real deployed headers/CSP on the production domain, not only local/static config checks.
- Release key operations runbook:
  - Document exact signing-key custody, rotation, revocation, and emergency replacement procedures.
- Disaster recovery drill:
  - Execute and document at least one full restore drill for signed profile/policy/vault export flows.

### P1 (Should Complete Before Wide Adoption)

- Accessibility hardening:
  - Run and fix full keyboard/screen-reader audit across all modules.
- Browser/device coverage:
  - Add explicit support matrix and smoke verification for target browsers/OS versions.
- Localization QA:
  - Native-language review pass for RU/FA copy quality and line-break/layout polish.
- Operational support policy:
  - Define triage labels, severity levels, and target response windows in issue workflow docs.

### P2 (Post-GA Hardening)

- Formal compatibility policy:
  - Publish deprecation/compatibility guarantees for envelope/profile/policy schemas.
- Performance budgets:
  - Add explicit bundle-size and startup-performance budgets with CI enforcement.
- Privacy documentation:
  - Add a dedicated privacy statement clarifying zero-runtime-network behavior and local storage boundaries.

## Category Scorecard

- Design: RC quality, with remaining accessibility/browser polish.
- Data coverage: Strong baseline, now includes major token/key-block classes.
- Guides and information: Good baseline, needs production ops runbooks and support policy detail.
- README: Release-ready baseline with script and governance alignment.
- Options and features: Broad and coherent; next priority is operational hardening rather than feature breadth.

