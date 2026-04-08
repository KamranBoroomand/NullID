# NullID Release Readiness

Last updated: 2026-04-08

This document separates what is now complete inside the repository from the external operator work that still must happen before NullID should be called generally available.

## 1. Repo-Side GA Status

Repo-side GA preparation is complete for the current codebase.

Completed inside the repo:

- Validation path is documented and automated through `npm run validate`.
- Release packaging, release verification, reproducible build, and signed-release workflows are implemented and aligned with the docs.
- Manual-only deployment, release, recovery, and operator checklists now exist in-repo:
  - [`docs/release-runbook.md`](./release-runbook.md)
  - [`docs/recovery-runbook.md`](./recovery-runbook.md)
  - [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md)
  - [`docs/ga-operator-checklist.md`](./ga-operator-checklist.md)
- README and release docs now point at the actual supported release path instead of a partial or stale process description.
- Product limitations remain explicit and unchanged: no new trust or identity claim was added for GA prep.

## 2. Latest Repo Validation Evidence

Latest local GA-prep validation on 2026-04-08:

- `npm run typecheck` passed
- `npm run i18n:check` passed
- `npm test` passed
- `npm run e2e` passed
- `npm run validate` passed
- `SOURCE_DATE_EPOCH=1735689600 npm run build:repro` passed
- `npm run release:dry-run -- --tag ga-prep-local` passed

## 3. External Operator Tasks Required Before GA

These are still required before final GA sign-off and cannot be completed by repo edits alone:

- Confirm branch protection and required-check settings on the real GitHub repository.
- Verify the real deployed site headers/CSP and static-host behavior on the production domain.
- If GitHub Pages is the live host, confirm an equivalent header-setting layer exists; Pages alone does not apply the repo header baseline.
- Execute and sign off a real restore/recovery drill for shared-passphrase HMAC-protected profile, policy, and vault exports.
- Confirm maintainer-approved release key custody, rotation, revocation, and emergency replacement procedures.
- Complete final manual release/tag/deploy sign-off using [`docs/ga-operator-checklist.md`](./ga-operator-checklist.md).

Until those items are complete, NullID should be treated as:

- codebase-ready for GA
- not fully GA-signed-off operationally

## 4. Intentional Product Limitations

These are not GA blockers because they are intentional, documented limits of the current product:

- Workflow packages are unsigned and do not prove sender identity.
- Shared-passphrase HMAC remains tamper-detection for parties that already share a passphrase; it is not public-key identity.
- Top-level workflow metadata remains package-declared unless the same content is also hashed inside an included artifact.
- Schema-2 safe-share wrapper fields remain compatibility metadata and are not cross-checked against the embedded workflow package.
- `NULLID:ENC:1` protects the optional outer exported file transport; it does not add sender identity to workflow packages.
- Product behavior remains local-first and offline-first, with no required runtime backend.

## 5. Deferred Technical Debt

These are real follow-up items, but they are not required to call the current repo code-complete for GA:

- Accessibility audit and remediation across the full module set
- Explicit browser/device support matrix
- Native-language RU/FA editorial review
- Operational support/triage policy docs
- Formal compatibility/deprecation policy for long-term schema support
- Performance budgets and enforcement

## 6. Bottom Line

The repository is now code-complete for GA preparation.

What remains is external-only:

- operator confirmation
- real-host verification
- restore drill execution
- final tag/release/deploy sign-off
