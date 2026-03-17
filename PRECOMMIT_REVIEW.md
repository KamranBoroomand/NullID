# Pre-commit Review

## Checks run

- `npm ci` - passed
- `npm run typecheck` - passed
- `npm run i18n:check` - passed
- `npm run lint` - passed
- `npm test` - passed
- `npm run build` - passed
- `npm run verify:build` - passed
- `npm run audit:headers` - passed
- `npm run release:dry-run` - passed
- `npm run e2e` - passed
- `npm run test:visual` - passed

## What passed

- All requested non-browser and browser checks passed locally.
- Playwright/browser binaries were available; no environment workaround was needed.
- One intentional snapshot refresh was required after the sanitize-module wording cleanup:
  - `tests/e2e/app.spec.ts-snapshots/mobile-sanitize-darwin.png`
- After that refresh, the full E2E suite and the visual suite both passed again.

## What could not be verified due to environment limits

- None.

## Files cleaned up

- Updated `.gitignore` to ignore:
  - `.DS_Store`
  - `playwright-report/`
  - `test-results/`
- Removed tracked/generated noise:
  - `tests/e2e/.DS_Store`
  - `playwright-report/index.html`
  - `test-results/.last-run.json`
- Removed transient Playwright output directories from the working tree after verification:
  - `playwright-report/`
  - `test-results/`

## Files intentionally changed

- Hygiene and wording consistency:
  - `src/App.tsx`
  - `src/views/SanitizeView.tsx`
  - `src/views/VaultView.tsx`
  - `src/content/guideContent.ts`
  - `src/content/guidePhraseTranslations.ts`
  - `src/i18n.tsx`
- Snapshot refresh:
  - `tests/e2e/app.spec.ts-snapshots/mobile-sanitize-darwin.png`
- Generated tree kept in sync with source/test changes:
  - `build-test/**`
- Existing broader app/docs/test changes already present in the working tree were revalidated rather than broadly rewritten. Notable current areas include:
  - `README.md`
  - `scripts/nullid-local.mjs`
  - `src/utils/**`
  - `src/__tests__/**`
  - `tests/e2e/**`
  - `docs/password-storage-hashing.md`

## Risky or unresolved items

- `build-test/` is still a tracked generated tree by repo convention. The paired `src/` + `build-test/` diff is expected here, but it remains review noise.
- The repository still contains tracked historical artifact directories outside this pass, notably `output/playwright/**` and `output/visual-drift-*`. They were not changed here, but they are worth a separate hygiene decision if they are no longer intentionally versioned.
- Untracked top-level review docs are present and are not referenced elsewhere in the repo:
  - `AUDIT.md`
  - `HARDENING_NOTES.md`
  - `PHASE3_REVIEW.md`
  - `PHASE4_STABILIZATION.md`
- Those files may be intentional, but they should be staged only on purpose.

## Exact recommendation

- Safe to commit if the current untracked review docs are intentionally part of the changeset.
- If those review docs are not meant to ship, exclude them first; otherwise the repo is in a high-confidence commit-ready state.
