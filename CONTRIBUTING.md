# Contributing to NullID

## Development Setup

1. Install Node.js 18+ (latest LTS recommended).
2. Install dependencies:

```bash
npm ci
```

3. Start local development server:

```bash
npm run dev
```

## Required Local Checks

Before opening a PR, run:

```bash
npm run validate
```

This runs typecheck, i18n coverage, offline lint policy, unit tests, e2e tests, build, and build-manifest verification.

## Pull Request Expectations

- Keep changes scoped and reviewable.
- Add or update tests for behavior changes.
- Update docs/help text when UX or CLI behavior changes.
- Keep browser and CLI behavior aligned for shared features.
- Do not introduce runtime network calls in `src/`.

## Commit Guidance

- Use clear commit messages that describe behavior-level changes.
- Prefer one logical change per commit.

## Security-Sensitive Changes

If touching crypto, storage, sanitization rules, or release integrity scripts:

- add focused regression tests
- update `docs/threat-model.md` and/or `docs/release-security-checklist.md` when assumptions change
- call out risk and migration impact in the PR description

## Documentation

When adding features, update at least one of:

- `README.md`
- `docs/complete-tool-roadmap.md`
- in-app guide content (`src/content/guideContent.ts`)
