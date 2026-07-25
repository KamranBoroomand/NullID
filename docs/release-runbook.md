# NullID Release Runbook

Use this runbook to evaluate and package the supported browser/PWA and local Node CLI release scope from the repository. Real-host checks and maintainer approval are recorded separately from local repository validation.

## Preconditions

- The intended release commit is checked out.
- Local workspace changes are intentional and reviewable.
- Node.js 20+ and npm are installed.
- Playwright Chromium is installed when browser E2E validation is required: `npm run e2e:install`.

## 1. Repository Validation

Run the matrix in [`docs/release-readiness.md`](./release-readiness.md) for the exact commit. At minimum, keep the command output or CI run URLs for:

```bash
npm ci
npm audit --audit-level=high
git diff --check
npm run typecheck
npm run check:i18n
npm run docs:links
npm run lint
npm run lint:network
npm run dead-code
npm run duplicate-code
npm run coverage
npm test
npm run test:e2e
npm run test:e2e:production
npm run build
npm run verify:build
npm run audit:headers
npm run release:bundle
npm run release:verify
npm run release:dry-run
```

Optional desktop bootstrap validation is separate. Run it only for a future release that explicitly includes a native desktop binary:

```bash
npm run desktop:smoke
```

## 2. Build Outputs

Build from clean dependencies:

```bash
SOURCE_DATE_EPOCH=1735689600 npm run build
npm run verify:build
```

Expected `dist/` files include:

- `build.json`
- `deploy-manifest.json`
- `SHA256SUMS`
- `sbom.json`
- stamped service-worker output

## 3. Package And Verify

Create the release bundle and verify it locally:

```bash
npm run release:bundle -- --tag vX.Y.Z
npm run release:verify
```

Or run the combined gate:

```bash
npm run release:dry-run -- --tag vX.Y.Z
```

Expected `release/` contents:

- `nullid-vX.Y.Z-dist.tar.gz`
- `nullid-vX.Y.Z-SHA256SUMS.txt`
- `nullid-vX.Y.Z-deploy-manifest.json`
- `nullid-vX.Y.Z-sbom.json`
- `nullid-vX.Y.Z-release-manifest.json`
- `nullid-vX.Y.Z-release-checksums.txt`

## 4. Reproducibility Check

Package the same clean `dist/` output twice with the same tag and compare archive checksums:

```bash
npm run release:bundle -- --tag repro-check
shasum -a 256 release/nullid-repro-check-dist.tar.gz
npm run release:bundle -- --tag repro-check
shasum -a 256 release/nullid-repro-check-dist.tar.gz
```

Matching hashes are expected. If they differ, capture both hashes, preserve the differing archives, and identify the nondeterministic file before proceeding.

## 5. Deploy And Verify

1. Publish the verified `dist/` output to the intended static host.
2. For subpath hosting, build with the correct `VITE_BASE` and verify routing after refreshes.
3. Run [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md) against the real deployed URL.
4. Confirm the service worker update path and static security headers on the deployed host.
5. Record commit SHA, tag, deployed URL, validation commands or CI URLs, release artifact checksums, and maintainer approval.

## 6. Desktop Bootstrap Scope

`desktop/tauri` is an optional experimental packaging bootstrap. `bundle.active: false` means no supported native desktop distribution is currently shipped.

Missing Rust/Cargo validation does not block browser/PWA or CLI release readiness. If a future desktop binary is included, run `npm run desktop:smoke` with Rust/Cargo installed and record the desktop validation separately.

## 7. Rollback

### Bad deploy before a release tag

1. Do not create the release tag.
2. Revert or fix the default branch.
3. Re-run the repository validation matrix.
4. Rebuild, redeploy, and rerun deployment verification.

### Bad deploy after a release tag

1. Do not re-use the same tag for different artifacts.
2. Revert or fix on the default branch and deploy the corrected site.
3. Mark the bad release as superseded in release notes or GitHub release metadata if needed.
4. Cut a corrective tag after validation and deployment verification.

### Bad local packaging state

1. Remove stale local outputs (`dist/` and `release/`).
2. Rebuild with a fixed `SOURCE_DATE_EPOCH`.
3. Re-run release bundle, release verification, and reproducibility checks.
