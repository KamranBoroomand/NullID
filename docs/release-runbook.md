# NullID Release Runbook

Last updated: 2026-04-08

Use this runbook for the repo-side GA release path. It covers what can be prepared and verified from the repository itself. Real-host validation and final operator sign-off live in [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md) and [`docs/ga-operator-checklist.md`](./ga-operator-checklist.md).

## Preconditions

- Release changes are merged to the default branch.
- Local workspace is clean enough to identify the release commit intentionally.
- Node.js 20 and npm are installed.
- `npm ci` has been run for the exact commit being released.

## 1. Final Local Validation

Run the documented repo validation path first:

```bash
npm ci
npm run e2e:install
npm run validate
```

If the release changes touch visual surfaces or snapshot baselines, also run:

```bash
npm run test:visual
```

## 2. Build Reproducible Outputs

Build deterministic release inputs before packaging:

```bash
SOURCE_DATE_EPOCH=1735689600 npm run build:repro
```

Expected outputs:

- `dist/SHA256SUMS`
- `dist/deploy-manifest.json`
- `dist/sbom.json`

## 3. Package And Verify Release Artifacts

Create the release bundle and verify its checksums locally:

```bash
npm run release:bundle -- --tag vX.Y.Z
npm run release:verify
```

Or run the combined dry-run gate:

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

## 4. Intended Publish Sequence

Use this order so site validation happens before the permanent release tag:

1. Merge the final GA-prep commit to the default branch.
2. Confirm `Quality Gates` passed on that commit.
3. If UI surfaces changed, confirm `Visual Regression Gate` passed or review the approved visual diff artifacts.
4. If release/deploy surfaces changed, confirm `Release Dry-Run Gate` passed or dispatch it manually from the default branch.
5. Dispatch the manual GitHub Pages workflow from the default branch, or publish the same `dist/` output to the intended static host.
6. Complete [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md) against the real deployed site.
7. Only after deployment checks pass, create and push the final annotated tag, for example `v0.1.0`.
8. Monitor `.github/workflows/release-signed.yml` until the signed bundle, signatures, and provenance attestation complete.
9. Verify release artifacts with `npm run release:verify`, `cosign verify-blob`, and `gh attestation verify` as described in [`docs/release-security-checklist.md`](./release-security-checklist.md).
10. Complete the final maintainer sign-off in [`docs/ga-operator-checklist.md`](./ga-operator-checklist.md).

## 5. Rollback

### Bad deploy, no bad tag yet

1. Do not create the release tag.
2. Revert the offending commit on the default branch or restore the last known good state.
3. Re-run `npm run validate`.
4. Re-dispatch the Pages workflow from the corrected default-branch commit.
5. Re-run the deployment verification checklist.

### Bad deploy after the release tag exists

1. Do not re-use the same tag for different bits.
2. Revert or fix on the default branch and deploy the corrected site.
3. Mark the bad release as superseded in release notes or GitHub release metadata if needed.
4. Cut a new corrective tag, for example `v0.1.1`, after validation succeeds again.

### Bad local packaging state

1. Remove stale local outputs:
   ```bash
   rm -rf dist release
   ```
2. Re-run:
   ```bash
   SOURCE_DATE_EPOCH=1735689600 npm run build:repro
   npm run release:dry-run -- --tag vX.Y.Z
   ```

## 6. Evidence To Keep

Capture or archive the following for the release record:

- Commit SHA and tag name
- `npm run validate` result
- `npm run release:dry-run -- --tag ...` result
- `dist/deploy-manifest.json`
- `dist/SHA256SUMS`
- `release/*release-manifest.json`
- `release/*release-checksums.txt`
- Deployed site URL plus header/CSP verification notes
- GitHub workflow run URLs for Quality Gates, Pages, Release Dry-Run, and Signed Release
