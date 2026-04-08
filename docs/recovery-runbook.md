# NullID Recovery Runbook

Last updated: 2026-04-08

Use this checklist to recover the repo build, release packaging flow, or static-site deployment from a clean machine or after a broken release/deploy. This runbook stays repo-focused; host-specific sign-off remains in [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md).

## 1. Restore From A Clean Clone

```bash
git clone <repo-url> NullID
cd NullID
git checkout <target-commit-or-tag>
npm ci
npm run e2e:install
```

Use the exact release commit or tag you intend to recover.

## 2. Rebuild The Repo Outputs

Run the supported restore validation path first:

```bash
npm run validate
```

Then rebuild deterministic outputs:

```bash
SOURCE_DATE_EPOCH=1735689600 npm run build:repro
```

## 3. Recreate Release Artifacts

```bash
npm run release:bundle -- --tag vX.Y.Z
npm run release:verify
```

If you want the combined local gate:

```bash
npm run release:dry-run -- --tag vX.Y.Z
```

## 4. Recover From A Broken Deploy

If the hosted site is bad but the repo still builds:

1. Identify the last known good commit on the default branch.
2. Revert the bad commit or apply a minimal fix on top of the default branch.
3. Re-run `npm run validate`.
4. Re-dispatch the manual Pages workflow from the corrected default-branch commit.
5. Re-run [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md) on the real site.

Do not change history on the default branch just to “hide” a broken deploy.

## 5. Recover From A Bad Release Tag

If the signed release was published from a bad commit:

1. Keep the published bad tag as historical evidence; do not re-point it at different artifacts.
2. Fix the issue on the default branch.
3. Re-run `npm run validate`.
4. Rebuild reproducible outputs and run `npm run release:dry-run -- --tag <new-tag>`.
5. Create a new corrective tag, for example `v0.1.1`.
6. Mark the bad GitHub release as superseded or withdrawn in notes if needed.

## 6. Evidence To Check After Recovery

Confirm all of the following before calling recovery complete:

- `npm run typecheck` passed
- `npm run i18n:check` passed
- `npm test` passed
- `npm run e2e` passed
- `npm run validate` passed
- `SOURCE_DATE_EPOCH=1735689600 npm run build:repro` passed
- `npm run release:verify` passed
- `dist/deploy-manifest.json` exists and matches the rebuilt files
- `dist/SHA256SUMS` exists and matches the rebuilt files
- `release/*release-checksums.txt` verifies the rebuilt release bundle
- The corrected site passes the deployment verification checklist

## 7. Recovery Limits

- This runbook restores the repo, release artifacts, and deployment flow. It does not replace a separate manual restore drill for shared-passphrase HMAC-protected profile, policy, or vault exports.
- If a signing/provenance workflow failed after tag creation, the fix path is a new corrective tag, not mutation of the old release artifacts.
