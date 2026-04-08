# NullID Release Security Checklist

Last updated: 2026-04-08

Use this checklist for every release candidate before tag publication.

Companion runbooks:

- [`docs/release-runbook.md`](./release-runbook.md)
- [`docs/recovery-runbook.md`](./recovery-runbook.md)
- [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md)
- [`docs/ga-operator-checklist.md`](./ga-operator-checklist.md)

## 1) Pre-tag gates
- [ ] Threat model deltas reviewed in `docs/threat-model.md`.
- [ ] No new runtime network calls introduced (`npm run lint`).
- [ ] Security header baseline passes (`npm run audit:headers`).
- [ ] Unit tests pass (`npm run test`).
- [ ] Type checks pass (`npm run typecheck`).
- [ ] Build reproducibility check passes (`SOURCE_DATE_EPOCH=1735689600 npm run build:repro`).
- [ ] Build outputs include `dist/sbom.json`, `dist/deploy-manifest.json`, and `dist/SHA256SUMS`.

## 1.1) Runtime hardening checks
- [ ] HTTPS enforced on production origin.
- [ ] Session cookie policy documented for deployment (`HttpOnly`, `Secure`, `SameSite=Strict`).
- [ ] Vault unlock hardening options reviewed (rate limiting, human check, optional MFA).

## 2) Adversarial regression gates
- [ ] Envelope tamper cases fail decryption/authentication.
- [ ] Hostile custom regex payloads are rejected/ignored safely.
- [ ] Malformed metadata payloads are handled without crashes.

Reference test corpus: `src/__tests__/adversarialCorpus.test.ts`.

## 3) Signed release + provenance gates
- [ ] Release pipeline runs from `.github/workflows/release-signed.yml`.
- [ ] Release dry-run gate passes from `.github/workflows/release-dry-run.yml`.
- [ ] Signed release workflow runs `npm run release:dry-run` before signing/publish.
- [ ] Release artifacts are packaged by `npm run release:bundle`.
- [ ] Release checksums verify via `npm run release:verify` or `node scripts/verify-release-bundle.mjs --dir ./release`.
- [ ] Keyless signatures are generated (`*.sig` + `*.pem`) for each release artifact.
- [ ] Provenance attestation is emitted via `actions/attest-build-provenance`.

`npm run release:verify` confirms the local release bundle checksums. Signature and provenance verification remain separate consumer/operator checks.

## 4) Manual verification commands (consumer side)
1. Verify release checksums:
   ```bash
   node scripts/verify-release-bundle.mjs --dir ./release
   ```
2. Verify an artifact signature with Sigstore keyless cert:
   ```bash
   cosign verify-blob \
     --certificate ./release/<artifact>.pem \
     --signature ./release/<artifact>.sig \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-identity-regexp 'https://github.com/<owner>/<repo>/.github/workflows/release-signed.yml@.*' \
     ./release/<artifact>
   ```
3. Verify GitHub provenance attestation:
   ```bash
   gh attestation verify ./release/<artifact> --repo <owner>/<repo>
   ```

## 5) Sign-off
- [ ] Security review completed by release owner.
- [ ] Dependency updates reviewed (Dependabot and/or `npm audit` findings triaged).
- [ ] Release notes include checksum + signature verification instructions.
- [ ] Tag is published only after all checklist items are complete.
