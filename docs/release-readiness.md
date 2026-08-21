# NullID Release Readiness

This is the repository validation checklist for NullID's supported browser/PWA and local Node CLI release scope.

Repository-level status wording:
"The browser/PWA and CLI source tree has passed the repository validation matrix. Live-host verification is performed separately after deployment."

Do not use repository validation as proof that a live host has the expected headers, service-worker behavior, deployment path, or release artifacts. Record those external checks separately after deployment.

## Repository Validation Matrix

Run these commands from a clean dependency install for the exact commit being evaluated:

- [ ] `npm ci`
- [ ] `npm audit --audit-level=high`
- [ ] `git diff --check`
- [ ] `npm run typecheck`
- [ ] `npm run check:i18n`
- [ ] `npm run docs:links`
- [ ] `npm run lint`
- [ ] `npm run lint:network`
- [ ] `npm run dead-code`
- [ ] `npm run duplicate-code`
- [ ] `npm run coverage`
- [ ] `npm run test`
- [ ] `npm run test:e2e`
- [ ] `npm run test:e2e:production`
- [ ] `npm run build`
- [ ] `npm run budget:entry`
- [ ] `npm run verify:build`
- [ ] `npm run audit:headers`
- [ ] `npm run release:bundle`
- [ ] `npm run release:verify`
- [ ] `npm run release:dry-run`

`npm run validate` covers the main browser/PWA and CLI matrix, including strict i18n, documentation links, linting, network linting, dead-code detection, duplicate-code detection, coverage, dependency and header audits, unit tests, application E2E, production PWA E2E at `/` and `/nullid-e2e/`, build verification, and release bundle verification.

## Optional Desktop Bootstrap

`desktop/tauri` is an optional experimental packaging bootstrap. It is not part of the supported browser/PWA and CLI release scope.

- `desktop/tauri/src-tauri/tauri.conf.json` has `bundle.active: false`.
- No supported native desktop distribution is shipped from this repository state.
- Rust/Cargo validation is required only for a future release that explicitly includes a desktop binary.
- Missing Rust/Cargo validation does not block browser/PWA or CLI release readiness.

If a future release includes a desktop binary, install Rust/Cargo and run:

```bash
npm run desktop:smoke
```

## Release Artifact Checks

Before tagging or publishing release artifacts, verify:

- `dist/sbom.json` is a CycloneDX SBOM produced by `@cyclonedx/cyclonedx-npm`.
- `dist/deploy-manifest.json` includes `sbom.json`, `build.json`, app assets, and service-worker output.
- `dist/SHA256SUMS` includes every deployable file listed by the manifest, including `sbom.json`.
- `npm run release:verify` confirms the release archive contains `SHA256SUMS`, `deploy-manifest.json`, and `sbom.json`, and that copied release artifacts match archive contents.
- Reproducibility is checked by packaging the same clean `dist/` output twice and comparing archive checksums. Any difference must be explained before release approval.

## Security And Threat Model Checks

- Runtime source remains offline by policy and passes `npm run lint:network`.
- Security headers are represented in the Cloudflare Pages static-host baseline and pass `npm run audit:headers`.
- Dependency audit has no high-or-critical findings.
- `docs/threat-model.md` matches current envelope, storage, release, and workflow behavior.
- `NULLID:ENC:2` is the current envelope format; legacy `NULLID:ENC:1` support is read/decrypt compatibility only.
- Secure Notes accepts canonical vault note version 3 and vault snapshot schema 2 only. Unsupported v1, v2, unversioned, schema-less, and obsolete fallback-key vault data is ignored during normal reads and imports.
- Workflow packages remain honest about trust: SHA-256 manifests detect changes to listed artifacts, but workflow packages do not assert sender identity.

## External Deployment Items

These cannot be proven by repository edits alone:

- Branch protection and required checks on the real GitHub repository.
- Real deployed-domain headers/CSP and service-worker behavior.
- Cloudflare Pages Git deployment status and custom-domain routing.
- Release key custody, rotation, revocation, and emergency replacement procedures.
- Restore drill for shared-passphrase HMAC-protected profile, policy, and vault exports.
- Maintainer release record with commit SHA, tag, deploy URL, validation evidence, and approver.

## Intentional Product Limits

- NullID is local-first and does not claim external cryptographic certification.
- Workflow packages are unsigned and do not prove sender identity.
- Shared-passphrase HMAC is tamper detection for parties that already share a passphrase, not public-key identity.
- Top-level workflow metadata is package-declared unless the same content is also carried inside hashed artifacts.
- The optional outer `NULLID:ENC:2` envelope protects exported-file confidentiality and AES-GCM integrity for passphrase holders; it does not add sender identity.
- localStorage fallback keeps vault payloads encrypted but still exposes ciphertext blobs and record metadata to the browser profile until wipe removes them.
- Profile export/import excludes vault blobs and vault-store metadata.
