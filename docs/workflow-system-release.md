# NullID Workflow System Release Notes

Operational GA runbooks now live in:

- [`docs/release-runbook.md`](./release-runbook.md)
- [`docs/recovery-runbook.md`](./recovery-runbook.md)
- [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md)
- [`docs/ga-operator-checklist.md`](./ga-operator-checklist.md)

This document covers the newly completed NullID workflow system:

- shared workflow package/report contract
- Verify Package
- Safe Share Assistant
- Incident Workflow
- workflow preset metadata
- CLI alignment for workflow export and inspection

## Release Summary

NullID now includes a task-oriented workflow layer on top of its existing security and privacy primitives.

Users can now:

- prepare local text snippets or files for safer sharing with `Safe Share Assistant`
- build local incident handoff packages with `Incident Workflow`
- inspect received workflow artifacts locally with `Verify Package`
- exchange receiver-friendly JSON workflow packages using one shared contract
- keep CLI and app flows aligned without adding a backend or SaaS dependency

The product remains local-first, offline-first, and explicit about what it can and cannot verify.

## User-Facing Highlights

### 1. Safe Share Assistant

`Safe Share Assistant` is a guided local producer flow for preparing material to share safely.

It combines existing NullID primitives into one path:

- choose text or file input
- choose a workflow preset
- review sanitize or metadata findings
- review transforms, warnings, and package scope
- optionally wrap the export in `NULLID:ENC:1`
- export a receiver-friendly `nullid-workflow-package`

Current Safe Share presets:

- `general-safe-share`
- `support-ticket`
- `external-minimum`
- `internal-investigation`
- `incident-handoff`
- `evidence-archive`

### 2. Incident Workflow

`Incident Workflow` is a guided local operational flow for responder-oriented packaging.

It supports:

- incident title, purpose, case reference, and recipient scope
- case notes and additional text artifacts
- file artifact review with metadata analysis and local cleanup when supported
- one incident package that records included items, transforms, warnings, and receiver-facing explanation

Current incident workflow modes:

- `incident-handoff`
- `evidence-archive`
- `minimal-disclosure-incident-share`
- `internal-investigation`

### 3. Verify Package

`Verify Package` is the receiver-side inspection surface for supported NullID artifacts.

It can currently inspect:

- `nullid-workflow-package`
- `nullid-safe-share`
- sanitize policy packs
- profile snapshots
- vault snapshots
- `NULLID:ENC:1` envelopes

It explains:

- artifact type
- verification state
- trust basis
- included artifacts or logical entries
- package-declared workflow metadata when present
- warnings and limitations

### 4. Shared Workflow Artifact Contract

NullID now uses a shared versioned contract for workflow exports:

- kind: `nullid-workflow-package`
- schema version: `1`

This contract records:

- package metadata
- workflow type and preset metadata
- produced-at timestamp
- producer metadata
- included artifacts and manifest entries
- transforms, warnings, and limitations
- human-readable workflow report fields

Those top-level workflow metadata fields are currently descriptive/package-declared. The current verifier authenticates artifact-manifest/hash behavior, not the whole top-level workflow JSON.

Legacy sanitize safe-share bundles remain supported and still embed the shared contract.

### 5. CLI Alignment

The CLI keeps its existing power-user shape while aligning with the workflow system:

- `bundle` can attach workflow metadata with `--workflow`
- `bundle` can carry incident-oriented metadata with `--title`, `--purpose`, `--case-ref`, and `--recipient`
- `package-inspect` can inspect supported workflow artifacts and encrypted envelopes locally

Example commands:

```bash
npm run cli -- bundle ./raw.log ./nullid-safe-share-bundle.json --preset nginx --workflow support-ticket
npm run cli -- bundle ./raw.log ./nullid-safe-share-bundle.json --preset nginx --workflow internal-investigation --title "Incident 2026-03-18" --purpose "Prepare an internal responder package." --case-ref CASE-142 --recipient "internal responders"
npm run cli -- package-inspect ./nullid-safe-share-bundle.json
npm run cli -- package-inspect ./nullid-safe-share-bundle.nullid --pass-env NULLID_PASSPHRASE
```

## Trust And Scope Limitations

These limits are intentional and should be stated clearly in release notes and user communications:

- Workflow packages are currently unsigned. They do not prove sender identity.
- Shared-secret HMAC in NullID remains an integrity/tamper-detection mechanism for parties that already share the secret. It is not public-key identity.
- Workflow packages do not currently carry a verifiable package-level signature payload.
- Inner workflow JSON is not encrypted. `NULLID:ENC:1` provides confidentiality and AES-GCM integrity for the optional outer exported file transport only.
- Top-level workflow metadata is package-declared unless separately hashed inside an artifact.
- Schema-2 safe-share wrapper fields are compatibility metadata; current verification is based on the embedded workflow package and does not cross-check duplicated outer wrapper fields.
- SHA-256 manifest entries help detect changes to included artifacts or recorded references. They do not prove omitted context was complete.
- Incident packages are operational handoff artifacts, not formal chain-of-custody systems.
- NullID remains local-only. It does not rely on a runtime backend, sync service, or SaaS workflow layer.

## Upgrade Notes

### Compatibility

- Existing primitive tools remain available. `:sanitize`, `:meta`, `:enc`, `:hash`, `:vault`, and the CLI primitives are still supported.
- Existing sanitize safe-share bundles are still supported and can be inspected through the shared workflow path.
- Existing profile, vault, and policy import/export trust semantics are unchanged.
- `NULLID:ENC:1` is unchanged and remains backward compatible.

### New Artifacts And Commands

- New workflow artifacts use `nullid-workflow-package`.
- New receiver-side inspection uses the app `Verify Package` surface and CLI `package-inspect`.
- `bundle` remains backward compatible when used without workflow flags.

### Validation Environment Note

- Full local validation can now use `NULLID_E2E_PORT` when the default Playwright port is already in use:

```bash
NULLID_E2E_PORT=4012 npm run validate
```

## Manual QA Checklist

Use this checklist for release-candidate manual verification in addition to automated tests.

### App Workflows

- [ ] Open `Safe Share Assistant` and export a text-based package with the `support-ticket` preset.
- [ ] Open the exported package in `Verify Package` and confirm it reports `Integrity checked`.
- [ ] Confirm the verification view shows an honest limit such as no sender identity claim.
- [ ] Open `Safe Share Assistant` in file mode with a supported image or PDF and confirm metadata findings and cleanup guidance appear.
- [ ] Open `Incident Workflow`, create a package with title, purpose, summary, notes, and at least one extra text artifact, then export it.
- [ ] Open that incident package in `Verify Package` and confirm the package-declared workflow report, reported transforms, and warnings are visible with unverified/descriptive labeling.
- [ ] Paste malformed JSON into `Verify Package` and confirm it fails safely as malformed or invalid.
- [ ] Paste a `NULLID:ENC:1` envelope into `Verify Package` without a passphrase and confirm it reports `Verification required` / passphrase required rather than pretending the payload is verified.

### CLI Alignment

- [ ] Run `bundle` without workflow flags and confirm the existing sanitize bundle path still works.
- [ ] Run `bundle` with `--workflow support-ticket` and inspect the result with `package-inspect`.
- [ ] Run `bundle` with `--workflow internal-investigation --title --purpose --case-ref --recipient` and confirm those fields appear in inspection output as package-declared workflow metadata rather than integrity-verified content.
- [ ] Wrap a workflow package in `NULLID:ENC:1` and confirm `package-inspect` can inspect it with `--pass` or `--pass-env`.
- [ ] Inspect a signed policy/profile/vault artifact with the correct verification passphrase and confirm the label remains `HMAC verified`, not a public-key identity claim.

### Trust Language And UX

- [ ] Confirm `Safe Share Assistant`, `Incident Workflow`, and `Verify Package` all use consistent wording for warnings, limitations, and verification state.
- [ ] Confirm receiver-facing text distinguishes unsigned, integrity-checked, verification-required, mismatch, invalid, malformed, and unsupported states honestly.
- [ ] Confirm schema-2 safe-share inspection states that verification is based on the embedded workflow package and that duplicated outer wrapper fields are not cross-checked.
- [ ] Confirm workflow report/policy/preset metadata is described as package-declared unless separately hashed.
- [ ] Confirm no workflow surface claims sender identity, signature authenticity, or chain-of-custody that the current implementation cannot prove.

### Documentation

- [ ] README reflects the workflow system and links to the workflow docs.
- [ ] `docs/safe-share-assistant.md`, `docs/incident-workflow.md`, `docs/verify-package.md`, and `docs/workflow-package-contract.md` remain consistent with current behavior.
- [ ] Release notes include the trust/scope limitations above without overstating authenticity guarantees.

## Short Release Notes Draft

Use this short draft for a changelog entry or release announcement:

> NullID now includes a complete local workflow layer for preparing and verifying sensitive artifacts. This release adds `Safe Share Assistant`, `Incident Workflow`, `Verify Package`, and the shared `nullid-workflow-package` contract so producers and receivers can exchange reviewable local packages without a backend. The CLI stays aligned through workflow-aware `bundle` exports and `package-inspect`.
>
> Trust remains explicit: workflow packages are currently unsigned, shared-secret HMAC remains integrity-only where used, and `NULLID:ENC:1` protects file transport but does not prove sender identity. Existing primitive tools and sanitize safe-share bundles remain supported.

## What’s Next

GA-specific operator work now lives in:

- [`docs/release-readiness.md`](./release-readiness.md)
- [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md)
- [`docs/ga-operator-checklist.md`](./ga-operator-checklist.md)

Longer-range follow-ups after GA remain:

- broader receiver inspection for additional archive-style workflow artifacts
- future workflow-contract extensions for verifiable package signatures, if NullID later adopts an identity-bearing model
- more operational polish around handoff/report templates and richer incident review flows
