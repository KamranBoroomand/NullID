# Workflow Package Contract

`nullid-workflow-package` is NullID's versioned local JSON contract for workflow artifacts that can be inspected locally and checked against SHA-256 artifact-manifest metadata.

## What It Is For

The contract gives NullID one shared shape for workflow bundles and reports that need to travel between:

- browser UI exports
- CLI automation flows
- future receiver-side verification
- future incident-oriented reporting and handoff flows

The goal is reuse, not replacement. Existing formats still matter:

- `NULLID:ENC:1` remains the encryption envelope format
- existing hash and integrity helpers remain the trust primitives
- current policy pack, profile, vault, and archive semantics remain intact
- legacy sanitize safe-share bundles can still be read through compatibility mapping

## Current Use

In the current milestone set, the contract is emitted by:

- the app `Safe Share Assistant` as a direct `nullid-workflow-package`
- the app `Incident Workflow` as a direct `nullid-workflow-package`
- the app `Log Sanitizer` safe-share export as an embedded compatibility bundle
- the CLI `bundle` command, with optional Safe Share / incident-oriented workflow metadata via `--workflow`

The CLI also has a minimal inspection path:

```bash
npm run cli -- package-inspect ./nullid-safe-share-bundle.json
npm run cli -- package-inspect ./nullid-safe-share-bundle.nullid --pass-env NULLID_PASSPHRASE
```

The app now has a receiver-facing `Verify Package` surface built on the same contract and trust vocabulary.

## Contract Shape

The shared contract can now appear either:

- directly as `kind: "nullid-workflow-package"`
- nested inside a compatibility safe-share bundle as `workflowPackage`

Core fields include:

- `schemaVersion`
- `kind`
- `packageType`
- `workflowType`
- `producedAt`
- `producer`
- `workflowPreset`
- `summary`
- `report`
- `trust`
- `artifacts`
- `policy`
- `transforms`
- `warnings`
- `limitations`

In the current contract, fields such as `summary`, `report`, `workflowPreset`, `policy`, `warnings`, and `limitations` are package-declared metadata. Receivers can read them, but the contract does not currently authenticate those top-level fields as a whole.

For current producer flows, artifacts can include:

- original input reference metadata
- sanitized output payload
- policy snapshot
- Safe Share report payloads
- incident context and incident report payloads
- included binary file payloads encoded as base64 when a workflow exports them directly

The shared `report` block is now the common explainability section used by both Safe Share and Incident Workflow. It can carry:

- package purpose and audience
- included, transformed, and preserved artifact summaries
- what a receiver can verify locally
- what a receiver still cannot verify

## Trust Semantics

This contract is intentionally conservative.

- Unsigned packages do not assert sender identity.
- SHA-256 artifact entries help detect changes to listed artifacts, but they are not signatures.
- The current inner workflow `trust.packageSignature.method` is `none`. The contract does not carry a verifiable package-level signature payload.
- The current inner workflow `trust.encryptedPayload.method` is `none`. `NULLID:ENC:1` is an optional outer envelope for the exported file, not inner workflow-package encryption.
- Top-level workflow metadata and schema-2 safe-share wrapper fields should be treated as package-declared unless they are separately hashed or cross-checked by some other mechanism.

Those rules are reflected directly in the contract's `trust` section, receiver-facing warning text, and the `Verify Package` / `package-inspect` trust vocabulary.

## Backward Compatibility

This milestone preserves current behavior by extending rather than replacing:

- Direct workflow package export does not remove or break safe-share bundles.
- Safe-share bundles stay `kind: "nullid-safe-share"`.
- The bundle schema moves forward to `schemaVersion: 2`.
- The shared contract is embedded as `workflowPackage`.
- Current schema-2 safe-share verification is based on that embedded workflow package; duplicated outer bundle fields remain compatibility metadata and are not cross-checked yet.
- Legacy safe-share bundles without `workflowPackage` can still be mapped into the shared contract for inspection and future receiver flows.

## How Future Features Build On It

This contract is the foundation for:

- Safe Share Assistant producing richer package types without inventing a second artifact schema
- Verify Package / receiver flows inspecting one shared payload model across web and CLI
- Incident Workflow reports and handoff bundles reusing the same artifact, trust, and summary vocabulary
- shared receiver-facing reporting that `Verify Package` and `package-inspect` can explain consistently
- workflow presets and policy metadata being attached consistently across producer paths

Receiver verification, Safe Share Assistant exports, and first-class Incident Workflow exports now all sit on the same shared contract. Later milestones can keep expanding producer and receiver coverage without inventing a second package schema.
