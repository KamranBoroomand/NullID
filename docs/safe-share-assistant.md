# Safe Share Assistant

`Safe Share Assistant` is NullID's first workflow-oriented producer surface for preparing sensitive material to share safely without leaving the local app.

## What It Does

The assistant turns several lower-level primitives into one guided local flow:

- text classification and sanitize review
- file metadata analysis and, when supported, local cleanup
- workflow preset selection
- transform and warning review
- export as a `nullid-workflow-package`
- optional outer `NULLID:ENC:1` protection for the exported file

It is intentionally not a replacement for the lower-level tools. `:sanitize`, `:meta`, and `:enc` still exist for direct control and power-user workflows.

## Current Presets

- `general-safe-share`: balanced disclosure reduction for routine sharing
- `support-ticket`: keeps enough context for debugging while scrubbing obvious secrets
- `external-minimum`: reduces context more aggressively and avoids raw file payloads when local cleanup is unavailable
- `internal-investigation`: preserves more internal responder context while still scrubbing obvious secrets
- `incident-handoff`: preserves more context for another responder and can include original file bytes with explicit warnings
- `evidence-archive`: preserves context more conservatively and allows original file packaging when needed

These presets are grounded in existing NullID behavior. They do not add new signing or identity claims.

## What Gets Exported

The assistant exports a `nullid-workflow-package` containing, as appropriate:

- producer and workflow metadata
- workflow preset metadata
- included artifacts or source references
- SHA-256 manifest entries
- policy metadata
- transform summaries
- warnings and limitations
- receiver-facing human-readable summary fields

Those top-level workflow summary/report/policy fields are currently package-declared metadata. Receivers can inspect them, but current verification primarily proves SHA-256 manifest/hash self-consistency for included artifacts rather than authenticating the whole top-level workflow JSON.

For text-based sharing, the package currently includes sanitized output, a sanitize policy snapshot, and a Safe Share report artifact.

For file-based sharing, the package may include:

- a source reference only
- a locally cleaned file payload
- the original file payload when the preset explicitly allows preserving context
- a Safe Share report artifact

## Protection and Verification

- Workflow packages are unsigned in this step. They do not prove sender identity.
- SHA-256 manifest entries help detect changes to included artifacts but are not signatures.
- The inner workflow package remains plain JSON. Wrapping the exported file in `NULLID:ENC:1` adds confidentiality and AES-GCM integrity for that outer file transport, not public-key authenticity.
- Receivers can inspect exported packages locally in the app's `Verify Package` surface or with CLI `package-inspect`.

## CLI Relationship

The CLI does not expose a full interactive Safe Share wizard in this milestone.

Instead, `bundle` can now attach Safe Share workflow metadata with `--workflow` so power users can keep using the existing sanitize-driven automation path:

```bash
npm run cli -- bundle ./raw.log ./nullid-safe-share-bundle.json --preset nginx --workflow support-ticket
npm run cli -- package-inspect ./nullid-safe-share-bundle.json
```

That preserves the current CLI shape while aligning its exported workflow metadata with the app's shared package contract.

When the CLI uses that compatibility bundle path, `package-inspect` bases workflow verification on the embedded workflow package. Duplicated outer safe-share wrapper fields remain compatibility metadata and are not currently cross-checked.

## Difference From Incident Workflow

`Safe Share Assistant` is the general producer flow for preparing one text snippet or file-oriented share.

`Incident Workflow` builds on the same primitives and contract when you need:

- incident title, purpose, case reference, and recipient scope
- responder notes or case context alongside prepared artifacts
- a clearer incident-oriented report explaining what was transformed, preserved, and hashed
- one incident package instead of a single-asset share package
