# Incident Workflow

`Incident Workflow` is NullID's first incident-oriented producer surface. It turns the repo's existing local primitives into one operational package flow instead of leaving notes, sanitize output, metadata review, and export steps scattered across separate tools.

## What It Does

The workflow composes these existing NullID capabilities:

- Safe Share text/file preparation helpers
- sanitize policy machinery for notes and extra text artifacts
- local metadata analysis and browser-supported cleanup for file artifacts
- SHA-256-backed workflow packaging
- optional outer `NULLID:ENC:1` protection for the exported file
- receiver-side compatibility with the existing `Verify Package` surface and CLI `package-inspect`

## Incident Modes

The current incident workflow modes are:

- `incident-handoff`: responder-to-responder handoff with context and honest limits
- `evidence-archive`: preserve more context while still recording what was cleaned or left intact
- `minimal-disclosure-incident-share`: reduce context aggressively for tightly scoped or external incident sharing
- `internal-investigation`: keep more internal responder context available while still scrubbing obvious secrets

These modes reuse the existing Safe Share preset machinery rather than inventing a second policy system.

## App Flow

In the app:

1. Open `Incident Workflow`.
2. Record the incident title, package purpose, optional case reference, recipient scope, and short summary.
3. Prepare case notes locally; the default template uses the same incident headings available in `Secure Notes`.
4. Add extra text snippets or file artifacts.
5. Review sanitize findings for notes/text and metadata signals for files.
6. Decide whether to include source references, apply local metadata cleanup, and wrap the export in `NULLID:ENC:1`.
7. Review the final package summary, included artifacts, transform log, warnings, and receiver-verification explanation.
8. Export the `nullid-workflow-package`.

## What Gets Exported

An incident package currently includes:

- incident context metadata
- an incident report artifact
- prepared note/text/file artifacts flattened into the shared workflow package contract
- SHA-256 manifest entries for included artifacts and references
- transform summaries describing what NullID changed or recorded
- warnings and limitations that stay explicit about trust and scope

Incident title/purpose/audience/report metadata remains package-declared in the current contract. Receivers can inspect it, but the current verifier mainly proves SHA-256 manifest/hash self-consistency for included artifacts rather than authenticating that top-level incident narrative as a whole.

## Trust And Verification

- Incident packages are unsigned in this step. They do not prove sender identity.
- SHA-256 manifest entries help detect changes to included artifacts, but they are not signatures.
- The inner workflow package remains plain JSON. `NULLID:ENC:1` protects the exported file when you wrap it, but that is still confidentiality/integrity for holders of the passphrase, not public-key authenticity.
- Receivers can inspect the package locally with the app `Verify Package` module or CLI `package-inspect`.

## CLI Alignment

The CLI does not expose a new incident wizard in this milestone.

Instead, the existing `bundle` path now carries incident-oriented workflow metadata for power users:

```bash
npm run cli -- bundle ./raw.log ./nullid-safe-share-bundle.json \
  --preset nginx \
  --workflow internal-investigation \
  --title "Incident 2026-03-18" \
  --purpose "Prepare an internal responder package." \
  --case-ref CASE-142 \
  --recipient "internal responders"

npm run cli -- package-inspect ./nullid-safe-share-bundle.json
```

That keeps the CLI aligned with the incident package vocabulary without replacing the existing automation-friendly sanitize/bundle flow.

That CLI path still emits a schema-2 safe-share wrapper, so verification is based on the embedded workflow package and not on duplicated outer wrapper fields.

## What Remains Manual

This step does not claim to provide:

- public-key sender identity
- legal or forensic chain-of-custody guarantees
- automatic cleanup for every file format
- full case management or multi-step incident orchestration beyond packaging

Lower-level tools such as `Log Sanitizer`, `Metadata Inspector`, `Encrypt / Decrypt`, and `Secure Notes` still remain available when you need direct control.
