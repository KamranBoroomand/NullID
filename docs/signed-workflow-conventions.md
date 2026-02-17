# Signed Workflow Key-Hint Conventions

This document defines operating conventions for saved key-hint profiles used in NullID signed exports/imports.

## Scope
- Applies to signed profile exports, signed sanitizer policy packs, and signed vault snapshots.
- Applies to both browser UI flows and imported payload verification.

## Core Rules
- Key hints are identifiers, not secrets.
- Never store passphrases, private keys, or recovery phrases inside key-hint fields.
- Keep hints short, stable, and versioned (for example: `team-alpha-v3`).
- Use one shared key-hint profile catalog across tools (`nullid:signing:key-hints`).

## Naming Convention
- Recommended pattern: `<owner-or-team>-<purpose>-v<version>`.
- Examples:
  - `secops-policy-v2`
  - `compliance-vault-v4`
  - `release-profile-v1`

## Rotation Convention
- Rotate by incrementing the trailing `-vN` suffix.
- Keep previous profile entries until all required legacy imports complete.
- Prefer explicit profile selection during export to avoid accidental drift.

## Verify-Before-Import Convention
- If a payload includes signature metadata, require explicit verification dialog review before import.
- Confirm that the payload key hint matches the expected profile for the source workflow.
- Treat mismatched or unknown key hints as high-risk and reject unless manually re-validated out of band.
- Require verification secrets/passphrases only in local UI context; do not log or persist them.

## Legacy Migration
- Legacy sanitizer key-hint profiles (`nullid:sanitize:key-hints`) are read and merged into the shared key on first use.
- After migration, new profile management should use the shared key-hint catalog only.

## CI/Automation Notes
- CI should validate signed payload integrity, but must not embed live signing secrets in workflows.
- Use deterministic fixtures for signed import/export tests and tamper cases.
