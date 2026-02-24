# NullID Complete Tool Roadmap

This roadmap tracks the major expansion areas required to make NullID a complete, broad-support offline security tool.

## Phase 1: Coverage Backbone (Current)
- [x] Expand local CLI coverage beyond hash/sanitize.
- [x] Add CLI commands for redaction, encryption/decryption, password generation, and metadata inspection.
- [x] Add structured sanitize format support in CLI (`json`, `ndjson`, `csv`, `xml`, `yaml`, `text`, `auto`).
- [x] Add recursive sanitize directory mode for local automation and CI usage.
- [x] Add stronger encryption profiles while preserving `NULLID:ENC:1` compatibility.

## Phase 2: Team and Pipeline Readiness
- [x] Signed policy packs with explicit verify-before-import workflow.
- [x] Saved key-hint profiles and key rotation UX.
- [x] Pre-commit helper command for sanitize/redact enforcement.
- [x] CI templates for PR log sanitization + artifact checks.
- [x] Workspace policy baseline files (`nullid.policy.json`) with deterministic merge rules.

## Phase 3: Platform Breadth
- [x] PDF metadata stripping workflow.
- [x] Office document metadata workflow (`docx/xlsx/pptx`).
- [x] Archive bundle sanitization (`zip`/folder package manifests).
- [x] Desktop packaging path (Tauri) for regulated/offline desktop environments.

## Phase 4: Trust Hardening
- [x] Deterministic SBOM generation in build outputs.
- [x] Reproducibility validation hooks in CI matrix workflow.
- [x] Signed releases and provenance attestations.
- [x] Expanded adversarial test corpus (malformed metadata, hostile regex payloads, envelope tamper cases).
- [x] Formal security review checklist for release candidates.

## Phase 5: Post-Phase Hardening (Active)
- [x] Metadata parsing hardening for malformed edge files and uncommon/vendor EXIF tags.
- [x] Explicit signed export/import verification dialogs (no browser prompt/confirm dependency).
- [x] Shared saved key-hint profiles reused across profile, policy pack, and vault signing flows.
- [x] Visual regression snapshots for module-specific mobile layouts (sanitize, metadata, vault).
- [x] Gap review + prioritization for next assurance track.

## Phase 6: Complete Tool Rollout (Current)
- [x] Expand visual snapshot matrix to desktop + theme variants.
- [x] Add workflow-level visual regression gate with snapshot drift reporting.
- [x] Extend signed workflow docs with key-hint profile operating conventions (`docs/signed-workflow-conventions.md`).
- [x] Add password-storage hash lab with Argon2id/PBKDF2 + legacy compatibility warnings.
- [x] Add vault unlock hardening controls (rate limiting, human check, optional MFA).
- [x] Add static-host security header baseline files (`public/_headers`, `vercel.json`) and validation script.
- [x] Add release dry-run workflow gate enforcing `release:bundle` + `release:verify` before publish.
- [x] Harden desktop Tauri packaging with cross-platform smoke coverage (macOS/Linux/Windows).
- [x] Extend archive sanitization manifest contract with per-file findings + severity totals and regression tests.
- [x] Add signed import/export trust-state labels (`unsigned`, `verified`, `mismatch`) across profile/policy/vault flows.

## Delivery Notes
- Each phase is designed to remain fully offline-first.
- Browser and CLI behavior should stay schema-compatible where applicable.
- Backward compatibility requirement: previously generated envelopes and exports must continue importing/decrypting.
