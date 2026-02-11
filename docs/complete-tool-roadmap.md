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
- [ ] Signed releases and provenance attestations.
- [ ] Expanded adversarial test corpus (malformed metadata, hostile regex payloads, envelope tamper cases).
- [ ] Formal security review checklist for release candidates.

## Delivery Notes
- Each phase is designed to remain fully offline-first.
- Browser and CLI behavior should stay schema-compatible where applicable.
- Backward compatibility requirement: previously generated envelopes and exports must continue importing/decrypting.
