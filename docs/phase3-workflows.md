# NullID Phase 3 Workflows

This document describes the platform-breadth workflows added in Phase 3.

## 1) PDF metadata scrubbing (CLI)
Command:
- `npm run cli -- pdf-clean <input.pdf> <output.pdf>`

Behavior:
- Best-effort, in-place-length metadata redaction to avoid breaking PDF xref offsets.
- Scrubs common Info dictionary fields (`Author`, `Creator`, `Producer`, `Title`, `Subject`, `Keywords`, `CreationDate`, `ModDate`).
- Scrubs visible XMP packet content when present in plain text.

Limitations:
- Encrypted PDFs are not supported.
- Metadata stored in compressed/encrypted object streams may not be fully scrubbed.
- This is a practical privacy workflow, not a formal PDF rewrite engine.

## 2) Office metadata cleanup (CLI)
Command:
- `npm run cli -- office-clean <input.docx|input.xlsx|input.pptx> <output-file>`

Behavior:
- Extracts OOXML package locally.
- Rewrites `docProps/core.xml` and `docProps/app.xml` with sanitized values.
- Removes `docProps/custom.xml` and `docProps/person.xml` when present.
- Repackages as Office file with same extension.

Requirements:
- `zip` and `unzip` must be available in the environment.

## 3) Archive sanitize + manifest (CLI)
Command:
- `npm run cli -- archive-sanitize <input-dir|input.zip> <output.zip> [--baseline <nullid.policy.json>] [--sanitize-text true|false]`

Behavior:
- Accepts folder or zip source.
- Applies sanitize rules to selected text extensions.
- Preserves binary files.
- Emits `nullid-archive-manifest.json` into output archive with hashes, per-file sanitization status, per-file finding summaries, and severity totals.

## 4) Desktop packaging path (Tauri scaffold)
Command:
- `npm run desktop:init`

Behavior:
- Bootstraps `desktop/tauri` with minimal Tauri v2 scaffold and config.
- Keeps bundling disabled by default (`bundle.active=false`) until project-specific hardening is complete.

Next hardening for desktop path:
- Define capability/permission policy explicitly.
- Add release signing and provenance for desktop binaries.
- Keep platform-specific smoke tests healthy for macOS/Windows/Linux (`.github/workflows/desktop-tauri-smoke.yml`).
