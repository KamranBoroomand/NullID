# NullID
Offline-first security toolbox for hashing, redaction, sanitization, encryption, and secure local notes, with matching browser + CLI workflows and no external services.

## Table of Contents
1. [Overview](#overview)
2. [Core Features](#core-features)
3. [Tech Stack](#tech-stack)
4. [Architecture](#architecture)
5. [Quick Start](#quick-start)
6. [Configuration](#configuration)
7. [Scripts](#scripts)
8. [Deployment](#deployment)
9. [Security/Quality Notes](#securityquality-notes)
10. [Roadmap](#roadmap)

## Overview
NullID is a Vite + React + TypeScript single-page app designed as a terminal-style local security workbench. It provides practical security and privacy tooling without relying on backend services.

The app is organized into focused modules:
- Hash & Verify
- Text Redaction
- Log Sanitizer
- Metadata Inspector
- Encrypt / Decrypt
- Password & Passphrase generator
- Secure Notes vault
- Self-test diagnostics
- Built-in Guide
- Local automation CLI

## Core Features
- Hash & Verify: SHA-256, SHA-512, and SHA-1 (legacy) for text and files, plus digest comparison and multiple output formats.
- Text Redaction: detector-based masking for common PII/secrets with custom regex rules and overlap-safe resolution.
- Log Sanitizer: preset-driven cleanup with rule toggles, reusable local policy packs (import/export), explicit signed-pack verification dialogs, shared saved key-hint profiles, JSON-aware masking, batch file processing, safe-share bundle export, and broader format handling in CLI (`text/json/ndjson/csv/xml/yaml`).
- Metadata Inspector: local metadata parsing (JPEG/TIFF EXIF, PNG/WebP/GIF metadata hints), compatibility diagnostics, clean image re-encoding with before/after preview and resize options, plus CLI workflows for PDF and Office metadata cleanup.
- Encrypt / Decrypt: versioned `NULLID:ENC:1` envelope using PBKDF2 + AES-GCM with text/file support and selectable KDF profiles (`compat`, `strong`, `paranoid`).
- Password & Passphrase: random generators with entropy estimates, presets, and copy hygiene support.
- Secure Notes Vault: encrypted notes, auto-lock, panic lock (`Ctrl+Shift+L`), and import/export (plain + encrypted) with integrity metadata, shared key-hint profiles, and explicit verification dialogs for signed snapshots.
- Self-test: operational checks plus browser capability probes (secure context, WebCrypto, IndexedDB, clipboard, service worker, codec support) with remediation hints.
- Installable PWA: install on desktop and mobile (including iOS) with offline app-shell caching and standalone launch.
- Local CLI parity: `hash`, `sanitize`, `sanitize-dir`, `bundle`, `redact`, `enc`, `dec`, `pwgen`, `meta`, `pdf-clean`, `office-clean`, `archive-sanitize`, `precommit`, and `policy-init`.

## Tech Stack
- Frontend: React 18, TypeScript 5, Vite 5
- Cryptography:
  - WebCrypto (`PBKDF2`, `AES-GCM`) for encryption
  - `@noble/hashes` for SHA-1/SHA-256/SHA-512
- Storage:
  - IndexedDB for vault persistence
  - localStorage fallback for restricted environments
- Testing:
  - Node test runner for utility tests
  - Playwright for end-to-end browser coverage

## Architecture
High-level layout:

```text
src/
  components/      # shell, layout, command palette, toasts
  views/           # per-tool UI modules
  utils/           # crypto, hashing, storage, redaction helpers
  hooks/           # persistence and UX hooks
  content/         # guide/help content
  theme/           # tokenized theme system
tests/e2e/         # Playwright tests
scripts/           # custom lint and repo checks
```

Runtime shape:
- `src/App.tsx` manages active module, command palette, theming, status, and global actions.
- Tool behavior is implemented in `src/views/*` and backed by isolated utilities in `src/utils/*`.
- Persistent preferences use localStorage keys under `nullid:*`; vault data is stored separately in IndexedDB.
- No runtime API client exists; all processing is local to the browser tab.

## Quick Start
Requirements:
- Node.js 18+ (or newer LTS)
- npm

Install and run:

```bash
npm ci
npm run dev
```

Default dev URL:
- `http://127.0.0.1:4173` (Playwright target)

Validation run:

```bash
npm run validate
```

Local CLI (no server/services):

```bash
npm run cli -- help
```

## Configuration
Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_BASE` | `/` | Base path for Vite builds (set this for subpath hosting such as GitHub Pages). |
| `PW_REUSE_SERVER` | unset | If set to `1`, Playwright reuses an already running dev server. |

Local persisted app state:
- UI/tool preferences are stored under `nullid:*` localStorage keys.
- Vault content and metadata are stored in IndexedDB (`nullid-vault`) with automatic localStorage fallback if IndexedDB is unavailable.

## Scripts
Available npm scripts:

| Script | Command | Description |
| --- | --- | --- |
| `npm run dev` | `vite` | Start local dev server. |
| `npm run cli` | `node scripts/nullid-local.mjs` | Run local CLI workflows (`hash`, `sanitize`, `sanitize-dir`, `bundle`, `redact`, `enc`, `dec`, `pwgen`, `meta`, `precommit`, `policy-init`) without external services. |
| `npm run build` | `tsc -b && vite build && node scripts/generate-sbom.mjs dist/sbom.json && node scripts/generate-build-manifest.mjs` | Type-check, build production assets, generate deterministic SBOM (`dist/sbom.json`), and generate deterministic `deploy-manifest.json` + `SHA256SUMS`. |
| `npm run verify:build` | `node scripts/verify-build-manifest.mjs` | Verify all built file hashes/sizes against the manifest. |
| `npm run build:repro` | `npm run build && npm run verify:build` | Build and immediately verify reproducible static artifact integrity. |
| `npm run sbom` | `node scripts/generate-sbom.mjs` | Generate lockfile-based SBOM JSON for dependency inventory. |
| `npm run setup:precommit` | `node scripts/install-precommit.mjs` | Install `.git/hooks/pre-commit` helper for local NullID sanitize/redact enforcement. |
| `npm run release:bundle` | `node scripts/package-release.mjs` | Package signed-release inputs in `release/` (dist tarball + checksum/manifest/SBOM assets). |
| `npm run release:verify` | `node scripts/verify-release-bundle.mjs` | Verify bundled release artifacts against generated release checksums. |
| `npm run desktop:init` | `node scripts/tauri-init.mjs` | Bootstrap `desktop/tauri` packaging path (Tauri v2 scaffold). |
| `npm run assets:brand` | `node scripts/generate-brand-assets.mjs` | Regenerate social preview and app icon assets from the shared brand template. |
| `npm run preview` | `vite preview` | Preview the production build locally. |
| `npm run typecheck` | `tsc -b` | Run TypeScript project checks. |
| `npm run lint` | `node scripts/lint.js` | Enforce offline policy by scanning for disallowed network patterns. |
| `npm run test` | `tsc -p tsconfig.test.json && node --test build-test/__tests__/*.js` | Compile and run utility unit tests. |
| `npm run e2e` | `playwright test` | Execute browser end-to-end tests. |
| `npm run validate` | `npm run typecheck && npm run lint && npm run test && npm run e2e && npm run build && npm run verify:build` | Full validation pipeline. |

Team enforcement helpers:
- Commit `nullid.policy.json` as the workspace baseline used by CLI merge rules.
- Install local enforcement with `npm run setup:precommit`.
- Reuse CI templates from `.github/workflow-templates/nullid-pr-sanitize.yml` and `.github/workflow-templates/nullid-artifact-checks.yml`.
- Platform-breadth workflow reference: `docs/phase3-workflows.md`.
- Signed release + provenance workflow: `.github/workflows/release-signed.yml`.
- Pages workflow runs validation/build checks on PRs and only deploys on `main` push.
- Signed export/import operating conventions: `docs/signed-workflow-conventions.md`.
- Release-candidate security checklist: `docs/release-security-checklist.md`.

## Deployment
NullID is a static frontend deployment:

1. Build:
   ```bash
   npm ci
   SOURCE_DATE_EPOCH=1735689600 npm run build
   ```
2. Verify build reproducibility metadata:
   ```bash
   npm run verify:build
   ```
3. Publish the `dist/` folder to any static host (GitHub Pages, Netlify, Vercel static output, S3 + CDN, etc.).
4. Serve over HTTPS so service workers and install prompts work reliably in browsers.
5. If deploying to a repository subpath, set `VITE_BASE` during build. Example:
   ```bash
   SOURCE_DATE_EPOCH=1735689600 VITE_BASE=/your-repo-name/ npm run build
   ```

Reproducibility guidance:
- Use `npm ci` (lockfile install) and a pinned Node runtime across environments.
- Keep `SOURCE_DATE_EPOCH` fixed for byte-for-byte comparable manifests.
- Compare `dist/SHA256SUMS` across CI/local builds to confirm parity.
- Commit and maintain `nullid.policy.json` for deterministic workspace sanitize baseline merges (`strict-override` or `prefer-stricter`).

## Security/Quality Notes
- Offline-first by design: there is no runtime API integration, and lint checks scan `src/` for disallowed `fetch`/HTTP usage.
- Encryption envelope format is explicit and versioned (`NULLID:ENC:1`) with authenticated encryption (AES-GCM + AAD) and configurable PBKDF2 strength profiles for encryption.
- Vault keys are derived from passphrases using PBKDF2; vault operations include canary verification and lock/wipe flows.
- Clipboard copy helpers include best-effort auto-clear behavior to reduce residue after copying sensitive outputs.
- Sanitizer policy packs, batch runs, and safe-share bundles are fully local and do not require paid infrastructure; signed packs support explicit verify-before-import.
- Build outputs now include `dist/sbom.json`; reproducibility checks still validate full artifact integrity via `SHA256SUMS`.
- Release workflow includes keyless Sigstore signatures and GitHub provenance attestations for packaged release artifacts.
- Quality gates include unit tests (`cryptoEnvelope`, hash behavior, profile integrity, vault snapshot integrity, redaction overlap, theme contrast), Playwright e2e coverage, and module-specific mobile visual regression snapshots (run when platform baselines are present under `tests/e2e/app.spec.ts-snapshots/`).
- This project is not represented as an externally audited cryptography product; validate threat model and controls before high-risk production use.

## Roadmap
- [x] Continue hardening metadata parsing against malformed edge files and uncommon vendor tags.
- [x] Expand signed export UX beyond prompts (saved key-hint profiles + explicit verification dialogs).
- [x] Add visual regression snapshots for module-specific mobile layouts.
- [x] Continue complete-tool rollout tracked in `docs/complete-tool-roadmap.md`.
