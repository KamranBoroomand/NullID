# NullID
Offline-first security toolbox for hashing, redaction, sanitization, encryption, and secure local notes, all running entirely in the browser.

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

## Core Features
- Hash & Verify: SHA-256, SHA-512, and SHA-1 (legacy) for text and files, plus digest comparison and multiple output formats.
- Text Redaction: detector-based masking for common PII/secrets with custom regex rules and overlap-safe resolution.
- Log Sanitizer: preset-driven log cleanup with rule toggles, diff preview, JSON-aware masking, and downloadable output.
- Metadata Inspector: local metadata parsing (JPEG/TIFF EXIF, PNG/WebP/GIF metadata hints), compatibility diagnostics, and clean image re-encoding with before/after preview and resize options.
- Encrypt / Decrypt: versioned `NULLID:ENC:1` envelope using PBKDF2 + AES-GCM with text/file support.
- Password & Passphrase: random generators with entropy estimates, presets, and copy hygiene support.
- Secure Notes Vault: encrypted notes, auto-lock, panic lock (`Ctrl+Shift+L`), and import/export (plain + encrypted) with integrity metadata and optional signing.
- Self-test: operational checks plus browser capability probes (secure context, WebCrypto, IndexedDB, clipboard, service worker, codec support) with remediation hints.
- Installable PWA: install on desktop and mobile (including iOS) with offline app-shell caching and standalone launch.

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
| `npm run build` | `tsc -b && vite build && node scripts/generate-build-manifest.mjs` | Type-check, build production assets, and generate deterministic `deploy-manifest.json` + `SHA256SUMS`. |
| `npm run verify:build` | `node scripts/verify-build-manifest.mjs` | Verify all built file hashes/sizes against the manifest. |
| `npm run build:repro` | `npm run build && npm run verify:build` | Build and immediately verify reproducible static artifact integrity. |
| `npm run assets:brand` | `node scripts/generate-brand-assets.mjs` | Regenerate social preview and app icon assets from the shared brand template. |
| `npm run preview` | `vite preview` | Preview the production build locally. |
| `npm run typecheck` | `tsc -b` | Run TypeScript project checks. |
| `npm run lint` | `node scripts/lint.js` | Enforce offline policy by scanning for disallowed network patterns. |
| `npm run test` | `tsc -p tsconfig.test.json && node --test build-test/__tests__/*.js` | Compile and run utility unit tests. |
| `npm run e2e` | `playwright test` | Execute browser end-to-end tests. |
| `npm run validate` | `npm run typecheck && npm run lint && npm run test && npm run e2e && npm run build && npm run verify:build` | Full validation pipeline. |

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

## Security/Quality Notes
- Offline-first by design: there is no runtime API integration, and lint checks scan `src/` for disallowed `fetch`/HTTP usage.
- Encryption envelope format is explicit and versioned (`NULLID:ENC:1`) with authenticated encryption (AES-GCM + AAD).
- Vault keys are derived from passphrases using PBKDF2; vault operations include canary verification and lock/wipe flows.
- Clipboard copy helpers include best-effort auto-clear behavior to reduce residue after copying sensitive outputs.
- Quality gates include unit tests (`cryptoEnvelope`, hash behavior, profile integrity, vault snapshot integrity, redaction overlap, theme contrast) and Playwright e2e coverage.
- This project is not represented as an externally audited cryptography product; validate threat model and controls before high-risk production use.

## Roadmap
- Continue hardening metadata parsing against malformed edge files and uncommon vendor tags.
- Expand signed export UX beyond prompts (saved key-hint profiles + explicit verification dialogs).
- Add visual regression snapshots for module-specific mobile layouts.
- Add CI workflow to diff `SHA256SUMS` across matrix builds automatically.
