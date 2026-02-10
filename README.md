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
- Metadata Inspector: local EXIF parsing and clean image re-encoding with before/after preview and resize options.
- Encrypt / Decrypt: versioned `NULLID:ENC:1` envelope using PBKDF2 + AES-GCM with text/file support.
- Password & Passphrase: random generators with entropy estimates, presets, and copy hygiene support.
- Secure Notes Vault: encrypted notes, auto-lock, panic lock (`Ctrl+Shift+L`), and import/export (plain + encrypted).
- Self-test: quick checks for crypto roundtrip, file envelope roundtrip, storage backend health, and hash responsiveness.

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
| `npm run build` | `tsc -b && vite build` | Type-check and build production assets to `dist/`. |
| `npm run preview` | `vite preview` | Preview the production build locally. |
| `npm run typecheck` | `tsc -b` | Run TypeScript project checks. |
| `npm run lint` | `node scripts/lint.js` | Enforce offline policy by scanning for disallowed network patterns. |
| `npm run test` | `tsc -p tsconfig.test.json && node --test build-test/__tests__/*.js` | Compile and run utility unit tests. |
| `npm run e2e` | `playwright test` | Execute browser end-to-end tests. |
| `npm run validate` | `npm run typecheck && npm run lint && npm run test && npm run e2e && npm run build` | Full validation pipeline. |

## Deployment
NullID is a static frontend deployment:

1. Build:
   ```bash
   npm run build
   ```
2. Publish the `dist/` folder to any static host (GitHub Pages, Netlify, Vercel static output, S3 + CDN, etc.).
3. If deploying to a repository subpath, set `VITE_BASE` during build. Example:
   ```bash
   VITE_BASE=/your-repo-name/ npm run build
   ```

## Security/Quality Notes
- Offline-first by design: there is no runtime API integration, and lint checks scan `src/` for disallowed `fetch`/HTTP usage.
- Encryption envelope format is explicit and versioned (`NULLID:ENC:1`) with authenticated encryption (AES-GCM + AAD).
- Vault keys are derived from passphrases using PBKDF2; vault operations include canary verification and lock/wipe flows.
- Clipboard copy helpers include best-effort auto-clear behavior to reduce residue after copying sensitive outputs.
- Quality gates include unit tests (`cryptoEnvelope`, hash behavior, redaction overlap, theme contrast) and Playwright e2e coverage.
- This project is not represented as an externally audited cryptography product; validate threat model and controls before high-risk production use.

## Roadmap
- Expand self-test diagnostics with broader browser capability probes and clearer remediation hints.
- Add more import/export integrity checks and optional signed profile/vault metadata.
- Extend metadata cleaning support and compatibility diagnostics for additional image formats.
- Increase automated regression coverage for module-specific edge cases and mobile behavior.
- Improve packaging/documentation for reproducible static deployments across environments.
