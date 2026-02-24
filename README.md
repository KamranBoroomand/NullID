# NullID
Offline-first security toolbox for hashing, redaction, sanitization, encryption, and secure local notes, with matching browser and CLI workflows and no external services.

![NullID preview](./nullid-preview.png)

## Table of Contents
1. [Overview](#overview)
2. [Why NullID](#why-nullid)
3. [Core Capabilities](#core-capabilities)
4. [Tech Stack](#tech-stack)
5. [Quick Start](#quick-start)
6. [CLI Quick Examples](#cli-quick-examples)
7. [Configuration](#configuration)
8. [Scripts](#scripts)
9. [Deployment](#deployment)
10. [Security Model and Limits](#security-model-and-limits)
11. [Quality Gates](#quality-gates)
12. [Project Structure](#project-structure)
13. [Contributing](#contributing)
14. [FAQ](#faq)
15. [Roadmap](#roadmap)
16. [License](#license)

## Overview
NullID is a Vite + React + TypeScript single-page app designed as a local security workbench. It also ships a local Node CLI (`scripts/nullid-local.mjs`) so browser and automation workflows stay aligned.

Focused modules in the app:
- Hash and Verify
- Text Redaction
- Log Sanitizer
- Metadata Inspector
- Encrypt and Decrypt
- Password and Passphrase Generator
- Secure Notes Vault
- Self-test Diagnostics
- Built-in Guide

CLI commands include:
- `hash`
- `sanitize`
- `sanitize-dir`
- `bundle`
- `redact`
- `enc`
- `dec`
- `pwgen`
- `meta`
- `pdf-clean`
- `office-clean`
- `archive-sanitize`
- `precommit`
- `policy-init`

## Why NullID
- Keep sensitive processing local: no runtime API calls or backend requirements.
- Give teams one toolchain for browser usage and terminal automation.
- Preserve reproducibility and release trust with deterministic build metadata (`deploy-manifest.json`, `SHA256SUMS`, `dist/sbom.json`).
- Make operational security tasks faster for incident response, developer logs, and secure note handling.

## Core Capabilities
- Hash and verify: SHA-256, SHA-512, and SHA-1 (legacy) for text/files with digest comparison.
- Text redaction: detector-based masking for common secrets/PII with overlap-safe conflict handling.
- Log sanitization: presets and custom policies, structured-format support (`text/json/ndjson/csv/xml/yaml`), and safe-share bundle export.
- Metadata inspection/cleanup: image metadata parsing with local clean re-encode flows; CLI support for PDF and Office cleanup.
- Encryption and vault workflows: versioned `NULLID:ENC:1` envelopes with authenticated encryption, configurable KDF profiles, and encrypted local vault storage.
- Password storage hashing lab: local salted hash generation/verification with `Argon2id` (recommended), `PBKDF2-SHA256` (compat), and legacy SHA options kept for migrations.
- Secure UX affordances: panic lock (`Ctrl+Shift+L`), unlock rate limiting, optional human-check challenges, optional WebAuthn MFA for vault unlock, clipboard hygiene helpers, signed export/import verification dialogs, and session-cookie signaling.
- Installable PWA: desktop/mobile support with offline app-shell caching.

## Tech Stack
- Frontend: React 18, TypeScript 5, Vite 5
- Cryptography: WebCrypto (`PBKDF2`, `AES-GCM`) and `@noble/hashes`
- Storage: IndexedDB with localStorage fallback
- Testing: Node test runner + Playwright end-to-end coverage
- Packaging path: optional Tauri bootstrap under `desktop/tauri`

## Quick Start
Requirements:
- Node.js 18+ (newer LTS recommended)
- npm

Install dependencies:

```bash
npm ci
```

Run the web app:

```bash
npm run dev
```

Dev URL:
- `http://127.0.0.1:4173`

Run the full validation pipeline:

```bash
npm run validate
```

Check CLI help:

```bash
npm run cli -- help
```

## CLI Quick Examples
Hash a file:

```bash
npm run cli -- hash ./artifact.bin --algo sha512
```

Sanitize one log file:

```bash
npm run cli -- sanitize ./raw.log ./clean.log --preset nginx
```

Sanitize an entire directory with a baseline policy:

```bash
npm run cli -- sanitize-dir ./logs ./logs-clean --baseline ./nullid.policy.json --ext .log,.json --report ./sanitize-report.json
```

Encrypt and decrypt a file:

```bash
npm run cli -- enc ./secret.txt ./secret.enc --pass-env NULLID_PASS --profile strong
npm run cli -- dec ./secret.enc ./secret.decrypted.txt --pass-env NULLID_PASS
```

Initialize team policy baseline:

```bash
npm run cli -- policy-init ./nullid.policy.json --preset nginx
```

## Configuration
Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_BASE` | `/` | Base path for Vite build output (set when hosting under a subpath). |
| `PW_REUSE_SERVER` | unset | If set to `1`, Playwright reuses an existing local dev server. |

Local state behavior:
- UI/tool preferences use `localStorage` keys under `nullid:*`.
- Vault data is stored in IndexedDB (`nullid-vault`) with localStorage fallback in restricted environments.

## Scripts
Primary npm scripts:

| Script | Command | Description |
| --- | --- | --- |
| `npm run dev` | `vite` | Start local dev server (`127.0.0.1:4173`). |
| `npm run cli` | `node scripts/nullid-local.mjs` | Run local CLI workflows. |
| `npm run build` | `tsc -b && vite build && node scripts/generate-sbom.mjs dist/sbom.json && node scripts/generate-build-manifest.mjs` | Type-check, build, and generate SBOM/manifest/checksums. |
| `npm run verify:build` | `node scripts/verify-build-manifest.mjs` | Verify built artifact hashes and sizes. |
| `npm run build:repro` | `npm run build && npm run verify:build` | Build and verify reproducibility metadata in one run. |
| `npm run sbom` | `node scripts/generate-sbom.mjs` | Generate lockfile-based SBOM JSON. |
| `npm run setup:precommit` | `node scripts/install-precommit.mjs` | Install local pre-commit helper for sanitize/redact enforcement. |
| `npm run release:bundle` | `node scripts/package-release.mjs` | Package release inputs into `release/`. |
| `npm run release:verify` | `node scripts/verify-release-bundle.mjs` | Verify packaged release artifacts/checksums. |
| `npm run release:dry-run` | `node scripts/release-dry-run.mjs` | Run release bundle + checksum verification gate before publish. |
| `npm run desktop:init` | `node scripts/tauri-init.mjs` | Bootstrap desktop packaging path (`desktop/tauri`). |
| `npm run desktop:smoke` | `node scripts/desktop-smoke.mjs` | Validate desktop Tauri packaging inputs and compile smoke checks. |
| `npm run assets:brand` | `node scripts/generate-brand-assets.mjs` | Regenerate social/app icon assets from template. |
| `npm run preview` | `vite preview` | Preview production build locally. |
| `npm run typecheck` | `tsc -b` | Run TypeScript project checks. |
| `npm run lint` | `node scripts/lint.js` | Enforce offline policy (no runtime network calls in `src/`). |
| `npm run audit:headers` | `node scripts/verify-security-headers.mjs` | Verify static-host header configs include required security baseline headers. |
| `npm run audit:deps` | `npm audit --audit-level=high` | Run dependency vulnerability audit (network required). |
| `npm run security:check` | `npm run audit:headers && npm run lint && npm run test` | Run local security checks (header baseline + no-network policy + unit tests). |
| `npm run test` | `tsc -p tsconfig.test.json && node --test build-test/__tests__/*.js` | Compile and run utility tests. |
| `npm run e2e` | `playwright test` | Run Playwright end-to-end tests. |
| `npm run test:visual` | `playwright test tests/e2e/visual-regression.spec.ts` | Run desktop visual regression matrix (core modules × light/dark themes). |
| `npm run test:visual:update` | `playwright test tests/e2e/visual-regression.spec.ts --update-snapshots` | Refresh visual snapshot baselines after intentional UI changes. |
| `npm run visual:drift-report` | `node scripts/collect-visual-drift.mjs` | Build drift summary artifacts (`json` + markdown) from Playwright diff output. |
| `npm run test:e2e:i18n-layout` | `playwright test tests/e2e/i18n-layout.spec.ts` | Run RU/FA layout integrity tests. |
| `npm run validate` | `npm run typecheck && npm run lint && npm run test && npm run e2e && npm run build && npm run verify:build` | Full local quality pipeline. |

Team references:
- CI templates: `.github/workflow-templates/nullid-pr-sanitize.yml`, `.github/workflow-templates/nullid-artifact-checks.yml`
- Pages workflow: `.github/workflows/pages.yml`
- Reproducibility workflow: `.github/workflows/reproducibility.yml`
- Visual regression workflow: `.github/workflows/visual-regression.yml`
- Desktop Tauri smoke workflow: `.github/workflows/desktop-tauri-smoke.yml`
- Release dry-run workflow: `.github/workflows/release-dry-run.yml`
- Signed release workflow: `.github/workflows/release-signed.yml`
- Dependency monitoring: `.github/dependabot.yml`
- Platform breadth notes: `docs/phase3-workflows.md`
- Signed workflow conventions: `docs/signed-workflow-conventions.md`
- Release checklist: `docs/release-security-checklist.md`

## Deployment
NullID deploys as static files.

1. Build with deterministic timestamp:
   ```bash
   npm ci
   SOURCE_DATE_EPOCH=1735689600 npm run build
   ```
2. Verify generated artifacts:
   ```bash
   npm run verify:build
   ```
3. Publish `dist/` to any static host (GitHub Pages, Netlify, Vercel static, S3 + CDN, etc.).
4. Serve over HTTPS so service workers and install prompts work correctly.
5. Apply security headers (`Content-Security-Policy`, `X-Content-Type-Options`, etc.) using `public/_headers` or `vercel.json`.
6. For server-backed deployments, set session cookies server-side with `HttpOnly`, `Secure`, and `SameSite=Strict`.
7. For subpath hosting, set `VITE_BASE` at build time:
   ```bash
   SOURCE_DATE_EPOCH=1735689600 VITE_BASE=/your-repo-name/ npm run build
   ```

Reproducibility notes:
- Use `npm ci` and pinned Node versions in all environments.
- Keep `SOURCE_DATE_EPOCH` fixed when comparing outputs.
- Compare `dist/SHA256SUMS` across CI and local builds for parity.
- Maintain committed `nullid.policy.json` when relying on deterministic baseline merges.

## Security Model and Limits
- Offline-first by design: no runtime API client; lint checks scan for disallowed network primitives in `src/`.
- Encryption envelope format is explicit and versioned (`NULLID:ENC:1`) with authenticated encryption (AES-GCM + AAD).
- KDF settings are profile-driven (`compat`, `strong`, `paranoid`) with optional UI/CLI overrides and explicit weak-choice warnings.
- Vault operations use passphrase-derived keys and canary verification.
- Vault unlock can enforce local rate limiting, optional human checks, and optional WebAuthn MFA.
- Session cookie signaling is available in-app with `SameSite=Strict` and `Secure` on HTTPS origins.
- Build/release trust is reinforced by deterministic manifests, checksums, SBOM, and signed release provenance.

Important limits:
- NullID is not represented as an externally audited cryptography product.
- Clipboard history managers and compromised local hosts can still expose data.
- PBKDF2 is CPU-hard, not memory-hard; high-risk deployments may require additional controls.
- `HttpOnly` cookie flags cannot be set from browser JavaScript and must be configured at the server/edge layer.

Security references:
- Threat model draft: `docs/threat-model.md`
- Release security checklist: `docs/release-security-checklist.md`

## Quality Gates
- Unit tests cover crypto envelopes, hashing behavior, policy integrity, vault snapshot integrity, redaction overlap, and theme contrast.
- Playwright covers end-to-end browser behavior.
- RU/FA i18n layout checks catch overflow and clipping regressions.
- Visual snapshots cover desktop core modules in both light/dark theme modes via `tests/e2e/visual-regression.spec.ts`.
- Visual regression CI uploads diff artifacts plus drift summaries and fails on unapproved changes.

## Project Structure
```text
src/
  components/      # shell/layout/interaction primitives
  views/           # tool modules
  utils/           # crypto, hashing, storage, redaction, metadata helpers
  hooks/           # persistence and UI behavior hooks
  content/         # built-in guide content
  theme/           # tokenized theme definitions
scripts/           # CLI and build/release automation
tests/e2e/         # Playwright specs
docs/              # roadmap, threat model, release and workflow docs
desktop/tauri/     # optional desktop packaging path
```

## Contributing
1. Install dependencies with `npm ci`.
2. Run `npm run validate` before opening a PR.
3. Add/update tests for behavior changes.
4. Keep docs and CLI help text aligned with feature changes.
5. If your team uses policy baselines, commit `nullid.policy.json` updates intentionally.

Optional local helper:

```bash
npm run setup:precommit
```

## FAQ
**Why include Quick Start and Deployment in the README?**
They solve different problems: Quick Start helps users run the project now, while Deployment helps maintainers/operators publish a production build safely.

**Can someone just fork instead of building?**
Forking copies source code on GitHub. Running the app, validating behavior, or hosting it still requires build and deploy steps.

**Does NullID send data to external services?**
No runtime service integration is expected. Core processing is local, and lint checks enforce the offline policy in source code.

**Is this intended as certified cryptography software?**
No. It uses standard primitives and includes integrity controls, but it is not presented as externally audited or formally certified.

## Roadmap
Status updated: February 24, 2026.

Current focus:
- [x] Expand visual snapshot matrix to include desktop coverage and theme variants (desktop baseline snapshots exist for each core module and theme mode).
- [x] Add workflow-level visual regression gating with artifact-based drift reporting (CI uploads diff artifacts and fails on unapproved drift).
- [x] Add release dry-run automation that enforces `release:bundle` and `release:verify` before publish (release workflow blocks publish on failed dry-run checks).

Next up:
- [x] Harden `desktop/tauri` packaging with cross-platform smoke tests (macOS, Linux, Windows CI legs).
- [x] Extend `archive-sanitize` reporting with per-file finding summaries and severity totals (JSON report contract plus test coverage).
- [x] Improve signed import/export trust-state visibility for key-hint profiles (UI state labels for unsigned, verified, and mismatch paths).

Completed recently:
- [x] Metadata parsing hardening for malformed edge files and uncommon vendor tags.
- [x] Signed export/import verification dialogs and shared key-hint profile reuse.
- [x] Module-specific mobile visual regression snapshots.
- [x] Deterministic SBOM + build-manifest + checksum verification pipeline.
- [x] Signed release and provenance workflow integration.

Phase-by-phase history and rationale are tracked in `docs/complete-tool-roadmap.md`.

## License
MIT. See `LICENSE`.
