# NullID

NullID is an offline-first Vite + React + TypeScript SPA with a terminal-style UI. All tooling ships locally; no runtime network calls or external CDNs.

## Scripts

```bash
npm ci
npm run dev       # start on http://localhost:5173
npm run validate  # typecheck + lint + tests + build (outputs to dist/)
npm run build     # production build (outputs to dist/)
npm run preview   # preview production build
```

## Deploy

- `npm run build` emits the static site to `dist/`.
- For GitHub Pages, the workflow sets `VITE_BASE` to `/${REPO_NAME}/` and publishes `dist/`.

## Clean export checklist

- Install dependencies: `npm ci`
- Validate and build locally: `npm run validate`
- Preview the production bundle: `npm run preview`
- Deploy via GitHub Pages: push to `main`; the Pages workflow publishes `dist/`.
- Zip-ready folder: exclude `node_modules/`, `dist/`, `docs/`, `coverage/`, `build-test/`, `.env*`, and OS/editor artifacts.

## Responsive test checklist

Manually spot-check the UI (minimal page scrolling; internal panels should scroll instead):

- 1280x800 (13" MacBook)
- 1366x768
- 1440x900
- 1920x1080

## Tools: capabilities & limits

- **Hash & Verify**: SHA-256 / SHA-512 / SHA-1 (legacy). Text + chunked file hashing, hex/base64/`sha256sum` output, verify mode (case/whitespace-tolerant).
- **Password Generator**: Uses `crypto.getRandomValues` + rejection sampling. Presets (high security, no symbols, PIN), ambiguity toggle, accurate entropy display, copy-to-clipboard with toast.
- **Passphrase Generator**: Local 7,776-entry diceware-style list (offline), configurable word count/separators, optional casing/digit/symbol injection, entropy shown.
- **Encrypt / Decrypt**: Versioned envelope (`NULLID:ENC:1`) with PBKDF2 + AES-GCM (AAD bound). Text and file sealing, `.nullid` download, clean failure on bad passphrase, optional auto-clear timer.
- **Secure Notes (Vault)**: IndexedDB-backed, PBKDF2-derived vault key + AES-GCM per note. Unlock required to view; titles/bodies encrypted; canary check, auto-lock timer, export/import, wipe.
- **Metadata Inspector**: EXIF parse for common images (JPEG/PNG/WebP). HEIC and non-images are called out as unsupported. Canvas re-encode to strip metadata; before/after fields and removed keys listed.
- **Text Redaction**: Preset detectors (email/phone/IP/token/ID), highlight view, full/partial mask modes, custom regex rules with validation, copy/download outputs.
- **Log Sanitizer**: Presets for nginx/apache/auth/JSON logs, rule toggles, replacement counts + lines changed report, token-level diff highlighting.

## Safety & offline checks

- No runtime network traffic: verify with `rg "fetch" src` or devtools network tab (should stay empty).
- Cryptography uses WebCrypto + local dependencies; no analytics, fonts, or CDN assets.
- “Wipe data” clears local storage and IndexedDB vault content.
