# NullID Desktop Bootstrap

This folder is an optional experimental bootstrap for packaging NullID with Tauri. It is not part of the supported browser/PWA and local Node CLI release scope.

`src-tauri/tauri.conf.json` currently sets `bundle.active` to `false`, so this repository does not ship a supported native desktop distribution.

## Prerequisites

- Rust toolchain
- Tauri system dependencies (platform-specific)
- Node.js + npm

## Suggested first run

1. Install Tauri CLI (workspace level):
   `npm i -D @tauri-apps/cli`
2. Build web assets:
   `npm run build`
3. Run desktop dev:
   `npx tauri dev --config desktop/tauri/src-tauri/tauri.conf.json`

Run the smoke check only when validating a future desktop-binary release:

```bash
npm run desktop:smoke
```

## Security note

Keep NullID's local-first stance: avoid adding network permissions or capabilities unless a future desktop release explicitly requires them and documents the new trust boundary.
