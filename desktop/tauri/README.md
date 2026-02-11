# NullID Desktop (Tauri Path)

This folder is a bootstrap for packaging NullID as a desktop app with Tauri.

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

## Security note
Keep NullID's offline-first stance: avoid adding network permissions/capabilities unless explicitly required.
