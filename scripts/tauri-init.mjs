#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const desktopRoot = path.resolve(root, "desktop", "tauri");
const srcTauriRoot = path.join(desktopRoot, "src-tauri");
const force = process.argv.includes("--force");

if (fs.existsSync(desktopRoot) && !force) {
  console.error(`[tauri-init] ${path.relative(root, desktopRoot)} already exists (use --force to overwrite)`);
  process.exit(1);
}

if (force && fs.existsSync(desktopRoot)) {
  fs.rmSync(desktopRoot, { recursive: true, force: true });
}

fs.mkdirSync(srcTauriRoot, { recursive: true });

const tauriConf = {
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "NullID",
  "version": "0.1.0",
  "identifier": "com.nullid.app",
  "build": {
    "beforeDevCommand": "npm run dev -- --host 127.0.0.1 --port 4173",
    "beforeBuildCommand": "npm run build",
    "frontendDist": "../../dist",
    "devUrl": "http://127.0.0.1:4173"
  },
  "app": {
    "windows": [
      {
        "title": "NullID",
        "width": 1280,
        "height": 860,
        "resizable": true
      }
    ]
  },
  "bundle": {
    "active": false,
    "targets": "all",
    "icon": [
      "../../public/icons/icon-192.png",
      "../../public/icons/icon-512.png"
    ]
  }
};

const cargoToml = `[package]
name = "nullid-desktop"
version = "0.1.0"
edition = "2021"

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[features]
default = ["custom-protocol"]
custom-protocol = ["tauri/custom-protocol"]
`;

const mainRs = `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
`;

const buildRs = `fn main() {
    tauri_build::build()
}
`;

const readme = `# NullID Desktop (Tauri Path)

This folder is a bootstrap for packaging NullID as a desktop app with Tauri.

## Prerequisites
- Rust toolchain
- Tauri system dependencies (platform-specific)
- Node.js + npm

## Suggested first run
1. Install Tauri CLI (workspace level):\n   \`npm i -D @tauri-apps/cli\`
2. Build web assets:\n   \`npm run build\`
3. Run desktop dev:\n   \`npx tauri dev --config desktop/tauri/src-tauri/tauri.conf.json\`

## Security note
Keep NullID's offline-first stance: avoid adding network permissions/capabilities unless explicitly required.
`;

const gitignore = `target/
Cargo.lock
`;

fs.writeFileSync(path.join(srcTauriRoot, "tauri.conf.json"), `${JSON.stringify(tauriConf, null, 2)}\n`, "utf8");
fs.writeFileSync(path.join(srcTauriRoot, "Cargo.toml"), cargoToml, "utf8");
fs.writeFileSync(path.join(srcTauriRoot, "build.rs"), buildRs, "utf8");
fs.mkdirSync(path.join(srcTauriRoot, "src"), { recursive: true });
fs.writeFileSync(path.join(srcTauriRoot, "src", "main.rs"), mainRs, "utf8");
fs.writeFileSync(path.join(desktopRoot, "README.md"), readme, "utf8");
fs.writeFileSync(path.join(srcTauriRoot, ".gitignore"), gitignore, "utf8");

console.log(`[tauri-init] scaffolded ${path.relative(root, desktopRoot)}`);
