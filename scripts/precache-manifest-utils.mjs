import fs from "node:fs";
import path from "node:path";
import { compareStrings, isSafeRelativePath, resolveInside, sha256Hex } from "./artifact-safety.mjs";

export const PRECACHE_MANIFEST_NAME = "nullid-precache-manifest.json";
export const PRECACHE_MANIFEST_KIND = "nullid-runtime-shell-manifest";
export const PRECACHE_MANIFEST_SCHEMA_VERSION = 2;

const REQUIRED_APP_SHELL_FILES = ["favicon.svg", "index.html", "manifest.webmanifest"];
const OPTIONAL_APP_SHELL_FILES = [
  "nullid-preview.png",
  "brand/nullid-icon-dark.svg",
  "brand/nullid-icon-light.svg",
  "brand/nullid-lockup-dark.svg",
  "brand/nullid-lockup-light.svg",
  "brand/nullid-mark-dark.svg",
  "brand/nullid-mark-light.svg",
  "brand/nullid-wordmark-dark.svg",
  "brand/nullid-wordmark-light.svg",
  "icons/favicon-16.png",
  "icons/favicon-32.png",
  "icons/icon-192.png",
  "icons/icon-256.png",
  "icons/icon-512.png",
  "icons/icon-512-maskable.png",
  "icons/icon.ico",
  "icons/apple-touch-icon.png",
];

export function resolveDistArg(argv) {
  const distFlag = argv.indexOf("--dist");
  if (distFlag >= 0) {
    const value = argv[distFlag + 1];
    if (!value) throw new Error("--dist requires a directory");
    return path.resolve(value);
  }
  return path.resolve(argv[0] || "dist");
}

export function readViteManifest(distDir) {
  const manifestPath = path.join(distDir, ".vite", "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`missing Vite manifest: ${manifestPath}`);
  }
  const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("invalid Vite manifest: expected an object");
  }
  return parsed;
}

export function collectRuntimeAssetsFromViteManifest(manifest) {
  const assets = new Set();
  for (const [key, entry] of Object.entries(manifest)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`invalid Vite manifest entry: ${key}`);
    }
    addRuntimeAsset(assets, entry.file, `file in ${key}`);
    for (const cssAsset of entry.css ?? []) addRuntimeAsset(assets, cssAsset, `css in ${key}`);
    for (const asset of entry.assets ?? []) addRuntimeAsset(assets, asset, `asset in ${key}`);
  }
  return Array.from(assets).sort(compareStrings);
}

export function buildPrecacheManifest(distDir, assets) {
  const runtimeShellAssets = collectRuntimeShellAssets(distDir, assets);
  const entries = runtimeShellAssets.map((asset) => {
    const fullPath = resolveInside(distDir, asset.path, "precache asset");
    const stat = fs.lstatSync(fullPath, { throwIfNoEntry: false });
    if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`precache asset is missing or unsupported: ${asset.path}`);
    }
    const data = fs.readFileSync(fullPath);
    return {
      path: asset.path,
      bytes: data.byteLength,
      sha256: sha256Hex(data),
      required: asset.required,
    };
  });
  const contentHash = sha256Hex(Buffer.from(JSON.stringify(entries), "utf8"));
  return {
    schemaVersion: PRECACHE_MANIFEST_SCHEMA_VERSION,
    kind: PRECACHE_MANIFEST_KIND,
    assetCount: entries.length,
    contentHash,
    assets: entries.map((entry) => entry.path),
    entries,
  };
}

export function readPrecacheManifest(distDir) {
  const manifestPath = path.join(distDir, PRECACHE_MANIFEST_NAME);
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`missing precache manifest: ${manifestPath}`);
  }
  const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("precache manifest must be an object");
  }
  if (parsed.schemaVersion !== PRECACHE_MANIFEST_SCHEMA_VERSION) {
    throw new Error(`precache manifest schemaVersion must be ${PRECACHE_MANIFEST_SCHEMA_VERSION}`);
  }
  if (parsed.kind !== PRECACHE_MANIFEST_KIND) {
    throw new Error(`precache manifest kind must be ${PRECACHE_MANIFEST_KIND}`);
  }
  if (!Array.isArray(parsed.assets) || parsed.assets.some((asset) => typeof asset !== "string" || !isSafeRelativePath(asset))) {
    throw new Error("precache manifest contains invalid assets");
  }
  if (!Array.isArray(parsed.entries)) {
    throw new Error("precache manifest entries must be an array");
  }
  if (!Number.isInteger(parsed.assetCount) || parsed.assetCount !== parsed.entries.length || parsed.assetCount !== parsed.assets.length) {
    throw new Error("precache manifest assetCount must match entries.length and assets.length");
  }
  if (typeof parsed.contentHash !== "string" || !/^[a-f0-9]{64}$/u.test(parsed.contentHash)) {
    throw new Error("precache manifest contentHash must be a SHA-256 hex digest");
  }
  const sorted = [...parsed.assets].sort(compareStrings);
  if (JSON.stringify(sorted) !== JSON.stringify(parsed.assets)) {
    throw new Error("precache manifest assets must be sorted");
  }
  const seenAssets = new Set(parsed.assets);
  if (seenAssets.size !== parsed.assets.length) {
    throw new Error("precache manifest assets must be unique");
  }
  for (const entry of parsed.entries) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("precache manifest entries must be exact objects");
    }
    const keys = Object.keys(entry).sort();
    if (JSON.stringify(keys) !== JSON.stringify(["bytes", "path", "required", "sha256"])) {
      throw new Error("precache manifest entries must have exact path/bytes/sha256/required fields");
    }
    if (typeof entry.path !== "string" || !isSafeRelativePath(entry.path)) {
      throw new Error("precache manifest entry path is invalid");
    }
    if (!Number.isInteger(entry.bytes) || entry.bytes < 0) {
      throw new Error("precache manifest entry bytes is invalid");
    }
    if (typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(entry.sha256)) {
      throw new Error("precache manifest entry sha256 is invalid");
    }
    if (typeof entry.required !== "boolean") {
      throw new Error("precache manifest entry required flag is invalid");
    }
  }
  const entryAssets = parsed.entries.map((entry) => entry.path);
  if (JSON.stringify(entryAssets) !== JSON.stringify(parsed.assets)) {
    throw new Error("precache manifest assets must match entry paths");
  }
  const expectedContentHash = sha256Hex(Buffer.from(JSON.stringify(parsed.entries), "utf8"));
  if (parsed.contentHash !== expectedContentHash) {
    throw new Error("precache manifest contentHash must match entries");
  }
  return parsed;
}

function collectRuntimeShellAssets(distDir, runtimeAssets) {
  const assets = new Map();
  for (const asset of runtimeAssets) {
    if (!isSafeRelativePath(asset)) throw new Error(`unsafe runtime asset: ${String(asset)}`);
    assets.set(asset, { path: asset, required: true });
  }
  for (const file of REQUIRED_APP_SHELL_FILES) {
    const fullPath = resolveInside(distDir, file, "required app-shell asset");
    const stat = fs.lstatSync(fullPath, { throwIfNoEntry: false });
    if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`required app-shell asset is missing or unsupported: ${file}`);
    }
    assets.set(file, { path: file, required: true });
  }
  for (const file of OPTIONAL_APP_SHELL_FILES) {
    const fullPath = resolveInside(distDir, file, "optional app-shell asset");
    const stat = fs.lstatSync(fullPath, { throwIfNoEntry: false });
    if (!stat) continue;
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`optional app-shell asset is unsupported: ${file}`);
    }
    assets.set(file, { path: file, required: false });
  }
  return Array.from(assets.values()).sort((left, right) => compareStrings(left.path, right.path));
}

function addRuntimeAsset(assets, value, context) {
  if (value === undefined) return;
  if (typeof value !== "string" || !isSafeRelativePath(value)) {
    throw new Error(`unsafe Vite manifest ${context}: ${String(value)}`);
  }
  assets.add(value);
}
