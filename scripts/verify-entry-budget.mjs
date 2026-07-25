#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { isSafeRelativePath, resolveInside } from "./artifact-safety.mjs";

const distDir = path.resolve(process.argv[2] || "dist");

try {
  const maxEntryBytes = readBudget(process.env.NULLID_ENTRY_BUDGET_BYTES);
  const indexPath = path.join(distDir, "index.html");
  if (!fs.existsSync(indexPath)) {
    throw new Error(`missing built index: ${indexPath}`);
  }

  const html = fs.readFileSync(indexPath, "utf8");
  const entryScripts = extractModuleScriptPaths(html);
  if (entryScripts.length === 0) {
    throw new Error("no module entry scripts found in dist/index.html");
  }
  const modulePreloads = extractModulePreloadPaths(html);
  const manifest = readViteManifest(distDir);

  const initialGraph = collectInitialJavaScriptGraph(manifest, entryScripts, modulePreloads);
  const measured = initialGraph.map((entryPath) => {
    const fullPath = resolveInside(distDir, entryPath, "initial JavaScript asset");
    const stat = fs.lstatSync(fullPath, { throwIfNoEntry: false });
    if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`initial JavaScript asset is missing or unsupported: ${entryPath}`);
    }
    const bytes = fs.readFileSync(fullPath);
    return {
      path: entryPath,
      rawBytes: stat.size,
      gzipBytes: zlib.gzipSync(bytes).byteLength,
      brotliBytes: zlib.brotliCompressSync(bytes).byteLength,
    };
  });

  const totals = measured.reduce(
    (acc, entry) => ({
      rawBytes: acc.rawBytes + entry.rawBytes,
      gzipBytes: acc.gzipBytes + entry.gzipBytes,
      brotliBytes: acc.brotliBytes + entry.brotliBytes,
    }),
    { rawBytes: 0, gzipBytes: 0, brotliBytes: 0 },
  );
  if (totals.rawBytes > maxEntryBytes) {
    const details = measured.map((entry) => `${entry.path}=${formatBytes(entry.rawBytes)}`).join(", ");
    throw new Error(
      `initial JavaScript graph budget exceeded (${formatBytes(totals.rawBytes)} raw; max ${formatBytes(maxEntryBytes)}): ${details}`,
    );
  }

  const summary = measured.map((entry) => `${entry.path}=${formatBytes(entry.rawBytes)}`).join(", ");
  console.log(
    `[budget] initial JavaScript graph budget passed (raw ${formatBytes(totals.rawBytes)}, gzip ${formatBytes(totals.gzipBytes)}, brotli ${formatBytes(totals.brotliBytes)}; files: ${summary}; max ${formatBytes(maxEntryBytes)})`,
  );
} catch (error) {
  console.error(`[budget] ${error instanceof Error ? error.message : "entry budget verification failed"}`);
  process.exit(1);
}

function readBudget(value) {
  if (!value) return 500 * 1024;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error("NULLID_ENTRY_BUDGET_BYTES must be a positive integer");
  }
  return parsed;
}

function extractModuleScriptPaths(html) {
  const scripts = [];
  const scriptRe = /<script\b[^>]*\btype=(["'])module\1[^>]*>/giu;
  for (const match of html.matchAll(scriptRe)) {
    const tag = match[0];
    const srcMatch = tag.match(/\bsrc=(["'])([^"']+)\1/iu);
    if (!srcMatch) continue;
    const relPath = normalizeBuiltAssetPath(srcMatch[2]);
    if (!relPath) continue;
    scripts.push(relPath);
  }
  return scripts;
}

function extractModulePreloadPaths(html) {
  const scripts = [];
  const preloadRe = /<link\b[^>]*\brel=(["'])modulepreload\1[^>]*>/giu;
  for (const match of html.matchAll(preloadRe)) {
    const tag = match[0];
    const hrefMatch = tag.match(/\bhref=(["'])([^"']+)\1/iu);
    if (!hrefMatch) continue;
    const relPath = normalizeBuiltAssetPath(hrefMatch[2]);
    if (!relPath || !isJavaScriptAsset(relPath)) continue;
    scripts.push(relPath);
  }
  return scripts;
}

function readViteManifest(rootDir) {
  const manifestPath = path.join(rootDir, ".vite", "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`missing Vite manifest: ${manifestPath}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new Error(`invalid Vite manifest: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("invalid Vite manifest: expected an object");
  }
  return parsed;
}

function collectInitialJavaScriptGraph(manifest, entryScripts, modulePreloads) {
  const byFile = new Map();
  for (const [key, entry] of Object.entries(manifest)) {
    if (isManifestEntry(entry) && typeof entry.file === "string") {
      byFile.set(entry.file, key);
    }
  }

  const visitedManifestKeys = new Set();
  const files = new Set();
  const visitManifestKey = (key) => {
    if (visitedManifestKeys.has(key)) return;
    const entry = manifest[key];
    if (!isManifestEntry(entry)) {
      throw new Error(`invalid Vite manifest entry: ${key}`);
    }
    visitedManifestKeys.add(key);
    if (isJavaScriptAsset(entry.file)) {
      files.add(assertSafeBuiltAssetPath(entry.file));
    }
    for (const importedKey of entry.imports ?? []) {
      if (typeof importedKey !== "string") {
        throw new Error(`invalid Vite manifest import in ${key}`);
      }
      visitManifestKey(importedKey);
    }
  };

  for (const entryPath of entryScripts) {
    const manifestKey = byFile.get(entryPath);
    if (!manifestKey) {
      throw new Error(`entry script is missing from Vite manifest: ${entryPath}`);
    }
    visitManifestKey(manifestKey);
  }

  for (const preloadPath of modulePreloads) {
    const manifestKey = byFile.get(preloadPath);
    if (manifestKey) {
      visitManifestKey(manifestKey);
    } else {
      files.add(assertSafeBuiltAssetPath(preloadPath));
    }
  }

  return Array.from(files).sort();
}

function isManifestEntry(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (typeof value.file !== "string") return false;
  if (value.imports !== undefined && (!Array.isArray(value.imports) || value.imports.some((entry) => typeof entry !== "string"))) {
    return false;
  }
  return true;
}

function normalizeBuiltAssetPath(value) {
  let pathname;
  try {
    pathname = new URL(value, "https://nullid.local/").pathname;
  } catch {
    return null;
  }
  const assetIndex = pathname.indexOf("/assets/");
  const relPath = decodeURIComponent(assetIndex >= 0 ? pathname.slice(assetIndex + 1) : pathname.replace(/^\/+/, ""));
  if (!isSafeRelativePath(relPath)) {
    throw new Error(`unsafe entry script path: ${value}`);
  }
  return assertSafeBuiltAssetPath(relPath);
}

function assertSafeBuiltAssetPath(relPath) {
  if (!isSafeRelativePath(relPath)) {
    throw new Error(`unsafe built asset path: ${relPath}`);
  }
  return relPath;
}

function isJavaScriptAsset(relPath) {
  return /\.m?js$/iu.test(relPath);
}

function formatBytes(bytes) {
  return `${(bytes / 1024).toFixed(1)} KiB`;
}
