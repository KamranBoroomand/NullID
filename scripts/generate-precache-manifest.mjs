#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  PRECACHE_MANIFEST_NAME,
  buildPrecacheManifest,
  collectRuntimeAssetsFromViteManifest,
  readViteManifest,
  resolveDistArg,
} from "./precache-manifest-utils.mjs";

try {
  const distDir = resolveDistArg(process.argv.slice(2));
  const viteManifest = readViteManifest(distDir);
  const assets = collectRuntimeAssetsFromViteManifest(viteManifest);
  const manifest = buildPrecacheManifest(distDir, assets);
  fs.writeFileSync(path.join(distDir, PRECACHE_MANIFEST_NAME), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`[precache] manifest written (${manifest.assetCount} runtime-shell assets)`);
} catch (error) {
  console.error(`[precache] ${error instanceof Error ? error.message : "manifest generation failed"}`);
  process.exit(1);
}
