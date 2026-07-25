#!/usr/bin/env node
import {
  buildPrecacheManifest,
  collectRuntimeAssetsFromViteManifest,
  readPrecacheManifest,
  readViteManifest,
  resolveDistArg,
} from "./precache-manifest-utils.mjs";

try {
  const distDir = resolveDistArg(process.argv.slice(2));
  const expectedAssets = collectRuntimeAssetsFromViteManifest(readViteManifest(distDir));
  const expected = buildPrecacheManifest(distDir, expectedAssets);
  const actual = readPrecacheManifest(distDir);

  if (JSON.stringify(actual.assets) !== JSON.stringify(expected.assets)) {
    throw new Error("precache manifest asset list does not match the runtime shell graph");
  }
  if (actual.contentHash !== expected.contentHash) {
    throw new Error("precache manifest contentHash does not match runtime shell bytes");
  }
  console.log(`[precache] manifest verified (${actual.assetCount} runtime-shell assets)`);
} catch (error) {
  console.error(`[precache] ${error instanceof Error ? error.message : "manifest verification failed"}`);
  process.exit(1);
}
