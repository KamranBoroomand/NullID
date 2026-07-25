import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

describe("service-worker precache manifest generation", () => {
  it("includes every runtime asset from the Vite dependency graph deterministically", () => {
    const distDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-precache-manifest-"));
    try {
      fs.mkdirSync(path.join(distDir, ".vite"), { recursive: true });
      fs.mkdirSync(path.join(distDir, "assets"), { recursive: true });
      const runtimeAssets = [
        "assets/index.js",
        "assets/index.css",
        "assets/react-vendor.js",
        "assets/HashView.js",
        "assets/HashView.css",
        "assets/hash.js",
        "assets/runtimePhraseTranslations.js",
        "assets/workflowPhraseTranslations.js",
      ];
      const shellAssets = [
        "brand/nullid-mark-dark.svg",
        "favicon.svg",
        "icons/icon-192.png",
        "index.html",
        "manifest.webmanifest",
      ];
      runtimeAssets.forEach((asset) => fs.writeFileSync(path.join(distDir, asset), `asset:${asset}`));
      shellAssets.forEach((asset) => {
        fs.mkdirSync(path.dirname(path.join(distDir, asset)), { recursive: true });
        fs.writeFileSync(path.join(distDir, asset), `shell:${asset}`);
      });
      fs.writeFileSync(path.join(distDir, "sbom.json"), "{}");
      fs.writeFileSync(path.join(distDir, "deploy-manifest.json"), "{}");
      fs.writeFileSync(path.join(distDir, "SHA256SUMS"), "");
      fs.writeFileSync(
        path.join(distDir, ".vite", "manifest.json"),
        JSON.stringify({
          "index.html": {
            file: "assets/index.js",
            isEntry: true,
            css: ["assets/index.css"],
            imports: ["_react-vendor.js"],
            dynamicImports: [
              "src/views/HashView.tsx",
              "src/content/runtimePhraseTranslations.ts",
              "src/content/workflowPhraseTranslations.ts",
            ],
          },
          "_react-vendor.js": {
            file: "assets/react-vendor.js",
          },
          "src/views/HashView.tsx": {
            file: "assets/HashView.js",
            css: ["assets/HashView.css"],
            imports: ["src/utils/hash.ts"],
          },
          "src/utils/hash.ts": {
            file: "assets/hash.js",
          },
          "src/content/runtimePhraseTranslations.ts": {
            file: "assets/runtimePhraseTranslations.js",
            isDynamicEntry: true,
          },
          "src/content/workflowPhraseTranslations.ts": {
            file: "assets/workflowPhraseTranslations.js",
            isDynamicEntry: true,
          },
        }),
      );

      execFileSync(process.execPath, ["scripts/generate-precache-manifest.mjs", "--dist", distDir], { stdio: "pipe" });

      const manifest = JSON.parse(fs.readFileSync(path.join(distDir, "nullid-precache-manifest.json"), "utf8")) as {
        schemaVersion: number;
        kind: string;
        assets: string[];
        entries: Array<{ path: string; bytes: number; sha256: string; required: boolean }>;
        assetCount: number;
        contentHash: string;
      };
      const expectedAssets = [...runtimeAssets, ...shellAssets].sort();
      assert.equal(manifest.schemaVersion, 2);
      assert.equal(manifest.kind, "nullid-runtime-shell-manifest");
      assert.equal(manifest.assetCount, expectedAssets.length);
      assert.match(manifest.contentHash, /^[a-f0-9]{64}$/);
      assert.deepEqual(manifest.assets, expectedAssets);
      assert.deepEqual(manifest.entries.map((entry) => entry.path), expectedAssets);
      assert.equal(manifest.entries.every((entry) => entry.bytes > 0 && /^[a-f0-9]{64}$/u.test(entry.sha256)), true);
      assert.equal(manifest.entries.find((entry) => entry.path === "index.html")?.required, true);
      assert.equal(manifest.assets.includes("sbom.json"), false);
      assert.equal(manifest.assets.includes("deploy-manifest.json"), false);
      assert.equal(manifest.assets.includes("SHA256SUMS"), false);
    } finally {
      fs.rmSync(distDir, { recursive: true, force: true });
    }
  });

  it("derives the service-worker identity from runtime and app-shell content bytes", () => {
    const distA = createRuntimeShellDist("NullID A");
    const distChangedShell = createRuntimeShellDist("NullID B");
    try {
      for (const distDir of [distA, distChangedShell]) {
        execFileSync(process.execPath, ["scripts/generate-precache-manifest.mjs", "--dist", distDir], { stdio: "pipe" });
        execFileSync(process.execPath, ["scripts/write-build-info.mjs", distDir], {
          stdio: "pipe",
          env: { ...process.env, VITE_BUILD_ID: "same-commit", SOURCE_DATE_EPOCH: "1735689600" },
        });
      }

      const manifestA = JSON.parse(fs.readFileSync(path.join(distA, "nullid-precache-manifest.json"), "utf8")) as { contentHash: string };
      const manifestChangedShell = JSON.parse(fs.readFileSync(path.join(distChangedShell, "nullid-precache-manifest.json"), "utf8")) as { contentHash: string };
      const swA = fs.readFileSync(path.join(distA, "sw.js"), "utf8");
      const swChangedShell = fs.readFileSync(path.join(distChangedShell, "sw.js"), "utf8");

      assert.notEqual(manifestA.contentHash, manifestChangedShell.contentHash);
      assert.notEqual(swA, swChangedShell);
    } finally {
      fs.rmSync(distA, { recursive: true, force: true });
      fs.rmSync(distChangedShell, { recursive: true, force: true });
    }
  });

  it("stamps service-worker cache identity from runtime and worker-template content", () => {
    const distA = createStampedDist("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const distSameRuntime = createStampedDist("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const distChangedRuntime = createStampedDist("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    try {
      execFileSync(process.execPath, ["scripts/write-build-info.mjs", distA], {
        stdio: "pipe",
        env: { ...process.env, VITE_BUILD_ID: "commit-a", SOURCE_DATE_EPOCH: "1735689600" },
      });
      execFileSync(process.execPath, ["scripts/write-build-info.mjs", distSameRuntime], {
        stdio: "pipe",
        env: { ...process.env, VITE_BUILD_ID: "commit-b", SOURCE_DATE_EPOCH: "1735689600" },
      });
      execFileSync(process.execPath, ["scripts/write-build-info.mjs", distChangedRuntime], {
        stdio: "pipe",
        env: { ...process.env, VITE_BUILD_ID: "commit-a", SOURCE_DATE_EPOCH: "1735689600" },
      });

      const swA = fs.readFileSync(path.join(distA, "sw.js"), "utf8");
      const swSameRuntime = fs.readFileSync(path.join(distSameRuntime, "sw.js"), "utf8");
      const swChangedRuntime = fs.readFileSync(path.join(distChangedRuntime, "sw.js"), "utf8");

      assert.match(extractCacheVersion(swA), /^precache-[a-f0-9]{32}$/);
      assert.equal(swA.includes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), true);
      assert.equal(swA, swSameRuntime);
      assert.notEqual(swA, swChangedRuntime);
      assert.notEqual(extractCacheVersion(swA), extractCacheVersion(swChangedRuntime));
      assert.equal(swA.includes("commit-a"), false);
      assert.equal(swSameRuntime.includes("commit-b"), false);
    } finally {
      fs.rmSync(distA, { recursive: true, force: true });
      fs.rmSync(distSameRuntime, { recursive: true, force: true });
      fs.rmSync(distChangedRuntime, { recursive: true, force: true });
    }
  });

  it("changes the stamped cache identity when only the service-worker template changes", () => {
    const runtimeHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const distA = createStampedDist(runtimeHash, "worker logic A");
    const distWorkerOnly = createStampedDist(runtimeHash, "worker logic B");
    try {
      for (const distDir of [distA, distWorkerOnly]) {
        execFileSync(process.execPath, ["scripts/write-build-info.mjs", distDir], {
          stdio: "pipe",
          env: { ...process.env, VITE_BUILD_ID: "same-commit", SOURCE_DATE_EPOCH: "1735689600" },
        });
      }

      const swA = fs.readFileSync(path.join(distA, "sw.js"), "utf8");
      const swWorkerOnly = fs.readFileSync(path.join(distWorkerOnly, "sw.js"), "utf8");

      assert.notEqual(extractCacheVersion(swA), extractCacheVersion(swWorkerOnly));
      assert.notEqual(swA, swWorkerOnly);
    } finally {
      fs.rmSync(distA, { recursive: true, force: true });
      fs.rmSync(distWorkerOnly, { recursive: true, force: true });
    }
  });
});

function createRuntimeShellDist(shellMarker: string) {
  const distDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-runtime-shell-"));
  fs.mkdirSync(path.join(distDir, ".vite"), { recursive: true });
  fs.mkdirSync(path.join(distDir, "assets"), { recursive: true });
  fs.writeFileSync(path.join(distDir, "assets", "index.js"), "console.log('runtime');");
  fs.writeFileSync(path.join(distDir, "index.html"), `<div>${shellMarker}</div><script type="module" src="/assets/index.js"></script>`);
  fs.writeFileSync(path.join(distDir, "manifest.webmanifest"), JSON.stringify({ name: shellMarker }));
  fs.writeFileSync(path.join(distDir, "favicon.svg"), `<svg><title>${shellMarker}</title></svg>`);
  fs.writeFileSync(
    path.join(distDir, ".vite", "manifest.json"),
    JSON.stringify({
      "index.html": {
        file: "assets/index.js",
        isEntry: true,
      },
    }),
  );
  fs.copyFileSync(path.resolve("public", "sw.js"), path.join(distDir, "sw.js"));
  return distDir;
}

function createStampedDist(contentHash: string, workerMarker = "worker logic") {
  const distDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-sw-stamp-"));
  fs.writeFileSync(
    path.join(distDir, "nullid-precache-manifest.json"),
    `${JSON.stringify(
      {
        schemaVersion: 2,
        kind: "nullid-runtime-shell-manifest",
        assetCount: 1,
        contentHash,
        assets: ["assets/index.js"],
        entries: [{ path: "assets/index.js", bytes: 1, sha256: "0".repeat(64), required: true }],
      },
      null,
      2,
    )}\n`,
  );
  fs.writeFileSync(
    path.join(distDir, "sw.js"),
    [
      'const CACHE_VERSION = "__NULLID_BUILD_ID__";',
      'const RUNTIME_SHELL_HASH = "__NULLID_RUNTIME_SHELL_HASH__";',
      'const CACHE_NAME = `nullid-cache-app-${CACHE_VERSION}`;',
      "void RUNTIME_SHELL_HASH;",
      `// ${workerMarker}`,
      "",
    ].join("\n"),
  );
  return distDir;
}

function extractCacheVersion(source: string) {
  const match = source.match(/const CACHE_VERSION = "([^"]+)"/u);
  assert.ok(match, "stamped service-worker cache version");
  return match[1];
}
