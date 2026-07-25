#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const distDir = path.resolve(process.argv[2] || "dist");
if (!fs.existsSync(distDir) || !fs.statSync(distDir).isDirectory()) {
  console.error(`[build-info] dist directory missing: ${distDir}`);
  process.exit(1);
}

const sourceDateEpoch = parseSourceDateEpoch(process.env.SOURCE_DATE_EPOCH);
const timestamp =
  process.env.VITE_BUILD_TIMESTAMP ||
  process.env.GITHUB_RUN_STARTED_AT ||
  (sourceDateEpoch === null ? null : new Date(sourceDateEpoch * 1000).toISOString());

const payload = {
  schemaVersion: 1,
  commit: cleanString(process.env.VITE_BUILD_ID || process.env.GITHUB_SHA),
  ref: cleanString(process.env.GITHUB_REF),
  runId: cleanString(process.env.GITHUB_RUN_ID),
  timestamp,
  sourceDateEpoch,
};

fs.writeFileSync(path.join(distDir, "build.json"), `${JSON.stringify(payload, null, 2)}\n`, "utf8");
const runtimeShellHash = readPrecacheContentHash(distDir);
const workerLogicHash = readServiceWorkerLogicHash(distDir);
const cacheVersion = deriveCacheVersion({ runtimeShellHash, workerLogicHash });
stampServiceWorker(distDir, {
  cacheVersion,
  runtimeShellHash,
});
console.log("[build-info] wrote dist/build.json");

function cleanString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function parseSourceDateEpoch(value) {
  if (!value) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function stampServiceWorker(rootDir, identity) {
  const swPath = path.join(rootDir, "sw.js");
  if (!fs.existsSync(swPath)) return;
  const source = fs.readFileSync(swPath, "utf8");
  const buildToken = "__NULLID_BUILD_ID__";
  const runtimeHashToken = "__NULLID_RUNTIME_SHELL_HASH__";
  if (!source.includes(buildToken)) {
    throw new Error("[build-info] service worker build token missing");
  }
  if (!source.includes(runtimeHashToken)) {
    throw new Error("[build-info] service worker runtime shell hash token missing");
  }
  fs.writeFileSync(
    swPath,
    source
      .replaceAll(buildToken, sanitizeCacheVersion(identity.cacheVersion))
      .replaceAll(runtimeHashToken, identity.runtimeShellHash),
    "utf8",
  );
}

function readServiceWorkerLogicHash(rootDir) {
  const swPath = path.join(rootDir, "sw.js");
  if (!fs.existsSync(swPath)) return null;
  const source = fs.readFileSync(swPath, "utf8");
  const buildToken = "__NULLID_BUILD_ID__";
  const runtimeHashToken = "__NULLID_RUNTIME_SHELL_HASH__";
  if (!source.includes(buildToken)) {
    throw new Error("[build-info] service worker build token missing");
  }
  if (!source.includes(runtimeHashToken)) {
    throw new Error("[build-info] service worker runtime shell hash token missing");
  }
  return crypto.createHash("sha256").update(source, "utf8").digest("hex");
}

function deriveCacheVersion({ runtimeShellHash, workerLogicHash }) {
  const workerHash = workerLogicHash || "no-service-worker";
  const combined = crypto
    .createHash("sha256")
    .update(`nullid-cache-v2\nruntime:${runtimeShellHash}\nworker:${workerHash}\n`, "utf8")
    .digest("hex");
  return `precache-${combined.slice(0, 32)}`;
}

function readPrecacheContentHash(rootDir) {
  const manifestPath = path.join(rootDir, "nullid-precache-manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error("[build-info] precache manifest missing before service worker stamping");
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {
    throw new Error("[build-info] precache manifest is not valid JSON");
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    parsed.schemaVersion !== 2 ||
    parsed.kind !== "nullid-runtime-shell-manifest" ||
    !/^[a-f0-9]{64}$/u.test(parsed.contentHash)
  ) {
    throw new Error("[build-info] precache manifest content hash missing or invalid");
  }
  return parsed.contentHash;
}

function sanitizeCacheVersion(value) {
  const normalized = String(value || "dev").trim();
  if (/^[A-Za-z0-9._-]{1,80}$/.test(normalized)) return normalized;
  return crypto.createHash("sha256").update(normalized).digest("hex").slice(0, 32);
}
