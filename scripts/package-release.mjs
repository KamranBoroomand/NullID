#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

const argv = process.argv.slice(2);
const distDir = path.resolve(getOption(argv, "--dist") || "dist");
const outDir = path.resolve(getOption(argv, "--out") || "release");
const sourceTag = getOption(argv, "--tag") || process.env.RELEASE_TAG || process.env.GITHUB_REF_NAME || "dev";
const tag = sanitizeTag(sourceTag);

if (!fs.existsSync(distDir) || !fs.statSync(distDir).isDirectory()) {
  console.error(`[release] dist directory missing: ${distDir}`);
  process.exit(1);
}

const requiredFiles = ["SHA256SUMS", "deploy-manifest.json", "sbom.json"];
requiredFiles.forEach((name) => {
  const fullPath = path.join(distDir, name);
  if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
    console.error(`[release] required dist file missing: ${fullPath}`);
    process.exit(1);
  }
});

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

const tarName = `nullid-${tag}-dist.tar.gz`;
const shaName = `nullid-${tag}-SHA256SUMS.txt`;
const manifestName = `nullid-${tag}-deploy-manifest.json`;
const sbomName = `nullid-${tag}-sbom.json`;
const bundleManifestName = `nullid-${tag}-release-manifest.json`;
const checksumsName = `nullid-${tag}-release-checksums.txt`;

const tarPath = path.join(outDir, tarName);
try {
  execFileSync("tar", ["-czf", tarPath, "-C", distDir, "."], { stdio: "pipe" });
} catch (error) {
  const detail = error instanceof Error ? error.message : String(error);
  console.error(`[release] failed to package dist archive: ${detail}`);
  process.exit(1);
}

copyFile(path.join(distDir, "SHA256SUMS"), path.join(outDir, shaName));
copyFile(path.join(distDir, "deploy-manifest.json"), path.join(outDir, manifestName));
copyFile(path.join(distDir, "sbom.json"), path.join(outDir, sbomName));

const manifest = {
  schemaVersion: 1,
  kind: "nullid-release-bundle",
  tag: sourceTag,
  safeTag: tag,
  generatedAt: new Date().toISOString(),
  sourceDateEpoch: parseSourceDateEpoch(process.env.SOURCE_DATE_EPOCH),
  git: {
    sha: process.env.GITHUB_SHA || null,
    ref: process.env.GITHUB_REF || null,
    runId: process.env.GITHUB_RUN_ID || null,
  },
  artifacts: [tarName, shaName, manifestName, sbomName],
};
fs.writeFileSync(path.join(outDir, bundleManifestName), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

const checksumTargets = fs
  .readdirSync(outDir)
  .filter((name) => name !== checksumsName)
  .sort((a, b) => a.localeCompare(b));

const checksumLines = checksumTargets.map((name) => {
  const digest = sha256Hex(fs.readFileSync(path.join(outDir, name)));
  return `${digest}  ${name}`;
});
fs.writeFileSync(path.join(outDir, checksumsName), `${checksumLines.join("\n")}\n`, "utf8");

console.log(`[release] packaged ${checksumTargets.length + 1} files in ${path.relative(process.cwd(), outDir)}`);

function getOption(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

function sanitizeTag(value) {
  const normalized = String(value || "dev").trim().replace(/[^0-9a-zA-Z._-]+/g, "-").replace(/-+/g, "-");
  return normalized || "dev";
}

function parseSourceDateEpoch(value) {
  if (!value) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.floor(parsed) : null;
}

function copyFile(source, target) {
  fs.copyFileSync(source, target);
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}
