#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  compareStrings,
  isIsoTimestamp,
  isNonNegativeInteger,
  isOsMetadataPath,
  isSafeRelativePath,
  resolveInside,
  SHA256_RE,
  sha256Hex,
} from "./artifact-safety.mjs";

const DIST_DIR = path.resolve("dist");
const MANIFEST_PATH = path.join(DIST_DIR, "deploy-manifest.json");
const SUMS_PATH = path.join(DIST_DIR, "SHA256SUMS");
const IGNORE = new Set(["deploy-manifest.json", "SHA256SUMS"]);

try {
  const manifest = readManifest();
  validateManifestShape(manifest);
  const manifestPaths = validateManifestEntries(manifest.files);
  verifyManifestFiles(manifest.files);
  verifyDistFileSet(manifestPaths);
  verifyChecksumFile(manifest.files);
  console.log(`build manifest verified (${manifest.files.length} files)`);
} catch (error) {
  console.error(`build manifest: ${error instanceof Error ? error.message : "verification failed"}`);
  process.exit(1);
}

function readManifest() {
  if (!fs.existsSync(MANIFEST_PATH)) {
    throw new Error(`missing manifest: ${MANIFEST_PATH}`);
  }
  try {
    return JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  } catch {
    throw new Error("manifest is not valid JSON");
  }
}

function validateManifestShape(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("manifest must be an object");
  }
  if (manifest.schemaVersion !== 1) {
    throw new Error("manifest.schemaVersion must be 1");
  }
  if (manifest.generatedAt !== null && !isIsoTimestamp(manifest.generatedAt)) {
    throw new Error("manifest.generatedAt must be null or an ISO timestamp");
  }
  if (manifest.sourceDateEpoch !== null && !isNonNegativeInteger(manifest.sourceDateEpoch)) {
    throw new Error("manifest.sourceDateEpoch must be null or a non-negative integer");
  }
  if (!Array.isArray(manifest.files)) {
    throw new Error("manifest.files must be an array");
  }
  if (!isNonNegativeInteger(manifest.fileCount) || manifest.fileCount !== manifest.files.length) {
    throw new Error("manifest.fileCount must match files.length");
  }
}

function validateManifestEntries(files) {
  const seen = new Set();
  const seenLower = new Set();
  let previousPath = "";
  files.forEach((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`invalid manifest entry at index ${index}`);
    }
    if (typeof entry.path !== "string" || !isSafeRelativePath(entry.path)) {
      throw new Error(`unsafe manifest path at index ${index}`);
    }
    if (seen.has(entry.path)) {
      throw new Error(`duplicate manifest path: ${entry.path}`);
    }
    const lower = entry.path.toLowerCase();
    if (seenLower.has(lower)) {
      throw new Error(`case-colliding manifest path: ${entry.path}`);
    }
    if (index > 0 && previousPath > entry.path) {
      throw new Error(`manifest files are not sorted at ${entry.path}`);
    }
    if (typeof entry.sha256 !== "string" || !SHA256_RE.test(entry.sha256)) {
      throw new Error(`invalid sha256 for ${entry.path}`);
    }
    if (!isNonNegativeInteger(entry.bytes)) {
      throw new Error(`invalid byte size for ${entry.path}`);
    }
    seen.add(entry.path);
    seenLower.add(lower);
    previousPath = entry.path;
  });
  return seen;
}

function verifyManifestFiles(files) {
  files.forEach((entry) => {
    const target = resolveInside(DIST_DIR, entry.path, "dist path");
    const stat = fs.lstatSync(target, { throwIfNoEntry: false });
    if (!stat) {
      throw new Error(`missing file from manifest: ${entry.path}`);
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`manifest path is not a regular file: ${entry.path}`);
    }
    const data = fs.readFileSync(target);
    if (sha256Hex(data) !== entry.sha256) {
      throw new Error(`hash mismatch for ${entry.path}`);
    }
    if (entry.bytes !== data.byteLength) {
      throw new Error(`size mismatch for ${entry.path}`);
    }
  });
}

function verifyDistFileSet(manifestPaths) {
  const distFiles = walkDistFiles();
  if (manifestPaths.size !== distFiles.length) {
    throw new Error(`manifest file count mismatch (${manifestPaths.size} vs ${distFiles.length})`);
  }
  distFiles.forEach((relPath) => {
    if (!manifestPaths.has(relPath)) {
      throw new Error(`dist file missing from manifest: ${relPath}`);
    }
  });
}

function verifyChecksumFile(files) {
  if (!fs.existsSync(SUMS_PATH) || !fs.lstatSync(SUMS_PATH).isFile()) {
    throw new Error("missing SHA256SUMS");
  }
  const lines = fs
    .readFileSync(SUMS_PATH, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const expectedLines = files.map((entry) => `${entry.sha256}  ${entry.path}`);
  if (lines.length !== expectedLines.length) {
    throw new Error(`SHA256SUMS line count mismatch (${lines.length} vs ${expectedLines.length})`);
  }
  const seen = new Set();
  lines.forEach((line, index) => {
    const match = line.match(/^([a-f0-9]{64}) {2}(.+)$/);
    if (!match) {
      throw new Error(`invalid SHA256SUMS line ${index + 1}`);
    }
    if (!isSafeRelativePath(match[2])) {
      throw new Error(`unsafe SHA256SUMS path on line ${index + 1}`);
    }
    if (seen.has(match[2])) {
      throw new Error(`duplicate SHA256SUMS path: ${match[2]}`);
    }
    seen.add(match[2]);
    if (line !== expectedLines[index]) {
      throw new Error(`SHA256SUMS mismatch on line ${index + 1}`);
    }
  });
}

function walkDistFiles() {
  const out = [];
  const stack = [DIST_DIR];
  while (stack.length) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => compareStrings(a.name, b.name));
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const rel = path.relative(DIST_DIR, full).replace(/\\/g, "/");
      if (isOsMetadataPath(rel)) continue;
      if (!isSafeRelativePath(rel)) {
        throw new Error(`unsafe dist path: ${rel}`);
      }
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        if (!IGNORE.has(rel)) out.push(rel);
      } else {
        throw new Error(`unsupported dist filesystem entry: ${rel}`);
      }
    }
  }
  return out.sort(compareStrings);
}
