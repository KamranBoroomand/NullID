import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const DIST_DIR = path.resolve("dist");
const MANIFEST_PATH = path.join(DIST_DIR, "deploy-manifest.json");
const SUMS_PATH = path.join(DIST_DIR, "SHA256SUMS");
const ignore = new Set(["deploy-manifest.json", "SHA256SUMS"]);

if (!fs.existsSync(MANIFEST_PATH)) {
  console.error(`missing manifest: ${MANIFEST_PATH}`);
  process.exit(1);
}

const manifestRaw = fs.readFileSync(MANIFEST_PATH, "utf8");
const manifest = JSON.parse(manifestRaw);

if (!Array.isArray(manifest.files)) {
  console.error("manifest.files must be an array");
  process.exit(1);
}

const seen = new Set();
manifest.files.forEach((entry, index) => {
  if (!entry || typeof entry.path !== "string" || typeof entry.sha256 !== "string") {
    throw new Error(`invalid manifest entry at index ${index}`);
  }
  if (seen.has(entry.path)) {
    throw new Error(`duplicate manifest path: ${entry.path}`);
  }
  seen.add(entry.path);
});

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

manifest.files.forEach((entry) => {
  const target = path.join(DIST_DIR, entry.path);
  if (!fs.existsSync(target)) {
    throw new Error(`missing file from manifest: ${entry.path}`);
  }
  const data = fs.readFileSync(target);
  const actualHash = sha256Hex(data);
  if (actualHash !== entry.sha256) {
    throw new Error(`hash mismatch for ${entry.path}`);
  }
  if (typeof entry.bytes === "number" && entry.bytes !== data.byteLength) {
    throw new Error(`size mismatch for ${entry.path}`);
  }
});

const distFiles = [];
const stack = [DIST_DIR];
while (stack.length) {
  const current = stack.pop();
  if (!current) continue;
  const entries = fs.readdirSync(current, { withFileTypes: true });
  entries.forEach((item) => {
    const full = path.join(current, item.name);
    if (item.isDirectory()) {
      stack.push(full);
      return;
    }
    const rel = path.relative(DIST_DIR, full).replace(/\\/g, "/");
    if (!ignore.has(rel)) distFiles.push(rel);
  });
}
distFiles.sort();

const manifestPaths = [...seen].sort();
if (manifestPaths.length !== distFiles.length) {
  throw new Error(`manifest file count mismatch (${manifestPaths.length} vs ${distFiles.length})`);
}
for (let i = 0; i < manifestPaths.length; i += 1) {
  if (manifestPaths[i] !== distFiles[i]) {
    throw new Error(`manifest path mismatch: expected ${distFiles[i]} got ${manifestPaths[i]}`);
  }
}

if (fs.existsSync(SUMS_PATH)) {
  const sumsLines = fs
    .readFileSync(SUMS_PATH, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const expectedLines = manifest.files.map((entry) => `${entry.sha256}  ${entry.path}`);
  if (sumsLines.length !== expectedLines.length) {
    throw new Error(`SHA256SUMS line count mismatch (${sumsLines.length} vs ${expectedLines.length})`);
  }
  expectedLines.forEach((line, index) => {
    if (sumsLines[index] !== line) {
      throw new Error(`SHA256SUMS mismatch on line ${index + 1}`);
    }
  });
}

console.log(`build manifest verified (${manifest.files.length} files)`);
