import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const DIST_DIR = path.resolve("dist");
const MANIFEST_NAME = "deploy-manifest.json";
const SUMS_NAME = "SHA256SUMS";
const skipOutputs = new Set([MANIFEST_NAME, SUMS_NAME]);

if (!fs.existsSync(DIST_DIR)) {
  console.error(`dist directory missing: ${DIST_DIR}`);
  process.exit(1);
}

function walkFiles(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length) {
    const current = stack.pop();
    if (!current) continue;
    const entries = fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    entries.forEach((entry) => {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else out.push(full);
    });
  }
  return out;
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

const files = walkFiles(DIST_DIR)
  .map((fullPath) => ({
    fullPath,
    relPath: path.relative(DIST_DIR, fullPath).replace(/\\/g, "/"),
  }))
  .filter(({ relPath }) => !skipOutputs.has(relPath))
  .sort((a, b) => a.relPath.localeCompare(b.relPath));

const manifestFiles = files.map(({ fullPath, relPath }) => {
  const data = fs.readFileSync(fullPath);
  return {
    path: relPath,
    bytes: data.byteLength,
    sha256: sha256Hex(data),
  };
});

const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH ? Number(process.env.SOURCE_DATE_EPOCH) : null;
const generatedAt = Number.isFinite(sourceDateEpoch)
  ? new Date((sourceDateEpoch ?? 0) * 1000).toISOString()
  : null;

const manifest = {
  schemaVersion: 1,
  generatedAt,
  sourceDateEpoch: Number.isFinite(sourceDateEpoch) ? sourceDateEpoch : null,
  fileCount: manifestFiles.length,
  files: manifestFiles,
};

const sums = manifestFiles.map((entry) => `${entry.sha256}  ${entry.path}`).join("\n");

fs.writeFileSync(path.join(DIST_DIR, MANIFEST_NAME), `${JSON.stringify(manifest, null, 2)}\n`);
fs.writeFileSync(path.join(DIST_DIR, SUMS_NAME), `${sums}\n`);

console.log(`build manifest generated (${manifestFiles.length} files)`);
