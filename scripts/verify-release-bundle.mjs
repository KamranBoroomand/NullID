#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import {
  isIsoTimestamp,
  isNonNegativeInteger,
  isOsMetadataPath,
  isSafeRelativePath,
  resolveInside,
  sanitizeTag,
  SHA256_RE,
  sha256Hex,
} from "./artifact-safety.mjs";

const argv = process.argv.slice(2);
const bundleDir = path.resolve(getOption(argv, "--dir") || argv[0] || "release");

try {
  if (!fs.existsSync(bundleDir) || !fs.statSync(bundleDir).isDirectory()) {
    throw new Error(`bundle directory missing: ${bundleDir}`);
  }
  const checksumFile = resolveChecksumFile(bundleDir, getOption(argv, "--checksums"));
  const checksumEntries = parseChecksumFile(checksumFile);
  verifyListedArtifacts(checksumEntries, checksumFile);
  const manifest = verifyReleaseManifest(checksumEntries);
  verifyArchive(checksumEntries, manifest);
  console.log(`[release] checksum verification passed (${checksumEntries.length} files)`);
} catch (error) {
  console.error(`[release] ${error instanceof Error ? error.message : "verification failed"}`);
  process.exit(1);
}

function parseChecksumFile(checksumFile) {
  const lines = fs
    .readFileSync(checksumFile, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0) {
    throw new Error(`empty checksums file: ${checksumFile}`);
  }
  const seen = new Set();
  const seenLower = new Set();
  return lines.map((line, index) => {
    const match = line.match(/^([a-f0-9]{64}) {2}(.+)$/);
    if (!match) throw new Error(`invalid checksum line ${index + 1}`);
    const [, expected, filename] = match;
    if (!isSafeRelativePath(filename)) throw new Error(`unsafe checksum path on line ${index + 1}`);
    const lower = filename.toLowerCase();
    if (seen.has(filename)) throw new Error(`duplicate checksum entry: ${filename}`);
    if (seenLower.has(lower)) throw new Error(`case-colliding checksum entry: ${filename}`);
    seen.add(filename);
    seenLower.add(lower);
    return { expected, filename };
  });
}

function verifyListedArtifacts(entries, checksumFile) {
  const checksumName = path.basename(checksumFile);
  const listed = new Set(entries.map((entry) => entry.filename));
  for (const entry of entries) {
    const fullPath = resolveInside(bundleDir, entry.filename, "artifact path");
    const stat = fs.lstatSync(fullPath, { throwIfNoEntry: false });
    if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`missing or unsupported artifact listed in checksums: ${entry.filename}`);
    }
    if (sha256Hex(fs.readFileSync(fullPath)) !== entry.expected) {
      throw new Error(`checksum mismatch for ${entry.filename}`);
    }
  }
  const actual = fs
    .readdirSync(bundleDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => name !== checksumName && !name.endsWith(".sig") && !name.endsWith(".pem") && !isOsMetadataPath(name));
  for (const name of actual) {
    if (!listed.has(name)) throw new Error(`unlisted release artifact: ${name}`);
  }
}

function verifyReleaseManifest(entries) {
  const manifestEntries = entries.filter((entry) => entry.filename.endsWith("-release-manifest.json"));
  if (manifestEntries.length !== 1) throw new Error("expected exactly one release manifest");
  const manifestPath = resolveInside(bundleDir, manifestEntries[0].filename, "release manifest path");
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {
    throw new Error("release manifest is not valid JSON");
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("release manifest must be an object");
  if (manifest.schemaVersion !== 1 || manifest.kind !== "nullid-release-bundle") throw new Error("invalid release manifest kind/schema");
  if (typeof manifest.tag !== "string" || typeof manifest.safeTag !== "string" || sanitizeTag(manifest.tag) !== manifest.safeTag) {
    throw new Error("release manifest tag/safeTag mismatch");
  }
  if (manifest.generatedAt !== null && !isIsoTimestamp(manifest.generatedAt)) throw new Error("invalid release manifest generatedAt");
  if (manifest.sourceDateEpoch !== null && !isNonNegativeInteger(manifest.sourceDateEpoch)) throw new Error("invalid release manifest sourceDateEpoch");
  if (!manifest.git || typeof manifest.git !== "object" || Array.isArray(manifest.git)) throw new Error("invalid release manifest git metadata");
  for (const key of ["sha", "ref", "runId"]) {
    if (manifest.git[key] !== null && typeof manifest.git[key] !== "string") throw new Error(`invalid release manifest git.${key}`);
  }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error("release manifest artifacts must be non-empty");
  const expectedListed = new Set([...manifest.artifacts, manifestEntries[0].filename]);
  const listed = new Set(entries.map((entry) => entry.filename));
  if (expectedListed.size !== listed.size) throw new Error("release manifest artifact set does not match checksums");
  for (const name of expectedListed) {
    if (!isSafeRelativePath(name) || !listed.has(name)) throw new Error(`release manifest references missing artifact: ${name}`);
  }
  return manifest;
}

function verifyArchive(entries, manifest) {
  const tarNames = manifest.artifacts.filter((name) => name.endsWith(".tar.gz"));
  if (tarNames.length !== 1) throw new Error("release manifest must reference exactly one dist tar.gz");
  const tarEntries = parseTarGz(resolveInside(bundleDir, tarNames[0], "release archive path"));
  for (const required of ["SHA256SUMS", "deploy-manifest.json", "sbom.json"]) {
    if (!tarEntries.has(required)) throw new Error(`archive missing ${required}`);
  }

  const externalSha = readArtifact(entries, "-SHA256SUMS.txt");
  const externalManifest = readArtifact(entries, "-deploy-manifest.json");
  const externalSbom = readArtifact(entries, "-sbom.json");
  if (!tarEntries.get("SHA256SUMS").equals(externalSha)) throw new Error("archive SHA256SUMS differs from copied artifact");
  if (!tarEntries.get("deploy-manifest.json").equals(externalManifest)) throw new Error("archive deploy manifest differs from copied artifact");
  if (!tarEntries.get("sbom.json").equals(externalSbom)) throw new Error("archive SBOM differs from copied artifact");

  const deployManifest = JSON.parse(tarEntries.get("deploy-manifest.json").toString("utf8"));
  if (!Array.isArray(deployManifest.files)) throw new Error("archive deploy manifest has no files array");
  const expectedDist = new Map(deployManifest.files.map((entry) => [entry.path, entry]));
  for (const [name, data] of tarEntries) {
    if (name === "deploy-manifest.json" || name === "SHA256SUMS") continue;
    const expected = expectedDist.get(name);
    if (!expected) throw new Error(`archive contains file missing from deploy manifest: ${name}`);
    if (!SHA256_RE.test(expected.sha256) || sha256Hex(data) !== expected.sha256 || data.byteLength !== expected.bytes) {
      throw new Error(`archive deploy manifest mismatch for ${name}`);
    }
  }
}

function parseTarGz(tarPath) {
  const data = zlib.gunzipSync(fs.readFileSync(tarPath));
  const entries = new Map();
  const seenLower = new Set();
  for (let offset = 0; offset < data.byteLength; offset += 512) {
    const header = data.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    verifyTarChecksum(header);
    const name = readTarString(header, 0, 100);
    const prefix = readTarString(header, 345, 155);
    const relPath = prefix ? `${prefix}/${name}` : name;
    const typeflag = header[156];
    if (typeflag !== 0 && typeflag !== 48) throw new Error(`unsupported tar entry type for ${relPath}`);
    if (!isSafeRelativePath(relPath)) throw new Error(`unsafe tar entry path: ${relPath}`);
    const lower = relPath.toLowerCase();
    if (entries.has(relPath) || seenLower.has(lower)) throw new Error(`duplicate tar entry: ${relPath}`);
    const size = readTarOctal(header, 124, 12);
    const start = offset + 512;
    const end = start + size;
    if (end > data.byteLength) throw new Error(`truncated tar entry: ${relPath}`);
    entries.set(relPath, Buffer.from(data.subarray(start, end)));
    seenLower.add(lower);
    offset = start + Math.ceil(size / 512) * 512 - 512;
  }
  return entries;
}

function verifyTarChecksum(header) {
  const expected = readTarOctal(header, 148, 8);
  const copy = Buffer.from(header);
  copy.fill(0x20, 148, 156);
  const actual = copy.reduce((sum, byte) => sum + byte, 0);
  if (actual !== expected) throw new Error("tar checksum mismatch");
}

function readArtifact(entries, suffix) {
  const matches = entries.filter((entry) => entry.filename.endsWith(suffix));
  if (matches.length !== 1) throw new Error(`expected exactly one ${suffix} artifact`);
  return fs.readFileSync(resolveInside(bundleDir, matches[0].filename, "release artifact path"));
}

function getOption(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

function resolveChecksumFile(dir, requestedPath) {
  if (requestedPath) {
    const full = path.resolve(requestedPath);
    if (!fs.existsSync(full)) throw new Error(`requested checksum file missing: ${requestedPath}`);
    const rel = path.relative(dir, full);
    if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("checksum file must be inside release directory");
    return full;
  }
  const matches = fs.readdirSync(dir).filter((name) => name.endsWith("-release-checksums.txt"));
  if (matches.length !== 1) throw new Error("could not find exactly one release checksums file");
  return path.join(dir, matches[0]);
}

function readTarString(header, offset, length) {
  const bytes = header.subarray(offset, offset + length);
  const zero = bytes.indexOf(0);
  return bytes.subarray(0, zero >= 0 ? zero : bytes.length).toString("utf8");
}

function readTarOctal(header, offset, length) {
  const raw = readTarString(header, offset, length).trim();
  if (!/^[0-7]+$/.test(raw)) throw new Error("invalid tar numeric field");
  return Number.parseInt(raw, 8);
}
