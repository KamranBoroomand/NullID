#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { compareStrings, isOsMetadataPath, isSafeRelativePath, sanitizeTag, sha256Hex } from "./artifact-safety.mjs";

const argv = process.argv.slice(2);
const distDir = path.resolve(getOption(argv, "--dist") || "dist");
const outDir = path.resolve(getOption(argv, "--out") || "release");
const sourceTag = getOption(argv, "--tag") || process.env.RELEASE_TAG || process.env.GITHUB_REF_NAME || "dev";
const tag = sanitizeTag(sourceTag);
const sourceDateEpoch = parseSourceDateEpoch(process.env.SOURCE_DATE_EPOCH);

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
fs.writeFileSync(tarPath, gzipDeterministic(buildTarArchive(distDir, sourceDateEpoch ?? 0)));

copyFile(path.join(distDir, "SHA256SUMS"), path.join(outDir, shaName));
copyFile(path.join(distDir, "deploy-manifest.json"), path.join(outDir, manifestName));
copyFile(path.join(distDir, "sbom.json"), path.join(outDir, sbomName));

const manifest = {
  schemaVersion: 1,
  kind: "nullid-release-bundle",
  tag: sourceTag,
  safeTag: tag,
  generatedAt: sourceDateEpoch === null ? null : new Date(sourceDateEpoch * 1000).toISOString(),
  sourceDateEpoch,
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
  .filter((name) => name !== checksumsName && !isOsMetadataPath(name))
  .sort(compareStrings);

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

function parseSourceDateEpoch(value) {
  if (!value) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function copyFile(source, target) {
  fs.copyFileSync(source, target);
}

function buildTarArchive(rootDir, mtime) {
  const chunks = [];
  for (const relPath of walkFiles(rootDir)) {
    const fullPath = path.join(rootDir, relPath);
    const data = fs.readFileSync(fullPath);
    chunks.push(createTarHeader(relPath, data.byteLength, mtime));
    chunks.push(data);
    const padding = (512 - (data.byteLength % 512)) % 512;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function walkFiles(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => compareStrings(a.name, b.name));
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const relPath = path.relative(rootDir, fullPath).replace(/\\/g, "/");
      if (isOsMetadataPath(relPath)) continue;
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        assertSafeTarPath(relPath);
        out.push(relPath);
      } else {
        throw new Error(`[release] unsupported dist entry: ${relPath}`);
      }
    }
  }
  return out.sort(compareStrings);
}

function createTarHeader(relPath, size, mtime) {
  const header = Buffer.alloc(512, 0);
  const { name, prefix } = splitTarPath(relPath);
  writeString(header, name, 0, 100);
  writeOctal(header, 0o644, 100, 8);
  writeOctal(header, 0, 108, 8);
  writeOctal(header, 0, 116, 8);
  writeOctal(header, size, 124, 12);
  writeOctal(header, mtime, 136, 12);
  header.fill(0x20, 148, 156);
  header[156] = "0".charCodeAt(0);
  writeString(header, "ustar", 257, 6);
  writeString(header, "00", 263, 2);
  writeString(header, "root", 265, 32);
  writeString(header, "root", 297, 32);
  writeString(header, prefix, 345, 155);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeOctal(header, checksum, 148, 8);
  return header;
}

function splitTarPath(relPath) {
  const encoded = Buffer.from(relPath);
  if (encoded.byteLength <= 100) return { name: relPath, prefix: "" };
  const parts = relPath.split("/");
  for (let index = 1; index < parts.length; index += 1) {
    const prefix = parts.slice(0, index).join("/");
    const name = parts.slice(index).join("/");
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) {
      return { name, prefix };
    }
  }
  throw new Error(`[release] tar path too long: ${relPath}`);
}

function writeString(header, value, offset, length) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength > length) throw new Error(`[release] tar field too long: ${value}`);
  bytes.copy(header, offset);
}

function writeOctal(header, value, offset, length) {
  const text = value.toString(8).padStart(length - 1, "0");
  if (text.length > length - 1) throw new Error(`[release] tar numeric field too large: ${value}`);
  header.write(text, offset, length - 1, "ascii");
  header[offset + length - 1] = 0;
}

function gzipDeterministic(buffer) {
  const out = zlib.gzipSync(buffer, { level: 9 });
  out.writeUInt32LE(0, 4);
  return out;
}

function assertSafeTarPath(relPath) {
  if (!isSafeRelativePath(relPath)) {
    throw new Error(`[release] unsafe tar path: ${relPath}`);
  }
}
