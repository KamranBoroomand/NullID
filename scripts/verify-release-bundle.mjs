#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const argv = process.argv.slice(2);
const bundleDir = path.resolve(getOption(argv, "--dir") || argv[0] || "release");
if (!fs.existsSync(bundleDir) || !fs.statSync(bundleDir).isDirectory()) {
  console.error(`[release] bundle directory missing: ${bundleDir}`);
  process.exit(1);
}

const checksumFile = resolveChecksumFile(bundleDir, getOption(argv, "--checksums"));
if (!checksumFile) {
  console.error("[release] could not find a release checksums file (expected *-release-checksums.txt)");
  process.exit(1);
}

const lines = fs
  .readFileSync(checksumFile, "utf8")
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter(Boolean);

if (lines.length === 0) {
  console.error(`[release] empty checksums file: ${checksumFile}`);
  process.exit(1);
}

let verified = 0;
for (const line of lines) {
  const match = line.match(/^([a-f0-9]{64})\s{2}(.+)$/i);
  if (!match) {
    console.error(`[release] invalid checksum line: ${line}`);
    process.exit(1);
  }
  const [, expected, filename] = match;
  const fullPath = path.join(bundleDir, filename);
  if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
    console.error(`[release] missing artifact listed in checksums: ${filename}`);
    process.exit(1);
  }
  const actual = sha256Hex(fs.readFileSync(fullPath));
  if (actual !== expected) {
    console.error(`[release] checksum mismatch for ${filename}`);
    process.exit(1);
  }
  verified += 1;
}

console.log(`[release] checksum verification passed (${verified} files)`);

function getOption(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

function resolveChecksumFile(dir, requestedPath) {
  if (requestedPath) {
    const full = path.resolve(requestedPath);
    return fs.existsSync(full) ? full : null;
  }
  const matches = fs.readdirSync(dir).filter((name) => name.endsWith("-release-checksums.txt"));
  if (matches.length !== 1) return null;
  return path.join(dir, matches[0]);
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}
