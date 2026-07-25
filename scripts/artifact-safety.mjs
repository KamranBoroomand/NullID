import crypto from "node:crypto";
import path from "node:path";

export const SHA256_RE = /^[a-f0-9]{64}$/;

export function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

export function sanitizeTag(value) {
  const normalized = String(value || "dev").trim().replace(/[^0-9a-zA-Z._-]+/g, "-").replace(/-+/g, "-");
  return normalized || "dev";
}

export function isOsMetadataPath(relPath) {
  const parts = relPath.split("/");
  const name = parts.at(-1) ?? relPath;
  return name === ".DS_Store" || name.startsWith("._") || parts.includes("__MACOSX");
}

export function isSafeRelativePath(relPath) {
  if (!relPath || relPath.includes("\0") || relPath.includes("\\") || path.isAbsolute(relPath)) return false;
  if (/%(?:2e|2f|5c)/i.test(relPath)) return false;
  if (isOsMetadataPath(relPath)) return false;
  const parts = relPath.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) return false;
  return path.posix.normalize(relPath) === relPath;
}

export function resolveInside(root, relPath, context = "path") {
  if (!isSafeRelativePath(relPath)) throw new Error(`unsafe ${context}: ${relPath}`);
  const target = path.resolve(root, relPath);
  const relative = path.relative(root, target);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${context} escapes root: ${relPath}`);
  }
  return target;
}

export function isIsoTimestamp(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && !Number.isNaN(Date.parse(value));
}

export function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}
