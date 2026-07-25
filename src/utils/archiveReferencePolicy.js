// @ts-check

const MAX_REFERENCE_ENTRIES = 4096;
const MAX_REFERENCE_PATH_CHARS = 4096;
const SHA256_RE = /^[a-f0-9]{64}$/u;
const WINDOWS_RESERVED_NAMES = new Set([
  "CON",
  "PRN",
  "AUX",
  "NUL",
  ...Array.from({ length: 9 }, (_unused, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_unused, index) => `LPT${index + 1}`),
]);

/**
 * @typedef {"archive-manifest" | "workflow-package"} ArchiveReferenceSource
 * @typedef {{ path: string, sha256: string, source: ArchiveReferenceSource }} ArchiveReferenceEntry
 */

export class ArchiveReferenceManifestError extends Error {
  /**
   * @param {string} message
   */
  constructor(message) {
    super(`Invalid archive reference manifest: ${message}`);
    this.name = "ArchiveReferenceManifestError";
  }
}

/**
 * @param {ArchiveReferenceEntry[]} entries
 * @returns {ArchiveReferenceEntry[]}
 */
export function validateArchiveReferenceEntries(entries) {
  if (entries.length > MAX_REFERENCE_ENTRIES) {
    throw new ArchiveReferenceManifestError(`entry count exceeds ${MAX_REFERENCE_ENTRIES}`);
  }

  const exact = new Set();
  const conservative = new Map();
  /** @type {ArchiveReferenceEntry[]} */
  const normalizedEntries = [];

  entries.forEach((entry, index) => {
    const path = normalizeArchiveReferencePath(entry.path, index);
    const sha256 = normalizeArchiveReferenceSha256(entry.sha256, index);
    if (exact.has(path)) {
      throw new ArchiveReferenceManifestError(`duplicate path: ${path}`);
    }
    exact.add(path);

    const conservativeKey = path.normalize("NFC").toLocaleLowerCase("en-US");
    const owner = conservative.get(conservativeKey);
    if (owner && owner !== path) {
      throw new ArchiveReferenceManifestError(`case/Unicode path collision: ${path}`);
    }
    conservative.set(conservativeKey, path);
    normalizedEntries.push({ path, sha256, source: entry.source });
  });

  return normalizedEntries;
}

/**
 * @param {unknown} value
 * @param {number} index
 */
function normalizeArchiveReferenceSha256(value, index) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw new ArchiveReferenceManifestError(`entry ${index + 1} must contain a canonical SHA-256 hash`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {number} index
 */
function normalizeArchiveReferencePath(value, index) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_REFERENCE_PATH_CHARS) {
    throw new ArchiveReferenceManifestError(`entry ${index + 1} has an invalid path`);
  }
  const problem = validateSafeRelativeReferencePath(value);
  if (problem) {
    throw new ArchiveReferenceManifestError(`${problem}: ${value}`);
  }
  return value;
}

/**
 * @param {string} value
 */
function validateSafeRelativeReferencePath(value) {
  if (value.includes("\0")) return "path contains a NUL byte";
  if (value.includes("\\")) return "path contains backslashes";
  if (value.startsWith("//")) return "path is a UNC path";
  if (value.startsWith("/")) return "path is absolute";
  if (/^[A-Za-z]:/u.test(value)) return "path contains a Windows drive letter";
  if (value.endsWith("/")) return "path must identify a file, not a directory";

  const segments = value.split("/");
  for (const segment of segments) {
    if (!segment) return "path contains empty segments";
    if (segment === "." || segment === "..") return "path contains traversal segments";
    if (segment.includes(":")) return "path contains a Windows-unsafe colon";
    if (containsWindowsForbiddenCharacter(segment)) return "path contains Windows-forbidden characters";
    if (/[. ]$/u.test(segment)) return "path component ends with a Windows-unsafe dot or space";
    const deviceName = segment.split(".")[0].toLocaleUpperCase("en-US");
    if (WINDOWS_RESERVED_NAMES.has(deviceName)) {
      return `path contains reserved Windows device name ${deviceName}`;
    }
  }
  return null;
}

/**
 * @param {string} segment
 */
function containsWindowsForbiddenCharacter(segment) {
  for (const character of segment) {
    const codePoint = character.codePointAt(0) ?? 0;
    if ((codePoint > 0 && codePoint <= 0x1f) || '<>"|?*'.includes(character)) {
      return true;
    }
  }
  return false;
}
