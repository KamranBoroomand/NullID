import { extractWorkflowPackage } from "./workflowPackage.js";

export interface ArchiveInspectionEntry {
  path: string;
  directory: boolean;
  compressionMethod: number;
  compressionLabel: string;
  compressedBytes: number;
  uncompressedBytes: number;
  sha256: string | null;
  status: "hashed" | "directory" | "unsupported";
  detail: string;
}

export interface ArchiveInspectionResult {
  schemaVersion: 1;
  kind: "nullid-archive-inspection";
  createdAt: string;
  fileCount: number;
  directoryCount: number;
  entryCount: number;
  entries: ArchiveInspectionEntry[];
  warnings: string[];
}

export interface ArchiveReferenceEntry {
  path: string;
  sha256: string;
  source: "archive-manifest" | "workflow-package";
}

export type ArchiveComparisonStatus = "matched" | "missing" | "extra" | "hash-mismatch" | "unsupported" | "not-checked";

export interface ArchiveVerificationEntryResult extends ArchiveInspectionEntry {
  verification: "matched" | "mismatch" | "extra" | "directory" | "unsupported";
  comparisonStatus: ArchiveComparisonStatus | null;
  expectedSha256?: string;
}

export interface ArchiveVerificationResult {
  matched: number;
  mismatched: number;
  missingFromArchive: number;
  extraInArchive: number;
  entries: ArchiveVerificationEntryResult[];
  manifestEntries: ArchiveReferenceEntry[];
  groups: {
    matched: ArchiveVerificationEntryResult[];
    missing: ArchiveReferenceEntry[];
    extra: ArchiveVerificationEntryResult[];
    hashMismatch: ArchiveVerificationEntryResult[];
    unsupported: ArchiveVerificationEntryResult[];
    notChecked: ArchiveVerificationEntryResult[];
  };
  localFacts: string[];
  expectedFacts: string[];
  declaredOnly: string[];
  manualReviewRecommendations: string[];
}

export interface ArchiveComparisonReport {
  schemaVersion: 1;
  kind: "nullid-archive-comparison-report";
  createdAt: string;
  summary: {
    matched: number;
    missing: number;
    extra: number;
    hashMismatch: number;
    unsupportedOrNotChecked: number;
  };
  localFacts: string[];
  expectedFacts: string[];
  declaredOnly: string[];
  manualReviewRecommendations: string[];
  sections: Array<{
    id: string;
    label: string;
    items: unknown[];
  }>;
  groups: {
    matched: Array<{ path: string; sha256: string | null; detail: string }>;
    missing: Array<{ path: string; expectedSha256: string; source: ArchiveReferenceEntry["source"] }>;
    extra: Array<{ path: string; sha256: string | null; detail: string }>;
    hashMismatch: Array<{ path: string; sha256: string | null; expectedSha256: string | null; detail: string }>;
    unsupported: Array<{ path: string; detail: string }>;
    notChecked: Array<{ path: string; detail: string }>;
  };
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;

export async function inspectZipArchiveBytes(bytes: Uint8Array): Promise<ArchiveInspectionResult> {
  const centralDirectory = readCentralDirectory(bytes);
  const entries = await Promise.all(
    centralDirectory.map(async (entry) => inspectEntry(bytes, entry)),
  );
  const warnings = entries
    .filter((entry) => entry.status === "unsupported")
    .map((entry) => `${entry.path}: ${entry.detail}`);

  return {
    schemaVersion: 1,
    kind: "nullid-archive-inspection",
    createdAt: new Date().toISOString(),
    fileCount: entries.filter((entry) => !entry.directory).length,
    directoryCount: entries.filter((entry) => entry.directory).length,
    entryCount: entries.length,
    entries,
    warnings,
  };
}

export function parseArchiveReferenceDocument(input: string): ArchiveReferenceEntry[] {
  const parsed = JSON.parse(input) as unknown;
  if (!parsed || typeof parsed !== "object") return [];

  if (isArchiveManifest(parsed)) {
    return parsed.files.reduce<ArchiveReferenceEntry[]>((acc, entry) => {
      if (!entry || typeof entry !== "object") return acc;
      const path = typeof entry.path === "string" ? entry.path : null;
      const sha256 = typeof entry.sha256After === "string"
        ? entry.sha256After
        : typeof entry.sha256 === "string"
          ? entry.sha256
          : null;
      if (!path || !sha256) return acc;
      acc.push({ path, sha256: sha256.toLowerCase(), source: "archive-manifest" });
      return acc;
    }, []);
  }

  try {
    const workflowPackage = extractWorkflowPackage(parsed);
    return workflowPackage.artifacts.reduce<ArchiveReferenceEntry[]>((acc, artifact) => {
      if (!artifact.sha256) return acc;
      const path = artifact.filename || artifact.id;
      if (!path) return acc;
      acc.push({ path, sha256: artifact.sha256.toLowerCase(), source: "workflow-package" });
      return acc;
    }, []);
  } catch {
    return [];
  }
}

export function verifyArchiveInspection(
  inspection: ArchiveInspectionResult,
  manifestEntries: ArchiveReferenceEntry[],
): ArchiveVerificationResult {
  const expectedByPath = new Map(manifestEntries.map((entry) => [entry.path, entry.sha256]));
  const seen = new Set<string>();
  const entries = inspection.entries.map<ArchiveVerificationEntryResult>((entry) => {
    if (entry.directory) {
      return { ...entry, verification: "directory" as const, comparisonStatus: null };
    }
    if (entry.status === "unsupported") {
      return { ...entry, verification: "unsupported" as const, comparisonStatus: expectedByPath.has(entry.path) ? "unsupported" : "not-checked" };
    }
    const expectedSha256 = expectedByPath.get(entry.path);
    if (!expectedSha256) {
      return { ...entry, verification: "extra" as const, comparisonStatus: "extra" };
    }
    seen.add(entry.path);
    return {
      ...entry,
      verification: entry.sha256 === expectedSha256 ? "matched" as const : "mismatch" as const,
      comparisonStatus: entry.sha256 === expectedSha256 ? "matched" as const : "hash-mismatch" as const,
      expectedSha256,
    };
  });

  const missingEntries = manifestEntries.filter((entry) => !seen.has(entry.path));
  const groups = {
    matched: entries.filter((entry) => entry.comparisonStatus === "matched"),
    missing: missingEntries,
    extra: entries.filter((entry) => entry.comparisonStatus === "extra"),
    hashMismatch: entries.filter((entry) => entry.comparisonStatus === "hash-mismatch"),
    unsupported: entries.filter((entry) => entry.comparisonStatus === "unsupported"),
    notChecked: entries.filter((entry) => entry.comparisonStatus === "not-checked"),
  };
  const localFacts = [
    `${inspection.fileCount} archive file hash(es) were computed locally from readable ZIP entry bytes.`,
    `${inspection.directoryCount} directory entr${inspection.directoryCount === 1 ? "y" : "ies"} were listed locally.`,
    ...(groups.unsupported.length > 0 || groups.notChecked.length > 0
      ? [`${groups.unsupported.length + groups.notChecked.length} archive entr${groups.unsupported.length + groups.notChecked.length === 1 ? "y was" : "ies were"} not fully comparable locally.`]
      : []),
  ];
  const expectedFacts = manifestEntries.length > 0
    ? [
        `${manifestEntries.length} expected archive hash entr${manifestEntries.length === 1 ? "y" : "ies"} were loaded from ${manifestEntries[0]?.source ?? "archive-manifest"}.`,
        "Expected facts come from the loaded manifest or workflow package, not from ZIP-declared metadata.",
      ]
    : [];
  const declaredOnly = manifestEntries.length > 0
    ? [
        "Expected path/hash pairs are declarative inputs until they are matched against locally computed archive bytes.",
      ]
    : [];
  const manualReviewRecommendations = buildArchiveManualReviewRecommendations(groups);
  return {
    matched: groups.matched.length,
    mismatched: groups.hashMismatch.length,
    missingFromArchive: groups.missing.length,
    extraInArchive: groups.extra.length,
    entries,
    manifestEntries,
    groups,
    localFacts,
    expectedFacts,
    declaredOnly,
    manualReviewRecommendations,
  };
}

export function buildArchiveComparisonReport(result: ArchiveVerificationResult): ArchiveComparisonReport {
  const summary = {
    matched: result.groups.matched.length,
    missing: result.groups.missing.length,
    extra: result.groups.extra.length,
    hashMismatch: result.groups.hashMismatch.length,
    unsupportedOrNotChecked: result.groups.unsupported.length + result.groups.notChecked.length,
  };
  return {
    schemaVersion: 1,
    kind: "nullid-archive-comparison-report",
    createdAt: new Date().toISOString(),
    summary,
    localFacts: [...result.localFacts],
    expectedFacts: [...result.expectedFacts],
    declaredOnly: [...result.declaredOnly],
    manualReviewRecommendations: [...result.manualReviewRecommendations],
    sections: [
      { id: "local-facts", label: "Local facts", items: result.localFacts.map((value) => ({ value })) },
      { id: "expected-facts", label: "Expected facts", items: result.expectedFacts.map((value) => ({ value })) },
      { id: "declared-only", label: "Declared only", items: result.declaredOnly.map((value) => ({ value })) },
      {
        id: "summary",
        label: "Summary",
        items: [
          { label: "Matched", value: summary.matched },
          { label: "Missing", value: summary.missing },
          { label: "Extra", value: summary.extra },
          { label: "Hash mismatch", value: summary.hashMismatch },
          { label: "Unsupported / not checked", value: summary.unsupportedOrNotChecked },
        ],
      },
      {
        id: "matched",
        label: "Matched",
        items: result.groups.matched.map((entry) => ({
          path: entry.path,
          sha256: entry.sha256,
          detail: entry.detail,
        })),
      },
      {
        id: "missing",
        label: "Missing",
        items: result.groups.missing.map((entry) => ({
          path: entry.path,
          expectedSha256: entry.sha256,
          source: entry.source,
        })),
      },
      {
        id: "extra",
        label: "Extra",
        items: result.groups.extra.map((entry) => ({
          path: entry.path,
          sha256: entry.sha256,
          detail: entry.detail,
        })),
      },
      {
        id: "hash-mismatch",
        label: "Hash mismatch",
        items: result.groups.hashMismatch.map((entry) => ({
          path: entry.path,
          sha256: entry.sha256,
          expectedSha256: entry.expectedSha256 ?? null,
          detail: entry.detail,
        })),
      },
      {
        id: "unsupported",
        label: "Unsupported",
        items: result.groups.unsupported.map((entry) => ({ path: entry.path, detail: entry.detail })),
      },
      {
        id: "not-checked",
        label: "Not checked",
        items: result.groups.notChecked.map((entry) => ({ path: entry.path, detail: entry.detail })),
      },
      { id: "review-recommendations", label: "Review recommendations", items: result.manualReviewRecommendations.map((value) => ({ value })) },
    ].filter((section) => section.items.length > 0),
    groups: {
      matched: result.groups.matched.map((entry) => ({
        path: entry.path,
        sha256: entry.sha256,
        detail: entry.detail,
      })),
      missing: result.groups.missing.map((entry) => ({
        path: entry.path,
        expectedSha256: entry.sha256,
        source: entry.source,
      })),
      extra: result.groups.extra.map((entry) => ({
        path: entry.path,
        sha256: entry.sha256,
        detail: entry.detail,
      })),
      hashMismatch: result.groups.hashMismatch.map((entry) => ({
        path: entry.path,
        sha256: entry.sha256,
        expectedSha256: entry.expectedSha256 ?? null,
        detail: entry.detail,
      })),
      unsupported: result.groups.unsupported.map((entry) => ({
        path: entry.path,
        detail: entry.detail,
      })),
      notChecked: result.groups.notChecked.map((entry) => ({
        path: entry.path,
        detail: entry.detail,
      })),
    },
  };
}

function buildArchiveManualReviewRecommendations(result: ArchiveVerificationResult["groups"]) {
  return [
    ...(result.hashMismatch.length > 0
      ? ["Review every hash mismatch first; the local archive bytes do not match the expected manifest/workflow-package values."]
      : []),
    ...(result.missing.length > 0
      ? ["Review missing expected entries next; they were declared externally but were not found in the inspected archive."]
      : []),
    ...(result.extra.length > 0
      ? ["Review extra archive entries; they exist locally in the ZIP but were not declared in the loaded expected set."]
      : []),
    ...(result.unsupported.length > 0 || result.notChecked.length > 0
      ? ["Review unsupported or not-checked entries manually; NullID could not fully compare those members locally."]
      : []),
    ...(result.hashMismatch.length === 0 && result.missing.length === 0 && result.extra.length === 0 && result.unsupported.length === 0 && result.notChecked.length === 0
      ? ["All declared entries matched locally computed hashes, but this still does not prove sender identity or archive completeness beyond the compared set."]
      : []),
  ];
}

async function inspectEntry(bytes: Uint8Array, entry: CentralDirectoryEntry): Promise<ArchiveInspectionEntry> {
  if (entry.path.endsWith("/")) {
    return {
      path: entry.path,
      directory: true,
      compressionMethod: entry.compressionMethod,
      compressionLabel: compressionMethodLabel(entry.compressionMethod),
      compressedBytes: entry.compressedBytes,
      uncompressedBytes: entry.uncompressedBytes,
      sha256: null,
      status: "directory",
      detail: "Directory entry",
    };
  }

  if (entry.encrypted) {
    return {
      path: entry.path,
      directory: false,
      compressionMethod: entry.compressionMethod,
      compressionLabel: compressionMethodLabel(entry.compressionMethod),
      compressedBytes: entry.compressedBytes,
      uncompressedBytes: entry.uncompressedBytes,
      sha256: null,
      status: "unsupported",
      detail: "Encrypted ZIP entries are not inspected locally in this surface.",
    };
  }

  try {
    const content = await readEntryContent(bytes, entry);
    return {
      path: entry.path,
      directory: false,
      compressionMethod: entry.compressionMethod,
      compressionLabel: compressionMethodLabel(entry.compressionMethod),
      compressedBytes: entry.compressedBytes,
      uncompressedBytes: entry.uncompressedBytes,
      sha256: await sha256Hex(content),
      status: "hashed",
      detail: "SHA-256 computed from extracted entry bytes.",
    };
  } catch (error) {
    return {
      path: entry.path,
      directory: false,
      compressionMethod: entry.compressionMethod,
      compressionLabel: compressionMethodLabel(entry.compressionMethod),
      compressedBytes: entry.compressedBytes,
      uncompressedBytes: entry.uncompressedBytes,
      sha256: null,
      status: "unsupported",
      detail: error instanceof Error ? error.message : "Unsupported ZIP entry",
    };
  }
}

async function readEntryContent(bytes: Uint8Array, entry: CentralDirectoryEntry): Promise<Uint8Array> {
  const offset = entry.localHeaderOffset;
  if (readUint32(bytes, offset) !== LOCAL_FILE_HEADER_SIGNATURE) {
    throw new Error("Local ZIP header mismatch.");
  }
  const nameLength = readUint16(bytes, offset + 26);
  const extraLength = readUint16(bytes, offset + 28);
  const dataOffset = offset + 30 + nameLength + extraLength;
  const compressed = bytes.subarray(dataOffset, dataOffset + entry.compressedBytes);

  if (entry.compressionMethod === 0) {
    return Uint8Array.from(compressed);
  }

  if (entry.compressionMethod === 8) {
    return inflateRaw(compressed);
  }

  throw new Error(`Unsupported ZIP compression method ${entry.compressionMethod}.`);
}

async function inflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream !== "function") {
    throw new Error("Raw deflate decompression is unavailable in this browser.");
  }
  const stream = new Blob([toArrayBuffer(bytes)]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)));
  return Array.from(digest)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function toArrayBuffer(bytes: Uint8Array) {
  return Uint8Array.from(bytes).buffer;
}

function readCentralDirectory(bytes: Uint8Array): CentralDirectoryEntry[] {
  const eocdOffset = findEocdOffset(bytes);
  const totalEntries = readUint16(bytes, eocdOffset + 10);
  const centralDirectoryOffset = readUint32(bytes, eocdOffset + 16);
  const entries: CentralDirectoryEntry[] = [];
  let offset = centralDirectoryOffset;

  for (let i = 0; i < totalEntries; i += 1) {
    if (readUint32(bytes, offset) !== CENTRAL_DIRECTORY_SIGNATURE) {
      throw new Error("ZIP central directory is malformed.");
    }
    const flags = readUint16(bytes, offset + 8);
    const compressionMethod = readUint16(bytes, offset + 10);
    const compressedBytes = readUint32(bytes, offset + 20);
    const uncompressedBytes = readUint32(bytes, offset + 24);
    const nameLength = readUint16(bytes, offset + 28);
    const extraLength = readUint16(bytes, offset + 30);
    const commentLength = readUint16(bytes, offset + 32);
    const localHeaderOffset = readUint32(bytes, offset + 42);
    const path = readText(bytes, offset + 46, nameLength);
    entries.push({
      path,
      compressionMethod,
      compressedBytes,
      uncompressedBytes,
      localHeaderOffset,
      encrypted: Boolean(flags & 0x0001),
    });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function findEocdOffset(bytes: Uint8Array) {
  const minOffset = Math.max(0, bytes.length - 65_557);
  for (let offset = bytes.length - 22; offset >= minOffset; offset -= 1) {
    if (readUint32(bytes, offset) === EOCD_SIGNATURE) {
      return offset;
    }
  }
  throw new Error("ZIP end-of-central-directory record not found.");
}

function readUint16(bytes: Uint8Array, offset: number) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readUint32(bytes: Uint8Array, offset: number) {
  return (
    bytes[offset]
    | (bytes[offset + 1] << 8)
    | (bytes[offset + 2] << 16)
    | (bytes[offset + 3] << 24)
  ) >>> 0;
}

function readText(bytes: Uint8Array, offset: number, length: number) {
  return new TextDecoder().decode(bytes.subarray(offset, offset + length));
}

function compressionMethodLabel(value: number) {
  if (value === 0) return "stored";
  if (value === 8) return "deflate";
  return `method-${value}`;
}

function isArchiveManifest(value: unknown): value is { kind: "nullid-archive-manifest"; files: Array<Record<string, unknown>> } {
  return Boolean(
    value
      && typeof value === "object"
      && "kind" in value
      && (value as { kind?: unknown }).kind === "nullid-archive-manifest"
      && "files" in value
      && Array.isArray((value as { files?: unknown }).files),
  );
}

interface CentralDirectoryEntry {
  path: string;
  compressionMethod: number;
  compressedBytes: number;
  uncompressedBytes: number;
  localHeaderOffset: number;
  encrypted: boolean;
}
