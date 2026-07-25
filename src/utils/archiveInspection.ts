import { extractWorkflowPackage } from "./workflowPackage.js";
import { ArchiveReferenceManifestError, validateArchiveReferenceEntries } from "./archiveReferencePolicy.js";
import {
  parseZipArchive,
  readZipEntryBytesAsync,
  zipCompressionLabel,
} from "./zipSafety.js";

type ParsedZipEntry = ReturnType<typeof parseZipArchive>["entries"][number];

interface ArchiveInspectionEntry {
  path: string;
  directory: boolean;
  compressionMethod: number;
  compressionLabel: string;
  compressedBytes: number;
  uncompressedBytes: number;
  sha256: string | null;
  status: "hashed" | "directory" | "rejected" | "unsupported" | "malformed" | "policy-limit";
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

type ArchiveComparisonStatus = "matched" | "missing" | "extra" | "hash-mismatch" | "unsupported" | "not-checked";

interface ArchiveVerificationEntryResult extends ArchiveInspectionEntry {
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

export async function inspectZipArchiveBytes(bytes: Uint8Array): Promise<ArchiveInspectionResult> {
  let centralDirectory: ParsedZipEntry[];
  try {
    centralDirectory = parseZipArchive(bytes).entries;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "ZIP archive is malformed or unsupported.";
    const entry = archiveProblemEntry(zipErrorStatus(error), detail);
    return {
      schemaVersion: 1,
      kind: "nullid-archive-inspection",
      createdAt: new Date().toISOString(),
      fileCount: 0,
      directoryCount: 0,
      entryCount: 1,
      entries: [entry],
      warnings: [`${entry.path}: ${entry.detail}`],
    };
  }
  const entries = await Promise.all(
    centralDirectory.map(async (entry) => inspectEntry(bytes, entry)),
  );
  const warnings = entries
    .filter((entry) => entry.status !== "hashed" && entry.status !== "directory")
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
    if (parsed.schemaVersion !== 2) {
      throw new ArchiveReferenceManifestError("unsupported schema version");
    }
    return validateArchiveReferenceEntries(parsed.files.map((entry, index) => {
      if (!entry || typeof entry !== "object") {
        throw new ArchiveReferenceManifestError(`entry ${index + 1} must be an object`);
      }
      const path = typeof entry.path === "string" ? entry.path : null;
      const sha256 = typeof entry.sha256After === "string"
        ? entry.sha256After
        : typeof entry.sha256 === "string"
          ? entry.sha256
          : null;
      if (!path || !sha256) {
        throw new ArchiveReferenceManifestError(`entry ${index + 1} must include path and sha256`);
      }
      return { path, sha256, source: "archive-manifest" as const };
    })) as ArchiveReferenceEntry[];
  }

  let workflowPackage: ReturnType<typeof extractWorkflowPackage>;
  try {
    workflowPackage = extractWorkflowPackage(parsed);
  } catch {
    return [];
  }
  return validateArchiveReferenceEntries(workflowPackage.artifacts.map((artifact, index) => {
    if (!artifact.sha256) {
      throw new ArchiveReferenceManifestError(`workflow artifact ${index + 1} must include sha256`);
    }
    const path = artifact.filename || artifact.id;
    if (!path) {
      throw new ArchiveReferenceManifestError(`workflow artifact ${index + 1} must include a path`);
    }
    return { path, sha256: artifact.sha256, source: "workflow-package" as const };
  })) as ArchiveReferenceEntry[];
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
    if (entry.status !== "hashed") {
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

async function inspectEntry(bytes: Uint8Array, entry: ParsedZipEntry): Promise<ArchiveInspectionEntry> {
  const path = typeof entry.path === "string" ? entry.path : "(entry)";
  const directory = Boolean(entry.directory);
  const compressionMethod = typeof entry.compressionMethod === "number" ? entry.compressionMethod : 0;
  const compressedBytes = typeof entry.compressedBytes === "number" ? entry.compressedBytes : 0;
  const uncompressedBytes = typeof entry.uncompressedBytes === "number" ? entry.uncompressedBytes : 0;
  const problem = isProblemRecord(entry.problem) ? entry.problem : null;

  if (problem) {
    return {
      path,
      directory,
      compressionMethod,
      compressionLabel: zipCompressionLabel(compressionMethod),
      compressedBytes,
      uncompressedBytes,
      sha256: null,
      status: problem.status,
      detail: problem.detail,
    };
  }

  if (directory) {
    return {
      path,
      directory: true,
      compressionMethod,
      compressionLabel: zipCompressionLabel(compressionMethod),
      compressedBytes,
      uncompressedBytes,
      sha256: null,
      status: "directory",
      detail: "Directory entry",
    };
  }

  try {
    const content = await readEntryContent(bytes, entry);
    return {
      path,
      directory: false,
      compressionMethod,
      compressionLabel: zipCompressionLabel(compressionMethod),
      compressedBytes,
      uncompressedBytes,
      sha256: await sha256Hex(content),
      status: "hashed",
      detail: "SHA-256 computed from extracted entry bytes.",
    };
  } catch (error) {
    return {
      path,
      directory: false,
      compressionMethod,
      compressionLabel: zipCompressionLabel(compressionMethod),
      compressedBytes,
      uncompressedBytes,
      sha256: null,
      status: zipErrorStatus(error),
      detail: error instanceof Error ? error.message : "Unsupported ZIP entry",
    };
  }
}

async function readEntryContent(bytes: Uint8Array, entry: ParsedZipEntry): Promise<Uint8Array> {
  return readZipEntryBytesAsync(bytes, entry, inflateRawBrowser);
}

async function inflateRawBrowser(
  bytes: Uint8Array,
  _entry: unknown,
  context?: { accountOutputBytes: (byteLength: number) => void },
): Promise<Uint8Array> {
  if (typeof DecompressionStream !== "function") {
    throw new Error("Raw deflate decompression is unavailable in this browser.");
  }
  const stream = new Blob([toArrayBuffer(bytes)]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      context?.accountOutputBytes(chunk.byteLength);
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } catch (error) {
    await reader.cancel(error).catch(() => undefined);
    throw error;
  }

  const output = new Uint8Array(total);
  let offset = 0;
  chunks.forEach((chunk) => {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  });
  return output;
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

function isArchiveManifest(value: unknown): value is { schemaVersion?: unknown; kind: "nullid-archive-manifest"; files: Array<Record<string, unknown>> } {
  return Boolean(
    value
      && typeof value === "object"
      && "kind" in value
      && (value as { kind?: unknown }).kind === "nullid-archive-manifest"
      && "files" in value
      && Array.isArray((value as { files?: unknown }).files),
  );
}

function archiveProblemEntry(status: ArchiveInspectionEntry["status"], detail: string): ArchiveInspectionEntry {
  return {
    path: "(archive)",
    directory: false,
    compressionMethod: 0,
    compressionLabel: "unknown",
    compressedBytes: 0,
    uncompressedBytes: 0,
    sha256: null,
    status,
    detail,
  };
}

function zipErrorStatus(error: unknown): ArchiveInspectionEntry["status"] {
  const category = typeof error === "object" && error !== null && "category" in error
    ? String((error as { category: unknown }).category)
    : "";
  if (category === "rejected") return "rejected";
  if (category === "policy-limit") return "policy-limit";
  if (category === "malformed") return "malformed";
  if (category === "unsupported") return "unsupported";
  return "unsupported";
}

function isProblemRecord(value: unknown): value is { status: ArchiveInspectionEntry["status"]; detail: string } {
  return Boolean(
    value
      && typeof value === "object"
      && ["rejected", "unsupported", "malformed", "policy-limit"].includes(String((value as { status?: unknown }).status))
      && typeof (value as { detail?: unknown }).detail === "string",
  );
}
