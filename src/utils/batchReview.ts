import {
  buildArchiveComparisonReport,
  inspectZipArchiveBytes,
  type ArchiveInspectionResult,
  type ArchiveVerificationResult,
} from "./archiveInspection.js";
import {
  analyzeMetadataFromBuffer,
  type MetadataAnalysisResult,
} from "./metadataAdvanced.js";
import { defaultRuleSetState, type RedactionRuleSet } from "./redaction.js";
import { scanSecrets, summarizeSecretFindings, type SecretScannerResult } from "./secretScanner.js";
import {
  analyzeStructuredText,
  summarizeStructuredAnalysis,
  type StructuredTextAnalysisResult,
} from "./structuredTextAnalyzer.js";
import {
  analyzeFinancialIdentifiers,
  summarizeFinancialReview,
  type FinancialReviewResult,
} from "./financialReview.js";
import {
  analyzePathPrivacy,
  summarizePathPrivacy,
  type PathPrivacyAnalysisResult,
} from "./pathPrivacy.js";

export type BatchReviewItemKind = "text" | "file";

export interface BatchReviewSummary {
  findings: string[];
  financial: string[];
  metadata: string[];
  pathPrivacy: string[];
  redaction: string[];
  secrets: string[];
  warnings: string[];
  regionSpecific: string[];
  unsupported: string[];
}

export interface BatchReviewItem {
  id: string;
  label: string;
  kind: BatchReviewItemKind;
  typeLabel: string;
  mediaType: string;
  sizeBytes: number;
  text?: string;
  fileName?: string;
  sourceBytes?: Uint8Array;
  metadataAnalysis?: MetadataAnalysisResult;
  archiveInspection?: ArchiveInspectionResult;
  structuredAnalysis?: StructuredTextAnalysisResult;
  financialReview?: FinancialReviewResult;
  pathPrivacy?: PathPrivacyAnalysisResult;
  secretScan?: SecretScannerResult;
  summary: BatchReviewSummary;
}

export interface BatchReviewExportReport {
  schemaVersion: 1;
  kind: "nullid-batch-review-report";
  createdAt: string;
  itemCount: number;
  items: Array<{
    id: string;
    label: string;
    kind: BatchReviewItemKind;
    typeLabel: string;
    mediaType: string;
    sizeBytes: number;
    fileName: string | null;
    sections: Array<{
      id: string;
      label: string;
      items: unknown[];
    }>;
  }>;
}

export async function createBatchTextReviewItem(input: {
  id: string;
  label: string;
  text: string;
  enabledRuleSets?: Record<Exclude<RedactionRuleSet, "general">, boolean>;
}): Promise<BatchReviewItem> {
  const structuredAnalysis = analyzeStructuredText(input.text, {
    enabledRuleSets: {
      ...defaultRuleSetState(),
      ...(input.enabledRuleSets ?? {}),
    },
  });
  const secretScan = scanSecrets(input.text);
  const financialReview = analyzeFinancialIdentifiers(input.text, {
    enabledRuleSets: {
      ...defaultRuleSetState(),
      ...(input.enabledRuleSets ?? {}),
    },
  });
  return {
    id: input.id,
    label: input.label,
    kind: "text",
    typeLabel: "text entry",
    mediaType: "text/plain;charset=utf-8",
    sizeBytes: new TextEncoder().encode(input.text).byteLength,
    text: input.text,
    structuredAnalysis,
    financialReview,
    secretScan,
    summary: buildTextSummary(structuredAnalysis, financialReview, secretScan),
  };
}

export async function createBatchFileReviewItem(input: {
  id: string;
  label: string;
  fileName: string;
  fileMediaType: string;
  sourceBytes: Uint8Array;
  enabledRuleSets?: Record<Exclude<RedactionRuleSet, "general">, boolean>;
}): Promise<BatchReviewItem> {
  const metadataAnalysis = analyzeMetadataFromBuffer(input.fileMediaType, input.sourceBytes, input.fileName);
  const maybeText = extractReviewableText(input.fileName, input.fileMediaType, input.sourceBytes);
  const structuredAnalysis = maybeText
    ? analyzeStructuredText(maybeText, {
        enabledRuleSets: {
          ...defaultRuleSetState(),
          ...(input.enabledRuleSets ?? {}),
        },
      })
    : undefined;
  const secretScan = maybeText ? scanSecrets(maybeText) : undefined;
  const financialReview = maybeText
    ? analyzeFinancialIdentifiers(maybeText, {
        enabledRuleSets: {
          ...defaultRuleSetState(),
          ...(input.enabledRuleSets ?? {}),
        },
      })
    : undefined;
  const pathPrivacy = analyzePathPrivacy(input.fileName);
  const archiveInspection = metadataAnalysis.format === "zip"
    ? await inspectZipArchiveBytes(input.sourceBytes)
    : undefined;

  return {
    id: input.id,
    label: input.label,
    kind: "file",
    typeLabel: `${metadataAnalysis.kind} file`,
    mediaType: input.fileMediaType || "application/octet-stream",
    sizeBytes: input.sourceBytes.length,
    fileName: input.fileName,
    sourceBytes: Uint8Array.from(input.sourceBytes),
    metadataAnalysis,
    archiveInspection,
    structuredAnalysis,
    financialReview,
    pathPrivacy,
    secretScan,
    summary: buildFileSummary(metadataAnalysis, structuredAnalysis, financialReview, pathPrivacy, secretScan, archiveInspection),
  };
}

export function buildBatchReviewExport(items: BatchReviewItem[]): BatchReviewExportReport {
  return {
    schemaVersion: 1,
    kind: "nullid-batch-review-report",
    createdAt: new Date().toISOString(),
    itemCount: items.length,
    items: items.map((item) => ({
      id: item.id,
      label: item.label,
      kind: item.kind,
      typeLabel: item.typeLabel,
      mediaType: item.mediaType,
      sizeBytes: item.sizeBytes,
      fileName: item.fileName ?? null,
      sections: buildBatchExportSections(item),
    })),
  };
}

export function itemToChecklistInput(item: BatchReviewItem) {
  return {
    label: item.label,
    typeLabel: item.typeLabel,
    verified: buildVerifiedLines(item),
    notProvable: buildNotProvableLines(item),
    manualReview: item.summary.warnings,
    remainingTraces: item.metadataAnalysis?.remainingTraces ?? [],
    regionSpecificDetections: item.summary.regionSpecific,
    unsupportedConditions: item.summary.unsupported,
  };
}

function buildTextSummary(
  structuredAnalysis: StructuredTextAnalysisResult,
  financialReview: FinancialReviewResult,
  secretScan: SecretScannerResult,
): BatchReviewSummary {
  return {
    findings: summarizeStructuredAnalysis(structuredAnalysis),
    financial: summarizeFinancialReview(financialReview),
    metadata: [],
    pathPrivacy: [],
    redaction: [`${structuredAnalysis.redactionMatches.length} redaction preview match(es) are available locally.`],
    secrets: summarizeSecretFindings(secretScan.findings),
    warnings: [
      "Text findings are pattern-based and should be reviewed before sharing.",
      ...structuredAnalysis.notes,
      ...secretScan.notes,
    ],
    regionSpecific: structuredAnalysis.regionGroups
      .filter((group) => group.total > 0)
      .map((group) => `${labelForRuleSet(group.ruleSet)}: ${group.total}`),
    unsupported: [],
  };
}

function buildFileSummary(
  metadataAnalysis: MetadataAnalysisResult,
  structuredAnalysis?: StructuredTextAnalysisResult,
  financialReview?: FinancialReviewResult,
  pathPrivacy?: PathPrivacyAnalysisResult,
  secretScan?: SecretScannerResult,
  archiveInspection?: ArchiveInspectionResult,
): BatchReviewSummary {
  return {
    findings: structuredAnalysis ? summarizeStructuredAnalysis(structuredAnalysis) : [],
    financial: financialReview ? summarizeFinancialReview(financialReview) : [],
    metadata: [
      `format: ${metadataAnalysis.format}`,
      `risk: ${metadataAnalysis.risk}`,
      ...metadataAnalysis.signals.slice(0, 6).map((signal) => `${signal.label}: ${signal.detail}`),
    ],
    pathPrivacy: pathPrivacy ? summarizePathPrivacy(pathPrivacy) : [],
    redaction: structuredAnalysis ? [`${structuredAnalysis.redactionMatches.length} text redaction preview match(es) are available locally.`] : [],
    secrets: secretScan ? summarizeSecretFindings(secretScan.findings) : [],
    warnings: [
      ...metadataAnalysis.guidance,
      ...metadataAnalysis.cannotGuarantee,
      ...(pathPrivacy?.findings.map((finding) => `${finding.label}: ${finding.reason}`) ?? []),
      ...(archiveInspection?.warnings ?? []),
    ],
    regionSpecific: structuredAnalysis
      ? structuredAnalysis.regionGroups
          .filter((group) => group.total > 0)
          .map((group) => `${labelForRuleSet(group.ruleSet)}: ${group.total}`)
      : [],
    unsupported: [
      ...(archiveInspection?.entries
        .filter((entry) => entry.status === "unsupported")
        .map((entry) => `${entry.path}: ${entry.detail}`) ?? []),
      ...(metadataAnalysis.recommendedSanitizer === "manual" ? ["Local cleanup is not fully supported for this file type in the current surface."] : []),
    ],
  };
}

function buildVerifiedLines(item: BatchReviewItem) {
  const lines = [`${item.kind === "text" ? "Text" : "File"} review ran locally.`];
  if (item.structuredAnalysis) {
    lines.push(`${item.structuredAnalysis.total} structured finding(s) were grouped locally.`);
  }
  if (item.financialReview) {
    lines.push(`${item.financialReview.total} financial identifier finding(s) were reviewed locally.`);
  }
  if (item.secretScan) {
    lines.push(`${item.secretScan.total} likely secret finding(s) were scanned locally.`);
  }
  if (item.metadataAnalysis) {
    lines.push(`${item.metadataAnalysis.format} metadata inspection ran locally.`);
  }
  if (item.archiveInspection) {
    lines.push(`${item.archiveInspection.fileCount} archive file hash(es) were computed locally.`);
  }
  if (item.pathPrivacy) {
    lines.push(`${item.pathPrivacy.total} filename/path privacy hint(s) were generated locally.`);
  }
  return lines;
}

function buildNotProvableLines(item: BatchReviewItem) {
  const lines = [
    "Pattern-based detectors do not prove a value is complete, active, or correctly classified.",
  ];
  if (item.metadataAnalysis) {
    lines.push("Metadata review does not prove that visible content or omitted attachments are safe to share.");
  }
  if (item.archiveInspection) {
    lines.push("Archive inspection does not prove sender identity or archive completeness beyond readable entries.");
  }
  if (item.pathPrivacy) {
    lines.push("Filename/path hints do not prove a label is truly identifying or sensitive in context.");
  }
  return lines;
}

function extractReviewableText(fileName: string, mediaType: string, sourceBytes: Uint8Array) {
  if (!looksTextReviewable(fileName, mediaType, sourceBytes)) return null;
  return new TextDecoder().decode(sourceBytes);
}

function looksTextReviewable(fileName: string, mediaType: string, sourceBytes: Uint8Array) {
  const lower = fileName.toLowerCase();
  if (
    mediaType.startsWith("text/")
    || /json|xml|yaml|csv|javascript/.test(mediaType)
    || /\.(txt|log|json|ndjson|csv|xml|yaml|yml|env|ini|md)$/i.test(lower)
  ) {
    return true;
  }
  const sample = sourceBytes.subarray(0, Math.min(sourceBytes.length, 512));
  let printable = 0;
  sample.forEach((value) => {
    if (value === 9 || value === 10 || value === 13 || (value >= 32 && value <= 126)) printable += 1;
  });
  return sample.length > 0 && printable / sample.length > 0.92;
}

function buildBatchExportSections(item: BatchReviewItem) {
  const sections: BatchReviewExportReport["items"][number]["sections"] = [];

  sections.push({
    id: "review-basis",
    label: "Review basis",
    items: buildVerifiedLines(item).map((value) => ({ value })),
  });

  if (item.metadataAnalysis) {
    sections.push({
      id: "metadata",
      label: "Metadata review",
      items: item.metadataAnalysis.reviewSections.map((section) => ({
        id: section.id,
        label: section.label,
        items: section.items,
      })),
    });
  }

  if (item.structuredAnalysis) {
    sections.push({
      id: "structured-analysis",
      label: "Structured text analysis",
      items: item.structuredAnalysis.findingGroups.map((group) => ({
        category: group.category,
        total: group.total,
      })),
    });
    sections.push({
      id: "regional-analysis",
      label: "Regional detection summary",
      items: item.structuredAnalysis.regionGroups
        .filter((group) => group.total > 0)
        .map((group) => ({
          ruleSet: group.ruleSet,
          total: group.total,
          labels: group.findings.map((finding) => finding.label),
        })),
    });
  }

  if (item.financialReview) {
    sections.push({
      id: "financial-review",
      label: "Financial identifier review",
      items: item.financialReview.findings.map((finding) => ({
        type: finding.label,
        category: finding.category,
        confidence: finding.confidence,
        evidence: finding.detectionKind,
        reason: finding.reason,
        preview: finding.preview,
      })),
    });
  }

  if (item.pathPrivacy) {
    sections.push({
      id: "path-privacy",
      label: "Filename / path privacy",
      items: item.pathPrivacy.findings.map((finding) => ({
        type: finding.label,
        confidence: finding.confidence,
        reason: finding.reason,
        replacement: finding.suggestedReplacement,
        segments: finding.flaggedSegments.map((segment) => segment.segment),
      })),
    });
  }

  if (item.secretScan) {
    sections.push({
      id: "secret-scan",
      label: "Secret scan",
      items: item.secretScan.findings.map((finding) => ({
        type: finding.label,
        confidence: finding.confidence,
        evidence: finding.evidence,
        reason: finding.reason,
        preview: finding.preview,
      })),
    });
  }

  if (item.archiveInspection) {
    sections.push({
      id: "archive-inspection",
      label: "Archive inspection",
      items: [
        {
          entryCount: item.archiveInspection.entryCount,
          fileCount: item.archiveInspection.fileCount,
          directoryCount: item.archiveInspection.directoryCount,
          warnings: item.archiveInspection.warnings,
        },
      ],
    });
  }

  const archiveVerification = buildAdHocArchiveVerification(item.archiveInspection);
  if (archiveVerification) {
    const report = buildArchiveComparisonReport(archiveVerification);
    sections.push({
      id: "archive-comparison",
      label: "Archive comparison",
      items: [report],
    });
  }

  sections.push({
    id: "manual-review",
    label: "Manual review",
    items: item.summary.warnings.map((value) => ({ value })),
  });

  if (item.summary.unsupported.length > 0) {
    sections.push({
      id: "unsupported",
      label: "Unsupported conditions",
      items: item.summary.unsupported.map((value) => ({ value })),
    });
  }

  return sections.filter((section) => section.items.length > 0);
}

function buildAdHocArchiveVerification(archiveInspection?: ArchiveInspectionResult): ArchiveVerificationResult | null {
  if (!archiveInspection) return null;
  return {
    matched: 0,
    mismatched: 0,
    missingFromArchive: 0,
    extraInArchive: 0,
    entries: [],
    manifestEntries: [],
    groups: {
      matched: [],
      missing: [],
      extra: [],
      hashMismatch: [],
      unsupported: archiveInspection.entries
        .filter((entry) => entry.status === "unsupported")
        .map((entry) => ({
          ...entry,
          verification: "unsupported" as const,
          comparisonStatus: "unsupported" as const,
        })),
      notChecked: archiveInspection.entries
        .filter((entry) => !entry.directory && entry.status === "hashed")
        .map((entry) => ({
          ...entry,
          verification: "matched" as const,
          comparisonStatus: "not-checked" as const,
        })),
    },
    localFacts: [
      `${archiveInspection.fileCount} archive file hash(es) were computed locally from readable ZIP entry bytes.`,
    ],
    expectedFacts: [],
    declaredOnly: [],
    manualReviewRecommendations: archiveInspection.warnings.length > 0
      ? ["Some archive members could not be compared or hashed locally; review those entries manually."]
      : ["Archive member hashes were computed locally, but no expected manifest/workflow package was loaded for comparison."],
  };
}

function labelForRuleSet(ruleSet: Exclude<RedactionRuleSet, "general">) {
  return ruleSet === "iran" ? "Iran / Persian" : "Russia";
}
