import type { ArchiveInspectionResult, ArchiveVerificationResult } from "./archiveInspection.js";
import type { MetadataAnalysisResult } from "./metadataAdvanced.js";
import type { ReceivedArtifactVerificationResult } from "./packageVerification.js";
import { renderExportReportText } from "./reporting.js";

export interface ReviewChecklistSection {
  id: string;
  label: string;
  items: string[];
}

export interface ReviewChecklist {
  schemaVersion: 1;
  kind: "nullid-review-checklist";
  title: string;
  createdAt: string;
  sections: ReviewChecklistSection[];
}

export interface BatchChecklistItem {
  label: string;
  typeLabel: string;
  verified: string[];
  declaredOnly?: string[];
  notProvable?: string[];
  manualReview?: string[];
  remainingTraces?: string[];
  regionSpecificDetections?: string[];
  unsupportedConditions?: string[];
}

export function createReviewChecklist(title: string, sections: ReviewChecklistSection[]): ReviewChecklist {
  return {
    schemaVersion: 1,
    kind: "nullid-review-checklist",
    title,
    createdAt: new Date().toISOString(),
    sections: sections
      .map((section) => ({
        ...section,
        items: uniqueLines(section.items),
      }))
      .filter((section) => section.items.length > 0),
  };
}

export interface ReviewChecklistRenderOptions {
  translate?: (value: string) => string;
  formatDateTime?: (value: number | string | Date) => string;
}

export function reviewChecklistToText(checklist: ReviewChecklist, options: ReviewChecklistRenderOptions = {}) {
  const localize = options.translate ?? ((value: string) => value);
  return renderExportReportText({
    title: checklist.title,
    createdAt: checklist.createdAt,
    sections: checklist.sections.map((section) => ({
      id: section.id,
      label: localize(section.label),
      items: section.items.map((item) => localize(item)),
    })),
  }, options);
}

export function buildVerificationChecklist(result: ReceivedArtifactVerificationResult): ReviewChecklist {
  return createReviewChecklist(`Verification checklist :: ${result.title}`, [
    { id: "verified", label: "What is verified", items: result.receiverExplanation.verified },
    { id: "declared-only", label: "What is declared only", items: result.receiverExplanation.declaredOnly },
    { id: "not-provable", label: "What is not provable", items: result.receiverExplanation.notProvable },
    { id: "manual-review", label: "What to review manually", items: result.receiverExplanation.manualReview },
  ]);
}

export function buildExposureChecklist(input: {
  title: string;
  analysis: MetadataAnalysisResult;
  archiveInspection?: ArchiveInspectionResult | null;
  archiveVerification?: ArchiveVerificationResult | null;
}): ReviewChecklist {
  const { analysis, archiveInspection, archiveVerification } = input;
  const metadataSections = analysis.reviewSections.reduce<Record<string, string[]>>((acc, section) => {
    acc[section.id] = section.items;
    return acc;
  }, {});
  const verified = [
    `${analysis.format} metadata inspection ran locally in this browser.`,
    ...(analysis.fields.length > 0 ? [`${analysis.fields.length} metadata field(s) were parsed locally.`] : []),
    ...(archiveInspection ? [`${archiveInspection.fileCount} archive file hash(es) were computed locally from extracted ZIP entry bytes.`] : []),
    ...(archiveVerification ? [`${archiveVerification.matched} archive entry hash(es) matched the loaded expected manifest.`] : []),
    ...(archiveVerification?.localFacts ?? []),
  ];
  const declaredOnly = [
    ...(archiveVerification?.expectedFacts ?? []),
    ...(archiveVerification?.declaredOnly ?? []),
  ];
  const notProvable = [
    "Sender identity or authorship is not proven by metadata review or archive comparison.",
    "Metadata cleanup cannot prove that visible page content, embedded previews, or omitted context are safe to share.",
    ...(archiveInspection ? ["Archive inspection does not prove archive completeness beyond the entries that were locally readable."] : []),
    ...analysis.cannotGuarantee,
  ];
  const reviewRecommendations = [
    ...(metadataSections["review-recommendations"] ?? analysis.guidance),
    ...(metadataSections["unsupported-cleanup"] ?? []),
    ...(archiveInspection?.warnings ?? []),
    ...(archiveVerification?.manualReviewRecommendations ?? []),
    ...(archiveVerification?.groups.hashMismatch.map((entry) => `${entry.path}: hash mismatch against the loaded expected value.`) ?? []),
    ...(archiveVerification?.groups.extra.map((entry) => `${entry.path}: present in the archive but not declared in the loaded expected set.`) ?? []),
    ...(archiveVerification?.groups.unsupported.map((entry) => `${entry.path}: could not be fully compared locally (${entry.detail}).`) ?? []),
    ...(archiveVerification?.groups.notChecked.map((entry) => `${entry.path}: not checked against expected hashes (${entry.detail}).`) ?? []),
    ...(archiveVerification?.groups.missing.map((entry) => `${entry.path}: expected by the loaded manifest/workflow package but missing from the inspected archive.`) ?? []),
  ];
  const remainingTraces = metadataSections["remaining-traces"] ?? analysis.remainingTraces;
  const unsupportedCleanup = [
    ...(metadataSections["unsupported-cleanup"] ?? []),
    ...(archiveInspection?.entries
      .filter((entry) => entry.status === "unsupported")
      .map((entry) => `${entry.path}: unsupported ZIP method or encryption state for local inspection.`) ?? []),
  ];

  return createReviewChecklist(input.title, [
    { id: "verified", label: "What is verified", items: verified },
    { id: "declared-only", label: "What is declared only", items: declaredOnly },
    { id: "not-provable", label: "What is not provable", items: notProvable },
    { id: "metadata-found", label: "Metadata found", items: metadataSections["metadata-found"] ?? analysis.metadataFound },
    { id: "removable-locally", label: "Removable locally", items: metadataSections["removable-locally"] ?? analysis.removable },
    { id: "remaining-traces", label: "Remaining traces", items: remainingTraces },
    { id: "unsupported-cleanup", label: "Unsupported cleanup", items: unsupportedCleanup },
    { id: "review-recommendations", label: "Review recommendations", items: reviewRecommendations },
  ]);
}

export function buildBatchChecklist(title: string, items: BatchChecklistItem[]): ReviewChecklist {
  return createReviewChecklist(title, [
    {
      id: "verified",
      label: "What is verified",
      items: items.flatMap((item) => item.verified.map((line) => `${item.label} (${item.typeLabel}): ${line}`)),
    },
    {
      id: "declared-only",
      label: "What is declared only",
      items: items.flatMap((item) => (item.declaredOnly ?? []).map((line) => `${item.label}: ${line}`)),
    },
    {
      id: "not-provable",
      label: "What is not provable",
      items: items.flatMap((item) => (item.notProvable ?? []).map((line) => `${item.label}: ${line}`)),
    },
    {
      id: "manual-review",
      label: "What to review manually",
      items: items.flatMap((item) => (item.manualReview ?? []).map((line) => `${item.label}: ${line}`)),
    },
    {
      id: "remaining-traces",
      label: "Possible remaining traces",
      items: items.flatMap((item) => (item.remainingTraces ?? []).map((line) => `${item.label}: ${line}`)),
    },
    {
      id: "region-detections",
      label: "Region-specific identifiers detected",
      items: items.flatMap((item) => (item.regionSpecificDetections ?? []).map((line) => `${item.label}: ${line}`)),
    },
    {
      id: "unsupported",
      label: "Unsupported conditions",
      items: items.flatMap((item) => (item.unsupportedConditions ?? []).map((line) => `${item.label}: ${line}`)),
    },
  ]);
}

function uniqueLines(items: string[]) {
  return Array.from(new Set(items.filter(Boolean)));
}
