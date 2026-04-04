import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildExposureChecklist, buildVerificationChecklist, reviewChecklistToText } from "../utils/reviewChecklist.js";
import type { MetadataAnalysisResult } from "../utils/metadataAdvanced.js";
import type { ReceivedArtifactVerificationResult } from "../utils/packageVerification.js";

describe("reviewChecklist", () => {
  it("builds verification checklist sections from actual verification results", () => {
    const result: ReceivedArtifactVerificationResult = {
      artifactType: "workflow-package",
      artifactKindLabel: "Workflow package",
      title: "Workflow package",
      verificationState: "integrity-checked",
      verificationLabel: "Integrity checked",
      trustBasis: [],
      verifiedChecks: ["Schema parsed successfully."],
      unverifiedChecks: ["Sender identity is not asserted."],
      warnings: ["Unsigned package."],
      limitations: ["Review before sharing."],
      facts: [],
      artifacts: [],
      transforms: [],
      policySummary: [],
      receiverExplanation: {
        verified: ["Schema parsed successfully."],
        declaredOnly: ["Transform summaries were parsed successfully but remain package-declared only."],
        notProvable: ["Sender identity is not asserted."],
        manualReview: ["Unsigned package."],
      },
    };

    const checklist = buildVerificationChecklist(result);
    assert.equal(checklist.sections.length, 4);
    assert.equal(checklist.sections[0]?.label, "What is verified");
    assert.match(reviewChecklistToText(checklist), /What is not provable/);
  });

  it("builds exposure checklist for archive and metadata review", () => {
    const checklist = buildExposureChecklist({
      title: "Exposure checklist",
      analysis: makeMetadataAnalysis({
        format: "zip",
        kind: "archive",
        risk: "medium",
        fields: [{ key: "docProps.core", value: "present" }],
        signals: [{ id: "embedded", label: "Embedded files", severity: "high", detail: "Embedded container markers found." }],
        recommendedSanitizer: "manual",
        commandHint: null,
        guidance: ["Review archive contents locally."],
        remainingTraces: ["Visible content still needs manual review."],
        removable: ["Some metadata can be stripped locally."],
        cannotGuarantee: ["Archive metadata cleanup cannot prove hidden previews were removed."],
      }),
      archiveInspection: {
        schemaVersion: 1,
        kind: "nullid-archive-inspection",
        createdAt: new Date().toISOString(),
        fileCount: 1,
        directoryCount: 0,
        entryCount: 1,
        entries: [{
          path: "docs/readme.txt",
          directory: false,
          compressionMethod: 0,
          compressionLabel: "stored",
          compressedBytes: 5,
          uncompressedBytes: 5,
          sha256: "abc",
          status: "hashed",
          detail: "SHA-256 computed from extracted entry bytes.",
        }],
        warnings: [],
      },
      archiveVerification: null,
    });

    assert.equal(checklist.sections.some((section) => section.label === "Remaining traces"), true);
    assert.equal(checklist.sections.some((section) => section.label === "Unsupported cleanup"), true);
    assert.equal(checklist.sections.some((section) => section.label === "Review recommendations"), true);
  });
});

function makeMetadataAnalysis(
  input: Omit<MetadataAnalysisResult, "unsupportedCleanup" | "reviewRecommendations" | "metadataFound" | "reviewSections">,
): MetadataAnalysisResult {
  return {
    ...input,
    unsupportedCleanup: ["This file type currently has no safe in-browser cleanup path in NullID."],
    reviewRecommendations: [...input.guidance],
    metadataFound: input.signals.map((signal) => `${signal.label}: ${signal.detail}`),
    reviewSections: [
      { id: "metadata-found", label: "Metadata found", items: input.signals.map((signal) => `${signal.label}: ${signal.detail}`) },
      { id: "removable-locally", label: "Removable locally", items: input.removable },
      { id: "remaining-traces", label: "Remaining traces", items: input.remainingTraces },
      { id: "unsupported-cleanup", label: "Unsupported cleanup", items: ["This file type currently has no safe in-browser cleanup path in NullID."] },
      { id: "review-recommendations", label: "Review recommendations", items: input.guidance },
    ],
  };
}
