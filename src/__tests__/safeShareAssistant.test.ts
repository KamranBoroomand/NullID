import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildSafeShareSanitizeConfig,
  createSafeShareFileWorkflowPackage,
  createSafeShareTextWorkflowPackage,
  getSafeSharePreset,
  resolveSafeShareAnalysisRuleSets,
} from "../utils/safeShareAssistant.js";
import type { MetadataAnalysisResult } from "../utils/metadataAdvanced.js";
import { buildRulesState } from "../utils/sanitizeEngine.js";
import { verifyWorkflowPackagePayload } from "../utils/workflowPackage.js";

const producer = {
  app: "NullID" as const,
  surface: "web" as const,
  module: "share",
  version: "0.1.0",
};

describe("safe share assistant", () => {
  it("creates a text workflow package with preset metadata and honest trust labels", async () => {
    const workflowPackage = await createSafeShareTextWorkflowPackage({
      presetId: "support-ticket",
      producer,
      inputText: "token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com",
      sourceLabel: "support.log",
      includeSourceReference: true,
      protectAtExport: true,
    });

    assert.equal(workflowPackage.workflowType, "safe-share-assistant");
    assert.equal(workflowPackage.workflowPreset?.id, "support-ticket");
    assert.equal(workflowPackage.workflowPreset?.label, "Support ticket / bug report");
    assert.equal(workflowPackage.trust.identity, "not-asserted");
    assert.equal(workflowPackage.trust.packageSignature.method, "none");
    assert.match(workflowPackage.warnings.join(" "), /sender identity is not asserted/i);
    assert.match(workflowPackage.limitations.join(" "), /NULLID:ENC:1 protection is applied to the exported file/i);
    assert.equal(workflowPackage.artifacts.some((artifact) => artifact.id === "shared-output"), true);
    assert.equal(workflowPackage.artifacts.some((artifact) => artifact.id === "safe-share-report"), true);
    assert.equal(workflowPackage.transforms?.some((transform) => transform.id === "safe-share-review"), true);
  });

  it("exports report-only file packages when cleanup is unavailable and the preset forbids original bytes", async () => {
    const sourceBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x01, 0x02, 0x03]);
    const workflowPackage = await createSafeShareFileWorkflowPackage({
      presetId: "external-minimum",
      producer,
      fileName: "evidence.docx",
      fileMediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      sourceBytes,
      analysis: makeMetadataAnalysis({
        format: "docx",
        kind: "document",
        risk: "high",
        fields: [{ key: "docProps.core", value: "present" }],
        signals: [{ id: "author", label: "Author identity", severity: "high", detail: "Author markers found." }],
        recommendedSanitizer: "mat2",
        commandHint: "mat2 evidence.docx",
        guidance: ["Run mat2 locally and re-analyze before wider sharing."],
        remainingTraces: ["Comments, tracked changes, speaker notes, and embedded previews may still remain."],
        removable: ["OOXML document properties in docProps/core.xml, app.xml, and custom.xml."],
        cannotGuarantee: ["Comments, tracked changes, embedded objects, and document body text are not removed by metadata-only handling."],
      }),
      applyMetadataClean: true,
      includeSourceReference: true,
      protectAtExport: false,
    });

    assert.equal(workflowPackage.workflowPreset?.id, "external-minimum");
    assert.equal(workflowPackage.artifacts.some((artifact) => artifact.kind === "binary"), false);
    assert.equal(workflowPackage.artifacts.some((artifact) => artifact.id === "safe-share-report"), true);
    assert.match(workflowPackage.warnings.join(" "), /No file payload was packaged/i);
    assert.match(workflowPackage.limitations.join(" "), /external tooling may still be required/i);
  });

  it("verifies a file package that includes a binary payload when the preset preserves context", async () => {
    const sourceBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03]);
    const workflowPackage = await createSafeShareFileWorkflowPackage({
      presetId: "evidence-archive",
      producer,
      fileName: "clip.mp4",
      fileMediaType: "video/mp4",
      sourceBytes,
      analysis: makeMetadataAnalysis({
        format: "mp4",
        kind: "video",
        risk: "medium",
        fields: [],
        signals: [{ id: "tooling", label: "Tooling fingerprints", severity: "medium", detail: "Container metadata markers found." }],
        recommendedSanitizer: "mat2",
        commandHint: "ffmpeg -i clip.mp4 -map_metadata -1 -c copy clip-clean.mp4",
        guidance: ["Use ffmpeg locally to strip metadata before wider distribution."],
        remainingTraces: ["Frame content, subtitle tracks, and burned-in overlays remain outside metadata cleanup."],
        removable: ["Container metadata atoms and common creation/location tags through external offline tools such as ffmpeg."],
        cannotGuarantee: ["Frame content, burned-in overlays, and subtitle tracks are outside metadata-only cleanup guarantees."],
      }),
      applyMetadataClean: false,
      includeSourceReference: true,
      protectAtExport: false,
    });

    const verified = await verifyWorkflowPackagePayload(workflowPackage);

    assert.equal(workflowPackage.artifacts.some((artifact) => artifact.kind === "binary"), true);
    assert.equal(verified.verificationState, "integrity-checked");
    assert.equal(
      verified.artifactChecks.some((artifact) => artifact.kind === "binary" && artifact.status === "verified"),
      true,
    );
    assert.match(workflowPackage.warnings.join(" "), /Original file bytes are included/i);
  });

  it("reuses a saved policy pack configuration without inventing a separate sanitize policy format", () => {
    const policy = buildSafeShareSanitizeConfig("general-safe-share", {
      id: "policy-1",
      name: "team-scrub",
      createdAt: "2026-03-17T10:00:00.000Z",
      config: {
        rulesState: buildRulesState(["maskIp"]),
        jsonAware: false,
        customRules: [{ id: "custom-1", pattern: "secret", replacement: "[secret]", flags: "gi", scope: "text" }],
      },
    });

    assert.equal(policy.rulesState.maskIp, true);
    assert.equal(policy.rulesState.maskEmail, false);
    assert.equal(policy.jsonAware, false);
    assert.equal(policy.customRules.length, 1);
  });

  it("exposes transparent preset behavior for new practical presets", () => {
    const preset = getSafeSharePreset("external-minimum-disclosure");
    const regionRules = resolveSafeShareAnalysisRuleSets("external-minimum-disclosure");

    assert.equal(preset.reviewChecklistEmphasis.length > 0, true);
    assert.equal(Array.isArray(preset.sanitizeRules), true);
    assert.deepEqual(regionRules, { iran: false, russia: false });
  });

  it("adds financial and filename privacy transforms to workflow packages", async () => {
    const textPackage = await createSafeShareTextWorkflowPackage({
      presetId: "customer-support-share",
      producer,
      inputText: "شماره کارت: ۶۰۳۷-۹۹۷۳-۹۱۸۹-۸۰۸۸",
      includeSourceReference: false,
    });
    const filePackage = await createSafeShareFileWorkflowPackage({
      presetId: "customer-support-share",
      producer,
      fileName: "alice/incident-4432/report.pdf",
      fileMediaType: "application/pdf",
      sourceBytes: new Uint8Array([1, 2, 3]),
      analysis: makeMetadataAnalysis({
        format: "pdf",
        kind: "document",
        risk: "medium",
        fields: [],
        signals: [{ id: "pdf-info", label: "Document info", severity: "medium", detail: "PDF info dictionary present." }],
        recommendedSanitizer: "browser-pdf",
        commandHint: null,
        guidance: ["Review PDF metadata and visible content locally."],
        remainingTraces: ["Visible page content remains outside metadata cleanup."],
        removable: ["Basic PDF metadata fields in the document info dictionary."],
        cannotGuarantee: ["Annotations and visible page content still require human review."],
      }),
      applyMetadataClean: false,
      includeSourceReference: true,
    });

    assert.equal(textPackage.transforms?.some((transform) => transform.id === "financial-review"), true);
    assert.equal(filePackage.transforms?.some((transform) => transform.id === "filename-privacy"), true);
  });
});

function makeMetadataAnalysis(
  input: Omit<MetadataAnalysisResult, "unsupportedCleanup" | "reviewRecommendations" | "metadataFound" | "reviewSections">,
): MetadataAnalysisResult {
  return {
    ...input,
    unsupportedCleanup: [],
    reviewRecommendations: [...input.guidance],
    metadataFound: input.signals.map((signal) => `${signal.label}: ${signal.detail}`),
    reviewSections: [
      { id: "metadata-found", label: "Metadata found", items: input.signals.map((signal) => `${signal.label}: ${signal.detail}`) },
      { id: "removable-locally", label: "Removable locally", items: input.removable },
      { id: "remaining-traces", label: "Remaining traces", items: input.remainingTraces },
      { id: "review-recommendations", label: "Review recommendations", items: input.guidance },
    ],
  };
}
