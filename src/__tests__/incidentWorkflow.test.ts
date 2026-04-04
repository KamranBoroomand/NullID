import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createIncidentFileArtifactPackage,
  createIncidentTextArtifactPackage,
  createIncidentWorkflowPackage,
} from "../utils/incidentWorkflow.js";
import type { MetadataAnalysisResult } from "../utils/metadataAdvanced.js";
import { verifyWorkflowPackagePayload } from "../utils/workflowPackage.js";

const producer = {
  app: "NullID" as const,
  surface: "web" as const,
  module: "incident",
  version: "0.1.0",
};

describe("incident workflow", () => {
  it("creates a composed incident package with flattened prepared artifacts and honest trust limits", async () => {
    const notesPackage = await createIncidentTextArtifactPackage({
      modeId: "incident-handoff",
      producer,
      inputText: "Summary: token=abcdefghijklmnopqrstuvwxyz12345 alice@example.com",
      sourceLabel: "case-notes.txt",
      includeSourceReference: true,
      protectAtExport: false,
    });

    const filePackage = await createIncidentFileArtifactPackage({
      modeId: "internal-investigation",
      producer,
      fileName: "capture.mp4",
      fileMediaType: "video/mp4",
      sourceBytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]),
      analysis: makeMetadataAnalysis({
        format: "mp4",
        kind: "video",
        risk: "medium",
        fields: [],
        signals: [{ id: "tooling", label: "Tooling fingerprints", severity: "medium", detail: "Container metadata markers found." }],
        recommendedSanitizer: "mat2",
        commandHint: "ffmpeg -i capture.mp4 -map_metadata -1 -c copy capture-clean.mp4",
        guidance: ["Use ffmpeg locally to strip metadata before wider distribution."],
        remainingTraces: ["Frame content, subtitle tracks, and burned-in overlays remain outside metadata cleanup."],
        removable: ["Container metadata atoms and common creation/location tags through external offline tools such as ffmpeg."],
        cannotGuarantee: ["Frame content, burned-in overlays, and subtitle tracks are outside metadata-only cleanup guarantees."],
      }),
      applyMetadataClean: false,
      includeSourceReference: true,
      protectAtExport: false,
    });

    const incidentPackage = await createIncidentWorkflowPackage({
      modeId: "internal-investigation",
      producer,
      incidentTitle: "Incident 2026-03-18",
      purpose: "Prepare an internal responder package.",
      caseReference: "CASE-142",
      recipientScope: "internal responders",
      summaryText: "Suspicious access token observed in captured logs.",
      preparedArtifacts: [
        { id: "notes", label: "Case notes", kind: "notes", workflowPackage: notesPackage },
        { id: "capture", label: "Responder capture", kind: "file", workflowPackage: filePackage },
      ],
      protectAtExport: true,
    });

    const verified = await verifyWorkflowPackagePayload(incidentPackage);

    assert.equal(incidentPackage.workflowType, "incident-workflow");
    assert.equal(incidentPackage.workflowPreset?.id, "internal-investigation");
    assert.equal(incidentPackage.summary.title, "Incident 2026-03-18");
    assert.equal(incidentPackage.report?.purpose, "Prepare an internal responder package.");
    assert.equal(incidentPackage.report?.audience, "internal responders");
    assert.equal(incidentPackage.artifacts.some((artifact) => artifact.id === "incident-context"), true);
    assert.equal(incidentPackage.artifacts.some((artifact) => artifact.id === "incident-report"), true);
    assert.equal(
      incidentPackage.artifacts.some((artifact) => artifact.kind === "binary" && /Responder capture/i.test(artifact.label)),
      true,
    );
    assert.match(incidentPackage.warnings.join(" "), /sender identity is not asserted/i);
    assert.match(incidentPackage.limitations.join(" "), /NULLID:ENC:1 protection is applied to the exported file/i);
    assert.equal(verified.verificationState, "integrity-checked");
    assert.equal(
      verified.artifactChecks.some((artifact) => artifact.kind === "binary" && artifact.status === "verified"),
      true,
    );
  });

  it("warns honestly when an incident package carries only context and stock template headings", async () => {
    const incidentPackage = await createIncidentWorkflowPackage({
      modeId: "incident-handoff",
      producer,
      incidentTitle: "Incident 2026-03-18",
      purpose: "",
      preparedArtifacts: [],
      notesTemplateUsed: true,
      protectAtExport: false,
    });

    assert.match(incidentPackage.warnings.join(" "), /No prepared incident artifacts were added/i);
    assert.match(incidentPackage.warnings.join(" "), /stock incident template headings/i);
    assert.equal(incidentPackage.report?.includedArtifacts.includes("Incident report"), true);
  });

  it("reuses the existing safe-share preset system for minimal disclosure incident mode", async () => {
    const workflowPackage = await createIncidentTextArtifactPackage({
      modeId: "minimal-disclosure-incident-share",
      producer,
      inputText: "token=abcdefghijklmnopqrstuvwxyz12345 203.0.113.10 alice@example.com",
      sourceLabel: "outbound-summary.txt",
      includeSourceReference: false,
      protectAtExport: false,
    });

    assert.equal(workflowPackage.workflowPreset?.id, "external-minimum");
    assert.equal(workflowPackage.report?.receiverCannotVerify.includes("Sender identity or authorship."), true);
    assert.match(workflowPackage.summary.title, /External share \/ minimum disclosure package/i);
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
