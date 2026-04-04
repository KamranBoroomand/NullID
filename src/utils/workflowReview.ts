import type { WorkflowPackage, WorkflowPackageTransform } from "./workflowPackage.js";

export interface WorkflowReviewSection {
  id: string;
  label: string;
  items: string[];
}

export interface WorkflowReviewDashboard {
  title: string;
  sections: WorkflowReviewSection[];
}

export function buildWorkflowReviewDashboard(workflowPackage: WorkflowPackage): WorkflowReviewDashboard {
  const includedArtifacts = workflowPackage.artifacts
    .filter((artifact) => artifact.included)
    .map((artifact) => `${artifact.label} (${artifact.kind}${artifact.bytes ? `, ${artifact.bytes} bytes` : ""})`);
  const transformSummaries = (workflowPackage.transforms ?? []).map((transform) => `${transform.label}: ${transform.summary}`);
  const metadataCleanup = (workflowPackage.transforms ?? [])
    .filter((transform) => /metadata/i.test(transform.type) || /metadata/i.test(transform.label))
    .flatMap((transform) => flattenTransform(transform));
  const sensitiveFindings = (workflowPackage.transforms ?? [])
    .filter((transform) => /sanitize|secret|analysis|financial|path-privacy/i.test(transform.type) || /sanitize|secret|analysis|financial|path privacy/i.test(transform.label))
    .flatMap((transform) => flattenTransform(transform));
  const presetTransparency = (workflowPackage.transforms ?? [])
    .filter((transform) => /safe-share/i.test(transform.type) || /safe share/i.test(transform.label))
    .flatMap((transform) => Object.entries(transform.metadata ?? {}).map(([key, value]) => `${transform.label} ${key}: ${String(value)}`));
  const regionalDetections = (workflowPackage.transforms ?? [])
    .filter((transform) => /analysis/i.test(transform.type) || /analysis/i.test(transform.label))
    .flatMap((transform) => (transform.report ?? []).filter((line) => /^iran:|^russia:/i.test(line)));
  const warnings = [...workflowPackage.warnings, ...workflowPackage.limitations];

  return {
    title: workflowPackage.summary.title || workflowPackage.workflowType,
    sections: [
      { id: "included", label: "Verified locally", items: includedArtifacts },
      { id: "transforms", label: "Detected and transformed", items: transformSummaries },
      { id: "preset", label: "Declared workflow context", items: presetTransparency },
      { id: "metadata", label: "Removed or cleaned locally", items: metadataCleanup },
      { id: "findings", label: "Detected sensitive content", items: sensitiveFindings },
      { id: "regional", label: "Region-aware detection summary", items: regionalDetections },
      { id: "warnings", label: "Review required", items: warnings },
    ].filter((section) => section.items.length > 0),
  };
}

function flattenTransform(transform: WorkflowPackageTransform) {
  return [
    transform.summary,
    ...(transform.applied ?? []).map((line) => `${transform.label} applied: ${line}`),
    ...(transform.report ?? []).map((line) => `${transform.label} reported: ${line}`),
  ];
}
