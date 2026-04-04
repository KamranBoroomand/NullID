import { toBase64 } from "./encoding.js";
import { hashBytes, hashText } from "./hash.js";
import type { MetadataAnalysisResult, MetadataSanitizer } from "./metadataAdvanced.js";
import { defaultRuleSetState, type RedactionRuleSet } from "./redaction.js";
import {
  applySanitizeRules,
  buildRulesState,
  type PolicyPack,
  type RuleKey,
  type SanitizePolicyConfig,
} from "./sanitizeEngine.js";
import {
  createWorkflowPackage,
  type WorkflowPackage,
  type WorkflowPackageProducer,
  type WorkflowPackageTransform,
} from "./workflowPackage.js";
import { scanSecrets, summarizeSecretFindings } from "./secretScanner.js";
import { analyzeStructuredText, summarizeStructuredAnalysis } from "./structuredTextAnalyzer.js";
import {
  analyzeFinancialIdentifiers,
  summarizeFinancialReview,
} from "./financialReview.js";
import {
  analyzePathPrivacy,
  summarizePathPrivacy,
} from "./pathPrivacy.js";

export type SafeSharePresetId =
  | "general-safe-share"
  | "support-ticket"
  | "external-minimum"
  | "internal-investigation"
  | "incident-handoff"
  | "evidence-archive"
  | "customer-support-share"
  | "legal-document-share"
  | "journalist-source-share"
  | "internal-incident-handoff"
  | "external-minimum-disclosure";

export type SafeShareShareClass =
  | "structured-log"
  | "json-text"
  | "freeform-text"
  | "image"
  | "pdf"
  | "office-document"
  | "video"
  | "archive"
  | "unknown-file";

export interface SafeSharePreset {
  id: SafeSharePresetId;
  label: string;
  description: string;
  includeSourceReferenceDefault: boolean;
  defaultApplyMetadataClean: boolean;
  allowOriginalBinaryPackaging: boolean;
  sanitizeRules: RuleKey[];
  jsonAware: boolean;
  analysisRuleSets: Record<Exclude<RedactionRuleSet, "general">, boolean>;
  reviewChecklistEmphasis: string[];
  guidance: string[];
  limitations: string[];
}

export interface SafeShareFinding {
  label: string;
  count: number;
}

export interface CreateSafeShareTextPackageInput {
  presetId: SafeSharePresetId;
  producer: WorkflowPackageProducer;
  inputText: string;
  sourceLabel?: string;
  includeSourceReference?: boolean;
  policyPack?: PolicyPack | null;
  policyOverride?: SanitizePolicyConfig;
  protectAtExport?: boolean;
  analysisRuleSets?: Record<Exclude<RedactionRuleSet, "general">, boolean>;
}

export interface CreateSafeShareFilePackageInput {
  presetId: SafeSharePresetId;
  producer: WorkflowPackageProducer;
  fileName: string;
  fileMediaType: string;
  sourceBytes: Uint8Array;
  analysis: MetadataAnalysisResult;
  cleanedBytes?: Uint8Array;
  cleanedMediaType?: string;
  cleanedLabel?: string;
  applyMetadataClean?: boolean;
  includeSourceReference?: boolean;
  protectAtExport?: boolean;
}

export const safeSharePresets: Record<SafeSharePresetId, SafeSharePreset> = {
  "general-safe-share": {
    id: "general-safe-share",
    label: "General safe share",
    description: "Balanced disclosure reduction for routine sharing of text snippets and locally cleanable files.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: false,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Review what changed before sharing.",
      "Check remaining identifiers that pattern matching cannot prove.",
    ],
    guidance: [
      "Balanced preset for sharing cleaned text or locally sanitized files.",
      "Keeps the package unsigned unless you add an outer NULLID:ENC:1 envelope at export.",
    ],
    limitations: [
      "Review the package before sharing; automated cleaning does not replace human judgment.",
      "If a file cannot be cleaned locally, this preset exports report data instead of raw file bytes.",
    ],
  },
  "support-ticket": {
    id: "support-ticket",
    label: "Support ticket / bug report",
    description: "Removes obvious secrets while keeping enough operational context for debugging.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: false,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "maskUser",
      "stripJsonSecrets",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Keep debugging context, but review secrets and direct identifiers.",
      "Confirm filenames and screenshots do not reveal customer or staff details.",
    ],
    guidance: [
      "Keeps timestamps and some context so the receiver can still debug.",
      "Best for log snippets, stack traces, and screenshots or PDFs that need metadata cleanup first.",
    ],
    limitations: [
      "Operational context is preserved where possible, so review the output for environment-specific clues.",
      "This preset does not prove sender identity or independent authenticity.",
    ],
  },
  "external-minimum": {
    id: "external-minimum",
    label: "External share / minimum disclosure",
    description: "Aggressively reduces context and avoids packaging original references by default.",
    includeSourceReferenceDefault: false,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: false,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "dropUA",
      "normalizeTs",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Minimize direct identifiers and contextual clues.",
      "Prefer reports or cleaned outputs over original binaries.",
    ],
    guidance: [
      "Use this when the receiver needs the least possible amount of original context.",
      "When file cleanup is unavailable, this preset exports a report-only package instead of raw file bytes.",
    ],
    limitations: [
      "Aggressive reduction may remove debugging context or chronology that an internal receiver would want.",
      "Hashes and manifests do not make the package signed or identity-bearing.",
    ],
  },
  "internal-investigation": {
    id: "internal-investigation",
    label: "Internal investigation package",
    description: "Preserves responder context for internal analysis while still scrubbing obvious secrets and tokens.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: true,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Preserve enough chronology for internal review.",
      "Make remaining traces and unprovable claims explicit to the receiver.",
    ],
    guidance: [
      "Designed for internal responders who need context, chronology, and attached notes without losing obvious secret hygiene.",
      "Original binaries can be preserved when needed, with explicit report metadata describing what stayed intact.",
    ],
    limitations: [
      "Internal investigation packages can still contain operationally sensitive context; review recipient scope before sharing.",
      "This preset improves packaging discipline, not evidence-chain or identity guarantees.",
    ],
  },
  "incident-handoff": {
    id: "incident-handoff",
    label: "Incident artifact handoff",
    description: "Preserves enough context for another responder while still scrubbing obvious secrets.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: true,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Preserve responder context without hiding what remained unchanged.",
      "Review original-binary inclusion carefully before forwarding.",
    ],
    guidance: [
      "Adds hashes, transform summaries, and receiver-facing warnings for another responder.",
      "If local file cleanup is unavailable, the original binary can still be packaged with explicit warnings.",
    ],
    limitations: [
      "This is a handoff package, not a full incident case workflow or evidence chain-of-custody system.",
      "Original binary inclusion can preserve residual metadata or context; review before wider sharing.",
    ],
  },
  "evidence-archive": {
    id: "evidence-archive",
    label: "Evidence archive / preserve context",
    description: "Preserves context more conservatively and allows original file packaging when needed.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: false,
    allowOriginalBinaryPackaging: true,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Prioritize context preservation and explicit warnings.",
      "Call out declared-only versus locally verified facts.",
    ],
    guidance: [
      "Use when preserving context matters more than aggressive reduction.",
      "Local cleanup is optional here; if you package the original binary, NullID makes that explicit in warnings and transforms.",
    ],
    limitations: [
      "Preserving more context can preserve more residual sensitivity.",
      "This preset is not a legal/forensic chain-of-custody guarantee.",
    ],
  },
  "customer-support-share": {
    id: "customer-support-share",
    label: "Customer support share",
    description: "Support-oriented sharing with explicit review of customer identifiers, filenames, and operational context.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: false,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Review customer numbers, financial identifiers, and path labels.",
      "Keep enough product context for support without exposing unnecessary personal data.",
    ],
    guidance: [
      "Designed for customer-support or vendor-support sharing with explicit review of identifiers and filenames.",
      "Uses the same local workflow package contract; no hidden behavior is added by the preset.",
    ],
    limitations: [
      "Operational context may still expose internal environment details if you choose to preserve it.",
      "This preset does not assert sender identity or customer authenticity.",
    ],
  },
  "legal-document-share": {
    id: "legal-document-share",
    label: "Legal document share",
    description: "Conservative legal/document sharing with stronger emphasis on visible review, identifiers, and residual traces.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: false,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "dropUA",
      "normalizeTs",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Review remaining document traces, metadata, and reference numbers manually.",
      "Prefer cleaned outputs and explicit reports over original binaries.",
    ],
    guidance: [
      "This preset favors explicit review sections and minimal hidden context for document sharing.",
      "Document numbers may still require human validation because pattern matching does not prove legal significance.",
    ],
    limitations: [
      "NullID does not make legal admissibility or evidentiary guarantees.",
      "Visible page content and embedded previews still need human review after metadata cleanup.",
    ],
  },
  "journalist-source-share": {
    id: "journalist-source-share",
    label: "Journalist source share",
    description: "Aggressive minimum-disclosure preset for source protection scenarios with explicit residual-risk reporting.",
    includeSourceReferenceDefault: false,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: false,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "dropUA",
      "normalizeTs",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Minimize identifying context, filenames, and reference labels.",
      "Review what remains visible or declared-only before external sharing.",
    ],
    guidance: [
      "Keeps source references off by default and emphasizes explicit reporting of what stayed unproven.",
      "Original binaries are not packaged automatically under this preset.",
    ],
    limitations: [
      "This preset reduces exposure but does not guarantee anonymity or source protection.",
      "Visible content, writing style, and contextual clues can still identify a source.",
    ],
  },
  "internal-incident-handoff": {
    id: "internal-incident-handoff",
    label: "Internal incident handoff",
    description: "Internal responder handoff with explicit transform reporting and practical review prompts.",
    includeSourceReferenceDefault: true,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: true,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Highlight what was verified locally versus declared only.",
      "Carry responder context without hiding residual identifiers or traces.",
    ],
    guidance: [
      "This preset keeps the handoff practical for internal teams while still surfacing transform and review data explicitly.",
      "Original binaries may still be included when local cleanup is unavailable, but the package says so directly.",
    ],
    limitations: [
      "Internal sharing still carries operational sensitivity and should be scoped carefully.",
      "The package is not signed and does not prove authorship or sender identity.",
    ],
  },
  "external-minimum-disclosure": {
    id: "external-minimum-disclosure",
    label: "External minimum disclosure",
    description: "Enhanced external-sharing preset with aggressive disclosure reduction and explicit review/export transparency.",
    includeSourceReferenceDefault: false,
    defaultApplyMetadataClean: true,
    allowOriginalBinaryPackaging: false,
    sanitizeRules: [
      "maskIp",
      "maskIpv6",
      "maskEmail",
      "maskPhoneIntl",
      "maskIranNationalId",
      "scrubJwt",
      "maskBearer",
      "maskAwsKey",
      "maskAwsSecret",
      "maskGithubToken",
      "maskSlackToken",
      "stripPrivateKeyBlock",
      "stripCookies",
      "dropUA",
      "normalizeTs",
      "maskUser",
      "stripJsonSecrets",
      "maskCard",
      "maskIban",
    ],
    jsonAware: true,
    analysisRuleSets: defaultRuleSetState(),
    reviewChecklistEmphasis: [
      "Focus on removed versus still-visible data before export.",
      "Avoid original payload inclusion and keep receiver claims minimal.",
    ],
    guidance: [
      "This is the stronger export-facing minimum-disclosure preset for external sharing.",
      "It records active rules and review emphasis directly in the package so the behavior stays inspectable.",
    ],
    limitations: [
      "Aggressive reduction may remove useful chronology or debugging context.",
      "This preset does not guarantee anonymity, authenticity, or completeness.",
    ],
  },
};

export const safeSharePresetIds = Object.keys(safeSharePresets) as SafeSharePresetId[];

export function getSafeSharePreset(id: SafeSharePresetId): SafeSharePreset {
  return safeSharePresets[id] ?? safeSharePresets["general-safe-share"];
}

export function buildSafeShareSanitizeConfig(presetId: SafeSharePresetId, policyPack?: PolicyPack | null): SanitizePolicyConfig {
  if (policyPack) {
    return {
      rulesState: { ...policyPack.config.rulesState },
      jsonAware: policyPack.config.jsonAware,
      customRules: [...policyPack.config.customRules],
    };
  }
  const preset = getSafeSharePreset(presetId);
  return {
    rulesState: buildRulesState(preset.sanitizeRules),
    jsonAware: preset.jsonAware,
    customRules: [],
  };
}

export function resolveSafeShareAnalysisRuleSets(
  presetId: SafeSharePresetId,
  override?: Record<Exclude<RedactionRuleSet, "general">, boolean>,
) {
  return {
    ...getSafeSharePreset(presetId).analysisRuleSets,
    ...(override ?? {}),
  };
}

export function classifyTextForSafeShare(input: string): SafeShareShareClass {
  const trimmed = input.trim();
  if (!trimmed) return "freeform-text";
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      JSON.parse(trimmed);
      return "json-text";
    } catch {
      // Continue to log/text heuristics.
    }
  }
  if (/(?:\b\d{1,3}(?:\.\d{1,3}){3}\b|\buser=|\bcookie=|\btoken=|\[[0-9]{1,2}\/[A-Za-z]{3}\/[0-9]{4})/i.test(trimmed)) {
    return "structured-log";
  }
  return "freeform-text";
}

export function classifyMetadataAnalysisForSafeShare(analysis: MetadataAnalysisResult): SafeShareShareClass {
  if (analysis.kind === "image") return "image";
  if (analysis.format === "pdf") return "pdf";
  if (analysis.format === "docx" || analysis.format === "xlsx" || analysis.format === "pptx") return "office-document";
  if (analysis.kind === "video") return "video";
  if (analysis.kind === "archive") return "archive";
  return "unknown-file";
}

export function summarizeSanitizeFindings(report: string[]): SafeShareFinding[] {
  return report
    .map((line) => {
      const match = line.match(/^(.*?):\s*(\d+)$/);
      if (!match) return null;
      return {
        label: match[1],
        count: Number(match[2]),
      };
    })
    .filter((entry): entry is SafeShareFinding => Boolean(entry))
    .sort((a, b) => b.count - a.count);
}

export async function createSafeShareTextWorkflowPackage(input: CreateSafeShareTextPackageInput): Promise<WorkflowPackage> {
  const preset = getSafeSharePreset(input.presetId);
  const policy = input.policyOverride ?? buildSafeShareSanitizeConfig(input.presetId, input.policyPack ?? null);
  const sanitize = applySanitizeRules(input.inputText, policy.rulesState, policy.customRules, policy.jsonAware);
  const findings = summarizeSanitizeFindings(sanitize.report);
  const classification = classifyTextForSafeShare(input.inputText);
  const analysisRuleSets = resolveSafeShareAnalysisRuleSets(input.presetId, input.analysisRuleSets);
  const structuredAnalysis = analyzeStructuredText(input.inputText, {
    enabledRuleSets: analysisRuleSets,
  });
  const secretScan = scanSecrets(input.inputText);
  const financialReview = analyzeFinancialIdentifiers(input.inputText, {
    enabledRuleSets: analysisRuleSets,
  });
  const includeSourceReference = input.includeSourceReference ?? preset.includeSourceReferenceDefault;
  const [inputHash, outputHash] = await Promise.all([
    hashText(input.inputText, "SHA-256"),
    hashText(sanitize.output, "SHA-256"),
  ]);
  const structuredAnalysisSummary = {
    countsByCategory: structuredAnalysis.countsByCategory,
    countsByRuleSet: structuredAnalysis.countsByRuleSet,
    total: structuredAnalysis.total,
    financialFindings: financialReview.total,
    secretFindings: secretScan.total,
  };
  const structuredAnalysisSummaryJson = JSON.stringify(structuredAnalysisSummary);

  const assistantReport = {
    mode: "text",
    workflowPreset: preset.id,
    classification,
    findings,
    activeSanitizeRules: preset.sanitizeRules,
    activeRegionRuleSets: analysisRuleSets,
    reviewChecklistEmphasis: preset.reviewChecklistEmphasis,
    linesAffected: sanitize.linesAffected,
    appliedRules: sanitize.applied,
    protectAtExport: Boolean(input.protectAtExport),
    structuredAnalysis,
    financialReview: {
      total: financialReview.total,
      countsByCategory: financialReview.countsByCategory,
      findings: financialReview.findings,
      notes: financialReview.notes,
    },
    secretScan: {
      total: secretScan.total,
      byType: secretScan.byType,
      notes: secretScan.notes,
    },
  };
  const assistantReportHash = await hashText(JSON.stringify(assistantReport), "SHA-256");

  const warnings = [
    ...(sanitize.applied.length === 0 ? ["No sanitize rules triggered; review the output manually before sharing."] : []),
    ...preset.guidance,
    "Unsigned package. Sender identity is not asserted.",
    "SHA-256 manifest entries help detect changes to included artifacts, but they are not a signature.",
  ];
  const limitations = [
    ...preset.limitations,
    ...(input.protectAtExport
      ? ["NULLID:ENC:1 protection is applied to the exported file, not as a sender signature inside the package."]
      : ["Without an outer NULLID:ENC:1 envelope, the exported package remains readable JSON on disk."]),
  ];
  const includedLabels = [
    ...(includeSourceReference ? [input.sourceLabel ? `Original input reference (${input.sourceLabel})` : "Original input reference"] : []),
    "Shared output",
    "Sanitize policy snapshot",
    "Structured analysis summary",
    "Safe Share report",
  ];

  const transforms: WorkflowPackageTransform[] = [
    {
      id: "safe-share-review",
      type: "safe-share",
      label: "Safe Share review",
      summary: `${preset.label} preset prepared a text safe-share package.`,
      report: [
        `classification:${classification}`,
        `findings:${findings.length}`,
        `source-reference:${includeSourceReference ? "included" : "omitted"}`,
        `active-rules:${preset.sanitizeRules.join(",")}`,
      ],
      metadata: {
        workflowPreset: preset.id,
        reviewChecklistEmphasis: preset.reviewChecklistEmphasis.join(","),
      },
    },
    {
      id: "structured-analysis",
      type: "text-analysis",
      label: "Structured text analysis",
      summary: `Local analysis grouped ${structuredAnalysis.total} finding${structuredAnalysis.total === 1 ? "" : "s"} across text categories.`,
      applied: summarizeStructuredAnalysis(structuredAnalysis),
      report: [
        ...structuredAnalysis.regionGroups
          .filter((group) => group.total > 0)
          .map((group) => `${group.ruleSet}: ${group.total}`),
        ...(secretScan.total > 0 ? [`likely secrets: ${secretScan.total}`] : []),
      ],
      metadata: {
        enabledRegionRuleSets: Object.entries(analysisRuleSets)
          .filter(([, enabled]) => enabled)
          .map(([key]) => key)
          .join(",") || "none",
      },
    },
    {
      id: "financial-review",
      type: "financial-review",
      label: "Financial identifier review",
      summary: financialReview.total > 0
        ? `${financialReview.total} financial identifier finding${financialReview.total === 1 ? "" : "s"} were reviewed locally before sharing.`
        : "No financial identifier findings were detected in the reviewed text.",
      applied: Object.entries(financialReview.countsByCategory)
        .filter(([, count]) => count > 0)
        .map(([category, count]) => `${category}: ${count}`),
      report: summarizeFinancialReview(financialReview),
      metadata: {
        patternBasedLabels: financialReview.findings
          .filter((finding) => finding.detectionKind === "pattern-based")
          .map((finding) => finding.label)
          .join(",") || "none",
      },
    },
    ...(secretScan.total > 0
      ? [{
          id: "secret-scan",
          type: "secret-scan",
          label: "Secret scan",
          summary: `${secretScan.total} pattern-based / likely secret finding${secretScan.total === 1 ? "" : "s"} detected locally before sharing.`,
          applied: Object.entries(secretScan.byType).map(([label, count]) => `${label}: ${count}`),
          report: summarizeSecretFindings(secretScan.findings),
          metadata: {
            heuristicCandidatesIncluded: "yes",
          },
        }]
      : []),
    {
      id: "sanitize-transform",
      type: "sanitize",
      label: "Sanitize transformation",
      summary: `Sanitized output ready (${sanitize.linesAffected} line${sanitize.linesAffected === 1 ? "" : "s"} changed).`,
      applied: sanitize.applied,
      report: sanitize.report,
      metadata: {
        classification,
      },
    },
  ];

  return createWorkflowPackage({
    packageType: "bundle",
    workflowType: "safe-share-assistant",
    producedAt: new Date().toISOString(),
    producer: input.producer,
    workflowPreset: {
      id: preset.id,
      label: preset.label,
      summary: preset.description,
    },
    summary: {
      title: `${preset.label} package`,
      description: "Safe Share Assistant export for text-based content.",
      highlights: [
        `Share class: ${formatShareClassLabel(classification)}`,
        `Applied rules: ${sanitize.applied.length}`,
        `Region detectors: ${Object.entries(analysisRuleSets).filter(([, enabled]) => enabled).map(([key]) => key).join(", ") || "none"}`,
        `Protection: ${input.protectAtExport ? "NULLID:ENC:1 at export" : "none"}`,
      ],
    },
    report: {
      purpose: `Prepare text content for ${preset.label.toLowerCase()}.`,
      includedArtifacts: includedLabels,
      transformedArtifacts: [
        "Safe Share review",
        "Structured text analysis",
        "Financial identifier review",
        ...(secretScan.total > 0 ? ["Secret scan"] : []),
        "Sanitize transformation",
      ],
      preservedArtifacts: includeSourceReference ? ["Original input reference only"] : [],
      receiverCanVerify: [
        "Workflow package structure and schema version.",
        "SHA-256 manifest entries for included inline artifacts and references.",
        ...(input.protectAtExport ? ["If wrapped at export, the outer NULLID:ENC:1 envelope can be decrypted and integrity-checked with the passphrase."] : []),
      ],
      receiverCannotVerify: [
        "Sender identity or authorship.",
        "Whether omitted context outside the included artifacts was complete.",
      ],
    },
    artifacts: [
      ...(includeSourceReference
        ? [{
            id: "source-input",
            role: "input",
            label: input.sourceLabel ? `Original input (${input.sourceLabel})` : "Original input",
            kind: "reference" as const,
            mediaType: "text/plain;charset=utf-8",
            included: false,
            bytes: new TextEncoder().encode(input.inputText).byteLength,
            sha256: inputHash.hex,
            filename: input.sourceLabel,
          }]
        : []),
      {
        id: "shared-output",
        role: "output",
        label: "Shared output",
        kind: "text",
        mediaType: "text/plain;charset=utf-8",
        included: true,
        bytes: new TextEncoder().encode(sanitize.output).byteLength,
        sha256: outputHash.hex,
        text: sanitize.output,
      },
      {
        id: "sanitize-policy",
        role: "policy",
        label: "Sanitize policy snapshot",
        kind: "json",
        mediaType: "application/json",
        included: true,
        bytes: new TextEncoder().encode(JSON.stringify(policy)).byteLength,
        sha256: (await hashText(JSON.stringify(policy), "SHA-256")).hex,
        json: policy,
      },
      {
        id: "structured-analysis-summary",
        role: "report",
        label: "Structured analysis summary",
        kind: "json",
        mediaType: "application/json",
        included: true,
        bytes: new TextEncoder().encode(structuredAnalysisSummaryJson).byteLength,
        sha256: (await hashText(structuredAnalysisSummaryJson, "SHA-256")).hex,
        json: structuredAnalysisSummary,
      },
      {
        id: "safe-share-report",
        role: "report",
        label: "Safe Share report",
        kind: "json",
        mediaType: "application/json",
        included: true,
        bytes: new TextEncoder().encode(JSON.stringify(assistantReport)).byteLength,
        sha256: assistantReportHash.hex,
        json: assistantReport,
      },
    ],
    policy: {
      type: "sanitize",
      config: policy,
      preset: preset.id,
      packName: input.policyPack?.name,
      baseline: null,
    },
    transforms,
    warnings,
    limitations,
  });
}

export async function createSafeShareFileWorkflowPackage(input: CreateSafeShareFilePackageInput): Promise<WorkflowPackage> {
  const preset = getSafeSharePreset(input.presetId);
  const classification = classifyMetadataAnalysisForSafeShare(input.analysis);
  const pathPrivacy = analyzePathPrivacy(input.fileName);
  const includeSourceReference = input.includeSourceReference ?? preset.includeSourceReferenceDefault;
  const sourceHash = await hashBytes(input.sourceBytes, "SHA-256");
  const shouldUseCleaned = Boolean(input.applyMetadataClean) && Boolean(input.cleanedBytes?.length);
  const includeOriginalBinary = !shouldUseCleaned && preset.allowOriginalBinaryPackaging;
  const sharedBytes = shouldUseCleaned ? input.cleanedBytes! : includeOriginalBinary ? input.sourceBytes : null;
  const sharedMediaType = shouldUseCleaned ? (input.cleanedMediaType || input.fileMediaType) : includeOriginalBinary ? input.fileMediaType : null;
  const sharedLabel = shouldUseCleaned
    ? (input.cleanedLabel || "Metadata-cleaned file")
    : includeOriginalBinary
      ? "Original file payload"
      : null;
  const sharedHash = sharedBytes ? await hashBytes(sharedBytes, "SHA-256") : null;

  const analysisReport = {
    mode: "file",
    workflowPreset: preset.id,
    classification,
    format: input.analysis.format,
    risk: input.analysis.risk,
    sanitizer: resolveSanitizerLabel(input.analysis.recommendedSanitizer),
    signals: input.analysis.signals,
    guidance: input.analysis.guidance,
    commandHint: input.analysis.commandHint,
    activeSanitizeRules: preset.sanitizeRules,
    reviewChecklistEmphasis: preset.reviewChecklistEmphasis,
    pathPrivacy,
    protectAtExport: Boolean(input.protectAtExport),
    binaryIncluded: Boolean(sharedBytes),
    cleaned: shouldUseCleaned,
  };
  const analysisHash = await hashText(JSON.stringify(analysisReport), "SHA-256");

  const warnings = [
    ...(shouldUseCleaned ? [] : input.analysis.signals.map((signal) => `${signal.label}: ${signal.detail}`)),
    ...preset.guidance,
    ...(includeOriginalBinary ? ["Original file bytes are included because this preset allows preserving context when local cleanup is unavailable or disabled."] : []),
    ...(!sharedBytes ? ["No file payload was packaged; this export contains analysis/report data plus source reference only."] : []),
    "Unsigned package. Sender identity is not asserted.",
    "SHA-256 manifest entries help detect changes to included artifacts, but they are not a signature.",
  ];
  const limitations = [
    ...preset.limitations,
    ...(input.analysis.commandHint && !shouldUseCleaned
      ? ["NullID could not fully clean this file locally; external tooling may still be required before broader sharing."]
      : []),
    ...(input.protectAtExport
      ? ["NULLID:ENC:1 protection is applied to the exported file, not as a sender signature inside the package."]
      : ["Without an outer NULLID:ENC:1 envelope, the exported package remains readable JSON on disk."]),
  ];
  const includedLabels = [
    ...(includeSourceReference ? [`Original file reference (${input.fileName})`] : []),
    ...(sharedLabel ? [sharedLabel] : []),
    "Safe Share report",
  ];
  const preservedArtifacts = [
    ...(includeOriginalBinary ? [`Original file payload (${input.fileName})`] : []),
    ...(includeSourceReference ? [`Original file reference (${input.fileName})`] : []),
  ];

  const transforms: WorkflowPackageTransform[] = [
    {
      id: "safe-share-review",
      type: "safe-share",
      label: "Safe Share review",
      summary: `${preset.label} preset prepared a file-oriented safe-share package.`,
      report: [
        `classification:${classification}`,
        `risk:${input.analysis.risk}`,
        `binary-included:${sharedBytes ? "yes" : "no"}`,
        `active-rules:${preset.sanitizeRules.join(",")}`,
      ],
      metadata: {
        workflowPreset: preset.id,
        reviewChecklistEmphasis: preset.reviewChecklistEmphasis.join(","),
      },
    },
    {
      id: "metadata-analysis",
      type: "metadata",
      label: "Metadata analysis",
      summary: `${input.analysis.format} analyzed locally with ${input.analysis.signals.length} metadata signal${input.analysis.signals.length === 1 ? "" : "s"}.`,
      applied: input.analysis.fields.map((field) => field.key),
      report: input.analysis.signals.map((signal) => `${signal.label}: ${signal.detail}`),
      metadata: {
        recommendedSanitizer: input.analysis.recommendedSanitizer,
        risk: input.analysis.risk,
      },
    },
    ...(shouldUseCleaned
        ? [{
            id: "metadata-clean",
            type: "metadata-clean",
            label: "Metadata cleanup",
            summary: "Local cleanup was applied before packaging the shareable file artifact.",
            applied: input.analysis.removable,
            report: input.analysis.cannotGuarantee,
            metadata: {
              outputMediaType: input.cleanedMediaType || input.fileMediaType,
            },
          }]
      : []),
    {
      id: "filename-privacy",
      type: "path-privacy",
      label: "Filename / path privacy",
      summary: pathPrivacy.total > 0
        ? `${pathPrivacy.total} filename/path privacy hint${pathPrivacy.total === 1 ? "" : "s"} were generated locally before export.`
        : "No filename/path privacy hints were generated from the current file label.",
      applied: pathPrivacy.suggestions.flatMap((suggestion) => suggestion.replacements.map((replacement) => `${replacement.segment} -> ${replacement.replacement}`)),
      report: summarizePathPrivacy(pathPrivacy),
      metadata: {
        normalizedPath: pathPrivacy.normalizedPath,
      },
    },
  ];

  return createWorkflowPackage({
    packageType: "bundle",
    workflowType: "safe-share-assistant",
    producedAt: new Date().toISOString(),
    producer: input.producer,
    workflowPreset: {
      id: preset.id,
      label: preset.label,
      summary: preset.description,
    },
    summary: {
      title: `${preset.label} package`,
      description: "Safe Share Assistant export for file-based content.",
      highlights: [
        `Share class: ${formatShareClassLabel(classification)}`,
        `Metadata risk: ${input.analysis.risk}`,
        `Filename hints: ${pathPrivacy.total}`,
        `Protection: ${input.protectAtExport ? "NULLID:ENC:1 at export" : "none"}`,
      ],
    },
    report: {
      purpose: `Prepare a file artifact for ${preset.label.toLowerCase()}.`,
      includedArtifacts: includedLabels,
      transformedArtifacts: [
        "Safe Share review",
        "Metadata analysis",
        ...(shouldUseCleaned ? ["Metadata cleanup"] : []),
        "Filename / path privacy",
      ],
      preservedArtifacts,
      receiverCanVerify: [
        "Workflow package structure and schema version.",
        "SHA-256 manifest entries for included inline artifacts and references.",
        ...(input.protectAtExport ? ["If wrapped at export, the outer NULLID:ENC:1 envelope can be decrypted and integrity-checked with the passphrase."] : []),
      ],
      receiverCannotVerify: [
        "Sender identity or authorship.",
        ...(sharedBytes ? [] : ["The original file bytes are not included in this package."]),
        ...(input.analysis.commandHint && !shouldUseCleaned ? ["External cleanup steps suggested by command hints are not proven by this package."] : []),
      ],
    },
    artifacts: [
      ...(includeSourceReference
        ? [{
            id: "source-file",
            role: "input",
            label: `Original file (${input.fileName})`,
            kind: "reference" as const,
            mediaType: input.fileMediaType || "application/octet-stream",
            included: false,
            bytes: input.sourceBytes.length,
            sha256: sourceHash.hex,
            filename: input.fileName,
          }]
        : []),
      ...(sharedBytes && sharedMediaType && sharedLabel && sharedHash
        ? [{
            id: shouldUseCleaned ? "shared-clean-file" : "shared-file",
            role: "output",
            label: sharedLabel,
            kind: "binary" as const,
            mediaType: sharedMediaType || "application/octet-stream",
            included: true,
            bytes: sharedBytes.length,
            sha256: sharedHash.hex,
            filename: shouldUseCleaned ? appendCleanSuffix(input.fileName, sharedMediaType) : input.fileName,
            base64: toBase64(sharedBytes),
          }]
        : []),
      {
        id: "safe-share-report",
        role: "report",
        label: "Safe Share report",
        kind: "json",
        mediaType: "application/json",
        included: true,
        bytes: new TextEncoder().encode(JSON.stringify(analysisReport)).byteLength,
        sha256: analysisHash.hex,
        json: analysisReport,
      },
    ],
    transforms,
    warnings,
    limitations,
  });
}

function appendCleanSuffix(fileName: string, mediaType: string) {
  const dot = fileName.lastIndexOf(".");
  const base = dot > 0 ? fileName.slice(0, dot) : fileName;
  const ext = dot > 0 ? fileName.slice(dot + 1) : extensionFromMediaType(mediaType);
  return `${base}-clean.${ext}`;
}

function extensionFromMediaType(mediaType: string) {
  if (mediaType.includes("pdf")) return "pdf";
  if (mediaType.includes("png")) return "png";
  if (mediaType.includes("webp")) return "webp";
  if (mediaType.includes("avif")) return "avif";
  return "bin";
}

function resolveSanitizerLabel(value: MetadataSanitizer) {
  if (value === "browser-image") return "browser image clean";
  if (value === "browser-pdf") return "browser pdf clean";
  if (value === "mat2") return "mat2 / external clean";
  return "analysis only";
}

export function formatShareClassLabel(value: SafeShareShareClass) {
  if (value === "structured-log") return "structured log";
  if (value === "json-text") return "JSON text";
  if (value === "freeform-text") return "freeform text";
  if (value === "office-document") return "office document";
  if (value === "unknown-file") return "unknown file";
  return value;
}
