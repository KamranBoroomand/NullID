import {
  defaultRuleSetState,
  formatIranBankCard,
  formatIranPhone,
  formatIranPostalCode,
  formatIranSheba,
  getRedactionDetectors,
  isOptionalRuleSet,
  normalizeMixedIdentifier,
  normalizeRussianPhone,
  resolveOverlaps,
  scanRedaction,
  type RedactionMatch,
  type RedactionDetectionKind,
  type RedactionRuleSet,
} from "./redaction.js";
import {
  analyzeFinancialIdentifiers,
  summarizeFinancialReview,
  type FinancialReviewResult,
} from "./financialReview.js";
import { scanSecrets, secretFindingsToRedactionMatches, type SecretScannerFinding } from "./secretScanner.js";

export type StructuredFindingCategory = "emails" | "phones" | "urls" | "ids" | "financial" | "secrets";

export interface StructuredTextFinding {
  start: number;
  end: number;
  key: string;
  label: string;
  category: StructuredFindingCategory;
  ruleSet: RedactionRuleSet;
  detectionKind: RedactionDetectionKind;
  confidence: "low" | "medium" | "high";
  reason: string;
  preview: string;
}

export interface StructuredFindingGroup {
  category: StructuredFindingCategory;
  total: number;
  findings: StructuredTextFinding[];
}

export interface StructuredRegionGroup {
  ruleSet: Exclude<RedactionRuleSet, "general">;
  total: number;
  findings: StructuredTextFinding[];
}

export interface StructuredTextAnalysisResult {
  total: number;
  findingGroups: StructuredFindingGroup[];
  countsByCategory: Record<StructuredFindingCategory, number>;
  regionGroups: StructuredRegionGroup[];
  countsByRuleSet: Record<Exclude<RedactionRuleSet, "general">, number>;
  findings: StructuredTextFinding[];
  redactionMatches: RedactionMatch[];
  financialReview: FinancialReviewResult;
  secretFindings: SecretScannerFinding[];
  notes: string[];
}

export interface StructuredTextAnalysisOptions {
  minimumSeverity?: "low" | "medium" | "high";
  minTokenLength?: number;
  enabledRuleSets?: Record<Exclude<RedactionRuleSet, "general">, boolean>;
  includeHeuristicSecretCandidates?: boolean;
}

const groupedCategories: StructuredFindingCategory[] = ["emails", "phones", "urls", "ids", "financial", "secrets"];

export function analyzeStructuredText(
  input: string,
  options: StructuredTextAnalysisOptions = {},
): StructuredTextAnalysisResult {
  const enabledRuleSets = {
    ...defaultRuleSetState(),
    ...(options.enabledRuleSets ?? {}),
  };
  const detectors = getRedactionDetectors().filter((detector) => {
    if (["token", "awskey", "awssecret", "github", "slack", "privatekey"].includes(detector.key)) {
      return false;
    }
    if (!isOptionalRuleSet(detector.ruleSet)) return ["email", "phone", "url", "ssn", "uuid", "generic-id-context"].includes(detector.key);
    if (["iran-card-context", "iran-sheba"].includes(detector.key)) return false;
    return enabledRuleSets[detector.ruleSet];
  });

  const redactionResult = scanRedaction(input, detectors, [], {
    minimumSeverity: options.minimumSeverity ?? "low",
    minTokenLength: options.minTokenLength ?? 20,
  });
  const secretResult = scanSecrets(input, {
    minCandidateLength: options.minTokenLength ?? 20,
    includeHeuristicCandidates: options.includeHeuristicSecretCandidates ?? true,
  });
  const financialReview = analyzeFinancialIdentifiers(input, {
    enabledRuleSets,
  });

  const nonSecretFindings = redactionResult.matches.map<StructuredTextFinding>((match) => ({
    start: match.start,
    end: match.end,
    key: match.key,
    label: match.label,
    category: categoryForMatch(match.key),
    ruleSet: match.ruleSet,
    detectionKind: match.detectionKind,
    confidence: severityToConfidence(match.severity),
    reason: reasonForMatch(match),
    preview: previewForMatch(match.key, input.slice(match.start, match.end)),
  }));
  const secretFindings = secretResult.findings.map<StructuredTextFinding>((finding) => ({
    start: finding.start,
    end: finding.end,
    key: finding.key,
    label: finding.label,
    category: "secrets",
    ruleSet: finding.ruleSet,
    detectionKind: finding.evidence === "pattern-safe" ? "pattern-based" : "heuristic",
    confidence: finding.confidence,
    reason: finding.reason,
    preview: previewValue(finding.preview),
  }));
  const financialFindings = financialReview.findings.map<StructuredTextFinding>((finding) => ({
    start: finding.start,
    end: finding.end,
    key: finding.key,
    label: finding.label,
    category: "financial",
    ruleSet: finding.ruleSet,
    detectionKind: finding.detectionKind,
    confidence: finding.confidence,
    reason: finding.reason,
    preview: finding.preview,
  }));

  const findings = resolveOverlaps(
    [...nonSecretFindings, ...financialFindings, ...secretFindings].map((finding) => ({
      ...finding,
      severity: confidenceToSeverity(finding.confidence),
    })),
  )
    .map(({ severity: _severity, ...finding }) => finding)
    .sort((a, b) => a.start - b.start);

  const findingGroups = groupedCategories.map<StructuredFindingGroup>((category) => {
    const grouped = findings.filter((finding) => finding.category === category);
    return {
      category,
      total: grouped.length,
      findings: grouped,
    };
  });
  const countsByCategory = findingGroups.reduce<Record<StructuredFindingCategory, number>>((acc, group) => {
    acc[group.category] = group.total;
    return acc;
  }, { emails: 0, phones: 0, urls: 0, ids: 0, financial: 0, secrets: 0 });

  const regionGroups = (["iran", "russia"] as Array<Exclude<RedactionRuleSet, "general">>).map<StructuredRegionGroup>((ruleSet) => {
    const grouped = findings.filter((finding) => finding.ruleSet === ruleSet);
    return {
      ruleSet,
      total: grouped.length,
      findings: grouped,
    };
  });
  const countsByRuleSet = regionGroups.reduce<Record<Exclude<RedactionRuleSet, "general">, number>>((acc, group) => {
    acc[group.ruleSet] = group.total;
    return acc;
  }, { iran: 0, russia: 0 });

  return {
    total: findings.length,
    findingGroups,
    countsByCategory,
    regionGroups,
    countsByRuleSet,
    findings,
    redactionMatches: resolveOverlaps([
      ...redactionResult.matches,
      ...financialReview.redactionMatches,
      ...secretFindingsToRedactionMatches(secretResult.findings),
    ]),
    financialReview,
    secretFindings: secretResult.findings,
    notes: [
      "Analysis stays local and uses deterministic pattern matching plus limited heuristics for likely secrets.",
      "Region-specific detectors remain opt-in. Pattern-based matches are still review aids, and heuristic matches have higher false-positive risk.",
      ...(Object.values(enabledRuleSets).some(Boolean)
        ? ["Optional Iran/Persian and Russia rules normalize local digit sets and common spacing variants before validation when that is safe."]
        : []),
      ...(financialReview.total > 0
        ? ["Financial identifier review is included with pattern-based card/IBAN checks and likely account/reference context hints."]
        : []),
    ],
  };
}

export function summarizeStructuredAnalysis(result: StructuredTextAnalysisResult): string[] {
  const summaries = result.findingGroups
    .filter((group) => group.total > 0)
    .map((group) => `${labelForCategory(group.category)}: ${group.total}`);
  const regional = result.regionGroups
    .filter((group) => group.total > 0)
    .map((group) => `${labelForRuleSet(group.ruleSet)}: ${group.total}`);
  return [...summaries, ...regional, ...summarizeFinancialReview(result.financialReview, 3)];
}

function categoryForMatch(key: string): StructuredFindingCategory {
  if (key === "email") return "emails";
  if (key === "phone" || key === "iran-phone" || key === "ru-phone") return "phones";
  if (key === "url") return "urls";
  if (["card", "iban", "iran-card-context", "iran-sheba"].includes(key)) return "financial";
  return "ids";
}

function reasonForMatch(match: RedactionMatch) {
  if (match.key === "email") return "Pattern-based detector matched an email address layout.";
  if (match.key === "phone") return "Heuristic detector matched a general phone-number layout.";
  if (match.key === "iran-phone") return "Pattern-based detector matched an optional Iran mobile-number format.";
  if (match.key === "ru-phone") return "Pattern-based detector matched an optional Russia phone-number format.";
  if (match.key === "iran-card-context") return "Pattern-based detector matched an Iran bank-card context and the digits passed a Luhn check.";
  if (match.key === "iran-postal-context") return "Pattern-based detector matched an Iran postal-code context and a plausible 10-digit code.";
  if (match.key === "iran-sheba") return "Pattern-based detector matched an Iran Sheba / IBAN-style value.";
  if (match.key === "ru-passport-context") return "Pattern-based detector matched a Russia passport context and plausible series/number layout.";
  if (match.key === "ru-document-context") return "Heuristic detector matched a Russia document-number context; review before sharing.";
  if (match.key === "url") return "Pattern-based detector matched a URL prefix and path layout.";
  if (match.ruleSet === "iran") return match.detectionKind === "heuristic"
    ? "Heuristic detector matched an optional Iran/Persian regional identifier; review for false positives."
    : "Pattern-based detector matched an optional Iran/Persian regional identifier.";
  if (match.ruleSet === "russia") return match.detectionKind === "heuristic"
    ? "Heuristic detector matched an optional Russia regional identifier; review for false positives."
    : "Pattern-based detector matched an optional Russia regional identifier.";
  return match.detectionKind === "heuristic"
    ? "Heuristic detector matched a structured identifier layout; review for false positives."
    : "Pattern-based detector matched a structured identifier layout.";
}

function labelForCategory(category: StructuredFindingCategory) {
  if (category === "emails") return "Emails";
  if (category === "phones") return "Phones";
  if (category === "urls") return "URLs";
  if (category === "ids") return "IDs";
  if (category === "financial") return "Financial identifiers";
  return "Likely secrets";
}

function labelForRuleSet(ruleSet: Exclude<RedactionRuleSet, "general">) {
  if (ruleSet === "iran") return "Iran / Persian";
  return "Russia";
}

function previewValue(value: string) {
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function previewForMatch(key: string, value: string) {
  if (key === "iran-phone") return formatIranPhone(value) ?? previewValue(value);
  if (key === "ru-phone") return normalizeRussianPhone(value) ?? previewValue(value);
  if (key === "iran-card-context") return formatIranBankCard(value) ?? previewValue(value);
  if (key === "iran-postal-context") return formatIranPostalCode(value) ?? previewValue(value);
  if (key === "iran-sheba") return formatIranSheba(value) ?? previewValue(value);
  if (key === "ru-passport-context") {
    const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
    return digits.length === 10 ? `${digits.slice(0, 2)} ${digits.slice(2, 4)} ${digits.slice(4)}` : previewValue(value);
  }
  return previewValue(value);
}

function severityToConfidence(value: "low" | "medium" | "high"): "low" | "medium" | "high" {
  return value;
}

function confidenceToSeverity(value: "low" | "medium" | "high"): "low" | "medium" | "high" {
  return value;
}
