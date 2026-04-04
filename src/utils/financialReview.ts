import {
  formatIranBankCard,
  formatIranSheba,
  isValidIban,
  isValidIranBankCard,
  isValidIranSheba,
  normalizeMixedIdentifier,
  passesLuhn,
  resolveOverlaps,
  type RedactionDetectionKind,
  type RedactionMatch,
  type RedactionRuleSet,
} from "./redaction.js";

export type FinancialFindingCategory = "bank-cards" | "ibans" | "accounts" | "references";
export type FinancialFindingConfidence = "low" | "medium" | "high";

export interface FinancialReviewFinding {
  start: number;
  end: number;
  key: string;
  label: string;
  category: FinancialFindingCategory;
  ruleSet: RedactionRuleSet;
  detectionKind: RedactionDetectionKind;
  confidence: FinancialFindingConfidence;
  reason: string;
  preview: string;
  normalized: string;
  mask: string;
}

export interface FinancialFindingGroup {
  category: FinancialFindingCategory;
  total: number;
  findings: FinancialReviewFinding[];
}

export interface FinancialReviewResult {
  total: number;
  countsByCategory: Record<FinancialFindingCategory, number>;
  findings: FinancialReviewFinding[];
  groups: FinancialFindingGroup[];
  redactionMatches: RedactionMatch[];
  notes: string[];
}

export interface FinancialReviewOptions {
  enabledRuleSets?: Record<Exclude<RedactionRuleSet, "general">, boolean>;
}

interface RawFinancialFinding extends FinancialReviewFinding {
  severity: FinancialFindingConfidence;
}

const categories: FinancialFindingCategory[] = ["bank-cards", "ibans", "accounts", "references"];

export function analyzeFinancialIdentifiers(
  input: string,
  options: FinancialReviewOptions = {},
): FinancialReviewResult {
  const enabledRuleSets = {
    iran: false,
    russia: false,
    ...(options.enabledRuleSets ?? {}),
  };
  const findings: RawFinancialFinding[] = [];

  findings.push(...scanBankCards(input, enabledRuleSets));
  findings.push(...scanIbans(input, enabledRuleSets));
  findings.push(...scanAccountNumbers(input));
  findings.push(...scanReferenceNumbers(input));

  const resolved = resolveOverlaps(
    findings.map((finding) => ({
      start: finding.start,
      end: finding.end,
      key: finding.key,
      label: finding.label,
      severity: finding.severity,
      mask: finding.mask,
      ruleSet: finding.ruleSet,
      detectionKind: finding.detectionKind,
      category: finding.category,
      confidence: finding.confidence,
      reason: finding.reason,
      preview: finding.preview,
      normalized: finding.normalized,
    })),
  )
    .map(({ severity: _severity, ...finding }) => finding as FinancialReviewFinding)
    .sort((a, b) => a.start - b.start);

  const groups = categories.map<FinancialFindingGroup>((category) => {
    const grouped = resolved.filter((finding) => finding.category === category);
    return {
      category,
      total: grouped.length,
      findings: grouped,
    };
  });
  const countsByCategory = groups.reduce<Record<FinancialFindingCategory, number>>((acc, group) => {
    acc[group.category] = group.total;
    return acc;
  }, { "bank-cards": 0, ibans: 0, accounts: 0, references: 0 });

  return {
    total: resolved.length,
    countsByCategory,
    findings: resolved,
    groups,
    redactionMatches: resolved.map<RedactionMatch>((finding) => ({
      start: finding.start,
      end: finding.end,
      key: finding.key,
      label: finding.label,
      severity: finding.confidence,
      mask: finding.mask,
      ruleSet: finding.ruleSet,
      detectionKind: finding.detectionKind,
    })),
    notes: [
      "Financial review stays local and uses conservative pattern-based or likely identifier matching.",
      "Pattern-based findings still do not prove an account, card, invoice, or banking identifier is active or correctly attributed.",
      "Context-driven account/reference findings are more false-positive prone and should be reviewed before redaction or export.",
    ],
  };
}

export function summarizeFinancialReview(result: FinancialReviewResult, limit = 8): string[] {
  return result.findings
    .slice(0, limit)
    .map((finding) => `${finding.label}: ${finding.reason} (${finding.detectionKind}, ${finding.confidence} confidence)`);
}

function scanBankCards(input: string, enabledRuleSets: Record<Exclude<RedactionRuleSet, "general">, boolean>) {
  const findings: RawFinancialFinding[] = [];
  const regex = /(?:[0-9\u06F0-\u06F9\u0660-\u0669][\s\-]*){12,19}/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    const value = match[0];
    const normalized = digitsOnly(value);
    if (!passesLuhn(value)) continue;
    const iranContext = enabledRuleSets.iran && isValidIranBankCard(value);
    findings.push({
      start: match.index,
      end: match.index + value.length,
      key: iranContext ? "financial-iran-bank-card" : "financial-bank-card",
      label: iranContext ? "Iran bank card" : "Bank card number",
      category: "bank-cards",
      ruleSet: iranContext ? "iran" : "general",
      detectionKind: "pattern-based",
      confidence: "high",
      severity: "high",
      reason: iranContext
        ? "Pattern-based 16-digit bank-card layout passed Luhn and matches Iran card formatting safely."
        : "Pattern-based bank-card layout passed a Luhn check.",
      preview: iranContext ? (formatIranBankCard(normalized) ?? previewValue(normalized)) : previewValue(normalized),
      normalized,
      mask: iranContext ? "[iran-card]" : "[financial-card]",
    });
  }
  return findings;
}

function scanIbans(input: string, enabledRuleSets: Record<Exclude<RedactionRuleSet, "general">, boolean>) {
  const findings: RawFinancialFinding[] = [];
  const regex = /(?<![A-Z0-9\u06F0-\u06F9\u0660-\u0669])[A-Z]{2}[0-9\u06F0-\u06F9\u0660-\u0669][A-Z0-9\u06F0-\u06F9\u0660-\u0669\s\-]{11,30}(?![A-Z0-9\u06F0-\u06F9\u0660-\u0669])/gi;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    const value = match[0];
    const normalized = compactIdentifier(value).toUpperCase();
    if (!isValidIban(value)) continue;
    const iranSheba = enabledRuleSets.iran && normalized.startsWith("IR") && isValidIranSheba(value);
    findings.push({
      start: match.index,
      end: match.index + value.length,
      key: iranSheba ? "financial-iran-sheba" : "financial-iban",
      label: iranSheba ? "Iran Sheba" : "IBAN / banking identifier",
      category: "ibans",
      ruleSet: iranSheba ? "iran" : "general",
      detectionKind: "pattern-based",
      confidence: "high",
      severity: "high",
      reason: iranSheba
        ? "Pattern-based Iran Sheba / IBAN layout matched safely after mixed-digit normalization."
        : "Pattern-based IBAN layout passed the checksum validation.",
      preview: iranSheba ? (formatIranSheba(normalized) ?? previewValue(normalized)) : previewValue(normalized),
      normalized,
      mask: iranSheba ? "[iran-sheba]" : "[iban]",
    });
  }
  return findings;
}

function scanAccountNumbers(input: string) {
  const findings: RawFinancialFinding[] = [];
  const regex = /\b(?:account|acct|account number|شماره\s*حساب|حساب|номер\s*сч[её]та|сч[её]т)\s*[:#=-]?\s*([0-9\u06F0-\u06F9\u0660-\u0669][0-9\u06F0-\u06F9\u0660-\u0669\s\-]{6,22}[0-9\u06F0-\u06F9\u0660-\u0669])\b/giu;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    const value = match[0];
    const normalized = compactIdentifier(match[1]);
    if (normalized.length < 8 || normalized.length > 24) continue;
    if (isLikelyAlreadyCovered(normalized)) continue;
    findings.push({
      start: match.index,
      end: match.index + value.length,
      key: "financial-account-like",
      label: "Account-like number",
      category: "accounts",
      ruleSet: "general",
      detectionKind: "heuristic",
      confidence: "medium",
      severity: "medium",
      reason: "Likely account-number context was paired with a long numeric or mixed identifier sequence.",
      preview: previewValue(normalized),
      normalized,
      mask: "[account-number]",
    });
  }
  return findings;
}

function scanReferenceNumbers(input: string) {
  const findings: RawFinancialFinding[] = [];
  const regex = /\b(?:invoice|invoice number|reference|reference number|ref|tracking number|شماره\s*فاکتور|شماره\s*مرجع|شماره\s*پیگیری|invoice\s*id|номер\s*сч[её]та|номер\s*плат[её]жа|референс)\s*[:#=-]?\s*([A-Z0-9\u06F0-\u06F9\u0660-\u0669][A-Z0-9\u06F0-\u06F9\u0660-\u0669\-\/]{5,23})\b/giu;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    const value = match[0];
    const normalized = compactIdentifier(match[1]);
    if (normalized.length < 6 || normalized.length > 24) continue;
    if (!/\d/.test(normalized)) continue;
    findings.push({
      start: match.index,
      end: match.index + value.length,
      key: "financial-reference-like",
      label: "Invoice / reference number",
      category: "references",
      ruleSet: "general",
      detectionKind: "heuristic",
      confidence: "low",
      severity: "low",
      reason: "Likely invoice, payment, or reference-number context was paired with an identifier-looking token.",
      preview: previewValue(normalized),
      normalized,
      mask: "[reference-number]",
    });
  }
  return findings;
}

function digitsOnly(value: string) {
  return normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
}

function compactIdentifier(value: string) {
  return normalizeMixedIdentifier(value).replace(/[\s-]+/g, "");
}

function isLikelyAlreadyCovered(value: string) {
  return passesLuhn(value) || isValidIban(value) || isValidIranSheba(value);
}

function previewValue(value: string) {
  if (value.length <= 12) return value;
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}
