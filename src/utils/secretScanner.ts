import {
  resolveOverlaps,
  type RedactionMatch,
  type RedactionRuleSet,
  type RedactionSeverity,
} from "./redaction.js";

export type SecretScannerConfidence = "low" | "medium" | "high";
export type SecretScannerEvidence = "pattern-safe" | "heuristic";

export interface SecretScannerFinding {
  start: number;
  end: number;
  key: string;
  label: string;
  confidence: SecretScannerConfidence;
  evidence: SecretScannerEvidence;
  reason: string;
  mask: string;
  preview: string;
  value: string;
  ruleSet: RedactionRuleSet;
}

export interface SecretScannerResult {
  total: number;
  byType: Record<string, number>;
  confidenceByType: Record<string, SecretScannerConfidence>;
  findings: SecretScannerFinding[];
  notes: string[];
}

interface SecretScannerDetector {
  key: string;
  label: string;
  regex: RegExp;
  confidence: SecretScannerConfidence;
  evidence: SecretScannerEvidence;
  mask: string;
  ruleSet?: RedactionRuleSet;
  validate?: (value: string) => boolean;
  reason: (value: string) => string;
}

export interface SecretScannerOptions {
  minCandidateLength?: number;
  highEntropyThreshold?: number;
  includeHeuristicCandidates?: boolean;
}

const confidenceRank: Record<SecretScannerConfidence, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

const detectors: SecretScannerDetector[] = [
  {
    key: "private-key",
    label: "Private key block",
    regex: /-----BEGIN (?:[A-Z0-9 ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]*?)PRIVATE KEY-----/g,
    confidence: "high",
    evidence: "pattern-safe",
    mask: "[private-key]",
    reason: () => "PEM block matched a private-key header and footer pair.",
  },
  {
    key: "jwt",
    label: "JWT",
    regex: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    confidence: "high",
    evidence: "pattern-safe",
    mask: "[jwt]",
    reason: () => "Three base64url segments matched a JWT layout.",
  },
  {
    key: "bearer",
    label: "Bearer token",
    regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/gi,
    confidence: "medium",
    evidence: "pattern-safe",
    mask: "[bearer-token]",
    reason: () => "Authorization-style bearer token syntax was found.",
  },
  {
    key: "github-token",
    label: "GitHub token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
    confidence: "high",
    evidence: "pattern-safe",
    mask: "[github-token]",
    reason: () => "Matched a GitHub token prefix and expected token body.",
  },
  {
    key: "slack-token",
    label: "Slack token",
    regex: /\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,}\b/g,
    confidence: "high",
    evidence: "pattern-safe",
    mask: "[slack-token]",
    reason: () => "Matched a Slack token prefix and token body format.",
  },
  {
    key: "aws-access-key",
    label: "AWS access key",
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    confidence: "high",
    evidence: "pattern-safe",
    mask: "[aws-access-key]",
    reason: () => "Matched an AWS access-key prefix and fixed-length body.",
  },
  {
    key: "aws-secret-context",
    label: "AWS secret in config",
    regex: /\baws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    confidence: "high",
    evidence: "pattern-safe",
    mask: "[aws-secret]",
    reason: () => "Config-style AWS secret assignment with a 40-character secret body was found.",
  },
  {
    key: "credential-assignment",
    label: "Credential-like assignment",
    regex: /\b(?:api(?:_|-)?key|client(?:_|-)?secret|access(?:_|-)?token|refresh(?:_|-)?token|secret|token|password|passwd)\b\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{12,}["']?/gi,
    confidence: "medium",
    evidence: "heuristic",
    mask: "[secret]",
    reason: () => "A credential-like field name was paired with a long token-looking value.",
  },
];

export function scanSecrets(input: string, options: SecretScannerOptions = {}): SecretScannerResult {
  const findings: SecretScannerFinding[] = [];
  const minCandidateLength = clamp(options.minCandidateLength ?? 20, 12, 120);
  const highEntropyThreshold = clamp(options.highEntropyThreshold ?? 3.6, 2.5, 5);
  const includeHeuristicCandidates = options.includeHeuristicCandidates ?? true;

  detectors.forEach((detector) => {
    const regex = new RegExp(detector.regex, detector.regex.flags);
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(input)) !== null) {
      const value = match[0];
      if (detector.validate && !detector.validate(value)) {
        if (!regex.global) break;
        continue;
      }
      findings.push({
        start: match.index,
        end: match.index + value.length,
        key: detector.key,
        label: detector.label,
        confidence: detector.confidence,
        evidence: detector.evidence,
        reason: detector.reason(value),
        mask: detector.mask,
        preview: previewValue(value),
        value,
        ruleSet: detector.ruleSet ?? "general",
      });
      if (!regex.global) break;
    }
  });

  if (includeHeuristicCandidates) {
    findings.push(
      ...scanHighEntropyCandidates(input, {
        minCandidateLength,
        highEntropyThreshold,
      }),
    );
  }

  const resolved = resolveOverlaps(
    findings.map((finding) => ({
      ...finding,
      severity: confidenceToSeverity(finding.confidence),
    })),
  )
    .map(({ severity: _severity, ...finding }) => finding)
    .sort((a, b) => a.start - b.start);

  const byType = resolved.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.label] = (acc[finding.label] || 0) + 1;
    return acc;
  }, {});
  const confidenceByType = resolved.reduce<Record<string, SecretScannerConfidence>>((acc, finding) => {
    const current = acc[finding.label];
    if (!current || confidenceRank[finding.confidence] > confidenceRank[current]) {
      acc[finding.label] = finding.confidence;
    }
    return acc;
  }, {});

  return {
    total: resolved.length,
    byType,
    confidenceByType,
    findings: resolved,
    notes: [
      "Pattern-based / likely secret findings only. Review before sharing or deleting.",
      "High-confidence results come from tighter token or key formats; heuristic candidates are more false-positive prone.",
    ],
  };
}

export function secretFindingsToRedactionMatches(findings: SecretScannerFinding[]): RedactionMatch[] {
  return findings.map((finding) => ({
    start: finding.start,
    end: finding.end,
    key: finding.key,
    label: finding.label,
    severity: confidenceToSeverity(finding.confidence),
    mask: finding.mask,
    ruleSet: finding.ruleSet,
    detectionKind: finding.evidence === "pattern-safe" ? "pattern-based" : "heuristic",
  }));
}

export function summarizeSecretFindings(findings: SecretScannerFinding[], limit = 8): string[] {
  return findings
    .slice(0, limit)
    .map((finding) => `${finding.label}: ${finding.reason} (${finding.evidence}, ${finding.confidence} confidence)`);
}

function scanHighEntropyCandidates(
  input: string,
  options: Required<Pick<SecretScannerOptions, "minCandidateLength" | "highEntropyThreshold">>,
): SecretScannerFinding[] {
  const matches: SecretScannerFinding[] = [];
  const regex = /(?<![A-Za-z0-9])[A-Za-z0-9._~+/=-]{20,160}(?![A-Za-z0-9])/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    const value = match[0];
    if (value.length < options.minCandidateLength) continue;
    if (!looksSecretLike(value)) continue;
    if (looksLikeJwt(value) || looksLikeUrl(value) || looksLikeEmail(value)) continue;
    const entropy = shannonEntropy(value);
    if (entropy < options.highEntropyThreshold) continue;

    matches.push({
      start: match.index,
      end: match.index + value.length,
      key: "high-entropy-candidate",
      label: "High-entropy candidate",
      confidence: "low",
      evidence: "heuristic",
      reason: `Long token-like string with estimated entropy ${entropy.toFixed(2)} bits/char.`,
      mask: "[secret-candidate]",
      preview: previewValue(value),
      value,
      ruleSet: "general",
    });
  }
  return matches;
}

function looksSecretLike(value: string) {
  if (/^\d+$/.test(value)) return false;
  if (/^[a-z]+$/i.test(value) && !/[0-9]/.test(value) && !/[_+=/-]/.test(value)) return false;
  const classes = Number(/[a-z]/.test(value)) + Number(/[A-Z]/.test(value)) + Number(/[0-9]/.test(value)) + Number(/[_+=/.-]/.test(value));
  return classes >= 3 || (classes >= 2 && value.length >= 28);
}

function looksLikeJwt(value: string) {
  return /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(value);
}

function looksLikeUrl(value: string) {
  return /^(?:https?:\/\/|www\.)/i.test(value);
}

function looksLikeEmail(value: string) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
}

function shannonEntropy(value: string) {
  const counts = new Map<string, number>();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  return Array.from(counts.values()).reduce((acc, count) => {
    const probability = count / value.length;
    return acc - probability * Math.log2(probability);
  }, 0);
}

function previewValue(value: string) {
  if (value.length <= 12) return value;
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function confidenceToSeverity(confidence: SecretScannerConfidence): RedactionSeverity {
  if (confidence === "high") return "high";
  if (confidence === "medium") return "medium";
  return "low";
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
