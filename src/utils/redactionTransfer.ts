import type { RedactionDetectionKind, RedactionMatch, RedactionRuleSet, RedactionSeverity } from "./redaction.js";

const REDACTION_DRAFT_STORAGE_KEY = "nullid:redact:draft";

interface StoredRedactionMatch {
  start: number;
  end: number;
  key: string;
  label: string;
  severity: RedactionSeverity;
  mask: string;
  ruleSet: RedactionRuleSet;
  detectionKind: RedactionDetectionKind;
}

export interface QueuedRedactionDraft {
  text: string;
  message?: string;
  matches?: StoredRedactionMatch[];
}

export function queueRedactionDraft(draft: QueuedRedactionDraft) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(
    REDACTION_DRAFT_STORAGE_KEY,
    JSON.stringify({
      text: draft.text,
      message: draft.message ?? null,
      matches: draft.matches ?? [],
      queuedAt: new Date().toISOString(),
    }),
  );
}

export function consumeRedactionDraft(): QueuedRedactionDraft | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(REDACTION_DRAFT_STORAGE_KEY);
  if (!raw) return null;
  window.localStorage.removeItem(REDACTION_DRAFT_STORAGE_KEY);
  try {
    const parsed = JSON.parse(raw) as Partial<QueuedRedactionDraft>;
    if (!parsed || typeof parsed.text !== "string") return null;
    return {
      text: parsed.text,
      message: typeof parsed.message === "string" ? parsed.message : undefined,
      matches: Array.isArray(parsed.matches)
        ? parsed.matches.filter(isStoredRedactionMatch)
        : undefined,
    };
  } catch {
    return null;
  }
}

function isStoredRedactionMatch(value: unknown): value is StoredRedactionMatch {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<RedactionMatch>;
  return typeof candidate.start === "number"
    && typeof candidate.end === "number"
    && typeof candidate.key === "string"
    && typeof candidate.label === "string"
    && typeof candidate.severity === "string"
    && typeof candidate.mask === "string"
    && typeof candidate.ruleSet === "string"
    && typeof candidate.detectionKind === "string";
}
