import type { RedactionDetectionKind, RedactionMatch, RedactionRuleSet, RedactionSeverity } from "./redaction.js";

const REDACTION_DRAFT_STORAGE_KEY = "nullid:redact:draft";
let ephemeralDraft: QueuedRedactionDraft | null = null;

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
  clearPersistedDraft();
  ephemeralDraft = {
    text: draft.text,
    message: draft.message,
    matches: draft.matches ?? [],
  };
}

export function consumeRedactionDraft(): QueuedRedactionDraft | null {
  if (typeof window === "undefined") return null;
  clearPersistedDraft();
  const draft = ephemeralDraft;
  ephemeralDraft = null;
  if (!draft || typeof draft.text !== "string") return null;
  return {
    text: draft.text,
    message: typeof draft.message === "string" ? draft.message : undefined,
    matches: Array.isArray(draft.matches) ? draft.matches.filter(isStoredRedactionMatch) : [],
  };
}

export function purgeLegacyRedactionDraft() {
  if (typeof window === "undefined") return;
  clearPersistedDraft();
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

function clearPersistedDraft() {
  try {
    window.localStorage.removeItem(REDACTION_DRAFT_STORAGE_KEY);
  } catch {
    // LocalStorage may be unavailable; queued drafts intentionally remain memory-only.
  }
}
