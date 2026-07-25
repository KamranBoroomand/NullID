import type { ThemeMode } from "../theme/tokens.js";
import { normalizeLocalMfaCredential } from "./localMfa.js";
import { PASSWORD_HASH_ALGORITHMS, PASSWORD_HASH_LIMITS } from "./passwordHashing.js";
import { getRedactionDetectors } from "./redaction.js";
import { getRuleKeys } from "./sanitizeEngine.js";
import { isCustomRegexWithinStaticBudgets } from "./customRegex.js";
import { SELF_TEST_INTERVAL_SECONDS } from "./selfTestSettings.js";
import { normalizeKeyHintProfileCollection } from "./keyHintProfiles.js";
import {
  canonicalMachineIdentifier,
  canonicalSemanticIdentity,
  normalizeMachineIdentifier,
  normalizeSemanticDisplayText,
} from "./semanticIdentity.js";

export type PersistentStateValidator<T> = (value: unknown) => value is T;
export type SupportedLocale = "en" | "fa" | "ru";
export type LayoutMode = "auto" | "mobile" | "desktop";
type ProfileImportEntryStatus = "import" | "skip" | "invalid";

export interface PersistedLocaleReadResult {
  locale: SupportedLocale | null;
  hadPersistedValue: boolean;
  hadInvalidValue: boolean;
}

export interface ProfileImportEntryIssue {
  key: string;
  reason: string;
}

export interface ProfileImportEntryDecision {
  status: ProfileImportEntryStatus;
  key: string;
  targetKey?: string;
  serializedValue?: string;
  reason?: string;
}

export interface ProfileExportEntryDecision {
  status: "export" | "skip";
  key: string;
  value?: unknown;
  reason?: string;
}

type StorageEncoding = "json" | "raw";

type ProfileValueResult = { ok: true; value: unknown } | { ok: false; reason: string };

type ProfileValueSchema = {
  normalize: (value: unknown) => ProfileValueResult;
  encoding?: StorageEncoding;
  description: string;
};

interface ProfileSchemaSummary {
  key: string;
  encoding: StorageEncoding;
  description: string;
}

interface PersistentStateSchemaSummary extends ProfileSchemaSummary {
  profilePolicy: "import-export" | "private-local-only";
}

export const DEFAULT_THEME_MODE: ThemeMode = "dark";
export const DEFAULT_LOCALE: SupportedLocale = "en";
export const DEFAULT_LAYOUT_MODE: LayoutMode = "auto";
export const SUPPORTED_LOCALES: SupportedLocale[] = ["en", "fa", "ru"];

const LOCALE_STORAGE_KEY = "nullid:locale";
const LEGACY_LANGUAGE_STORAGE_KEY = "nullid:language";

const NULLID_PREFIX = "nullid:";
const MAX_SHORT_STRING_LENGTH = 256;
const MAX_PROFILE_JSON_BYTES = 100_000;
const LAYOUT_MODES: readonly LayoutMode[] = ["auto", "mobile", "desktop"];
const REDACTION_RULE_SETS = ["iran", "russia"] as const;
const PASS_PHRASE_SEPARATORS = ["space", "-", ".", "_", "/", ":"] as const;
const PASS_PHRASE_DICTIONARIES = ["balanced", "extended", "maximal"] as const;
const PASS_PHRASE_CASE_STYLES = ["lower", "title", "random", "upper"] as const;
const PASS_PHRASE_NUMBER_MODES = ["none", "append-2", "append-4"] as const;
const PASS_PHRASE_SYMBOL_MODES = ["none", "append", "wrap"] as const;
const SANITIZE_RULE_KEYS = getRuleKeys();
const REDACTION_DETECTOR_KEYS = getRedactionDetectors().map((detector) => detector.key).sort();

const MODULE_KEYS = [
  "hash",
  "batch",
  "share",
  "incident",
  "secret",
  "analyze",
  "finance",
  "paths",
  "verify",
  "redact",
  "sanitize",
  "meta",
  "enc",
  "pw",
  "vault",
  "selftest",
  "guide",
] as const;

const booleanProfileKeys = new Set([
  "nullid:onboarding-complete",
  "nullid:secret:heuristics",
  "nullid:incident:include-source-reference",
  "nullid:incident:apply-metadata-clean",
  "nullid:incident:protect-export",
  "nullid:share:include-source-reference",
  "nullid:share:apply-metadata-clean",
  "nullid:share:protect-export",
  "nullid:redact:preserve-length",
  "nullid:sanitize:wrap",
  "nullid:sanitize:json",
  "nullid:selftest:auto-monitor",
  "nullid:vault:pref:unlock-rate-limit",
  "nullid:vault:pref:unlock-human-check",
  "nullid:vault:pref:session-cookie-enabled",
]);

const numberProfileKeys = new Set([
  "nullid:onboarding-step",
  "nullid:secret:min-length",
  "nullid:pw-batch-count",
  "nullid:pw-hash:salt",
  "nullid:pw-hash:pbkdf2-iterations",
  "nullid:pw-hash:argon2-memory",
  "nullid:pw-hash:argon2-passes",
  "nullid:pw-hash:argon2-parallelism",
  "nullid:redact:min-token-length",
  "nullid:selftest:interval",
]);

const shortStringProfileKeys = new Set([
  "nullid:profile:key-hint-selected",
  "nullid:sanitize:key-hint-selected",
  "nullid:share:policy-id",
  "nullid:incident:policy-id",
  "nullid:vault:pref:key-hint-selected",
]);

const enumProfileKeys = new Map<string, readonly string[]>([
  ["nullid:last-module", MODULE_KEYS],
  ["nullid:layout-mode", LAYOUT_MODES],
  ["nullid:hash:batch-algo", ["SHA-256", "SHA-512", "SHA-1"]],
  ["nullid:pw-batch-mode", ["password", "passphrase"]],
  ["nullid:pw-hash:algorithm", PASSWORD_HASH_ALGORITHMS],
  ["nullid:redact:mask", ["full", "partial"]],
  ["nullid:redact:min-severity", ["low", "medium", "high"]],
  ["nullid:sanitize:preset", ["nginx", "apache", "auth", "json"]],
  ["nullid:share:mode", ["text", "file"]],
  [
    "nullid:share:preset",
    [
      "general-safe-share",
      "support-ticket",
      "external-minimum",
      "internal-investigation",
      "incident-handoff",
      "evidence-archive",
      "customer-support-share",
      "legal-document-share",
      "journalist-source-share",
      "internal-incident-handoff",
      "external-minimum-disclosure",
    ],
  ],
  ["nullid:incident:mode", ["incident-handoff", "evidence-archive", "minimal-disclosure-incident-share", "internal-investigation"]],
  ["nullid:feedback-category", ["idea", "bug", "ux", "performance"]],
  ["nullid:feedback-priority", ["low", "medium", "high"]],
]);

const legacyProfileKeyTargets = new Map<string, string>([
  [LEGACY_LANGUAGE_STORAGE_KEY, LOCALE_STORAGE_KEY],
  ["nullid:vault:unlock-rate-limit", "nullid:vault:pref:unlock-rate-limit"],
  ["nullid:vault:unlock-human-check", "nullid:vault:pref:unlock-human-check"],
  ["nullid:vault:unlock-throttle", "nullid:vault:pref:unlock-throttle"],
  ["nullid:vault:session-cookie-enabled", "nullid:vault:pref:session-cookie-enabled"],
  ["nullid:vault:key-hint-selected", "nullid:vault:pref:key-hint-selected"],
]);

export function isThemeMode(value: unknown): value is ThemeMode {
  return value === "light" || value === "dark";
}

export function isSupportedLocale(value: unknown): value is SupportedLocale {
  return typeof value === "string" && (SUPPORTED_LOCALES as string[]).includes(value);
}

export function isLayoutMode(value: unknown): value is LayoutMode {
  return typeof value === "string" && (LAYOUT_MODES as readonly string[]).includes(value);
}

export function isClipboardPrefs(value: unknown): value is { enableAutoClearClipboard: boolean; clipboardClearSeconds: number } {
  if (!isExactPlainObject(value, ["enableAutoClearClipboard", "clipboardClearSeconds"])) return false;
  return (
    typeof value.enableAutoClearClipboard === "boolean" &&
    typeof value.clipboardClearSeconds === "number" &&
    Number.isInteger(value.clipboardClearSeconds) &&
    Number.isFinite(value.clipboardClearSeconds) &&
    value.clipboardClearSeconds >= 0 &&
    value.clipboardClearSeconds <= 3600
  );
}

export function normalizePersistentStateValue<T>(
  key: string,
  value: unknown,
  initial: T,
  validator?: PersistentStateValidator<T>,
): { ok: true; value: T } | { ok: false } {
  if (validator) return validator(value) ? { ok: true, value } : { ok: false };
  const schema = persistentStateValueSchemas.get(key);
  if (schema) {
    const normalized = schema.normalize(value);
    return normalized.ok ? { ok: true, value: normalized.value as T } : { ok: false };
  }
  return validateGenericPersistentStateValue(value, initial) ? { ok: true, value: value as T } : { ok: false };
}

function validateGenericPersistentStateValue<T>(value: unknown, initial: T): boolean {
  if (!isJsonValue(value)) return false;

  if (typeof initial === "boolean") return typeof value === "boolean";
  if (typeof initial === "number") return typeof value === "number" && Number.isFinite(value);
  if (typeof initial === "string") return typeof value === "string";
  if (Array.isArray(initial)) return Array.isArray(value);
  if (initial === null) return true;
  if (typeof initial === "object") return isPlainObject(value);
  return true;
}

export function readPersistedLocale(storage: Storage): SupportedLocale {
  return readPersistedLocaleResult(storage).locale ?? DEFAULT_LOCALE;
}

export function readPersistedLocaleResult(storage: Storage): PersistedLocaleReadResult {
  let hadPersistedValue = false;
  let hadInvalidValue = false;

  for (const key of [LOCALE_STORAGE_KEY, LEGACY_LANGUAGE_STORAGE_KEY]) {
    const raw = storage.getItem(key);
    if (raw == null) continue;
    hadPersistedValue = true;
    const locale = parseStoredLocale(raw);
    if (!locale) {
      hadInvalidValue = true;
      safeRemoveItem(storage, key);
      continue;
    }
    if (key !== LOCALE_STORAGE_KEY || raw !== locale) {
      try {
        storage.setItem(LOCALE_STORAGE_KEY, locale);
        if (key !== LOCALE_STORAGE_KEY) {
          storage.removeItem(key);
        }
      } catch {
        // A blocked migration should not prevent the locale from being used.
      }
    }
    return { locale, hadPersistedValue, hadInvalidValue };
  }

  return { locale: null, hadPersistedValue, hadInvalidValue };
}

export function writePersistedLocale(storage: Storage, locale: SupportedLocale) {
  storage.setItem(LOCALE_STORAGE_KEY, locale);
  storage.removeItem(LEGACY_LANGUAGE_STORAGE_KEY);
}

function validateProfileImportEntry(key: string, value: unknown): ProfileImportEntryDecision {
  if (!key.startsWith(NULLID_PREFIX)) {
    return skipProfileEntry(key, "outside the NullID local state namespace");
  }
  if (isPrivateVaultProfileKey(key)) {
    return skipProfileEntry(key, "private vault data is not imported through profiles");
  }

  const targetKey = legacyProfileKeyTargets.get(key) ?? key;
  const rule = profileImportRules.get(targetKey);
  if (!rule) {
    return skipProfileEntry(key, "profile key is not importable");
  }
  const normalized = rule.normalize(value);
  if (!normalized.ok) {
    return invalidProfileEntry(key, `profile value failed validation: ${normalized.reason}`);
  }

  const encoding = rule.encoding ?? "json";
  const serializedValue = encoding === "raw" ? String(normalized.value) : JSON.stringify(normalized.value);
  if (serializedValue.length > MAX_PROFILE_JSON_BYTES) {
    return invalidProfileEntry(key, "profile value is too large");
  }

  return { status: "import", key, targetKey, serializedValue };
}

export function classifyProfileExportEntry(key: string, rawValue: string | null): ProfileExportEntryDecision {
  if (!key.startsWith(NULLID_PREFIX)) {
    return skipProfileExportEntry(key, "outside the NullID local state namespace");
  }
  if (legacyProfileKeyTargets.has(key)) {
    return skipProfileExportEntry(key, "legacy profile key is import-only");
  }

  const value = parseProfileStorageValue(rawValue);
  const decision = validateProfileImportEntry(key, value);
  if (decision.status !== "import" || decision.targetKey !== key) {
    return skipProfileExportEntry(key, decision.reason ?? "profile key is not exportable");
  }
  const rule = profileImportRules.get(key);
  const normalized = rule?.normalize(value);
  return normalized?.ok ? { status: "export", key, value: normalized.value } : skipProfileExportEntry(key, "profile value failed validation");
}

export function validateProfileEntryValue(key: string, value: unknown): ProfileImportEntryDecision {
  return validateProfileImportEntry(key, value);
}

export function getProfileSchemaMatrix(): ProfileSchemaSummary[] {
  return Array.from(profileValueSchemas.entries())
    .map(([key, schema]) => ({ key, encoding: schema.encoding ?? "json", description: schema.description }))
    .sort((left, right) => left.key.localeCompare(right.key));
}

export function getPersistentStateSchemaMatrix(): PersistentStateSchemaSummary[] {
  return Array.from(persistentStateValueSchemas.entries())
    .map(([key, schema]) => ({
      key,
      encoding: schema.encoding ?? "json",
      description: schema.description,
      profilePolicy: profileValueSchemas.has(key) ? ("import-export" as const) : ("private-local-only" as const),
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
}

function parseProfileStorageValue(rawValue: string | null): unknown {
  if (rawValue == null) return null;
  try {
    return JSON.parse(rawValue) as unknown;
  } catch {
    return rawValue;
  }
}

function parseStoredLocale(raw: string): SupportedLocale | null {
  if (isSupportedLocale(raw)) return raw;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return isSupportedLocale(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function skipProfileEntry(key: string, reason: string): ProfileImportEntryDecision {
  return { status: "skip", key, reason };
}

function invalidProfileEntry(key: string, reason: string): ProfileImportEntryDecision {
  return { status: "invalid", key, reason };
}

function skipProfileExportEntry(key: string, reason: string): ProfileExportEntryDecision {
  return { status: "skip", key, reason };
}

function isPrivateVaultProfileKey(key: string): boolean {
  return (
    key === "nullid:vault:pref:mfa-credential" ||
    key === "nullid:vault:mfa-credential" ||
    key.startsWith("nullid:vault:data:") ||
    key.startsWith("nullid:vault:notes:") ||
    key.startsWith("nullid:vault:meta:") ||
    key.startsWith("nullid:vault:canary:") ||
    key.startsWith("nullid:vault:selftest:")
  );
}

function boundedShortString(value: unknown) {
  return typeof value === "string" && value.length <= MAX_SHORT_STRING_LENGTH;
}

function isJsonValue(value: unknown): boolean {
  if (value === null) return true;
  const valueType = typeof value;
  if (valueType === "string" || valueType === "boolean") return true;
  if (valueType === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (isPlainObject(value)) return Object.values(value).every(isJsonValue);
  return false;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isExactPlainObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function ok(value: unknown): ProfileValueResult {
  return { ok: true, value };
}

function invalid(reason: string): ProfileValueResult {
  return { ok: false, reason };
}

function schema(description: string, normalize: (value: unknown) => ProfileValueResult, encoding?: StorageEncoding): ProfileValueSchema {
  return { description, normalize, encoding };
}

function booleanSchema(description: string) {
  return schema(description, (value) => (typeof value === "boolean" ? ok(value) : invalid("expected boolean")));
}

function shortStringSchema(description: string) {
  return schema(description, (value) => (boundedShortString(value) ? ok(value) : invalid("expected bounded string")));
}

function enumSchema(description: string, values: readonly string[]) {
  return schema(description, (value) => (typeof value === "string" && values.includes(value) ? ok(value) : invalid("unsupported enum value")));
}

function numberSchema(description: string, min: number, max: number, integer = true) {
  return schema(description, (value) => {
    if (typeof value !== "number" || !Number.isFinite(value)) return invalid("expected finite number");
    if (integer && !Number.isInteger(value)) return invalid("expected integer");
    if (value < min || value > max) return invalid("number outside allowed range");
    return ok(value);
  });
}

function exactBooleanMapSchema(description: string, keys: readonly string[]) {
  return schema(description, (value) => {
    if (!isExactPlainObject(value, keys)) return invalid("expected exact boolean map");
    for (const key of keys) {
      if (typeof value[key] !== "boolean") return invalid(`expected boolean for ${key}`);
    }
    return ok(Object.fromEntries(keys.map((key) => [key, value[key]])));
  });
}

function passwordSettingsSchema() {
  const keys = ["length", "upper", "lower", "digits", "symbols", "avoidAmbiguity", "enforceMix", "blockSequential", "blockRepeats", "minUniqueChars"] as const;
  return schema("Password generator settings: exact object with length, character classes, hardening toggles and minUniqueChars.", (value) => {
    if (!isExactPlainObject(value, keys)) return invalid("expected exact password settings object");
    if (!isBoundedInteger(value.length, 8, 128)) return invalid("password length outside range");
    for (const key of ["upper", "lower", "digits", "symbols", "avoidAmbiguity", "enforceMix", "blockSequential", "blockRepeats"] as const) {
      if (typeof value[key] !== "boolean") return invalid(`expected boolean ${key}`);
    }
    if (!isBoundedInteger(value.minUniqueChars, 1, value.length)) return invalid("minUniqueChars outside range");
    return ok(Object.fromEntries(keys.map((key) => [key, value[key]])));
  });
}

function passphraseSettingsSchema() {
  const keys = ["words", "separator", "dictionaryProfile", "caseStyle", "numberMode", "symbolMode", "ensureUniqueWords"] as const;
  return schema("Passphrase generator settings: exact object with word count, separators, dictionary, casing, number/symbol mode and uniqueness.", (value) => {
    if (!isExactPlainObject(value, keys)) return invalid("expected exact passphrase settings object");
    if (!isBoundedInteger(value.words, 3, 16)) return invalid("word count outside range");
    if (!isOneOf(value.separator, PASS_PHRASE_SEPARATORS)) return invalid("unsupported separator");
    if (!isOneOf(value.dictionaryProfile, PASS_PHRASE_DICTIONARIES)) return invalid("unsupported dictionary profile");
    if (!isOneOf(value.caseStyle, PASS_PHRASE_CASE_STYLES)) return invalid("unsupported case style");
    if (!isOneOf(value.numberMode, PASS_PHRASE_NUMBER_MODES)) return invalid("unsupported number mode");
    if (!isOneOf(value.symbolMode, PASS_PHRASE_SYMBOL_MODES)) return invalid("unsupported symbol mode");
    if (typeof value.ensureUniqueWords !== "boolean") return invalid("expected ensureUniqueWords boolean");
    return ok(Object.fromEntries(keys.map((key) => [key, value[key]])));
  });
}

function sanitizeCustomRulesSchema() {
  const keys = ["id", "pattern", "replacement", "flags", "scope"] as const;
  return schema("Sanitizer custom rules: bounded array of exact rule objects with id, pattern, replacement, flags and scope.", (value) => {
    if (!Array.isArray(value) || value.length > 50) return invalid("expected bounded custom rule array");
    const rules = [];
    const seenIds = new Set<string>();
    for (const entry of value) {
      if (!isExactPlainObject(entry, keys)) return invalid("expected exact custom rule object");
      const id = typeof entry.id === "string" ? normalizeMachineIdentifier(entry.id, 128) : null;
      if (!id) return invalid("invalid custom rule id");
      if (!addUniqueValue(seenIds, canonicalMachineIdentifier(id, 128)!)) return invalid("duplicate custom rule id");
      if (!isBoundedString(entry.pattern, 1, 240)) return invalid("invalid custom rule pattern");
      if (!isBoundedString(entry.replacement, 0, 2000)) return invalid("invalid custom rule replacement");
      if (!isBoundedString(entry.flags, 0, 8) || /(.).*\1/u.test(entry.flags) || !/^[dgimsuvy]*$/u.test(entry.flags)) return invalid("invalid custom rule flags");
      if (!isOneOf(entry.scope, ["text", "json", "both"] as const)) return invalid("invalid custom rule scope");
      if (!isCustomRegexWithinStaticBudgets({ pattern: entry.pattern, flags: entry.flags, replacement: entry.replacement })) return invalid("invalid custom rule static budgets");
      rules.push({ id, pattern: entry.pattern, replacement: entry.replacement, flags: entry.flags, scope: entry.scope });
    }
    return ok(rules);
  });
}

function sanitizePolicyConfigSchemaValue(value: unknown): ProfileValueResult {
  if (!isExactPlainObject(value, ["rulesState", "jsonAware", "customRules"])) return invalid("expected exact sanitizer policy config");
  const rulesState = exactBooleanMapSchema("Sanitizer rule-state map.", SANITIZE_RULE_KEYS).normalize(value.rulesState);
  if (!rulesState.ok) return rulesState;
  if (typeof value.jsonAware !== "boolean") return invalid("expected jsonAware boolean");
  const customRules = sanitizeCustomRulesSchema().normalize(value.customRules);
  if (!customRules.ok) return customRules;
  return ok({ rulesState: rulesState.value, jsonAware: value.jsonAware, customRules: customRules.value });
}

function policyPacksSchema() {
  const keys = ["id", "name", "createdAt", "config"] as const;
  return schema("Sanitizer policy packs: bounded array of exact pack objects with exact sanitizer configs.", (value) => {
    if (!Array.isArray(value) || value.length > 20) return invalid("expected bounded policy pack array");
    const packs = [];
    const seenIds = new Set<string>();
    const seenNames = new Set<string>();
    for (const entry of value) {
      if (!isExactPlainObject(entry, keys)) return invalid("expected exact policy pack object");
      const id = typeof entry.id === "string" ? normalizeMachineIdentifier(entry.id, 128) : null;
      const name = normalizeBoundedText(entry.name, 1, 160);
      if (!id) return invalid("invalid policy pack id");
      if (!addUniqueValue(seenIds, canonicalMachineIdentifier(id, 128)!)) return invalid("duplicate policy pack id");
      if (!name) return invalid("invalid policy pack name");
      if (!addUniqueValue(seenNames, canonicalSemanticIdentity(name))) return invalid("duplicate policy pack name");
      const createdAt = normalizeCanonicalIsoTimestamp(entry.createdAt);
      if (!createdAt) return invalid("invalid policy pack timestamp");
      const config = sanitizePolicyConfigSchemaValue(entry.config);
      if (!config.ok) return config;
      packs.push({ id, name, createdAt, config: config.value });
    }
    return ok(packs);
  });
}

function keyHintProfilesSchema() {
  return schema("Signing/key-hint profiles: bounded array of exact key hint profile records.", (value) => {
    const normalized = normalizeKeyHintProfileCollection(value);
    return normalized.ok ? ok(normalized.value) : invalid(normalized.reason);
  });
}

function localMfaCredentialSchema() {
  return schema("Private local WebAuthn MFA credential: null or exact id/label/createdAt object. Not profile importable.", (value) => {
    const normalized = normalizeLocalMfaCredential(value);
    return normalized !== null || value === null ? ok(normalized) : invalid("invalid local MFA credential");
  });
}

function unlockThrottleSchema() {
  return schema("Vault unlock throttle state: exact failures and lockoutUntil counters.", (value) => {
    if (!isExactPlainObject(value, ["failures", "lockoutUntil"])) return invalid("expected exact unlock throttle object");
    if (!isBoundedInteger(value.failures, 0, 10_000)) return invalid("invalid failure count");
    if (typeof value.lockoutUntil !== "number" || !Number.isFinite(value.lockoutUntil) || value.lockoutUntil < 0) return invalid("invalid lockout timestamp");
    return ok({ failures: value.failures, lockoutUntil: value.lockoutUntil });
  });
}

function isBoundedString(value: unknown, min: number, max: number): value is string {
  return typeof value === "string" && value.length >= min && value.length <= max;
}

function normalizeBoundedText(value: unknown, min: number, max: number): string | null {
  if (typeof value !== "string") return null;
  const normalized = normalizeSemanticDisplayText(value);
  return normalized.length >= min && normalized.length <= max ? normalized : null;
}

function normalizeCanonicalIsoTimestamp(value: unknown): string | null {
  if (!isBoundedString(value, 1, 128)) return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  const canonical = new Date(timestamp).toISOString();
  return canonical === value ? canonical : null;
}

function addUniqueValue(seen: Set<string>, value: string): boolean {
  if (seen.has(value)) return false;
  seen.add(value);
  return true;
}

function isBoundedInteger(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}

function isOneOf<const T extends readonly string[]>(value: unknown, options: T): value is T[number] {
  return typeof value === "string" && (options as readonly string[]).includes(value);
}

function safeRemoveItem(storage: Storage, key: string) {
  try {
    storage.removeItem(key);
  } catch {
    // Best effort cleanup only.
  }
}

const numberProfileSchemas = new Map<string, ProfileValueSchema>([
  ["nullid:onboarding-step", numberSchema("Onboarding step index.", 0, 20)],
  ["nullid:secret:min-length", numberSchema("Secret scanner minimum token length.", 4, 256)],
  ["nullid:pw-batch-count", numberSchema("Password/passphrase batch count.", 1, 100)],
  ["nullid:pw-hash:salt", numberSchema("Password hash salt byte count.", PASSWORD_HASH_LIMITS.saltBytes.min, PASSWORD_HASH_LIMITS.saltBytes.max)],
  ["nullid:pw-hash:pbkdf2-iterations", numberSchema("PBKDF2 iteration count.", PASSWORD_HASH_LIMITS.pbkdf2.iterations.min, PASSWORD_HASH_LIMITS.pbkdf2.iterations.max)],
  ["nullid:pw-hash:argon2-memory", numberSchema("Argon2id memory cost.", PASSWORD_HASH_LIMITS.argon2.memory.min, PASSWORD_HASH_LIMITS.argon2.memory.max)],
  ["nullid:pw-hash:argon2-passes", numberSchema("Argon2id pass count.", PASSWORD_HASH_LIMITS.argon2.passes.min, PASSWORD_HASH_LIMITS.argon2.passes.max)],
  ["nullid:pw-hash:argon2-parallelism", numberSchema("Argon2id parallelism.", PASSWORD_HASH_LIMITS.argon2.parallelism.min, PASSWORD_HASH_LIMITS.argon2.parallelism.max)],
  ["nullid:redact:min-token-length", numberSchema("Redaction minimum token length.", 1, 256)],
  [
    "nullid:selftest:interval",
    numberSchema(
      "Self-test auto-monitor interval in seconds.",
      SELF_TEST_INTERVAL_SECONDS.min,
      SELF_TEST_INTERVAL_SECONDS.max,
    ),
  ],
]);

const profileValueSchemas = new Map<string, ProfileValueSchema>([
  ["nullid:theme", schema("Theme mode.", (value) => (isThemeMode(value) ? ok(value) : invalid("unsupported theme")))],
  [LOCALE_STORAGE_KEY, schema("Active locale.", (value) => (isSupportedLocale(value) ? ok(value) : invalid("unsupported locale")), "raw")],
  ["nullid:clipboard:prefs", schema("Clipboard preferences: exact object with auto-clear toggle and bounded timeout.", (value) => (isClipboardPrefs(value) ? ok(value) : invalid("invalid clipboard preferences")))],
  ["nullid:pw-settings", passwordSettingsSchema()],
  ["nullid:pp-settings", passphraseSettingsSchema()],
  ["nullid:sanitize:rules", exactBooleanMapSchema("Sanitizer built-in rule-state map.", SANITIZE_RULE_KEYS)],
  ["nullid:sanitize:custom", sanitizeCustomRulesSchema()],
  ["nullid:sanitize:policy-packs", policyPacksSchema()],
  ["nullid:signing:key-hints", keyHintProfilesSchema()],
  ["nullid:vault:pref:unlock-throttle", unlockThrottleSchema()],
  ["nullid:batch:rule-sets", exactBooleanMapSchema("Batch review optional regional rule-set map.", REDACTION_RULE_SETS)],
  ["nullid:analyze:rule-sets", exactBooleanMapSchema("Structured analyzer optional regional rule-set map.", REDACTION_RULE_SETS)],
  ["nullid:financial:rule-sets", exactBooleanMapSchema("Financial review optional regional rule-set map.", REDACTION_RULE_SETS)],
  ["nullid:redact:rule-sets", exactBooleanMapSchema("Text redaction optional regional rule-set map.", REDACTION_RULE_SETS)],
  ["nullid:redact:detectors", exactBooleanMapSchema("Text redaction detector enablement map.", REDACTION_DETECTOR_KEYS)],
  ...Array.from(booleanProfileKeys, (key) => [key, booleanSchema("Boolean profile preference.")] as const),
  ...Array.from(numberProfileKeys, (key) => [key, numberProfileSchemas.get(key) ?? numberSchema("Bounded numeric profile preference.", -1_000_000_000, 1_000_000_000, false)] as const),
  ...Array.from(shortStringProfileKeys, (key) => [key, shortStringSchema("Short local profile string.")] as const),
  ...Array.from(enumProfileKeys, ([key, values]) => [key, enumSchema("Enumerated profile preference.", values)] as const),
]);

const persistentStateValueSchemas = new Map<string, ProfileValueSchema>([
  ...profileValueSchemas,
  ["nullid:vault:pref:mfa-credential", localMfaCredentialSchema()],
]);

const profileImportRules = profileValueSchemas;
