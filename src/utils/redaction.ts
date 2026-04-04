export type RedactionSeverity = "low" | "medium" | "high";
export type RedactionMaskMode = "full" | "partial";
export type RedactionRuleSet = "general" | "iran" | "russia";
export type RedactionDetectionKind = "pattern-based" | "heuristic";

export interface RedactionMatch {
  start: number;
  end: number;
  key: string;
  label: string;
  severity: RedactionSeverity;
  mask: string;
  ruleSet: RedactionRuleSet;
  detectionKind: RedactionDetectionKind;
}

export interface RedactionDetector {
  key: string;
  label: string;
  regex: RegExp;
  severity: RedactionSeverity;
  mask: string;
  ruleSet: RedactionRuleSet;
  detectionKind: RedactionDetectionKind;
  validate?: (value: string) => boolean;
}

export interface RedactionCustomRule {
  label: string;
  regex: RegExp;
}

export interface RedactionChange extends RedactionMatch {
  original: string;
  replacement: string;
}

export interface ScanRedactionOptions {
  minimumSeverity: RedactionSeverity;
  minTokenLength: number;
}

export interface RedactionScanResult {
  counts: Record<string, number>;
  severityMap: Record<string, RedactionSeverity>;
  total: number;
  overall: RedactionSeverity;
  matches: RedactionMatch[];
}

const severityRank: Record<RedactionSeverity, number> = { low: 1, medium: 2, high: 3 };
const digitClass = "0-9\\u06F0-\\u06F9\\u0660-\\u0669";
const separatorClass = "[\\s\\u00A0\\u200C\\u200F\\u061C().\\-/_]*";
const persianNameContext = "(?:نام(?:\\s+و\\s+نام\\s+خانوادگی)?|گیرنده|مخاطب)";
const iranCardContext = "(?:شماره\\s*کارت|شماره‌کارت|کارت(?:\\s*بانکی)?|bank\\s*card|card\\s*number)";
const iranPostalContext = "(?:کد\\s*پستی|کدپستی|postal\\s*code|postcode)";
const iranShebaContext = "(?:شبا|شماره\\s*شبا|iban|sheba)";
const russianPassportContext = "(?:паспорт|серия\\s*и\\s*номер\\s*паспорта|серия\\s*паспорта|номер\\s*паспорта|passport)";
const russianPlateContext = "(?:гос(?:номер)?|vehicle\\s*plate|license\\s*plate|plate)";
const russianDocumentContext = "(?:документ|номер\\s*документа|document\\s*number)";
const regionSpacePattern = `${separatorClass}`;
const iranPhonePrefixPattern = "(?:\\+(?:98|۹۸|٩٨)|(?:00|۰۰|٠٠)?(?:98|۹۸|٩٨)|(?:0|۰|٠))?";
const iranBankCardPrefixes = new Set([
  "502229",
  "502806",
  "502908",
  "505785",
  "589210",
  "603769",
  "603770",
  "603799",
  "606256",
  "621986",
  "622106",
  "627353",
  "627381",
  "627412",
  "627488",
  "627648",
  "627760",
  "627961",
  "628023",
  "628157",
  "636214",
  "636795",
  "639194",
  "639346",
  "639347",
  "639370",
  "639599",
  "639607",
]);

const detectors: RedactionDetector[] = [
  {
    key: "email",
    label: "Email",
    regex: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
    severity: "medium",
    mask: "[email]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "phone",
    label: "Phone",
    regex: /(?:\+|00)?[0-9\u06F0-\u06F9\u0660-\u0669][0-9\u06F0-\u06F9\u0660-\u0669().\-\s]{7,18}[0-9\u06F0-\u06F9\u0660-\u0669]/g,
    severity: "low",
    mask: "[phone]",
    ruleSet: "general",
    detectionKind: "heuristic",
    validate: isLikelyPhone,
  },
  {
    key: "url",
    label: "URL",
    regex: /\b(?:https?:\/\/|www\.)[^\s<>()\[\]{}"'`]+/gi,
    severity: "medium",
    mask: "[url]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "token",
    label: "Bearer / token",
    regex: /\b(?:authorization[:=]\s*)?(?:bearer\s+)?[A-Za-z0-9._-]{20,}\b/gi,
    severity: "high",
    mask: "[token]",
    ruleSet: "general",
    detectionKind: "heuristic",
  },
  {
    key: "ip",
    label: "IP",
    regex: /(?<![0-9\u06F0-\u06F9\u0660-\u0669])(?:[0-9\u06F0-\u06F9\u0660-\u0669]{1,3}\.){3}[0-9\u06F0-\u06F9\u0660-\u0669]{1,3}(?![0-9\u06F0-\u06F9\u0660-\u0669])/g,
    severity: "medium",
    mask: "[ip]",
    ruleSet: "general",
    detectionKind: "pattern-based",
    validate: isValidIpv4,
  },
  {
    key: "ssn",
    label: "Generic ID",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: "high",
    mask: "[id]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "uuid",
    label: "Generic ID",
    regex: /\b[0-9A-F]{8}-[0-9A-F]{4}-[1-5][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b/gi,
    severity: "high",
    mask: "[id]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "generic-id-context",
    label: "Generic ID",
    regex: /\b(?:id|identifier|account|acct|customer|passport|license|employee|record|tax\s*id|national\s*id)\s*[:#=-]?\s*[A-Z0-9-]{5,24}\b/gi,
    severity: "high",
    mask: "[id]",
    ruleSet: "general",
    detectionKind: "heuristic",
  },
  {
    key: "iban",
    label: "IBAN",
    regex: /(?<![A-Z0-9\u06F0-\u06F9\u0660-\u0669])[A-Z]{2}[0-9\u06F0-\u06F9\u0660-\u0669]{2}[A-Z0-9\u06F0-\u06F9\u0660-\u0669]{11,30}(?![A-Z0-9\u06F0-\u06F9\u0660-\u0669])/gi,
    severity: "high",
    mask: "[iban]",
    ruleSet: "general",
    detectionKind: "pattern-based",
    validate: isValidIban,
  },
  {
    key: "card",
    label: "Credit card",
    regex: /(?:[0-9\u06F0-\u06F9\u0660-\u0669][ -]?){12,19}/g,
    severity: "high",
    mask: "[card]",
    ruleSet: "general",
    detectionKind: "pattern-based",
    validate: passesLuhn,
  },
  {
    key: "ipv6",
    label: "IPv6",
    regex: /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi,
    severity: "medium",
    mask: "[ipv6]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "awskey",
    label: "AWS key",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "high",
    mask: "[aws-key]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "awssecret",
    label: "AWS secret",
    regex: /\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b/gi,
    severity: "high",
    mask: "[aws-secret]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "github",
    label: "GitHub token",
    regex: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    severity: "high",
    mask: "[github-token]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "slack",
    label: "Slack token",
    regex: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g,
    severity: "high",
    mask: "[slack-token]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "privatekey",
    label: "Private key block",
    regex: /-----BEGIN (?:[A-Z0-9 ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]*?)PRIVATE KEY-----/g,
    severity: "high",
    mask: "[private-key]",
    ruleSet: "general",
    detectionKind: "pattern-based",
  },
  {
    key: "iran-id",
    label: "Iran national ID",
    regex: /(?<![0-9\u06F0-\u06F9\u0660-\u0669])[0-9\u06F0-\u06F9\u0660-\u0669]{10}(?![0-9\u06F0-\u06F9\u0660-\u0669])/g,
    severity: "high",
    mask: "[iran-id]",
    ruleSet: "iran",
    detectionKind: "pattern-based",
    validate: isValidIranNationalId,
  },
  {
    key: "iran-phone",
    label: "Iran phone",
    regex: new RegExp(`${iranPhonePrefixPattern}${regionSpacePattern}(?:9|۹|٩)[${digitClass}]${regionSpacePattern}(?:[${digitClass}]${regionSpacePattern}){8}`, "g"),
    severity: "medium",
    mask: "[iran-phone]",
    ruleSet: "iran",
    detectionKind: "pattern-based",
    validate: isValidIranPhone,
  },
  {
    key: "persian-name",
    label: "Persian name",
    regex: new RegExp(`${persianNameContext}\\s*[:：-]\\s*[\\u0600-\\u06FF]{2,}(?:\\s+[\\u0600-\\u06FF]{2,}){0,3}`, "g"),
    severity: "medium",
    mask: "[persian-name]",
    ruleSet: "iran",
    detectionKind: "heuristic",
  },
  {
    key: "iran-card-context",
    label: "Iran bank card",
    regex: new RegExp(`${iranCardContext}\\s*[:：-]?\\s*(?:[${digitClass}]${separatorClass}){15}[${digitClass}]`, "gi"),
    severity: "high",
    mask: "[iran-card]",
    ruleSet: "iran",
    detectionKind: "pattern-based",
    validate: isValidIranBankCardContext,
  },
  {
    key: "iran-postal-context",
    label: "Iran postal code",
    regex: new RegExp(`${iranPostalContext}\\s*[:：-]?\\s*(?:[${digitClass}]${separatorClass}){9}[${digitClass}]`, "gi"),
    severity: "medium",
    mask: "[iran-postal-code]",
    ruleSet: "iran",
    detectionKind: "pattern-based",
    validate: isValidIranPostalCodeContext,
  },
  {
    key: "iran-sheba",
    label: "Iran Sheba",
    regex: new RegExp(`(?:${iranShebaContext}\\s*[:：-]?\\s*)?(?:IR|ir)(?:${separatorClass}[${digitClass}]){24}`, "g"),
    severity: "high",
    mask: "[iran-sheba]",
    ruleSet: "iran",
    detectionKind: "pattern-based",
    validate: isValidIranSheba,
  },
  {
    key: "ru-phone",
    label: "Russia phone",
    regex: new RegExp(`(?:\\+7|8)${regionSpacePattern}(?:\\(?${regionSpacePattern}[${digitClass}]{3}${regionSpacePattern}\\)?${regionSpacePattern})?[${digitClass}]{3}${regionSpacePattern}[${digitClass}]{2}${regionSpacePattern}[${digitClass}]{2}`, "g"),
    severity: "medium",
    mask: "[ru-phone]",
    ruleSet: "russia",
    detectionKind: "pattern-based",
    validate: isValidRussianPhone,
  },
  {
    key: "ru-inn",
    label: "Russia INN",
    regex: new RegExp(`(?<![${digitClass}])(?:[${digitClass}]${separatorClass}){9,11}[${digitClass}](?![${digitClass}])`, "g"),
    severity: "high",
    mask: "[ru-inn]",
    ruleSet: "russia",
    detectionKind: "pattern-based",
    validate: isValidRussianInn,
  },
  {
    key: "ru-snils",
    label: "Russia SNILS",
    regex: new RegExp(`(?<![${digitClass}])(?:[${digitClass}]{3}${separatorClass}[${digitClass}]{3}${separatorClass}[${digitClass}]{3}${separatorClass}[${digitClass}]{2}|[${digitClass}]{11})(?![${digitClass}])`, "g"),
    severity: "high",
    mask: "[ru-snils]",
    ruleSet: "russia",
    detectionKind: "pattern-based",
    validate: isValidRussianSnils,
  },
  {
    key: "ru-passport-context",
    label: "Russia passport",
    regex: new RegExp(`${russianPassportContext}\\s*[:：№#-]?\\s*(?:(?:серия|series)\\s*[:：№#-]?\\s*[${digitClass}]{2}${separatorClass}[${digitClass}]{2}\\s*(?:номер|number|no\\.)\\s*[:：№#-]?\\s*[${digitClass}]{6}|[${digitClass}]{2}${separatorClass}[${digitClass}]{2}${separatorClass}[${digitClass}]{6}|[${digitClass}]{10})`, "giu"),
    severity: "high",
    mask: "[ru-passport]",
    ruleSet: "russia",
    detectionKind: "pattern-based",
    validate: isValidRussianPassportContext,
  },
  {
    key: "ru-document-context",
    label: "Russia document number",
    regex: new RegExp(`${russianDocumentContext}\\s*[:：№#-]?\\s*(?:[A-ZА-ЯЁ0-9\\u06F0-\\u06F9\\u0660-\\u0669]{2,6}${separatorClass}){2,5}`, "gi"),
    severity: "medium",
    mask: "[ru-document-number]",
    ruleSet: "russia",
    detectionKind: "heuristic",
    validate: isLikelyRussianDocumentContext,
  },
  {
    key: "ru-vehicle-context",
    label: "Russia vehicle plate",
    regex: new RegExp(`${russianPlateContext}\\s*[:：-]?\\s*[ABEKMHOPCTYXАВЕКМНОРСТУХ]${separatorClass}[${digitClass}]{3}${separatorClass}[ABEKMHOPCTYXАВЕКМНОРСТУХ]{2}${separatorClass}[${digitClass}]{2,3}`, "gi"),
    severity: "medium",
    mask: "[ru-vehicle-plate]",
    ruleSet: "russia",
    detectionKind: "pattern-based",
    validate: isValidRussianVehiclePlateContext,
  },
];

export function getRedactionDetectors(): RedactionDetector[] {
  return detectors.map((detector) => ({ ...detector }));
}

export function isOptionalRuleSet(ruleSet: RedactionRuleSet) {
  return ruleSet !== "general";
}

export function defaultRuleSetState(): Record<Exclude<RedactionRuleSet, "general">, boolean> {
  return {
    iran: false,
    russia: false,
  };
}

export function scanRedaction(
  text: string,
  rules: RedactionDetector[],
  custom: RedactionCustomRule[],
  options: ScanRedactionOptions,
): RedactionScanResult {
  const minimumRank = severityRank[options.minimumSeverity];
  const matches: RedactionMatch[] = [];

  const applyRule = (rule: RedactionDetector) => {
    if (severityRank[rule.severity] < minimumRank) return;
    const regex = new RegExp(rule.regex, rule.regex.flags);
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      if (rule.key === "token" && value.length < options.minTokenLength) {
        if (!regex.global) break;
        continue;
      }
      if (rule.validate && !rule.validate(value)) {
        if (!regex.global) break;
        continue;
      }
      matches.push({
        start: match.index,
        end: match.index + value.length,
        key: rule.key,
        label: rule.label,
        severity: rule.severity,
      mask: rule.mask,
      ruleSet: rule.ruleSet,
      detectionKind: rule.detectionKind,
    });
      if (!regex.global) break;
    }
  };

  rules.forEach((rule) => applyRule(rule));
  custom.forEach((rule) =>
    applyRule({
      key: rule.label,
      label: rule.label,
      regex: new RegExp(rule.regex, rule.regex.flags),
      severity: minimumRank > severityRank.medium ? "low" : "medium",
      mask: `[${rule.label}]`,
      ruleSet: "general",
      detectionKind: "heuristic",
    }),
  );

  const resolved = resolveOverlaps(matches);
  const counts = resolved.reduce<Record<string, number>>((acc, match) => {
    acc[match.label] = (acc[match.label] || 0) + 1;
    return acc;
  }, {});
  const severityMap = resolved.reduce<Record<string, RedactionSeverity>>((acc, match) => {
    acc[match.label] = acc[match.label] && severityRank[acc[match.label]] >= severityRank[match.severity]
      ? acc[match.label]
      : match.severity;
    return acc;
  }, {});
  const overall =
    (resolved
      .map((match) => match.severity)
      .sort((a, b) => severityRank[b] - severityRank[a])[0] as RedactionSeverity | undefined) || "low";

  return {
    counts,
    severityMap,
    total: resolved.length,
    overall,
    matches: resolved,
  };
}

export function resolveOverlaps<T extends Pick<RedactionMatch, "start" | "end" | "severity">>(matches: T[]) {
  if (matches.length === 0) return [];
  const byStart = [...matches].sort((a, b) => a.start - b.start);
  const resolved: T[] = [];
  let i = 0;
  while (i < byStart.length) {
    const group: T[] = [byStart[i]];
    let windowEnd = byStart[i].end;
    let j = i + 1;
    while (j < byStart.length && byStart[j].start < windowEnd) {
      group.push(byStart[j]);
      windowEnd = Math.max(windowEnd, byStart[j].end);
      j += 1;
    }
    const best = [...group].sort((a, b) => {
      const lenDiff = b.end - b.start - (a.end - a.start);
      if (lenDiff !== 0) return lenDiff;
      const sevDiff = severityRank[b.severity] - severityRank[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.start - b.start;
    })[0];
    resolved.push(best);
    i = j;
  }
  return resolved.sort((a, b) => a.start - b.start);
}

export function buildRedactionChanges(
  text: string,
  matches: RedactionMatch[],
  mode: RedactionMaskMode,
  preserveLength = false,
): RedactionChange[] {
  return matches.map((match) => {
    const original = text.slice(match.start, match.end);
    return {
      ...match,
      original,
      replacement: mode === "full"
        ? (preserveLength ? preserveMask(original, match.mask) : match.mask)
        : partialMask(original),
    };
  });
}

export function applyRedaction(
  text: string,
  matches: RedactionMatch[],
  mode: RedactionMaskMode,
  preserveLength = false,
) {
  if (!matches.length) return text;
  const changes = buildRedactionChanges(text, matches, mode, preserveLength);
  let cursor = 0;
  let output = "";
  changes.forEach((change) => {
    output += text.slice(cursor, change.start);
    output += change.replacement;
    cursor = change.end;
  });
  output += text.slice(cursor);
  return output;
}

export function partialMask(value: string) {
  if (value.length <= 4) return "*".repeat(value.length);
  return "*".repeat(Math.max(0, value.length - 4)) + value.slice(-4);
}

export function preserveMask(value: string, mask: string) {
  if (value.length <= mask.length) return "*".repeat(value.length);
  return `${mask}${"*".repeat(value.length - mask.length)}`;
}

export function toAsciiDigits(value: string) {
  return value
    .replace(/[۰-۹]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1728))
    .replace(/[٠-٩]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1584));
}

export function normalizeMixedIdentifier(value: string) {
  return toAsciiDigits(value)
    .replace(/[\u200c\u200f\u061c]/g, "")
    .replace(/[كﮎ]/g, "ک")
    .replace(/[يى]/g, "ی")
    .replace(/№/g, " ")
    .replace(/[‐‑–—﹣－]/g, "-")
    .replace(/[()]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function formatIranBankCard(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  if (digits.length !== 16) return digits || null;
  return `${digits.slice(0, 4)}-${digits.slice(4, 8)}-${digits.slice(8, 12)}-${digits.slice(12)}`;
}

export function normalizeIranPostalCode(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  return digits.length === 10 ? digits : null;
}

export function formatIranPostalCode(value: string) {
  const digits = normalizeIranPostalCode(value);
  if (!digits) return null;
  return `${digits.slice(0, 5)}-${digits.slice(5)}`;
}

export function normalizeIranSheba(value: string) {
  const normalized = normalizeMixedIdentifier(value).replace(/[-\s]/g, "").toUpperCase();
  const match = normalized.match(/IR\d{24}/);
  return match?.[0] ?? null;
}

export function formatIranSheba(value: string) {
  const normalized = normalizeIranSheba(value);
  if (!normalized) return null;
  return normalized.replace(/(.{4})(?=.)/g, "$1 ").trim();
}

export function normalizeIranPhone(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  if (/^09\d{9}$/.test(digits)) return digits;
  if (/^(?:98|0098)9\d{9}$/.test(digits)) return `0${digits.slice(-10)}`;
  return null;
}

export function formatIranPhone(value: string) {
  const normalized = normalizeIranPhone(value);
  if (!normalized) return null;
  return `${normalized.slice(0, 4)} ${normalized.slice(4, 7)} ${normalized.slice(7, 9)} ${normalized.slice(9, 11)}`;
}

export function passesLuhn(value: string) {
  const digits = toAsciiDigits(value).replace(/[^0-9]/g, "");
  if (digits.length < 12 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = Number(digits[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export function isLikelyPhone(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  return digits.length >= 10 && digits.length <= 15;
}

export function isValidIranNationalId(value: string) {
  const digits = toAsciiDigits(value).replace(/[^0-9]/g, "");
  if (!/^\d{10}$/.test(digits)) return false;
  if (/^(\d)\1{9}$/.test(digits)) return false;
  const check = Number(digits[9]);
  const sum = digits
    .slice(0, 9)
    .split("")
    .reduce((acc, ch, index) => acc + Number(ch) * (10 - index), 0);
  const remainder = sum % 11;
  return (remainder < 2 && check === remainder) || (remainder >= 2 && check === 11 - remainder);
}

export function isValidIranPhone(value: string) {
  return Boolean(normalizeIranPhone(value));
}

export function hasKnownIranBankCardPrefix(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  return digits.length >= 6 && iranBankCardPrefixes.has(digits.slice(0, 6));
}

export function isValidIranBankCard(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  return /^\d{16}$/.test(digits) && !/^(\d)\1{15}$/.test(digits) && passesLuhn(digits) && hasKnownIranBankCardPrefix(digits);
}

export function isValidIranBankCardContext(value: string) {
  const match = normalizeMixedIdentifier(value).match(/(\d(?:[0-9 -]{14,})\d)/);
  if (!match) return false;
  const digits = normalizeMixedIdentifier(match[1]).replace(/[^0-9]/g, "");
  return /^\d{16}$/.test(digits) && !/^(\d)\1{15}$/.test(digits) && passesLuhn(digits);
}

export function isValidIranPostalCode(value: string) {
  const digits = normalizeIranPostalCode(value) ?? "";
  if (!/^\d{10}$/.test(digits) || !/^\d/.test(digits) || /^(\d)\1{9}$/.test(digits)) return false;
  return !/(00000|11111|22222|33333|44444|55555|66666|77777|88888|99999)/.test(digits);
}

export function isValidIranPostalCodeContext(value: string) {
  const match = normalizeMixedIdentifier(value).match(/(\d(?:[\d -]{8,})\d)/);
  return match ? isValidIranPostalCode(match[1]) : false;
}

export function isValidIranSheba(value: string) {
  const normalized = normalizeIranSheba(value);
  if (!normalized) return false;
  return isValidIban(normalized);
}

export function isValidRussianPhone(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  return /^(?:7|8)\d{10}$/.test(digits);
}

export function normalizeRussianPhone(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  if (!/^(?:7|8)\d{10}$/.test(digits)) return null;
  const normalized = digits.startsWith("8") ? `7${digits.slice(1)}` : digits;
  return `+7 ${normalized.slice(1, 4)} ${normalized.slice(4, 7)}-${normalized.slice(7, 9)}-${normalized.slice(9, 11)}`;
}

export function isValidRussianInn(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  if (!/^\d{10}(\d{2})?$/.test(digits)) return false;
  if (digits.length === 10) {
    const checksum = innChecksum(digits.slice(0, 9), [2, 4, 10, 3, 5, 9, 4, 6, 8]);
    return checksum === Number(digits[9]);
  }
  const checksum11 = innChecksum(digits.slice(0, 10), [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]);
  const checksum12 = innChecksum(digits.slice(0, 11), [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]);
  return checksum11 === Number(digits[10]) && checksum12 === Number(digits[11]);
}

export function isValidRussianSnils(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  if (!/^\d{11}$/.test(digits)) return false;
  const serial = digits.slice(0, 9);
  const control = Number(digits.slice(9));
  const sum = serial.split("").reduce((acc, ch, index) => acc + Number(ch) * (9 - index), 0);
  let expected = 0;
  if (sum < 100) expected = sum;
  else if (sum === 100 || sum === 101) expected = 0;
  else expected = sum % 101 === 100 ? 0 : sum % 101;
  return expected === control;
}

export function isValidRussianPassport(value: string) {
  const digits = normalizeMixedIdentifier(value).replace(/[^0-9]/g, "");
  if (!/^\d{10}$/.test(digits) || /^(\d)\1{9}$/.test(digits)) return false;
  const series = Number(digits.slice(0, 2));
  return series >= 1 && series <= 99;
}

export function isValidRussianPassportContext(value: string) {
  const normalized = normalizeMixedIdentifier(value);
  const directMatch = normalized.match(/(\d{2}\s?\d{2}\s?\d{6}|\d{10})/);
  if (directMatch) return isValidRussianPassport(directMatch[1]);
  const digits = normalized.replace(/[^0-9]/g, "");
  return digits.length >= 10 ? isValidRussianPassport(digits.slice(-10)) : false;
}

export function isValidRussianVehiclePlate(value: string) {
  return /^[ABEKMHOPCTYXАВЕКМНОРСТУХ]\d{3}[ABEKMHOPCTYXАВЕКМНОРСТУХ]{2}\d{2,3}$/i.test(normalizeMixedIdentifier(value).replace(/[-\s]/g, ""));
}

export function isValidRussianVehiclePlateContext(value: string) {
  const match = normalizeMixedIdentifier(value).match(/[ABEKMHOPCTYXАВЕКМНОРСТУХ]\d{3}[ABEKMHOPCTYXАВЕКМНОРСТУХ]{2}\d{2,3}/i);
  return match ? isValidRussianVehiclePlate(match[0]) : false;
}

export function isLikelyRussianDocumentContext(value: string) {
  const normalized = normalizeMixedIdentifier(value).toUpperCase();
  if (!/(ДОКУМЕНТ|DOCUMENT)/.test(normalized)) return false;
  const body = normalized.replace(/.*?(?:ДОКУМЕНТ|DOCUMENT)[^A-ZА-ЯЁ0-9]*/u, "");
  const token = body.replace(/[^A-ZА-ЯЁ0-9]/gu, "");
  return token.length >= 6 && token.length <= 16 && /\d/.test(token);
}

export function isValidIban(value: string) {
  const trimmed = normalizeMixedIdentifier(value).replace(/[-\s]/g, "").toUpperCase();
  if (trimmed.length < 15 || trimmed.length > 34) return false;
  const rearranged = `${trimmed.slice(4)}${trimmed.slice(0, 4)}`;
  const converted = rearranged.replace(/[A-Z]/g, (ch) => `${ch.charCodeAt(0) - 55}`);
  let remainder = 0;
  for (let i = 0; i < converted.length; i += 1) {
    remainder = (remainder * 10 + Number(converted[i])) % 97;
  }
  return remainder === 1;
}

export function isValidIpv4(value: string) {
  const normalized = toAsciiDigits(value);
  const parts = normalized.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

function innChecksum(value: string, weights: number[]) {
  const sum = value.split("").reduce((acc, ch, index) => acc + Number(ch) * weights[index], 0);
  return (sum % 11) % 10;
}
