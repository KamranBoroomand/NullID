export type PathPrivacyFindingCategory = "names" | "employee-ids" | "case-ids" | "project-names" | "usernames-hostnames";
export type PathPrivacyConfidence = "low" | "medium" | "high";

export interface PathSegmentFlag {
  segment: string;
  index: number;
  start: number;
  end: number;
}

export interface PathPrivacyFinding {
  key: string;
  label: string;
  category: PathPrivacyFindingCategory;
  confidence: PathPrivacyConfidence;
  reason: string;
  suggestedReplacement: string;
  flaggedSegments: PathSegmentFlag[];
}

export interface PathPrivacySuggestion {
  original: string;
  preview: string;
  replacements: Array<{
    segment: string;
    replacement: string;
  }>;
}

export interface PathPrivacyAnalysisResult {
  input: string;
  normalizedPath: string;
  total: number;
  findings: PathPrivacyFinding[];
  suggestions: PathPrivacySuggestion[];
  notes: string[];
}

interface PathSegment {
  value: string;
  start: number;
  end: number;
  index: number;
}

export function analyzePathPrivacy(input: string): PathPrivacyAnalysisResult {
  const normalizedPath = normalizePath(input);
  const segments = toSegments(normalizedPath);
  const findings: PathPrivacyFinding[] = [];

  findings.push(...scanUsernamesAndHostnames(normalizedPath, segments));
  findings.push(...scanLikelyNames(segments));
  findings.push(...scanEmployeeIds(segments));
  findings.push(...scanCaseIds(segments));
  findings.push(...scanProjectNames(segments));

  const suggestions = findings.map<PathPrivacySuggestion>((finding) => {
    const replacements = uniqueSegmentReplacements(finding);
    return {
      original: normalizedPath,
      preview: applySegmentReplacements(normalizedPath, finding.flaggedSegments, replacements),
      replacements,
    };
  });

  return {
    input,
    normalizedPath,
    total: findings.length,
    findings,
    suggestions,
    notes: [
      "Filename/path privacy review stays local and only suggests preview-safe renames. It never renames files automatically.",
      "Path findings are conservative hints about potentially sensitive labels, usernames, hostnames, or internal project references.",
    ],
  };
}

export function summarizePathPrivacy(result: PathPrivacyAnalysisResult, limit = 6): string[] {
  return result.findings
    .slice(0, limit)
    .map((finding) => `${finding.label}: ${finding.reason}`);
}

function scanUsernamesAndHostnames(normalizedPath: string, segments: PathSegment[]) {
  const findings: PathPrivacyFinding[] = [];
  segments.forEach((segment, index) => {
    const previous = segments[index - 1]?.value.toLowerCase() ?? "";
    if (["users", "user", "home", "profile", "profiles"].includes(previous) && /^[a-z0-9._-]{3,32}$/i.test(stripExtension(segment.value)) && !isGenericSegment(segment.value)) {
      findings.push({
        key: "path-user-segment",
        label: "Username in path",
        category: "usernames-hostnames",
        confidence: "high",
        reason: "A user/home-directory path segment looks like a specific username.",
        suggestedReplacement: "user",
        flaggedSegments: [toFlag(segment)],
      });
      return;
    }
    if (/^(?:[a-z0-9-]+\.)+(?:local|lan|corp|internal|example|com|net|ru|ir)$/i.test(segment.value) || /^[a-z0-9-]{3,}\d{0,3}$/i.test(segment.value) && /server|host|node|prod|stage|dev/i.test(segment.value)) {
      findings.push({
        key: "path-host-segment",
        label: "Hostname in path",
        category: "usernames-hostnames",
        confidence: "medium",
        reason: "A path segment looks like a host or internal domain label.",
        suggestedReplacement: "host",
        flaggedSegments: [toFlag(segment)],
      });
    }
  });

  const networkMatch = normalizedPath.match(/(^|\/|\\\\)([A-Za-z0-9._-]+)@([A-Za-z0-9._-]+)/);
  if (networkMatch?.index != null) {
    const raw = networkMatch[0].replace(/^\/+/, "");
    const start = normalizedPath.indexOf(raw);
    const user = networkMatch[2];
    const host = networkMatch[3];
    findings.push({
      key: "path-user-host",
      label: "User and host reference",
      category: "usernames-hostnames",
      confidence: "high",
      reason: "The path contains a user@host-style reference.",
      suggestedReplacement: "user@host",
      flaggedSegments: [
        { segment: user, index: -1, start, end: start + user.length },
        { segment: host, index: -1, start: start + user.length + 1, end: start + raw.length },
      ],
    });
  }

  return dedupeFindings(findings);
}

function scanLikelyNames(segments: PathSegment[]) {
  return segments
    .filter((segment) => isNameLikeSegment(segment.value) && !isGenericSegment(segment.value))
    .map<PathPrivacyFinding>((segment) => ({
      key: "path-personal-name",
      label: "Personal name in filename/path",
      category: "names",
      confidence: "medium",
      reason: "A segment looks like a person name rather than a generic file label.",
      suggestedReplacement: "person-name",
      flaggedSegments: [toFlag(segment)],
    }));
}

function scanEmployeeIds(segments: PathSegment[]) {
  return segments
    .filter((segment) => /\b(?:emp|employee|staff|personnel|hr)[-_]?\d{3,10}\b/i.test(segment.value) || /(?:کارمند|پرسنلی|сотрудник)[-_]?\d{3,10}/iu.test(segment.value))
    .map<PathPrivacyFinding>((segment) => ({
      key: "path-employee-id",
      label: "Employee ID in filename/path",
      category: "employee-ids",
      confidence: "high",
      reason: "A segment includes a clear employee or personnel identifier pattern.",
      suggestedReplacement: "employee-id",
      flaggedSegments: [toFlag(segment)],
    }));
}

function scanCaseIds(segments: PathSegment[]) {
  return segments
    .filter((segment) => /\b(?:case|ticket|incident|issue|bug|casefile)[-_#]?[A-Z0-9]{3,16}\b/i.test(segment.value) || /(?:پرونده|تیکت|رخداد|обращение|инцидент)[-_#]?[A-Z0-9]{3,16}/iu.test(segment.value))
    .map<PathPrivacyFinding>((segment) => ({
      key: "path-case-id",
      label: "Case / ticket ID in filename/path",
      category: "case-ids",
      confidence: "high",
      reason: "A segment includes a ticket, case, or incident-style identifier.",
      suggestedReplacement: "case-id",
      flaggedSegments: [toFlag(segment)],
    }));
}

function scanProjectNames(segments: PathSegment[]) {
  const contextKeys = new Set(["projects", "project", "repos", "repo", "clients", "client", "campaigns", "teams", "internal", "programs"]);
  return segments.flatMap<PathPrivacyFinding>((segment, index) => {
    const previous = segments[index - 1]?.value.toLowerCase() ?? "";
    if (!contextKeys.has(previous) || isGenericSegment(segment.value)) return [];
    return [{
      key: "path-project-name",
      label: "Internal project name",
      category: "project-names",
      confidence: "low",
      reason: "A project-like directory segment may expose an internal codename or customer/project label.",
      suggestedReplacement: "project-name",
      flaggedSegments: [toFlag(segment)],
    }];
  });
}

function normalizePath(value: string) {
  return value.trim().replace(/\\/g, "/").replace(/\/+/g, "/");
}

function toSegments(path: string): PathSegment[] {
  const segments: PathSegment[] = [];
  const regex = /[^/]+/g;
  let match: RegExpExecArray | null;
  let index = 0;
  while ((match = regex.exec(path)) !== null) {
    segments.push({
      value: match[0],
      start: match.index,
      end: match.index + match[0].length,
      index,
    });
    index += 1;
  }
  return segments;
}

function isNameLikeSegment(value: string) {
  const base = stripExtension(value);
  if (base.length < 4 || base.length > 40) return false;
  if (/^\d+$/.test(base)) return false;
  if (/[A-Za-z]+[._][A-Za-z]+/.test(base) && !/[0-9]/.test(base)) return true;
  if (/^[A-Z][a-z]+(?:[._-][A-Z]?[a-z]+){1,2}$/.test(base)) return true;
  if (/^[\u0600-\u06FF]{2,}(?:[ _.-][\u0600-\u06FF]{2,}){1,2}$/u.test(base)) return true;
  if (/^[\u0400-\u04FF]{2,}(?:[ _.-][\u0400-\u04FF]{2,}){1,2}$/u.test(base)) return true;
  return false;
}

function isGenericSegment(value: string) {
  return /^(?:docs?|files?|images?|downloads?|exports?|reports?|screenshots?|attachments?|archive|archives|tmp|temp|desktop|documents|shared?)$/i.test(stripExtension(value));
}

function stripExtension(value: string) {
  return value.replace(/\.[A-Za-z0-9]{1,6}$/u, "");
}

function uniqueSegmentReplacements(finding: PathPrivacyFinding) {
  return Array.from(new Map(
    finding.flaggedSegments.map((segment) => [segment.segment, { segment: segment.segment, replacement: finding.suggestedReplacement }]),
  ).values());
}

function toFlag(segment: PathSegment): PathSegmentFlag {
  return {
    segment: segment.value,
    index: segment.index,
    start: segment.start,
    end: segment.end,
  };
}

function applySegmentReplacements(path: string, flaggedSegments: PathSegmentFlag[], replacements: Array<{ segment: string; replacement: string }>) {
  let next = path;
  replacements.forEach(({ segment, replacement }) => {
    next = next.replaceAll(segment, replacement);
  });
  if (flaggedSegments.length === 0) return path;
  return next;
}

function dedupeFindings(findings: PathPrivacyFinding[]) {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.key}:${finding.flaggedSegments.map((segment) => `${segment.start}:${segment.end}`).join(",")}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
