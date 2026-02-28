import { useMemo, useState, type ReactNode } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { resolveOverlaps, type RedactionMatch } from "../utils/redaction";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import type { ModuleKey } from "../components/ModuleList";
import { useI18n } from "../i18n";

type MaskMode = "full" | "partial";
type SeverityThreshold = "low" | "medium" | "high";

type Detector = {
  key: string;
  label: string;
  regex: RegExp;
  severity: "low" | "medium" | "high";
  mask: string;
  validate?: (value: string) => boolean;
};

type CustomRule = { label: string; regex: RegExp };

const detectors: Detector[] = [
  {
    key: "email",
    label: "Email",
    regex: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
    severity: "medium",
    mask: "[email]",
  },
  {
    key: "phone",
    label: "Phone",
    regex: /(?:\+|00)?[0-9\u06F0-\u06F9\u0660-\u0669][0-9\u06F0-\u06F9\u0660-\u0669().\-\s]{7,18}[0-9\u06F0-\u06F9\u0660-\u0669]/g,
    severity: "low",
    mask: "[phone]",
    validate: isLikelyPhone,
  },
  {
    key: "iran-id",
    label: "Iran national ID",
    regex: /(?<![0-9\u06F0-\u06F9\u0660-\u0669])[0-9\u06F0-\u06F9\u0660-\u0669]{10}(?![0-9\u06F0-\u06F9\u0660-\u0669])/g,
    severity: "high",
    mask: "[iran-id]",
    validate: isValidIranNationalId,
  },
  {
    key: "ru-phone",
    label: "Russia phone",
    regex: /(?:\+7|8)[\s(-]*[0-9\u06F0-\u06F9\u0660-\u0669]{3}[\s)-]*[0-9\u06F0-\u06F9\u0660-\u0669]{3}[\s-]*[0-9\u06F0-\u06F9\u0660-\u0669]{2}[\s-]*[0-9\u06F0-\u06F9\u0660-\u0669]{2}/g,
    severity: "medium",
    mask: "[ru-phone]",
    validate: isLikelyPhone,
  },
  {
    key: "token",
    label: "Bearer / token",
    regex: /\b(?:authorization[:=]\s*)?(?:bearer\s+)?[A-Za-z0-9._-]{20,}\b/gi,
    severity: "high",
    mask: "[token]",
  },
  {
    key: "ip",
    label: "IP",
    regex: /(?<![0-9\u06F0-\u06F9\u0660-\u0669])(?:[0-9\u06F0-\u06F9\u0660-\u0669]{1,3}\.){3}[0-9\u06F0-\u06F9\u0660-\u0669]{1,3}(?![0-9\u06F0-\u06F9\u0660-\u0669])/g,
    severity: "medium",
    mask: "[ip]",
    validate: isValidIpv4,
  },
  {
    key: "id",
    label: "ID",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: "high",
    mask: "[id]",
  },
  {
    key: "iban",
    label: "IBAN",
    regex: /(?<![A-Z0-9\u06F0-\u06F9\u0660-\u0669])[A-Z]{2}[0-9\u06F0-\u06F9\u0660-\u0669]{2}[A-Z0-9\u06F0-\u06F9\u0660-\u0669]{11,30}(?![A-Z0-9\u06F0-\u06F9\u0660-\u0669])/gi,
    severity: "high",
    mask: "[iban]",
    validate: isValidIban,
  },
  {
    key: "card",
    label: "Credit card",
    regex: /(?:[0-9\u06F0-\u06F9\u0660-\u0669][ -]?){12,19}/g,
    severity: "high",
    mask: "[card]",
    validate: passesLuhn,
  },
  {
    key: "ipv6",
    label: "IPv6",
    regex: /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi,
    severity: "medium",
    mask: "[ipv6]",
  },
  {
    key: "awskey",
    label: "AWS key",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "high",
    mask: "[aws-key]",
  },
  {
    key: "awssecret",
    label: "AWS secret",
    regex: /\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b/gi,
    severity: "high",
    mask: "[aws-secret]",
  },
  {
    key: "github",
    label: "GitHub token",
    regex: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    severity: "high",
    mask: "[github-token]",
  },
  {
    key: "slack",
    label: "Slack token",
    regex: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g,
    severity: "high",
    mask: "[slack-token]",
  },
  {
    key: "privatekey",
    label: "Private key block",
    regex: /-----BEGIN (?:[A-Z0-9 ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]*?)PRIVATE KEY-----/g,
    severity: "high",
    mask: "[private-key]",
  },
];

interface RedactViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function RedactView({ onOpenGuide }: RedactViewProps) {
  const { push } = useToast();
  const { t, tr, formatNumber } = useI18n();
  const [clipboardPrefs] = useClipboardPrefs();
  const [input, setInput] = useState("");
  const [maskMode, setMaskMode] = usePersistentState<MaskMode>("nullid:redact:mask", "full");
  const [minimumSeverity, setMinimumSeverity] = usePersistentState<SeverityThreshold>("nullid:redact:min-severity", "low");
  const [minTokenLength, setMinTokenLength] = usePersistentState<number>("nullid:redact:min-token-length", 20);
  const [preserveLength, setPreserveLength] = usePersistentState<boolean>("nullid:redact:preserve-length", false);
  const [customPattern, setCustomPattern] = useState("");
  const [customLabel, setCustomLabel] = useState("custom");
  const [customRules, setCustomRules] = useState<CustomRule[]>([]);
  const [output, setOutput] = useState("");
  const [detectorState, setDetectorState] = usePersistentState<Record<string, boolean>>(
    "nullid:redact:detectors",
    Object.fromEntries(detectors.map((detector) => [detector.key, true])) as Record<string, boolean>,
  );

  const activeDetectors = useMemo(
    () => detectors.filter((detector) => detectorState[detector.key] ?? true),
    [detectorState],
  );

  const findings = useMemo(
    () => scan(input, activeDetectors, customRules, { minimumSeverity, minTokenLength }),
    [activeDetectors, customRules, input, minTokenLength, minimumSeverity],
  );

  const redacted = useMemo(() => redact(input, findings.matches, maskMode, preserveLength), [findings.matches, input, maskMode, preserveLength]);
  const severityCounts = useMemo(() => {
    return findings.matches.reduce(
      (acc, match) => {
        acc[match.severity] += 1;
        return acc;
      },
      { high: 0, medium: 0, low: 0 },
    );
  }, [findings.matches]);
  const coverage = useMemo(() => {
    if (!input.length || findings.matches.length === 0) return 0;
    const maskedChars = findings.matches.reduce((sum, match) => sum + (match.end - match.start), 0);
    return Math.min(100, Math.round((maskedChars / Math.max(1, input.length)) * 100));
  }, [findings.matches, input.length]);

  const applyCustomRule = () => {
    if (!customPattern.trim()) return;
    try {
      const regex = new RegExp(customPattern, "gi");
      setCustomRules((prev) => [...prev, { label: customLabel || "custom", regex }]);
      setCustomPattern("");
      push("custom rule added", "accent");
    } catch (error) {
      console.error(error);
      push("invalid regex", "danger");
    }
  };

  const handleApply = () => {
    setOutput(redacted);
    push("text redacted", "accent");
  };

  const handleCopy = async () => {
    await writeClipboard(
      output || redacted,
      clipboardPrefs,
      (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"),
      "copied",
    );
  };

  const handleDownload = () => {
    const blob = new Blob([output || redacted], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "redacted.txt";
    link.click();
    URL.revokeObjectURL(url);
  };

  const exportFindingsReport = () => {
    const payload = {
      schemaVersion: 1,
      kind: "nullid-redaction-report",
      createdAt: new Date().toISOString(),
      config: {
        maskMode,
        minimumSeverity,
        minTokenLength,
        preserveLength,
        enabledDetectors: activeDetectors.map((detector) => detector.key),
      },
      summary: {
        totalFindings: findings.total,
        overallSeverity: findings.overall,
        coveragePercent: coverage,
        severityCounts,
      },
      byType: findings.counts,
      matches: findings.matches.slice(0, 400).map((match) => ({
        label: match.label,
        severity: match.severity,
        start: match.start,
        end: match.end,
        preview: input.slice(Math.max(0, match.start - 8), Math.min(input.length, match.end + 8)),
      })),
    };
    const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `nullid-redaction-report-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    push("redaction report exported", "accent");
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("redact")}>
          {t("guide.link")}
        </button>
      </div>
      <div className="grid-two">
        <div className="panel" aria-label={tr("Redaction input")}>
          <div className="panel-heading">
            <span>{tr("Input")}</span>
            <span className="panel-subtext">{tr("paste text")}</span>
          </div>
          <textarea
            className="textarea"
            placeholder={tr("Drop text for redaction...")}
            aria-label={tr("Redaction input")}
            value={input}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="controls-row">
            <span className="section-title">{tr("Mask mode")}</span>
            <div className="pill-buttons" role="group" aria-label={tr("Mask mode")}>
              {(["full", "partial"] as MaskMode[]).map((mode) => (
                <button key={mode} type="button" className={maskMode === mode ? "active" : ""} onClick={() => setMaskMode(mode)}>
                  {tr(mode)}
                </button>
              ))}
            </div>
          </div>
          <div className="controls-row">
            <label className="section-title" htmlFor="min-severity">
              {tr("Min severity")}
            </label>
            <select
              id="min-severity"
              className="select"
              value={minimumSeverity}
              onChange={(event) => setMinimumSeverity(event.target.value as SeverityThreshold)}
              aria-label={tr("Minimum severity filter")}
            >
              <option value="low">{tr("low")}</option>
              <option value="medium">{tr("medium")}</option>
              <option value="high">{tr("high")}</option>
            </select>
            <label className="section-title" htmlFor="token-length">
              {tr("Token min len")}
            </label>
            <input
              id="token-length"
              className="input"
              type="number"
              min={12}
              max={64}
              value={minTokenLength}
              onChange={(event) => setMinTokenLength(clamp(Number(event.target.value) || 0, 12, 64))}
              aria-label={tr("Minimum token detector length")}
            />
            <label className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
              <input
                type="checkbox"
                checked={preserveLength}
                onChange={(event) => setPreserveLength(event.target.checked)}
                aria-label={tr("Preserve replacement length")}
              />
              {tr("preserve length in full mask")}
            </label>
          </div>
        </div>
        <div className="panel" aria-label={tr("Redaction output")}>
          <div className="panel-heading">
            <span>{tr("Output")}</span>
            <span className="panel-subtext">{tr("preview + apply")}</span>
          </div>
          <div className="redact-preview" aria-label={tr("Highlight view")}>
            {highlight(input, findings.matches)}
          </div>
          <textarea className="textarea" readOnly value={output || redacted} aria-label={tr("Redacted output")} />
          <div className="controls-row">
            <button className="button" type="button" onClick={handleApply}>
              {tr("apply redaction")}
            </button>
            <button className="button" type="button" onClick={handleCopy}>
              {tr("copy")}
            </button>
            <button className="button" type="button" onClick={handleDownload}>
              {tr("download")}
            </button>
            <button className="button" type="button" onClick={exportFindingsReport}>
              {tr("export report")}
            </button>
          </div>
          <div className="status-line">
            <span>{tr("severity")}</span>
            <Chip label={tr(findings.overall)} tone={findings.overall === "high" ? "danger" : "accent"} />
            <span className="microcopy">{formatNumber(findings.total)} {tr("findings")}</span>
          </div>
          <div className="status-line">
            <span>{tr("coverage")}</span>
            <span className="tag">{formatNumber(coverage)}% {tr("chars masked")}</span>
            <span className="microcopy">
              {tr("high")} {formatNumber(severityCounts.high)} · {tr("medium")} {formatNumber(severityCounts.medium)} · {tr("low")} {formatNumber(severityCounts.low)}
            </span>
          </div>
        </div>
      </div>
      <div className="panel" aria-label={tr("Findings table")}>
        <div className="panel-heading">
          <span>{tr("Findings")}</span>
          <span className="panel-subtext">{tr("type / count / severity")}</span>
        </div>
        <div className="controls-row">
          {detectors.map((detector) => (
            <label key={detector.key} className="microcopy" style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
              <input
                type="checkbox"
                checked={detectorState[detector.key]}
                onChange={(event) => setDetectorState((prev) => ({ ...prev, [detector.key]: event.target.checked }))}
                aria-label={`${tr("Toggle")} ${tr(detector.label)}`}
              />
              {tr(detector.label)}
            </label>
          ))}
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{tr("type")}</th>
              <th>{tr("count")}</th>
              <th>{tr("severity")}</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(findings.counts).map(([key, count]) => (
              <tr key={key}>
                <td>{tr(key)}</td>
                <td>{formatNumber(count)}</td>
                <td>
                  <span className={`tag ${findings.severityMap[key] === "high" ? "tag-danger" : "tag-accent"}`}>
                    {tr(findings.severityMap[key])}
                  </span>
                </td>
              </tr>
            ))}
            {findings.total === 0 && (
              <tr>
                <td colSpan={3} className="muted">
                  {tr("no findings detected")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="panel" aria-label={tr("Custom rule")}>
        <div className="panel-heading">
          <span>{tr("Custom rule")}</span>
          <span className="panel-subtext">{tr("regex + label")}</span>
        </div>
        <div className="controls-row">
          <input
            className="input"
            placeholder={tr("Regex pattern")}
            value={customPattern}
            onChange={(event) => setCustomPattern(event.target.value)}
            aria-label={tr("Custom regex pattern")}
          />
          <input
            className="input"
            placeholder={tr("Label")}
            value={customLabel}
            onChange={(event) => setCustomLabel(event.target.value)}
            aria-label={tr("Custom regex label")}
          />
          <button className="button" type="button" onClick={applyCustomRule}>
            {tr("add")}
          </button>
        </div>
        <div className="microcopy">
          {tr("Safe handling: regex runs locally; errors are reported without applying. Custom rules mask with their label.")}
        </div>
      </div>
    </div>
  );
}

type Match = RedactionMatch;

function scan(
  text: string,
  rules: Detector[],
  custom: CustomRule[],
  options: { minimumSeverity: SeverityThreshold; minTokenLength: number },
) {
  const counts: Record<string, number> = {};
  const severityMap: Record<string, Detector["severity"]> = {};
  const matches: Match[] = [];
  const minimumRank = rank(options.minimumSeverity);

  const applyRule = (rule: Detector) => {
    if (rank(rule.severity) < minimumRank) return;
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
      counts[rule.label] = (counts[rule.label] || 0) + 1;
      severityMap[rule.label] = rule.severity;
      matches.push({ start: match.index, end: match.index + value.length, label: rule.label, severity: rule.severity });
      if (!regex.global) break;
    }
  };

  rules.forEach((rule) => applyRule(rule));
  custom.forEach((rule) =>
    applyRule({
      key: rule.label,
      label: rule.label,
      regex: new RegExp(rule.regex, rule.regex.flags),
      severity: minimumRank > rank("medium") ? "low" : "medium",
      mask: `[${rule.label}]`,
    }),
  );

  const resolved = resolveOverlaps(matches);
  const total = Object.values(counts).reduce((a, b) => a + (b || 0), 0);
  const worst =
    (resolved
      .map((match) => match.severity)
      .sort((a, b) => rank(b) - rank(a))[0] as "high" | "medium" | "low" | undefined) || "low";

  return { counts, total, overall: worst, matches: resolved, severityMap };
}

function redact(text: string, matches: Match[], mode: MaskMode, preserveLength = false) {
  if (!matches.length) return text;
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  let cursor = 0;
  let output = "";
  sorted.forEach((m) => {
    output += text.slice(cursor, m.start);
    const source = text.slice(m.start, m.end);
    output += mode === "full" ? (preserveLength ? preserveMask(source, m.label) : `[${m.label}]`) : partialMask(source);
    cursor = m.end;
  });
  output += text.slice(cursor);
  return output;
}

function partialMask(value: string) {
  if (value.length <= 4) return "*".repeat(value.length);
  return "*".repeat(Math.max(0, value.length - 4)) + value.slice(-4);
}

function passesLuhn(value: string) {
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

function isLikelyPhone(value: string) {
  const digits = toAsciiDigits(value).replace(/[^0-9]/g, "");
  return digits.length >= 10 && digits.length <= 15;
}

function isValidIranNationalId(value: string) {
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

function toAsciiDigits(value: string) {
  return value
    .replace(/[۰-۹]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1728))
    .replace(/[٠-٩]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1584));
}

function isValidIban(value: string) {
  const trimmed = toAsciiDigits(value).replace(/\s+/g, "").toUpperCase();
  if (trimmed.length < 15 || trimmed.length > 34) return false;
  const rearranged = `${trimmed.slice(4)}${trimmed.slice(0, 4)}`;
  const converted = rearranged.replace(/[A-Z]/g, (ch) => `${ch.charCodeAt(0) - 55}`);
  let remainder = 0;
  for (let i = 0; i < converted.length; i += 1) {
    const char = converted[i];
    remainder = (remainder * 10 + Number(char)) % 97;
  }
  return remainder === 1;
}

function isValidIpv4(value: string) {
  const normalized = toAsciiDigits(value);
  const parts = normalized.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

function highlight(text: string, matches: Match[]) {
  if (!matches.length) return <span className="muted">No findings yet.</span>;
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  const parts: ReactNode[] = [];
  let cursor = 0;
  sorted.forEach((m, index) => {
    parts.push(<span key={`p-${index}-pre`}>{text.slice(cursor, m.start)}</span>);
    parts.push(
      <mark key={`p-${index}-hit`} className={`highlight ${m.severity}`}>
        {text.slice(m.start, m.end)}
      </mark>,
    );
    cursor = m.end;
  });
  parts.push(<span key="tail">{text.slice(cursor)}</span>);
  return <div className="highlight-view">{parts}</div>;
}

function rank(value: "high" | "medium" | "low") {
  return value === "high" ? 3 : value === "medium" ? 2 : 1;
}

function preserveMask(value: string, label: string) {
  const base = `[${label}]`;
  if (value.length <= base.length) return "*".repeat(value.length);
  return `${base}${"*".repeat(value.length - base.length)}`;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
