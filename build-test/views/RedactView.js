import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useMemo, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { resolveOverlaps } from "../utils/redaction";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
import { useI18n } from "../i18n";
const detectors = [
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
        regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        severity: "medium",
        mask: "[ip]",
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
        regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi,
        severity: "high",
        mask: "[iban]",
        validate: isValidIban,
    },
    {
        key: "card",
        label: "Credit card",
        regex: /\b(?:\d[ -]?){12,19}\b/g,
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
];
export function RedactView({ onOpenGuide }) {
    const { push } = useToast();
    const { t } = useI18n();
    const [clipboardPrefs] = useClipboardPrefs();
    const [input, setInput] = useState("");
    const [maskMode, setMaskMode] = usePersistentState("nullid:redact:mask", "full");
    const [minimumSeverity, setMinimumSeverity] = usePersistentState("nullid:redact:min-severity", "low");
    const [minTokenLength, setMinTokenLength] = usePersistentState("nullid:redact:min-token-length", 20);
    const [preserveLength, setPreserveLength] = usePersistentState("nullid:redact:preserve-length", false);
    const [customPattern, setCustomPattern] = useState("");
    const [customLabel, setCustomLabel] = useState("custom");
    const [customRules, setCustomRules] = useState([]);
    const [output, setOutput] = useState("");
    const [detectorState, setDetectorState] = usePersistentState("nullid:redact:detectors", Object.fromEntries(detectors.map((detector) => [detector.key, true])));
    const activeDetectors = useMemo(() => detectors.filter((detector) => detectorState[detector.key] ?? true), [detectorState]);
    const findings = useMemo(() => scan(input, activeDetectors, customRules, { minimumSeverity, minTokenLength }), [activeDetectors, customRules, input, minTokenLength, minimumSeverity]);
    const redacted = useMemo(() => redact(input, findings.matches, maskMode, preserveLength), [findings.matches, input, maskMode, preserveLength]);
    const severityCounts = useMemo(() => {
        return findings.matches.reduce((acc, match) => {
            acc[match.severity] += 1;
            return acc;
        }, { high: 0, medium: 0, low: 0 });
    }, [findings.matches]);
    const coverage = useMemo(() => {
        if (!input.length || findings.matches.length === 0)
            return 0;
        const maskedChars = findings.matches.reduce((sum, match) => sum + (match.end - match.start), 0);
        return Math.min(100, Math.round((maskedChars / Math.max(1, input.length)) * 100));
    }, [findings.matches, input.length]);
    const applyCustomRule = () => {
        if (!customPattern.trim())
            return;
        try {
            const regex = new RegExp(customPattern, "gi");
            setCustomRules((prev) => [...prev, { label: customLabel || "custom", regex }]);
            setCustomPattern("");
            push("custom rule added", "accent");
        }
        catch (error) {
            console.error(error);
            push("invalid regex", "danger");
        }
    };
    const handleApply = () => {
        setOutput(redacted);
        push("text redacted", "accent");
    };
    const handleCopy = async () => {
        await writeClipboard(output || redacted, clipboardPrefs, (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"), "copied");
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
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("redact"), children: t("guide.link") }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Redaction input", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Input" }), _jsx("span", { className: "panel-subtext", children: "paste text" })] }), _jsx("textarea", { className: "textarea", placeholder: "Drop text for redaction...", "aria-label": "Redaction input", value: input, onChange: (event) => setInput(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "Mask mode" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Mask mode", children: ["full", "partial"].map((mode) => (_jsx("button", { type: "button", className: maskMode === mode ? "active" : "", onClick: () => setMaskMode(mode), children: mode }, mode))) })] }), _jsxs("div", { className: "controls-row", children: [_jsx("label", { className: "section-title", htmlFor: "min-severity", children: "Min severity" }), _jsxs("select", { id: "min-severity", className: "select", value: minimumSeverity, onChange: (event) => setMinimumSeverity(event.target.value), "aria-label": "Minimum severity filter", children: [_jsx("option", { value: "low", children: "low" }), _jsx("option", { value: "medium", children: "medium" }), _jsx("option", { value: "high", children: "high" })] }), _jsx("label", { className: "section-title", htmlFor: "token-length", children: "Token min len" }), _jsx("input", { id: "token-length", className: "input", type: "number", min: 12, max: 64, value: minTokenLength, onChange: (event) => setMinTokenLength(clamp(Number(event.target.value) || 0, 12, 64)), "aria-label": "Minimum token detector length" }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.35rem" }, children: [_jsx("input", { type: "checkbox", checked: preserveLength, onChange: (event) => setPreserveLength(event.target.checked), "aria-label": "Preserve replacement length" }), "preserve length in full mask"] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Redaction output", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Output" }), _jsx("span", { className: "panel-subtext", children: "preview + apply" })] }), _jsx("div", { className: "redact-preview", "aria-label": "Highlight view", children: highlight(input, findings.matches) }), _jsx("textarea", { className: "textarea", readOnly: true, value: output || redacted, "aria-label": "Redacted output" }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: handleApply, children: "apply redaction" }), _jsx("button", { className: "button", type: "button", onClick: handleCopy, children: "copy" }), _jsx("button", { className: "button", type: "button", onClick: handleDownload, children: "download" }), _jsx("button", { className: "button", type: "button", onClick: exportFindingsReport, children: "export report" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "severity" }), _jsx(Chip, { label: findings.overall.toUpperCase(), tone: findings.overall === "high" ? "danger" : "accent" }), _jsxs("span", { className: "microcopy", children: [findings.total, " findings"] })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "coverage" }), _jsxs("span", { className: "tag", children: [coverage, "% chars masked"] }), _jsxs("span", { className: "microcopy", children: ["high ", severityCounts.high, " \u00B7 medium ", severityCounts.medium, " \u00B7 low ", severityCounts.low] })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Findings table", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Findings" }), _jsx("span", { className: "panel-subtext", children: "type / count / severity" })] }), _jsx("div", { className: "controls-row", children: detectors.map((detector) => (_jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.35rem" }, children: [_jsx("input", { type: "checkbox", checked: detectorState[detector.key], onChange: (event) => setDetectorState((prev) => ({ ...prev, [detector.key]: event.target.checked })), "aria-label": `Toggle ${detector.label}` }), detector.label] }, detector.key))) }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "type" }), _jsx("th", { children: "count" }), _jsx("th", { children: "severity" })] }) }), _jsxs("tbody", { children: [Object.entries(findings.counts).map(([key, count]) => (_jsxs("tr", { children: [_jsx("td", { children: key }), _jsx("td", { children: count }), _jsx("td", { children: _jsx("span", { className: `tag ${findings.severityMap[key] === "high" ? "tag-danger" : "tag-accent"}`, children: findings.severityMap[key] }) })] }, key))), findings.total === 0 && (_jsx("tr", { children: _jsx("td", { colSpan: 3, className: "muted", children: "no findings detected" }) }))] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Custom rule", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Custom rule" }), _jsx("span", { className: "panel-subtext", children: "regex + label" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", placeholder: "Regex pattern", value: customPattern, onChange: (event) => setCustomPattern(event.target.value), "aria-label": "Custom regex pattern" }), _jsx("input", { className: "input", placeholder: "Label", value: customLabel, onChange: (event) => setCustomLabel(event.target.value), "aria-label": "Custom regex label" }), _jsx("button", { className: "button", type: "button", onClick: applyCustomRule, children: "add" })] }), _jsx("div", { className: "microcopy", children: "Safe handling: regex runs locally; errors are reported without applying. Custom rules mask with their label." })] })] }));
}
function scan(text, rules, custom, options) {
    const counts = {};
    const severityMap = {};
    const matches = [];
    const minimumRank = rank(options.minimumSeverity);
    const applyRule = (rule) => {
        if (rank(rule.severity) < minimumRank)
            return;
        const regex = new RegExp(rule.regex, rule.regex.flags);
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(text)) !== null) {
            const value = match[0];
            if (rule.key === "token" && value.length < options.minTokenLength) {
                if (!regex.global)
                    break;
                continue;
            }
            if (rule.validate && !rule.validate(value)) {
                if (!regex.global)
                    break;
                continue;
            }
            counts[rule.label] = (counts[rule.label] || 0) + 1;
            severityMap[rule.label] = rule.severity;
            matches.push({ start: match.index, end: match.index + value.length, label: rule.label, severity: rule.severity });
            if (!regex.global)
                break;
        }
    };
    rules.forEach((rule) => applyRule(rule));
    custom.forEach((rule) => applyRule({
        key: rule.label,
        label: rule.label,
        regex: new RegExp(rule.regex, rule.regex.flags),
        severity: minimumRank > rank("medium") ? "low" : "medium",
        mask: `[${rule.label}]`,
    }));
    const resolved = resolveOverlaps(matches);
    const total = Object.values(counts).reduce((a, b) => a + (b || 0), 0);
    const worst = resolved
        .map((match) => match.severity)
        .sort((a, b) => rank(b) - rank(a))[0] || "low";
    return { counts, total, overall: worst, matches: resolved, severityMap };
}
function redact(text, matches, mode, preserveLength = false) {
    if (!matches.length)
        return text;
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
function partialMask(value) {
    if (value.length <= 4)
        return "*".repeat(value.length);
    return "*".repeat(Math.max(0, value.length - 4)) + value.slice(-4);
}
function passesLuhn(value) {
    const digits = value.replace(/[^0-9]/g, "");
    if (digits.length < 12 || digits.length > 19)
        return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i -= 1) {
        let digit = Number(digits[i]);
        if (shouldDouble) {
            digit *= 2;
            if (digit > 9)
                digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
}
function isLikelyPhone(value) {
    const digits = toAsciiDigits(value).replace(/[^0-9]/g, "");
    return digits.length >= 10 && digits.length <= 15;
}
function isValidIranNationalId(value) {
    const digits = toAsciiDigits(value).replace(/[^0-9]/g, "");
    if (!/^\d{10}$/.test(digits))
        return false;
    if (/^(\d)\1{9}$/.test(digits))
        return false;
    const check = Number(digits[9]);
    const sum = digits
        .slice(0, 9)
        .split("")
        .reduce((acc, ch, index) => acc + Number(ch) * (10 - index), 0);
    const remainder = sum % 11;
    return (remainder < 2 && check === remainder) || (remainder >= 2 && check === 11 - remainder);
}
function toAsciiDigits(value) {
    return value
        .replace(/[۰-۹]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1728))
        .replace(/[٠-٩]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1584));
}
function isValidIban(value) {
    const trimmed = value.replace(/\s+/g, "").toUpperCase();
    if (trimmed.length < 15 || trimmed.length > 34)
        return false;
    const rearranged = `${trimmed.slice(4)}${trimmed.slice(0, 4)}`;
    const converted = rearranged.replace(/[A-Z]/g, (ch) => `${ch.charCodeAt(0) - 55}`);
    let remainder = 0;
    for (let i = 0; i < converted.length; i += 1) {
        const char = converted[i];
        remainder = (remainder * 10 + Number(char)) % 97;
    }
    return remainder === 1;
}
function highlight(text, matches) {
    if (!matches.length)
        return _jsx("span", { className: "muted", children: "No findings yet." });
    const sorted = [...matches].sort((a, b) => a.start - b.start);
    const parts = [];
    let cursor = 0;
    sorted.forEach((m, index) => {
        parts.push(_jsx("span", { children: text.slice(cursor, m.start) }, `p-${index}-pre`));
        parts.push(_jsx("mark", { className: `highlight ${m.severity}`, children: text.slice(m.start, m.end) }, `p-${index}-hit`));
        cursor = m.end;
    });
    parts.push(_jsx("span", { children: text.slice(cursor) }, "tail"));
    return _jsx("div", { className: "highlight-view", children: parts });
}
function rank(value) {
    return value === "high" ? 3 : value === "medium" ? 2 : 1;
}
function preserveMask(value, label) {
    const base = `[${label}]`;
    if (value.length <= base.length)
        return "*".repeat(value.length);
    return `${base}${"*".repeat(value.length - base.length)}`;
}
function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}
