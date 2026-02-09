import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useMemo, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import { usePersistentState } from "../hooks/usePersistentState";
import { resolveOverlaps } from "../utils/redaction";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
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
        regex: /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g,
        severity: "low",
        mask: "[phone]",
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
    const [clipboardPrefs] = useClipboardPrefs();
    const [input, setInput] = useState("");
    const [maskMode, setMaskMode] = usePersistentState("nullid:redact:mask", "full");
    const [customPattern, setCustomPattern] = useState("");
    const [customLabel, setCustomLabel] = useState("custom");
    const [customRules, setCustomRules] = useState([]);
    const [output, setOutput] = useState("");
    const [detectorState, setDetectorState] = usePersistentState("nullid:redact:detectors", Object.fromEntries(detectors.map((detector) => [detector.key, true])));
    const activeDetectors = useMemo(() => detectors.filter((detector) => detectorState[detector.key] ?? true), [detectorState]);
    const findings = useMemo(() => scan(input, activeDetectors, customRules), [activeDetectors, customRules, input]);
    const redacted = useMemo(() => redact(input, findings.matches, maskMode), [findings.matches, input, maskMode]);
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
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("redact"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Redaction input", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Input" }), _jsx("span", { className: "panel-subtext", children: "paste text" })] }), _jsx("textarea", { className: "textarea", placeholder: "Drop text for redaction...", "aria-label": "Redaction input", value: input, onChange: (event) => setInput(event.target.value) }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "Mask mode" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Mask mode", children: ["full", "partial"].map((mode) => (_jsx("button", { type: "button", className: maskMode === mode ? "active" : "", onClick: () => setMaskMode(mode), children: mode }, mode))) })] })] }), _jsxs("div", { className: "panel", "aria-label": "Redaction output", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Output" }), _jsx("span", { className: "panel-subtext", children: "preview + apply" })] }), _jsx("div", { className: "redact-preview", "aria-label": "Highlight view", children: highlight(input, findings.matches) }), _jsx("textarea", { className: "textarea", readOnly: true, value: output || redacted, "aria-label": "Redacted output" }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: handleApply, children: "apply redaction" }), _jsx("button", { className: "button", type: "button", onClick: handleCopy, children: "copy" }), _jsx("button", { className: "button", type: "button", onClick: handleDownload, children: "download" })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "severity" }), _jsx(Chip, { label: findings.overall.toUpperCase(), tone: findings.overall === "high" ? "danger" : "accent" }), _jsxs("span", { className: "microcopy", children: [findings.total, " findings"] })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Findings table", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Findings" }), _jsx("span", { className: "panel-subtext", children: "type / count / severity" })] }), _jsx("div", { className: "controls-row", children: detectors.map((detector) => (_jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.35rem" }, children: [_jsx("input", { type: "checkbox", checked: detectorState[detector.key], onChange: (event) => setDetectorState((prev) => ({ ...prev, [detector.key]: event.target.checked })), "aria-label": `Toggle ${detector.label}` }), detector.label] }, detector.key))) }), _jsxs("table", { className: "table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "type" }), _jsx("th", { children: "count" }), _jsx("th", { children: "severity" })] }) }), _jsxs("tbody", { children: [Object.entries(findings.counts).map(([key, count]) => (_jsxs("tr", { children: [_jsx("td", { children: key }), _jsx("td", { children: count }), _jsx("td", { children: _jsx("span", { className: `tag ${findings.severityMap[key] === "high" ? "tag-danger" : "tag-accent"}`, children: findings.severityMap[key] }) })] }, key))), findings.total === 0 && (_jsx("tr", { children: _jsx("td", { colSpan: 3, className: "muted", children: "no findings detected" }) }))] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Custom rule", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Custom rule" }), _jsx("span", { className: "panel-subtext", children: "regex + label" })] }), _jsxs("div", { className: "controls-row", children: [_jsx("input", { className: "input", placeholder: "Regex pattern", value: customPattern, onChange: (event) => setCustomPattern(event.target.value), "aria-label": "Custom regex pattern" }), _jsx("input", { className: "input", placeholder: "Label", value: customLabel, onChange: (event) => setCustomLabel(event.target.value), "aria-label": "Custom regex label" }), _jsx("button", { className: "button", type: "button", onClick: applyCustomRule, children: "add" })] }), _jsx("div", { className: "microcopy", children: "Safe handling: regex runs locally; errors are reported without applying. Custom rules mask with their label." })] })] }));
}
function scan(text, rules, custom) {
    const counts = {};
    const severityMap = {};
    const matches = [];
    const applyRule = (rule) => {
        const regex = new RegExp(rule.regex, rule.regex.flags);
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(text)) !== null) {
            const value = match[0];
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
        severity: "medium",
        mask: `[${rule.label}]`,
    }));
    const resolved = resolveOverlaps(matches);
    const total = Object.values(counts).reduce((a, b) => a + (b || 0), 0);
    const worst = resolved
        .map((match) => match.severity)
        .sort((a, b) => rank(b) - rank(a))[0] || "low";
    return { counts, total, overall: worst, matches: resolved, severityMap };
}
function redact(text, matches, mode) {
    if (!matches.length)
        return text;
    const sorted = [...matches].sort((a, b) => a.start - b.start);
    let cursor = 0;
    let output = "";
    sorted.forEach((m) => {
        output += text.slice(cursor, m.start);
        output += mode === "full" ? `[${m.label}]` : partialMask(text.slice(m.start, m.end));
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
