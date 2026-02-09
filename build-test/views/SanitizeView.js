import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useMemo, useState } from "react";
import "./styles.css";
import { usePersistentState } from "../hooks/usePersistentState";
import { useToast } from "../components/ToastHost";
import { useClipboardPrefs, writeClipboard } from "../utils/clipboard";
const rules = [
    {
        key: "maskIp",
        label: "Mask IP addresses",
        apply: (input) => replaceWithCount(input, /\b(\d{1,3}\.){3}\d{1,3}\b/g, "[ip]"),
    },
    {
        key: "maskIpv6",
        label: "Mask IPv6",
        apply: (input) => replaceWithCount(input, /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi, "[ipv6]"),
    },
    {
        key: "maskEmail",
        label: "Mask emails",
        apply: (input) => replaceWithCount(input, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[email]"),
    },
    {
        key: "scrubJwt",
        label: "Scrub JWT",
        apply: (input) => replaceWithCount(input, /(?:bearer\s+)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi, "[jwt]"),
    },
    {
        key: "maskBearer",
        label: "Mask bearer tokens",
        apply: (input) => replaceWithCount(input, /\b(?:authorization[:=]\s*)?(?:bearer\s+)[A-Za-z0-9._-]{20,}\b/gi, "[token]"),
    },
    {
        key: "maskCard",
        label: "Mask credit cards",
        apply: replaceCardNumbers,
    },
    {
        key: "maskIban",
        label: "Mask IBAN",
        apply: replaceIban,
    },
    {
        key: "maskAwsKey",
        label: "Mask AWS key",
        apply: (input) => replaceWithCount(input, /\bAKIA[0-9A-Z]{16}\b/g, "[aws-key]"),
    },
    {
        key: "maskAwsSecret",
        label: "Mask AWS secret",
        apply: (input) => replaceWithCount(input, /\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b/gi, "aws_secret_access_key=[redacted]"),
    },
    {
        key: "stripCookies",
        label: "Strip cookies",
        apply: (input) => replaceWithCount(input, /cookie=[^ ;\n]+/gi, "cookie=[stripped]"),
    },
    {
        key: "dropUA",
        label: "Drop user agents",
        apply: (input) => replaceWithCount(input, /ua=[^\s]+|user-agent:[^\n]+/gi, "ua=[dropped]"),
    },
    {
        key: "normalizeTs",
        label: "Normalize timestamps",
        apply: (input) => replaceWithCount(input, /\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\]/g, "[timestamp]"),
    },
    {
        key: "maskUser",
        label: "Mask usernames",
        apply: (input) => replaceWithCount(input, /\buser=([A-Za-z0-9._-]+)\b/gi, "user=[user]"),
    },
    {
        key: "stripJsonSecrets",
        label: "Strip JSON secrets",
        apply: (input) => replaceWithCount(input, /\"(token|secret|password)\"\s*:\s*\"[^\"]+\"/gi, '"$1":"[redacted]"'),
    },
];
const presets = {
    nginx: {
        label: "nginx access",
        description: "IPs, cookies, UA, JWT",
        sample: `127.0.0.1 - - [14/Mar/2025:10:12:33 +0000] "POST /auth" 200 user=alice token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 cookie=sessionid=abc123 ua=Mozilla/5.0`,
        rules: ["maskIp", "maskIpv6", "stripCookies", "dropUA", "scrubJwt", "maskBearer", "maskUser", "normalizeTs", "maskAwsKey", "maskAwsSecret", "maskCard", "maskIban"],
    },
    apache: {
        label: "apache access",
        description: "IPs, emails, JWT",
        sample: `10.0.0.2 - bob@example.com [14/Mar/2025:11:12:33 +0000] "GET /admin" 403 512 "-" "Mozilla/5.0" token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`,
        rules: ["maskIp", "maskIpv6", "maskEmail", "scrubJwt", "maskBearer", "normalizeTs", "maskCard", "maskIban"],
    },
    auth: {
        label: "auth log",
        description: "usernames + IPs",
        sample: `Mar 14 08:15:22 host sshd[1201]: Failed password for root from 203.0.113.10 port 22 ssh2`,
        rules: ["maskIp", "maskIpv6", "maskUser"],
    },
    json: {
        label: "JSON log",
        description: "drop secrets",
        sample: `{"ts":"2025-03-14T10:15:00Z","user":"alice","token":"abc.def.ghi","password":"hunter2","ip":"192.168.0.8"}`,
        rules: ["maskIp", "maskIpv6", "stripJsonSecrets", "maskUser", "maskAwsKey", "maskAwsSecret", "maskCard", "maskIban"],
    },
};
export function SanitizeView({ onOpenGuide }) {
    const { push } = useToast();
    const [clipboardPrefs] = useClipboardPrefs();
    const [log, setLog] = useState(presets.nginx.sample);
    const [rulesState, setRulesState] = usePersistentState("nullid:sanitize:rules", Object.fromEntries(rules.map((rule) => [rule.key, true])));
    const [preset, setPreset] = usePersistentState("nullid:sanitize:preset", "nginx");
    const [wrapLines, setWrapLines] = usePersistentState("nullid:sanitize:wrap", false);
    const [jsonAware, setJsonAware] = usePersistentState("nullid:sanitize:json", true);
    const [customRules, setCustomRules] = usePersistentState("nullid:sanitize:custom", []);
    const [customRuleDraft, setCustomRuleDraft] = useState({
        id: "",
        pattern: "",
        replacement: "",
        flags: "gi",
        scope: "both",
    });
    const [customRuleError, setCustomRuleError] = useState(null);
    const result = useMemo(() => applyRules(log, rulesState, customRules, jsonAware), [customRules, jsonAware, log, rulesState]);
    const applyPreset = (key) => {
        setPreset(key);
        setLog(presets[key].sample);
        const nextState = Object.fromEntries(rules.map((rule) => [rule.key, presets[key].rules.includes(rule.key)]));
        setRulesState(nextState);
    };
    const addCustomRule = () => {
        if (!customRuleDraft.pattern.trim()) {
            setCustomRuleError("Pattern is required");
            return;
        }
        try {
            // Validate regex
            // eslint-disable-next-line no-new
            new RegExp(customRuleDraft.pattern, customRuleDraft.flags);
            const next = { ...customRuleDraft, id: crypto.randomUUID() };
            setCustomRules((prev) => [...prev, next]);
            setCustomRuleDraft({ id: "", pattern: "", replacement: "", flags: "gi", scope: "both" });
            setCustomRuleError(null);
        }
        catch (error) {
            setCustomRuleError(error.message);
        }
    };
    const removeCustomRule = (id) => setCustomRules((prev) => prev.filter((rule) => rule.id !== id));
    return (_jsxs("div", { className: "workspace-scroll", children: [_jsx("div", { className: "guide-link", children: _jsx("button", { type: "button", className: "guide-link-button", onClick: () => onOpenGuide?.("sanitize"), children: "? guide" }) }), _jsxs("div", { className: "grid-two", children: [_jsxs("div", { className: "panel", "aria-label": "Sanitizer input", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Inbound log" }), _jsx("span", { className: "panel-subtext", children: "raw" })] }), _jsx("textarea", { className: "textarea", value: log, onChange: (event) => setLog(event.target.value), "aria-label": "Log input" }), _jsxs("div", { className: "controls-row", children: [_jsx("span", { className: "section-title", children: "Presets" }), _jsx("div", { className: "pill-buttons", role: "group", "aria-label": "Log presets", children: Object.keys(presets).map((key) => (_jsx("button", { type: "button", className: preset === key ? "active" : "", onClick: () => applyPreset(key), children: presets[key].label }, key))) })] })] }), _jsxs("div", { className: "panel", "aria-label": "Sanitized preview", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Preview" }), _jsx("span", { className: "panel-subtext", children: "diff" })] }), _jsxs("div", { className: "log-preview", role: "presentation", children: [_jsxs("div", { className: "log-line", children: [_jsx("span", { className: "log-marker", children: "-" }), _jsx("span", { className: "diff-remove", children: log })] }), _jsxs("div", { className: "log-line", children: [_jsx("span", { className: "log-marker", children: "+" }), _jsx("span", { className: "diff-add", style: { whiteSpace: wrapLines ? "pre-wrap" : "pre" }, children: highlightDiff(log, result.output) })] })] }), _jsxs("div", { className: "controls-row", children: [_jsx("button", { className: "button", type: "button", onClick: () => writeClipboard(result.output, clipboardPrefs, (message, tone) => push(message, tone === "danger" ? "danger" : tone === "accent" ? "accent" : "neutral"), "copied"), disabled: !result.output, children: "copy sanitized" }), _jsx("button", { className: "button", type: "button", onClick: () => {
                                            const blob = new Blob([result.output], { type: "text/plain" });
                                            const url = URL.createObjectURL(blob);
                                            const link = document.createElement("a");
                                            link.href = url;
                                            link.download = "nullid-sanitized.log";
                                            link.click();
                                            URL.revokeObjectURL(url);
                                        }, disabled: !result.output, children: "download sanitized" }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [_jsx("input", { type: "checkbox", checked: wrapLines, onChange: (event) => setWrapLines(event.target.checked), "aria-label": "Wrap long lines" }), "wrap long lines"] }), _jsxs("label", { className: "microcopy", style: { display: "flex", alignItems: "center", gap: "0.5rem" }, children: [_jsx("input", { type: "checkbox", checked: jsonAware, onChange: (event) => setJsonAware(event.target.checked), "aria-label": "Enable JSON redaction" }), "JSON-aware redaction"] })] }), _jsxs("div", { className: "status-line", children: [_jsx("span", { children: "Rules applied" }), _jsx("span", { className: "tag tag-accent", children: result.applied.length }), _jsxs("span", { className: "microcopy", children: ["lines changed: ", result.linesAffected] })] })] })] }), _jsxs("div", { className: "panel", "aria-label": "Rule toggles", children: [_jsxs("div", { className: "panel-heading", children: [_jsx("span", { children: "Rules" }), _jsx("span", { className: "panel-subtext", children: "toggle" })] }), _jsx("div", { className: "rule-grid", children: rules.map((rule) => (_jsxs("label", { className: "rule-tile", children: [_jsx("input", { type: "checkbox", checked: rulesState[rule.key], onChange: (event) => setRulesState((prev) => ({ ...prev, [rule.key]: event.target.checked })), "aria-label": rule.label }), _jsx("span", { children: rule.label })] }, rule.key))) }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: "Report" }), _jsx("div", { className: "microcopy", children: result.report.length === 0 ? "no replacements yet" : result.report.map((line) => _jsx("div", { children: line }, line)) })] }), _jsxs("div", { className: "note-box", children: [_jsx("div", { className: "section-title", children: "Custom rules" }), _jsxs("div", { className: "controls-row", style: { alignItems: "flex-end" }, children: [_jsxs("div", { style: { flex: 1, minWidth: "180px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-pattern", children: "Pattern (RegExp)" }), _jsx("input", { id: "custom-pattern", className: "input", value: customRuleDraft.pattern, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, pattern: event.target.value })), placeholder: "token=([A-Za-z0-9._-]+)" })] }), _jsxs("div", { style: { minWidth: "140px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-flags", children: "Flags" }), _jsx("input", { id: "custom-flags", className: "input", value: customRuleDraft.flags, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, flags: event.target.value })), placeholder: "gi" })] }), _jsxs("div", { style: { flex: 1, minWidth: "160px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-replacement", children: "Replacement" }), _jsx("input", { id: "custom-replacement", className: "input", value: customRuleDraft.replacement, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, replacement: event.target.value })), placeholder: "[redacted]" })] }), _jsxs("div", { style: { minWidth: "150px" }, children: [_jsx("label", { className: "microcopy", htmlFor: "custom-scope", children: "Scope" }), _jsxs("select", { id: "custom-scope", className: "select", value: customRuleDraft.scope, onChange: (event) => setCustomRuleDraft((prev) => ({ ...prev, scope: event.target.value })), children: [_jsx("option", { value: "both", children: "text + json" }), _jsx("option", { value: "text", children: "text only" }), _jsx("option", { value: "json", children: "json only" })] })] }), _jsx("button", { className: "button", type: "button", onClick: addCustomRule, children: "add rule" })] }), customRuleError && _jsx("div", { className: "microcopy", style: { color: "var(--danger)" }, children: customRuleError }), customRules.length === 0 ? (_jsx("div", { className: "microcopy", children: "no custom rules" })) : (_jsx("ul", { className: "note-list", children: customRules.map((rule) => (_jsxs("li", { children: [_jsxs("div", { className: "note-title", children: ["/", rule.pattern, "/", rule.flags] }), _jsxs("div", { className: "note-body", children: ["\u2192 ", rule.replacement || "[empty]", " (", rule.scope, ")"] }), _jsx("button", { className: "button", type: "button", onClick: () => removeCustomRule(rule.id), children: "remove" })] }, rule.id))) }))] })] })] }));
}
function replaceWithCount(input, regex, replacement) {
    let count = 0;
    const output = input.replace(regex, () => {
        count += 1;
        return replacement;
    });
    return { output, count };
}
function replaceCardNumbers(input) {
    const regex = /\b(?:\d[ -]?){12,19}\b/g;
    let count = 0;
    const output = input.replace(regex, (match) => {
        if (passesLuhn(match)) {
            count += 1;
            return "[card]";
        }
        return match;
    });
    return { output, count };
}
function replaceIban(input) {
    const regex = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi;
    let count = 0;
    const output = input.replace(regex, (match) => {
        if (isValidIban(match)) {
            count += 1;
            return "[iban]";
        }
        return match;
    });
    return { output, count };
}
function passesLuhn(value) {
    const digits = value.replace(/[^0-9]/g, "");
    if (digits.length < 12 || digits.length > 19)
        return false;
    let sum = 0;
    let doubleDigit = false;
    for (let i = digits.length - 1; i >= 0; i -= 1) {
        let digit = Number(digits[i]);
        if (doubleDigit) {
            digit *= 2;
            if (digit > 9)
                digit -= 9;
        }
        sum += digit;
        doubleDigit = !doubleDigit;
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
        remainder = (remainder * 10 + Number(converted[i])) % 97;
    }
    return remainder === 1;
}
function applyRules(input, rulesState, customRules, jsonAware) {
    let output = input;
    const applied = [];
    const report = [];
    let linesAffected = 0;
    const applyCustom = (value, scope) => {
        let current = value;
        customRules.forEach((rule) => {
            if (rule.scope !== "both" && rule.scope !== scope)
                return;
            try {
                const regex = new RegExp(rule.pattern, rule.flags);
                let count = 0;
                current = current.replace(regex, () => {
                    count += 1;
                    return rule.replacement;
                });
                if (count > 0) {
                    report.push(`Custom /${rule.pattern}/${rule.flags}: ${count}`);
                }
            }
            catch {
                // Skip invalid custom rules at runtime
            }
        });
        return current;
    };
    rules.forEach((rule) => {
        if (!rulesState[rule.key])
            return;
        const { output: next, count } = rule.apply(output);
        if (count > 0) {
            applied.push(rule.key);
            report.push(`${rule.label}: ${count}`);
            output = next;
        }
    });
    const redactKeys = ["token", "authorization", "password", "secret", "apikey", "session", "cookie"];
    const jsonClean = (value) => {
        if (Array.isArray(value))
            return value.map(jsonClean);
        if (value && typeof value === "object") {
            const entries = Object.entries(value).map(([key, val]) => {
                if (redactKeys.includes(key.toLowerCase()))
                    return [key, "[redacted]"];
                return [key, jsonClean(val)];
            });
            return Object.fromEntries(entries);
        }
        return value;
    };
    let jsonApplied = false;
    if (jsonAware) {
        try {
            const parsed = JSON.parse(output);
            const cleaned = jsonClean(parsed);
            output = JSON.stringify(cleaned, null, 2);
            jsonApplied = true;
            report.push("JSON secrets redacted");
        }
        catch {
            jsonApplied = false;
        }
    }
    output = applyCustom(output, jsonApplied ? "json" : "text");
    const inputLines = input.split("\n");
    const outputLines = output.split("\n");
    linesAffected = Math.max(inputLines.length, outputLines.length);
    linesAffected = inputLines.reduce((acc, line, idx) => (line === outputLines[idx] ? acc : acc + 1), 0);
    return { output, applied, report, linesAffected };
}
function highlightDiff(before, after) {
    if (before === after)
        return after;
    const beforeTokens = before.split(/(\s+)/);
    const afterTokens = after.split(/(\s+)/);
    return afterTokens.map((token, index) => {
        if (token === beforeTokens[index])
            return token;
        return (_jsx("mark", { className: "highlight medium", children: token }, index));
    });
}
