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
export const sanitizePresets = {
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
const ruleKeys = rules.map((rule) => rule.key);
const MAX_CUSTOM_PATTERN_LENGTH = 240;
const MAX_CUSTOM_REPLACEMENT_LENGTH = 2000;
export function getRuleKeys() {
    return [...ruleKeys];
}
export function getRuleLabel(key) {
    return rules.find((rule) => rule.key === key)?.label ?? key;
}
export function buildRulesState(enabledKeys) {
    const enabledSet = new Set(enabledKeys);
    return Object.fromEntries(ruleKeys.map((key) => [key, enabledSet.has(key)]));
}
export function defaultRulesState() {
    return Object.fromEntries(ruleKeys.map((key) => [key, true]));
}
export function defaultSanitizePolicy() {
    return {
        rulesState: defaultRulesState(),
        jsonAware: true,
        customRules: [],
    };
}
export function normalizePolicyConfig(input) {
    if (!isRecord(input))
        return null;
    const rulesStateInput = input.rulesState;
    const jsonAwareInput = input.jsonAware;
    const customRulesInput = input.customRules;
    if (!isRecord(rulesStateInput) || typeof jsonAwareInput !== "boolean" || !Array.isArray(customRulesInput))
        return null;
    const rulesState = { ...defaultRulesState() };
    ruleKeys.forEach((key) => {
        const value = rulesStateInput[key];
        if (typeof value === "boolean")
            rulesState[key] = value;
    });
    const customRules = customRulesInput.map(normalizeCustomRule).filter((rule) => Boolean(rule));
    return {
        rulesState,
        jsonAware: jsonAwareInput,
        customRules,
    };
}
export function applySanitizeRules(input, rulesState, customRules, jsonAware) {
    let output = input;
    const applied = [];
    const report = [];
    let linesAffected = 0;
    const applyCustom = (value, scope) => {
        let current = value;
        customRules.forEach((rule) => {
            if (rule.scope !== "both" && rule.scope !== scope)
                return;
            if (isUnsafeCustomRegexPattern(rule.pattern))
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
export function runBatchSanitize(inputs, policy) {
    return inputs.map((item) => {
        const result = applySanitizeRules(item.text, policy.rulesState, policy.customRules, policy.jsonAware);
        return {
            ...result,
            name: item.name,
            inputChars: item.text.length,
            outputChars: result.output.length,
        };
    });
}
function normalizeCustomRule(value) {
    if (!isRecord(value))
        return null;
    const id = typeof value.id === "string" && value.id.trim() ? value.id : crypto.randomUUID();
    const pattern = typeof value.pattern === "string" ? value.pattern : "";
    const replacement = typeof value.replacement === "string" ? value.replacement.slice(0, MAX_CUSTOM_REPLACEMENT_LENGTH) : "";
    const flags = typeof value.flags === "string" ? value.flags : "gi";
    const scope = value.scope === "text" || value.scope === "json" || value.scope === "both" ? value.scope : "both";
    if (!pattern.trim())
        return null;
    if (pattern.length > MAX_CUSTOM_PATTERN_LENGTH)
        return null;
    if (isUnsafeCustomRegexPattern(pattern))
        return null;
    try {
        // Validate regex
        // eslint-disable-next-line no-new
        new RegExp(pattern, flags);
    }
    catch {
        return null;
    }
    return { id, pattern, replacement, flags, scope };
}
function isUnsafeCustomRegexPattern(pattern) {
    const cleaned = pattern.replace(/\\./g, "_");
    if (cleaned.length > MAX_CUSTOM_PATTERN_LENGTH)
        return true;
    if (/(^|[^\\])\\[1-9]/.test(pattern))
        return true;
    if (/\((?:\?:)?[^()]{0,120}(?:\+|\*|\{[0-9,\s]+\})[^()]{0,120}\)\s*(?:\+|\*)/.test(cleaned))
        return true;
    if (/(?:\.\*|\.\+)\s*(?:\+|\*)/.test(cleaned))
        return true;
    return false;
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
function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
