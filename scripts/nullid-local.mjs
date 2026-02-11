#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const command = process.argv[2];
const args = process.argv.slice(3);

if (!command || command === "help" || command === "--help" || command === "-h") {
  printUsage();
  process.exit(0);
}

try {
  if (command === "hash") {
    runHash(args);
  } else if (command === "sanitize") {
    runSanitize(args);
  } else if (command === "bundle") {
    runBundle(args);
  } else {
    throw new Error(`Unknown command: ${command}`);
  }
} catch (error) {
  console.error(`[nullid-cli] ${(error instanceof Error ? error.message : String(error)).trim()}`);
  process.exit(1);
}

function runHash(argv) {
  const input = argv[0];
  if (!input) throw new Error("Usage: hash <input-file> [--algo sha256|sha512|sha1]");
  const algo = (getOption(argv, "--algo") || "sha256").toLowerCase();
  if (!["sha256", "sha512", "sha1"].includes(algo)) {
    throw new Error(`Unsupported hash algorithm: ${algo}`);
  }
  const buffer = fs.readFileSync(path.resolve(input));
  const hex = crypto.createHash(algo).update(buffer).digest("hex");
  console.log(JSON.stringify({ file: input, algorithm: algo, sha: hex }, null, 2));
}

function runSanitize(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error("Usage: sanitize <input-file> <output-file> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--json-aware true|false]");
  }

  const input = fs.readFileSync(path.resolve(inputPath), "utf8");
  const preset = getOption(argv, "--preset") || "nginx";
  const policyPath = getOption(argv, "--policy");
  const jsonAware = parseBoolean(getOption(argv, "--json-aware"), true);

  const policy = policyPath ? loadPolicy(path.resolve(policyPath)) : buildPolicyFromPreset(preset, jsonAware);
  const result = applySanitize(input, policy);
  fs.writeFileSync(path.resolve(outputPath), result.output, "utf8");
  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        linesAffected: result.linesAffected,
        appliedRules: result.applied,
        report: result.report,
      },
      null,
      2,
    ),
  );
}

function runBundle(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error("Usage: bundle <input-file> <output-json> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--json-aware true|false]");
  }
  const input = fs.readFileSync(path.resolve(inputPath), "utf8");
  const preset = getOption(argv, "--preset") || "nginx";
  const policyPath = getOption(argv, "--policy");
  const jsonAware = parseBoolean(getOption(argv, "--json-aware"), true);
  const policy = policyPath ? loadPolicy(path.resolve(policyPath)) : buildPolicyFromPreset(preset, jsonAware);
  const result = applySanitize(input, policy);
  const bundle = {
    schemaVersion: 1,
    kind: "nullid-safe-share",
    createdAt: new Date().toISOString(),
    tool: "sanitize",
    sourceFile: inputPath,
    policy,
    input: {
      bytes: Buffer.byteLength(input, "utf8"),
      sha256: sha256Hex(input),
    },
    output: {
      bytes: Buffer.byteLength(result.output, "utf8"),
      sha256: sha256Hex(result.output),
      text: result.output,
    },
    summary: {
      linesAffected: result.linesAffected,
      appliedRules: result.applied,
      report: result.report,
    },
  };
  fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  console.log(JSON.stringify({ output: outputPath, sha256: bundle.output.sha256, linesAffected: result.linesAffected }, null, 2));
}

function printUsage() {
  console.log(`
NullID local CLI (free, no servers)

Commands:
  hash <input-file> [--algo sha256|sha512|sha1]
  sanitize <input-file> <output-file> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--json-aware true|false]
  bundle <input-file> <output-json> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--json-aware true|false]

Examples:
  node scripts/nullid-local.mjs hash ./app.log
  node scripts/nullid-local.mjs sanitize ./raw.log ./clean.log --preset nginx
  node scripts/nullid-local.mjs bundle ./raw.log ./safe-share.json --policy ./policy.json
`.trim());
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function parseBoolean(value, fallback) {
  if (value == null) return fallback;
  const normalized = String(value).toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  return fallback;
}

function getOption(argv, flag) {
  const index = argv.findIndex((arg) => arg === flag);
  if (index < 0) return undefined;
  return argv[index + 1];
}

const presetRules = {
  nginx: ["maskIp", "maskIpv6", "stripCookies", "dropUA", "scrubJwt", "maskBearer", "maskUser", "normalizeTs", "maskAwsKey", "maskAwsSecret", "maskCard", "maskIban"],
  apache: ["maskIp", "maskIpv6", "maskEmail", "scrubJwt", "maskBearer", "normalizeTs", "maskCard", "maskIban"],
  auth: ["maskIp", "maskIpv6", "maskUser"],
  json: ["maskIp", "maskIpv6", "stripJsonSecrets", "maskUser", "maskAwsKey", "maskAwsSecret", "maskCard", "maskIban"],
};

const allRuleKeys = [
  "maskIp",
  "maskIpv6",
  "maskEmail",
  "scrubJwt",
  "maskBearer",
  "maskCard",
  "maskIban",
  "maskAwsKey",
  "maskAwsSecret",
  "stripCookies",
  "dropUA",
  "normalizeTs",
  "maskUser",
  "stripJsonSecrets",
];

function buildPolicyFromPreset(preset, jsonAware) {
  const selected = new Set(presetRules[preset] || presetRules.nginx);
  const rulesState = Object.fromEntries(allRuleKeys.map((key) => [key, selected.has(key)]));
  return { rulesState, jsonAware, customRules: [] };
}

function loadPolicy(policyPath) {
  const text = fs.readFileSync(policyPath, "utf8");
  const parsed = JSON.parse(text);
  const packEntry = Array.isArray(parsed?.packs) ? parsed.packs[0] : parsed?.pack;
  const config = packEntry?.config;
  if (!config || typeof config !== "object") {
    throw new Error("Invalid policy file: expected sanitize-policy-pack payload");
  }
  return {
    rulesState: normalizeRulesState(config.rulesState),
    jsonAware: Boolean(config.jsonAware),
    customRules: normalizeCustomRules(config.customRules),
  };
}

function normalizeRulesState(input) {
  const state = Object.fromEntries(allRuleKeys.map((key) => [key, false]));
  if (!input || typeof input !== "object") return state;
  allRuleKeys.forEach((key) => {
    if (typeof input[key] === "boolean") state[key] = input[key];
  });
  return state;
}

function normalizeCustomRules(input) {
  if (!Array.isArray(input)) return [];
  return input
    .map((rule) => {
      if (!rule || typeof rule !== "object") return null;
      if (typeof rule.pattern !== "string" || !rule.pattern.trim()) return null;
      const flags = typeof rule.flags === "string" ? rule.flags : "gi";
      try {
        // eslint-disable-next-line no-new
        new RegExp(rule.pattern, flags);
      } catch {
        return null;
      }
      return {
        id: typeof rule.id === "string" ? rule.id : crypto.randomUUID(),
        pattern: rule.pattern,
        replacement: typeof rule.replacement === "string" ? rule.replacement : "",
        flags,
        scope: rule.scope === "text" || rule.scope === "json" || rule.scope === "both" ? rule.scope : "both",
      };
    })
    .filter(Boolean);
}

function applySanitize(input, policy) {
  let output = input;
  const applied = [];
  const report = [];

  const applyRule = (enabled, label, fn) => {
    if (!enabled) return;
    const next = fn(output);
    if (next.count > 0) {
      output = next.output;
      report.push(`${label}: ${next.count}`);
      applied.push(label);
    }
  };

  applyRule(policy.rulesState.maskIp, "maskIp", (value) => replaceWithCount(value, /\b(\d{1,3}\.){3}\d{1,3}\b/g, "[ip]"));
  applyRule(policy.rulesState.maskIpv6, "maskIpv6", (value) => replaceWithCount(value, /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi, "[ipv6]"));
  applyRule(policy.rulesState.maskEmail, "maskEmail", (value) => replaceWithCount(value, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[email]"));
  applyRule(policy.rulesState.scrubJwt, "scrubJwt", (value) =>
    replaceWithCount(value, /(?:bearer\s+)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi, "[jwt]"),
  );
  applyRule(policy.rulesState.maskBearer, "maskBearer", (value) =>
    replaceWithCount(value, /\b(?:authorization[:=]\s*)?(?:bearer\s+)[A-Za-z0-9._-]{20,}\b/gi, "[token]"),
  );
  applyRule(policy.rulesState.maskAwsKey, "maskAwsKey", (value) => replaceWithCount(value, /\bAKIA[0-9A-Z]{16}\b/g, "[aws-key]"));
  applyRule(policy.rulesState.maskAwsSecret, "maskAwsSecret", (value) =>
    replaceWithCount(value, /\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b/gi, "aws_secret_access_key=[redacted]"),
  );
  applyRule(policy.rulesState.stripCookies, "stripCookies", (value) => replaceWithCount(value, /cookie=[^ ;\n]+/gi, "cookie=[stripped]"));
  applyRule(policy.rulesState.dropUA, "dropUA", (value) => replaceWithCount(value, /ua=[^\s]+|user-agent:[^\n]+/gi, "ua=[dropped]"));
  applyRule(policy.rulesState.normalizeTs, "normalizeTs", (value) =>
    replaceWithCount(value, /\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\]/g, "[timestamp]"),
  );
  applyRule(policy.rulesState.maskUser, "maskUser", (value) => replaceWithCount(value, /\buser=([A-Za-z0-9._-]+)\b/gi, "user=[user]"));
  applyRule(policy.rulesState.stripJsonSecrets, "stripJsonSecrets", (value) =>
    replaceWithCount(value, /\"(token|secret|password)\"\s*:\s*\"[^\"]+\"/gi, '"$1":"[redacted]"'),
  );
  applyRule(policy.rulesState.maskCard, "maskCard", replaceCardNumbers);
  applyRule(policy.rulesState.maskIban, "maskIban", replaceIban);

  const redactKeys = ["token", "authorization", "password", "secret", "apikey", "session", "cookie"];
  const jsonClean = (value) => {
    if (Array.isArray(value)) return value.map(jsonClean);
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, redactKeys.includes(key.toLowerCase()) ? "[redacted]" : jsonClean(item)]),
      );
    }
    return value;
  };

  let scope = "text";
  if (policy.jsonAware) {
    try {
      const parsed = JSON.parse(output);
      output = JSON.stringify(jsonClean(parsed), null, 2);
      scope = "json";
      report.push("json-aware-clean: 1");
    } catch {
      scope = "text";
    }
  }

  policy.customRules.forEach((rule) => {
    if (rule.scope !== "both" && rule.scope !== scope) return;
    const regex = new RegExp(rule.pattern, rule.flags);
    let count = 0;
    output = output.replace(regex, () => {
      count += 1;
      return rule.replacement;
    });
    if (count > 0) report.push(`custom:${rule.pattern}:${count}`);
  });

  const inputLines = input.split("\n");
  const outputLines = output.split("\n");
  const linesAffected = inputLines.reduce((count, line, index) => (line === outputLines[index] ? count : count + 1), 0);
  return { output, applied, report, linesAffected };
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

function isValidIban(value) {
  const trimmed = value.replace(/\s+/g, "").toUpperCase();
  if (trimmed.length < 15 || trimmed.length > 34) return false;
  const rearranged = `${trimmed.slice(4)}${trimmed.slice(0, 4)}`;
  const converted = rearranged.replace(/[A-Z]/g, (ch) => `${ch.charCodeAt(0) - 55}`);
  let remainder = 0;
  for (let i = 0; i < converted.length; i += 1) {
    remainder = (remainder * 10 + Number(converted[i])) % 97;
  }
  return remainder === 1;
}
