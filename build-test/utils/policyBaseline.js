import { normalizePolicyConfig } from "./sanitizeEngine.js";
export const WORKSPACE_POLICY_SCHEMA_VERSION = 1;
export function normalizeWorkspacePolicyBaseline(input) {
    if (!isRecord(input) || input.kind !== "nullid-policy-baseline")
        return null;
    if (Number(input.schemaVersion) !== WORKSPACE_POLICY_SCHEMA_VERSION)
        return null;
    if (!isRecord(input.sanitize))
        return null;
    const mergeMode = input.sanitize.mergeMode === "prefer-stricter" ? "prefer-stricter" : "strict-override";
    const defaultConfig = normalizePolicyConfig(input.sanitize.defaultConfig);
    if (!defaultConfig)
        return null;
    const packsSource = Array.isArray(input.sanitize.packs) ? input.sanitize.packs : [];
    const packs = packsSource
        .map((entry) => normalizeBaselinePack(entry))
        .filter((entry) => Boolean(entry));
    return {
        schemaVersion: WORKSPACE_POLICY_SCHEMA_VERSION,
        kind: "nullid-policy-baseline",
        sanitize: {
            mergeMode,
            defaultConfig,
            packs,
        },
    };
}
export function mergeSanitizePolicyConfig(base, override, mode = "strict-override") {
    const mergedRules = mergeRules(base.rulesState, override.rulesState, mode);
    const mergedCustomRules = mergeCustomRules(base.customRules, override.customRules);
    return {
        rulesState: mergedRules,
        jsonAware: mode === "prefer-stricter" ? base.jsonAware || override.jsonAware : override.jsonAware,
        customRules: mergedCustomRules,
    };
}
function mergeRules(base, override, mode) {
    const keys = Object.keys(base);
    const merged = {};
    keys.forEach((key) => {
        merged[key] = mode === "prefer-stricter" ? base[key] || override[key] : override[key];
    });
    return merged;
}
function mergeCustomRules(base, override) {
    const map = new Map();
    [...base, ...override].forEach((rule) => {
        const identity = `${rule.scope}::${rule.flags}::${rule.pattern}::${rule.replacement}`;
        map.set(identity, {
            ...rule,
            id: rule.id || crypto.randomUUID(),
        });
    });
    return Array.from(map.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([, rule]) => rule);
}
function normalizeBaselinePack(entry) {
    if (!isRecord(entry))
        return null;
    const name = typeof entry.name === "string" ? entry.name.trim() : "";
    if (!name)
        return null;
    const config = normalizePolicyConfig(entry.config);
    if (!config)
        return null;
    return {
        id: crypto.randomUUID(),
        name,
        createdAt: typeof entry.createdAt === "string" ? entry.createdAt : new Date().toISOString(),
        config,
    };
}
function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
