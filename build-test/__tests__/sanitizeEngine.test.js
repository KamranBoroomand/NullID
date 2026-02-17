import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { applySanitizeRules, buildRulesState, normalizePolicyConfig, runBatchSanitize } from "../utils/sanitizeEngine.js";
describe("sanitize engine", () => {
    it("applies selected built-in rules", () => {
        const state = buildRulesState(["maskEmail", "maskIp"]);
        const input = "email alice@example.com from 203.0.113.10";
        const result = applySanitizeRules(input, state, [], true);
        assert.equal(result.output.includes("[email]"), true);
        assert.equal(result.output.includes("[ip]"), true);
        assert.equal(result.applied.includes("maskEmail"), true);
    });
    it("applies custom rules on text scope", () => {
        const state = buildRulesState([]);
        const input = "token=abc123";
        const result = applySanitizeRules(input, state, [{ id: "c1", pattern: "token=([a-z0-9]+)", replacement: "token=[redacted]", flags: "gi", scope: "text" }], false);
        assert.equal(result.output, "token=[redacted]");
    });
    it("normalizes imported policy config", () => {
        const config = normalizePolicyConfig({
            rulesState: { maskEmail: true, maskIp: false },
            jsonAware: true,
            customRules: [{ pattern: "secret", replacement: "[x]", flags: "gi", scope: "both" }],
        });
        assert.equal(Boolean(config), true);
        assert.equal(config?.rulesState.maskEmail, true);
        assert.equal(Array.isArray(config?.customRules), true);
    });
    it("runs batch sanitize for multiple files", () => {
        const outputs = runBatchSanitize([
            { name: "a.log", text: "alice@example.com" },
            { name: "b.log", text: "203.0.113.50" },
        ], {
            rulesState: buildRulesState(["maskEmail", "maskIp"]),
            jsonAware: false,
            customRules: [],
        });
        assert.equal(outputs.length, 2);
        assert.equal(outputs[0].output.includes("[email]"), true);
        assert.equal(outputs[1].output.includes("[ip]"), true);
    });
    it("masks Persian/Russian phone numbers and Iran national IDs", () => {
        const state = buildRulesState(["maskPhoneIntl", "maskIranNationalId"]);
        const input = "fa: ۰۹۱۲۳۴۵۶۷۸۹ id: ۱۰۰۰۰۰۰۰۰۱ ru: +7 (912) 345-67-89";
        const result = applySanitizeRules(input, state, [], false);
        assert.equal(result.output.includes("[phone]"), true);
        assert.equal(result.output.includes("[iran-id]"), true);
        assert.equal(result.applied.includes("maskPhoneIntl"), true);
        assert.equal(result.applied.includes("maskIranNationalId"), true);
    });
    it("masks Persian-digit IPv4 and credit cards", () => {
        const state = buildRulesState(["maskIp", "maskCard"]);
        const input = "ip=۱۹۲.۱۶۸.۰.۱ card=۴۱۱۱ ۱۱۱۱ ۱۱۱۱ ۱۱۱۱";
        const result = applySanitizeRules(input, state, [], false);
        assert.equal(result.output.includes("[ip]"), true);
        assert.equal(result.output.includes("[card]"), true);
        assert.equal(result.applied.includes("maskIp"), true);
        assert.equal(result.applied.includes("maskCard"), true);
    });
});
