import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  applySanitizeRules,
  applySanitizeRulesAsync,
  buildRulesState,
  normalizePolicyConfig,
  runBatchSanitize,
  runBatchSanitizeAsync,
} from "../utils/sanitizeEngine.js";

describe("sanitize engine", () => {
  it("applies selected built-in rules", () => {
    const state = buildRulesState(["maskEmail", "maskIp"]);
    const input = "email alice@example.com from 203.0.113.10";
    const result = applySanitizeRules(input, state, [], true);
    assert.equal(result.output.includes("[email]"), true);
    assert.equal(result.output.includes("[ip]"), true);
    assert.equal(result.applied.includes("maskEmail"), true);
  });

  it("applies custom rules on text scope through the worker path", async () => {
    const state = buildRulesState([]);
    const input = "token=abc123";
    const result = await applySanitizeRulesAsync(
      input,
      state,
      [{ id: "c1", pattern: "token=([a-z0-9]+)", replacement: "token=[redacted]", flags: "gi", scope: "text" }],
      false,
    );
    assert.equal(result.output, "token=[redacted]");
  });

  it("completes supported concurrent harmless custom rules without false timeouts", async () => {
    const state = buildRulesState([]);
    for (const count of [10, 25, 50]) {
      const results = await Promise.all(
        Array.from({ length: count }, (_, index) =>
          applySanitizeRulesAsync(
            `item ${index} token=abc${index}`,
            state,
            [{ id: `safe-${index}`, pattern: "token=([a-z0-9]+)", replacement: "token=[redacted]", flags: "gi", scope: "text" }],
            false,
          ),
        ),
      );

      assert.equal(results.every((result) => result.output.includes("token=[redacted]")), true, `${count} all replaced`);
      assert.equal(results.some((result) => result.report.some((entry) => /skipped \(timeout\)/i.test(entry))), false, `${count} no timeouts`);
    }
  });

  it("fails closed instead of committing built-in-only output when a custom rule is invalid", async () => {
    const input = "email alice@example.com token=abc123";
    const result = await applySanitizeRulesAsync(
      input,
      buildRulesState(["maskEmail"]),
      [{ id: "invalid", pattern: "token=(", replacement: "token=[redacted]", flags: "g", scope: "text" }],
      false,
    );

    assert.equal(result.output, input);
    assert.equal(result.report.some((entry) => /custom:invalid|syntax|failed|regex/i.test(entry)), true);
  });

  it("cancels underlying custom regex work through AbortSignal", async () => {
    const controller = new AbortController();
    const input = `token=abc ${"a".repeat(4096)}!`;
    const promise = applySanitizeRulesAsync(
      input,
      buildRulesState([]),
      [{ id: "cancelled", pattern: "(a+)+$", replacement: "[x]", flags: "g", scope: "text" }],
      false,
      { signal: controller.signal },
    );

    controller.abort();
    const result = await promise;

    assert.equal(result.output, input);
    assert.equal(result.report.some((entry) => /cancelled/i.test(entry)), true);
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
    assert.equal(config?.customRules.length, 1);
    assert.equal(config?.customRules[0]?.pattern, "secret");
  });

  it("keeps finite and nested custom regexes out of the synchronous path", () => {
    const config = normalizePolicyConfig({
      rulesState: { maskEmail: false, maskIp: false },
      jsonAware: false,
      customRules: [{ pattern: "(a+)+", replacement: "[x]", flags: "g", scope: "both" }],
    });
    assert.equal(Boolean(config), true);
    assert.equal(config?.customRules.length, 1);
    const result = applySanitizeRules("aaaa!", buildRulesState([]), config?.customRules ?? [], false);
    assert.equal(result.output, "aaaa!");
    assert.equal(result.report.some((entry) => /worker path/i.test(entry)), true);
  });

  it("bounds custom regex bypass samples in workers without accepting partial output", async () => {
    const almost = `${"a".repeat(1024)}!`;
    const timeoutPatterns = [
      "^((a+)){10}$",
      "^((((a+))))+$",
      "^(a|aa)+$",
    ];
    for (const pattern of timeoutPatterns) {
      const result = await applySanitizeRulesAsync(
        almost,
        buildRulesState([]),
        [{ id: pattern, pattern, replacement: "[x]", flags: "g", scope: "text" }],
        false,
      );
      assert.equal(result.output, almost, pattern);
      assert.equal(result.report.some((entry) => /failed \((timeout|worker-error|budget|syntax-error)\)/i.test(entry)), true, pattern);
    }
    const finiteInput = "a".repeat(30);
    const finite = await applySanitizeRulesAsync(
      finiteInput,
      buildRulesState([]),
      [{ id: "finite", pattern: "^(a+){2,10}$", replacement: "[x]", flags: "g", scope: "text" }],
      false,
    );
    assert.equal(finite.output, "[x]");
    assert.equal(finite.report.some((entry) => /Custom \/\^\(a\+\)\{2,10\}\$\/g: 1/i.test(entry)), true);
  });

  it("runs advanced but bounded regex features in workers", async () => {
    const result = await applySanitizeRulesAsync(
      "book token=secret Ελληνικά",
      buildRulesState([]),
      [
        { id: "backref", pattern: "([a-z])\\1", replacement: "xx", flags: "g", scope: "text" },
        { id: "lookaround", pattern: "(?<=token=)[a-z]+", replacement: "[redacted]", flags: "g", scope: "text" },
        { id: "unicode", pattern: "\\p{Script=Greek}+", replacement: "[unicode]", flags: "gu", scope: "text" },
      ],
      false,
    );
    assert.equal(result.output, "bxxk token=[redacted] [unicode]");
  });

  it("runs batch sanitize for multiple files", () => {
    const outputs = runBatchSanitize(
      [
        { name: "a.log", text: "alice@example.com" },
        { name: "b.log", text: "203.0.113.50" },
      ],
      {
        rulesState: buildRulesState(["maskEmail", "maskIp"]),
        jsonAware: false,
        customRules: [],
      },
    );
    assert.equal(outputs.length, 2);
    assert.equal(outputs[0].output.includes("[email]"), true);
    assert.equal(outputs[1].output.includes("[ip]"), true);
  });

  it("continues batch diagnostics after a timed-out custom rule without committing the failed artifact", async () => {
    const outputs = await runBatchSanitizeAsync(
      [
        { name: "a.log", text: `${"a".repeat(4096)}! token=abc123` },
        { name: "b.log", text: "token=def456" },
      ],
      {
        rulesState: buildRulesState([]),
        jsonAware: false,
        customRules: [
          { id: "danger", pattern: "(a+)+$", replacement: "[x]", flags: "g", scope: "text" },
          { id: "safe", pattern: "token=[a-z0-9]+", replacement: "token=[redacted]", flags: "g", scope: "text" },
        ],
      },
    );
    assert.equal(outputs.length, 2);
    assert.equal(outputs[0].output, `${"a".repeat(4096)}! token=abc123`);
    assert.equal(outputs[0].commitAllowed, false);
    assert.equal(outputs[1].output, "token=[redacted]");
    assert.equal(outputs[1].commitAllowed, true);
    assert.equal(outputs.some((output) => output.report.some((entry) => /failed \(timeout\)/i.test(entry))), true);
  });

  it("keeps failed batch artifacts uncommitted while continuing later diagnostics", async () => {
    const outputs = await runBatchSanitizeAsync(
      [
        { name: "invalid.log", text: "alice@example.com token=abc123" },
        { name: "valid.log", text: "token=def456" },
      ],
      {
        rulesState: buildRulesState(["maskEmail"]),
        jsonAware: false,
        customRules: [
          { id: "invalid", pattern: "token=(", replacement: "token=[redacted]", flags: "g", scope: "text" },
          { id: "safe", pattern: "token=[a-z0-9]+", replacement: "token=[redacted]", flags: "g", scope: "text" },
        ],
      },
    );

    assert.equal(outputs[0].output, "alice@example.com token=abc123");
    assert.equal(outputs[0].report.some((entry) => /invalid|syntax|failed|regex/i.test(entry)), true);
    assert.equal(outputs[1].output, "token=def456");
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

  it("masks platform tokens and private key blocks", () => {
    const state = buildRulesState(["maskGithubToken", "maskSlackToken", "stripPrivateKeyBlock"]);
    const syntheticGithubToken = `${["gh", "p_"].join("")}${["0123456789abcdef", "0123456789abcdef", "0123"].join("")}`;
    const syntheticSlackToken = `${["xox", "b"].join("")}-${["123456789012", "abcdefghijklmnop"].join("-")}`;
    const input =
      `gh=${syntheticGithubToken}\nslack=${syntheticSlackToken}\n-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----`;
    const result = applySanitizeRules(input, state, [], false);
    assert.equal(result.output.includes("[github-token]"), true);
    assert.equal(result.output.includes("[slack-token]"), true);
    assert.equal(result.output.includes("[private-key]"), true);
    assert.equal(result.applied.includes("maskGithubToken"), true);
    assert.equal(result.applied.includes("maskSlackToken"), true);
    assert.equal(result.applied.includes("stripPrivateKeyBlock"), true);
  });
});
