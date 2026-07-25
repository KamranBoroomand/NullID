import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mergeSanitizePolicyConfig, normalizeWorkspacePolicyBaseline } from "../utils/policyBaseline.js";
import { buildRulesState } from "../utils/sanitizeEngine.js";

describe("workspace policy baseline", () => {
  const base = {
    rulesState: buildRulesState(["maskIp", "maskEmail"]),
    jsonAware: false,
    customRules: [
      {
        id: "base-rule",
        pattern: "token=([a-z0-9]+)",
        replacement: "token=[redacted]",
        flags: "gi",
        scope: "text" as const,
      },
    ],
  };

  const override = {
    rulesState: buildRulesState(["maskIp", "maskBearer"]),
    jsonAware: true,
    customRules: [
      {
        id: "override-rule",
        pattern: "password=([^\n]+)",
        replacement: "password=[redacted]",
        flags: "gi",
        scope: "text" as const,
      },
    ],
  };

  it("applies strict override mode deterministically", () => {
    const merged = mergeSanitizePolicyConfig(base, override, "strict-override");
    assert.equal(merged.rulesState.maskBearer, true);
    assert.equal(merged.rulesState.maskEmail, false);
    assert.equal(merged.jsonAware, true);
    assert.equal(merged.customRules.length, 2);
  });

  it("applies prefer-stricter mode", () => {
    const merged = mergeSanitizePolicyConfig(base, override, "prefer-stricter");
    assert.equal(merged.rulesState.maskBearer, true);
    assert.equal(merged.rulesState.maskEmail, true);
    assert.equal(merged.jsonAware, true);
  });

  it("normalizes workspace baseline payload", () => {
    const baseline = normalizeWorkspacePolicyBaseline({
      schemaVersion: 1,
      kind: "nullid-policy-baseline",
      sanitize: {
        mergeMode: "strict-override",
        defaultConfig: override,
        packs: [
          {
            name: "org-default",
            createdAt: "2026-02-11T00:00:00.000Z",
            config: override,
          },
        ],
      },
    });
    assert.equal(Boolean(baseline), true);
    assert.equal(baseline?.sanitize.packs.length, 1);
    assert.equal(baseline?.sanitize.defaultConfig.rulesState.maskBearer, true);
  });
});
