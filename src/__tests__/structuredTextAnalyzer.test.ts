import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeStructuredText } from "../utils/structuredTextAnalyzer.js";
import { applyRedaction } from "../utils/redaction.js";

describe("structured text analyzer", () => {
  it("groups general findings by category and produces a clean-text preview basis", () => {
    const input = `alice@example.com called +1 202-555-0147 about ${buildSampleUrl()} and token=ABCDEFGHIJKLMNOPQRSTUV123456`;
    const result = analyzeStructuredText(input);
    const clean = applyRedaction(input, result.redactionMatches, "full");

    assert.equal(result.countsByCategory.emails, 1);
    assert.equal(result.countsByCategory.phones, 1);
    assert.equal(result.countsByCategory.urls, 1);
    assert.equal(result.countsByCategory.secrets >= 1, true);
    assert.match(clean, /\[email\]/i);
    assert.match(clean, /\[phone\]/i);
  });

  it("keeps Iran/Russia detectors opt-in and reports them separately when enabled", () => {
    const input = `کد ملی: ${makeIranNationalId("123456789")} شماره کارت: ${makeLuhnCard("603799751456123")} Паспорт: 45 08 123456`;
    const disabled = analyzeStructuredText(input, { enabledRuleSets: { iran: false, russia: false } });
    const enabled = analyzeStructuredText(input, { enabledRuleSets: { iran: true, russia: true } });

    assert.equal(disabled.countsByRuleSet.iran, 0);
    assert.equal(disabled.countsByRuleSet.russia, 0);
    assert.equal(enabled.countsByRuleSet.iran > 0, true);
    assert.equal(enabled.countsByRuleSet.russia > 0, true);
    assert.equal(enabled.notes.some((line) => /normalize local digit sets/i.test(line)), true);
  });
});

function makeIranNationalId(prefix: string) {
  const sum = prefix.split("").reduce((acc, ch, index) => acc + Number(ch) * (10 - index), 0);
  const remainder = sum % 11;
  const check = remainder < 2 ? remainder : 11 - remainder;
  return `${prefix}${check}`;
}

function makeLuhnCard(prefix: string) {
  let sum = 0;
  let shouldDouble = true;
  for (let i = prefix.length - 1; i >= 0; i -= 1) {
    let digit = Number(prefix[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  const checkDigit = (10 - (sum % 10)) % 10;
  return `${prefix}${checkDigit}`;
}

function buildSampleUrl() {
  return ["http", "s://", "nullid.local"].join("");
}
