import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeFinancialIdentifiers } from "../utils/financialReview.js";

describe("financialReview", () => {
  it("detects Iranian cards and Sheba values after mixed-digit normalization", () => {
    const result = analyzeFinancialIdentifiers(
      "شماره کارت: ۶۰۳۷-۹۹۷۳-۹۱۸۹-۸۰۸۸ شبا IR۸۲۰۵۴۰۱۰۲۶۸۰۰۲۰۸۱۷۹۰۹۰۰۲",
      { enabledRuleSets: { iran: true, russia: false } },
    );

    assert.equal(result.findings.some((finding) => finding.label === "Iran bank card"), true);
    assert.equal(result.findings.some((finding) => finding.label === "Iran Sheba"), true);
    assert.equal(result.redactionMatches.length >= 2, true);
  });

  it("labels account and reference contexts conservatively", () => {
    const result = analyzeFinancialIdentifiers("account number: 123456789012 invoice: INV-44321");

    assert.equal(result.findings.some((finding) => finding.label === "Account-like number"), true);
    assert.equal(result.findings.some((finding) => finding.label === "Invoice / reference number"), true);
    assert.equal(result.findings.some((finding) => finding.detectionKind === "heuristic"), true);
  });
});
