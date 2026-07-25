import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildBatchReviewExport, createBatchFileReviewItem, createBatchTextReviewItem } from "../utils/batchReview.js";

describe("batchReview", () => {
  it("creates a text review item with grouped findings", async () => {
    const item = await createBatchTextReviewItem({
      id: "text-1",
      label: "entry",
      text: "alice@example.com token=ABCDEFGHIJKLMNOPQRSTUV123456 شماره کارت: ۶۰۳۷-۹۹۷۳-۹۱۸۹-۸۰۸۸",
      enabledRuleSets: { iran: true, russia: false },
    });

    assert.equal(item.kind, "text");
    assert.equal(item.structuredAnalysis?.countsByCategory.emails, 1);
    assert.equal(item.structuredAnalysis?.countsByCategory.financial ? item.structuredAnalysis.countsByCategory.financial > 0 : false, true);
    assert.equal(item.financialReview?.total ? item.financialReview.total > 0 : false, true);
    assert.equal(item.secretScan?.total ? item.secretScan.total > 0 : false, true);
    assert.equal(item.summary.redaction.length > 0, true);
  });

  it("creates a file review item and exports a report", async () => {
    const bytes = new TextEncoder().encode("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456");
    const item = await createBatchFileReviewItem({
      id: "file-1",
      label: "employee-12345.txt",
      fileName: "employee-12345.txt",
      fileMediaType: "text/plain",
      sourceBytes: bytes,
    });
    const report = buildBatchReviewExport([item]);

    assert.equal(item.kind, "file");
    assert.equal(item.metadataAnalysis?.format, "unknown");
    assert.equal(item.secretScan?.total ? item.secretScan.total > 0 : false, true);
    assert.equal(item.pathPrivacy?.findings.length ? item.pathPrivacy.findings.length > 0 : false, true);
    assert.equal(report.itemCount, 1);
    assert.equal(report.items[0]?.sections.some((section) => section.id === "secret-scan"), true);
    assert.equal(report.items[0]?.sections.some((section) => section.id === "path-privacy"), true);
  });
});
