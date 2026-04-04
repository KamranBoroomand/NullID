import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildArchiveComparisonReport,
  verifyArchiveInspection,
} from "../utils/archiveInspection.js";

describe("archiveInspection", () => {
  it("groups matched, missing, extra, and hash-mismatch results explicitly", () => {
    const inspection = {
      schemaVersion: 1 as const,
      kind: "nullid-archive-inspection" as const,
      createdAt: new Date().toISOString(),
      fileCount: 3,
      directoryCount: 0,
      entryCount: 3,
      entries: [
        {
          path: "docs/readme.txt",
          directory: false,
          compressionMethod: 0,
          compressionLabel: "stored",
          compressedBytes: 13,
          uncompressedBytes: 13,
          sha256: "1612156f640b4c019a738d4857bb1f2d08cb9c75a359e15d13f6f89ba16f7c83",
          status: "hashed" as const,
          detail: "SHA-256 computed from extracted entry bytes.",
        },
        {
          path: "data/report.json",
          directory: false,
          compressionMethod: 0,
          compressionLabel: "stored",
          compressedBytes: 11,
          uncompressedBytes: 11,
          sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          status: "hashed" as const,
          detail: "SHA-256 computed from extracted entry bytes.",
        },
        {
          path: "extra.txt",
          directory: false,
          compressionMethod: 0,
          compressionLabel: "stored",
          compressedBytes: 5,
          uncompressedBytes: 5,
          sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          status: "hashed" as const,
          detail: "SHA-256 computed from extracted entry bytes.",
        },
      ],
      warnings: [],
    };
    const result = verifyArchiveInspection(inspection, [
      { path: "docs/readme.txt", sha256: "1612156f640b4c019a738d4857bb1f2d08cb9c75a359e15d13f6f89ba16f7c83", source: "archive-manifest" },
      { path: "data/report.json", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", source: "archive-manifest" },
      { path: "missing.txt", sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", source: "archive-manifest" },
    ]);
    const report = buildArchiveComparisonReport(result);

    assert.equal(result.groups.matched.some((entry) => entry.path === "docs/readme.txt"), true);
    assert.equal(result.groups.hashMismatch.some((entry) => entry.path === "data/report.json"), true);
    assert.equal(result.groups.missing.some((entry) => entry.path === "missing.txt"), true);
    assert.equal(report.groups.hashMismatch.length, 1);
    assert.equal(report.groups.missing.length, 1);
    assert.equal(report.sections.some((section) => section.label === "Matched"), true);
    assert.equal(report.sections.some((section) => section.label === "Missing"), true);
    assert.equal(report.sections.some((section) => section.label === "Hash mismatch"), true);
    assert.equal(report.sections.some((section) => section.label === "Local facts"), true);
    assert.equal(report.manualReviewRecommendations.length > 0, true);
  });
});
