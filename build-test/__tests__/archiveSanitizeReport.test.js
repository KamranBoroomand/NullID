import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

describe("archive-sanitize report contract", () => {
  it("includes per-file findings and severity totals in manifest", () => {
    if (!hasCommand("zip") || !hasCommand("unzip")) {
      return;
    }

    const root = path.resolve(process.cwd());
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-archive-test-"));

    try {
      const inputDir = path.join(tempRoot, "input");
      const extractedDir = path.join(tempRoot, "out");
      const outputZip = path.join(tempRoot, "sanitized.zip");
      fs.mkdirSync(inputDir, { recursive: true });

      fs.writeFileSync(
        path.join(inputDir, "sensitive.log"),
        "user=alice@example.com token=abcdefghijklmnopqrstuvwxyz12345 from 203.0.113.42\n",
        "utf8",
      );
      fs.writeFileSync(path.join(inputDir, "notes.txt"), "just text with no secrets\n", "utf8");
      fs.writeFileSync(path.join(inputDir, "raw.bin"), Buffer.from([0x00, 0xff, 0x88, 0x99]));
      fs.writeFileSync(path.join(inputDir, "binary.log"), Buffer.from([0x00, 0xff, 0x88, 0x99]));

      execFileSync("node", ["scripts/nullid-local.mjs", "archive-sanitize", inputDir, outputZip], {
        cwd: root,
        stdio: "pipe",
      });

      fs.mkdirSync(extractedDir, { recursive: true });
      execFileSync("unzip", ["-q", outputZip, "-d", extractedDir], { stdio: "pipe" });

      const manifestPath = path.join(extractedDir, "nullid-archive-manifest.json");
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

      assert.equal(manifest.kind, "nullid-archive-manifest");
      assert.equal(manifest.schemaVersion, 2);
      assert.equal(typeof manifest.summary.findingTotal, "number");
      assert.equal(typeof manifest.summary.severityTotals.high, "number");
      assert.equal(typeof manifest.summary.severityTotals.medium, "number");
      assert.equal(typeof manifest.summary.severityTotals.low, "number");
      assert.equal(manifest.summary.findingTotal > 0, true);

      const sensitive = manifest.files.find((entry) => entry.path === "sensitive.log");
      assert.equal(Boolean(sensitive), true);
      assert.equal(sensitive.findings.scanned, true);
      assert.equal(sensitive.findings.total > 0, true);
      assert.equal(sensitive.findings.bySeverity.high > 0, true);

      const binary = manifest.files.find((entry) => entry.path === "binary.log");
      assert.equal(Boolean(binary), true);
      assert.equal(binary.findings.scanned, false);
      assert.equal(binary.findings.reason, "binary");
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });
});

function hasCommand(name) {
  try {
    const checker = process.platform === "win32" ? "where" : "which";
    execFileSync(checker, [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
