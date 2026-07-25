#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const rootDir = path.resolve(getOption(argv, "--root") || "test-results");
const outDir = path.resolve(getOption(argv, "--out") || "output");
const cwd = process.cwd();

const entries = fs.existsSync(rootDir) ? collectDiffEntries(rootDir) : [];
const report = {
  schemaVersion: 1,
  kind: "nullid-visual-drift-report",
  generatedAt: new Date().toISOString(),
  root: path.relative(cwd, rootDir),
  driftCount: entries.length,
  entries,
};

fs.mkdirSync(outDir, { recursive: true });
const jsonPath = path.join(outDir, "visual-drift-report.json");
const mdPath = path.join(outDir, "visual-drift-summary.md");
fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
fs.writeFileSync(mdPath, renderMarkdown(report), "utf8");

console.log(`[visual] drift report written: ${path.relative(cwd, jsonPath)} (${entries.length} diff artifact${entries.length === 1 ? "" : "s"})`);

function collectDiffEntries(baseDir) {
  const files = walkFiles(baseDir).filter((filePath) => filePath.endsWith("-diff.png"));
  return files
    .map((diffPath) => {
      const stem = diffPath.slice(0, -"-diff.png".length);
      const expectedPath = `${stem}-expected.png`;
      const actualPath = `${stem}-actual.png`;
      return {
        label: path.basename(stem),
        diff: toRelative(diffPath),
        expected: fs.existsSync(expectedPath) ? toRelative(expectedPath) : null,
        actual: fs.existsSync(actualPath) ? toRelative(actualPath) : null,
      };
    })
    .sort((a, b) => a.diff.localeCompare(b.diff));
}

function walkFiles(dir) {
  const entries = [];
  for (const name of fs.readdirSync(dir)) {
    const fullPath = path.join(dir, name);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      entries.push(...walkFiles(fullPath));
    } else if (stat.isFile()) {
      entries.push(fullPath);
    }
  }
  return entries;
}

function toRelative(filePath) {
  return path.relative(cwd, filePath);
}

function renderMarkdown(report) {
  if (report.driftCount === 0) {
    return "# Visual Drift Summary\n\nNo visual drift artifacts were detected.\n";
  }
  const lines = ["# Visual Drift Summary", "", `Detected ${report.driftCount} diff artifact${report.driftCount === 1 ? "" : "s"}.`, ""];
  report.entries.forEach((entry, index) => {
    lines.push(`${index + 1}. ${entry.label}`);
    lines.push(`   - diff: \`${entry.diff}\``);
    if (entry.expected) lines.push(`   - expected: \`${entry.expected}\``);
    if (entry.actual) lines.push(`   - actual: \`${entry.actual}\``);
  });
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function getOption(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}
