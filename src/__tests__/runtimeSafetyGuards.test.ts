import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

describe("runtime safety static guards", () => {
  it("keeps user-controlled custom regex execution out of production main-thread paths", () => {
    const violations = listProductionRuntimeFiles()
      .flatMap((file) => {
        const source = fs.readFileSync(file, "utf8");
        return source.split("\n").flatMap((line, index) => {
          if (isAllowedCustomRegexRuntime(file, line)) return [];
          const userControlledRegex =
            /(?:new\s+RegExp|RegExp)\(\s*(?:entry|rule|task|customRuleDraft|rawPattern|pattern)\.(?:pattern|regex)\b/u.test(line)
            || /(?:new\s+RegExp|RegExp)\(\s*(?:entry|rule|task|customRuleDraft|rawPattern|pattern)\b/u.test(line)
            || /\.(?:match|replace|search|split)\(\s*(?:entry|rule|task|customRuleDraft|rawPattern|pattern)\.(?:pattern|regex)\b/u.test(line);
          return userControlledRegex ? [`${file}:${index + 1}:${line.trim()}`] : [];
        });
      });

    assert.deepEqual(violations, []);
  });

  it("pins Windows filesystem safety evidence outside the Tauri smoke job", () => {
    const quality = fs.readFileSync(".github/workflows/quality-gates.yml", "utf8");
    const tauriSmoke = fs.readFileSync(".github/workflows/desktop-tauri-smoke.yml", "utf8");

    assert.match(quality, /windows-latest/u);
    assert.match(quality, /CLI filesystem safety.*windows/i);
    assert.match(quality, /(?:npm\s+test\s+--|node\s+--test)\s+.*nullidLocalCli/u);
    assert.doesNotMatch(tauriSmoke, /CLI filesystem safety/u);
  });

  it("keeps custom-regex-dependent UI exports behind commitAllowed", () => {
    const sanitize = fs.readFileSync("src/views/SanitizeView.tsx", "utf8");
    const redact = fs.readFileSync("src/views/RedactView.tsx", "utf8");
    const safeShare = fs.readFileSync("src/views/SafeShareView.tsx", "utf8");
    const incident = fs.readFileSync("src/views/IncidentWorkflowView.tsx", "utf8");
    const workflowBuilder = fs.readFileSync("src/utils/safeShareAssistant.ts", "utf8");

    assert.match(sanitize, /const canCommitSanitized = result\.commitAllowed/u);
    assert.match(sanitize, /exportShareBundle[\s\S]+if \(!result\.commitAllowed\)/u);
    assert.match(sanitize, /disabled=\{isExportingBundle \|\| !canCommitSanitized\}/u);
    assert.match(sanitize, /batchResults\.some\(\(item\) => !item\.commitAllowed\)/u);

    assert.match(redact, /const canCommitRedaction = findings\.commitAllowed/u);
    assert.match(redact, /handleApply[\s\S]+if \(!canCommitRedaction\)/u);
    assert.match(redact, /disabled=\{!canCommitRedaction\}/u);

    assert.match(safeShare, /if \(!textPreview\.commitAllowed\)/u);
    assert.match(safeShare, /disabled=\{isExporting \|\| !previewPackage \|\| \(mode === "text" && !textPreview\.commitAllowed\)\}/u);
    assert.match(incident, /if \(!notesPreview\.commitAllowed\)/u);
    assert.match(incident, /disabled=\{isExporting \|\| !previewPackage \|\| !notesPreview\.commitAllowed\}/u);
    assert.match(workflowBuilder, /if \(!sanitize\.commitAllowed\)/u);
  });
});

function listProductionRuntimeFiles() {
  const roots = ["src", "scripts"];
  const out: string[] = [];
  const visit = (target: string) => {
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      fs.readdirSync(target)
        .filter((entry) => !entry.startsWith("."))
        .forEach((entry) => visit(path.join(target, entry)));
      return;
    }
    if (/\.(?:ts|tsx|js|mjs)$/u.test(target) && !target.includes(`${path.sep}__tests__${path.sep}`)) {
      out.push(target);
    }
  };
  roots.forEach((root) => visit(root));
  return out.sort();
}

function isAllowedCustomRegexRuntime(file: string, line: string) {
  const normalized = file.split(path.sep).join("/");
  if (normalized === "src/utils/customRegexWorker.ts") return true;
  if (normalized === "src/utils/customRegex.ts" && line.includes("new RegExp(task.pattern")) return true;
  if (normalized === "scripts/nullid-local.mjs" && line.includes("new RegExp(task.pattern")) return true;
  if (normalized === "src/utils/redaction.ts" && line.includes("new RegExp(rule.regex, rule.regex.flags)")) return true;
  return false;
}
