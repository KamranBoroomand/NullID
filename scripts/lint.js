import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const ROOT = process.cwd();
const SCAN_DIRS = ["src"];
const FILE_RE = /\.(ts|tsx|js|jsx)$/i;
const URL_RE = /\bhttps?:\/\/|wss?:\/\//i;
const NETWORK_CONSTRUCTORS = new Set(["WebSocket", "EventSource", "XMLHttpRequest"]);
const NETWORK_CALLS = new Set(["fetch", "importScripts"]);
const NETWORK_PROPERTIES = new Set(["fetch", "sendBeacon", "open"]);

const issues = [];

for (const dir of SCAN_DIRS) {
  walk(path.join(ROOT, dir));
}

if (issues.length > 0) {
  for (const issue of issues) {
    console.error(`lint: ${issue.file}:${issue.line}:${issue.column} ${issue.message}`);
  }
  process.exitCode = 1;
} else {
  console.log("lint: no disallowed network calls detected");
}

function walk(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "docs" || entry.name === "build-test") {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    if (!entry.isFile() || !FILE_RE.test(entry.name)) continue;
    scanFile(full);
  }
}

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);

  visit(sourceFile);

  function visit(node) {
    if (ts.isStringLiteralLike(node) && URL_RE.test(node.text)) {
      report(node, `hardcoded external URL literal "${node.text}"`);
    } else if (ts.isTemplateExpression(node)) {
      if (URL_RE.test(node.head.text) || node.templateSpans.some((span) => URL_RE.test(span.literal.text))) {
        report(node, "hardcoded external URL template literal");
      }
    } else if (ts.isCallExpression(node)) {
      const callName = resolveCallName(node.expression);
      if (callName && NETWORK_CALLS.has(callName)) {
        report(node, `disallowed network call "${callName}(...)"`);
      }
      if (callName && NETWORK_PROPERTIES.has(callName)) {
        if (callName === "open" && isLikelyXmlHttpRequestOpen(node.expression)) {
          report(node, 'disallowed XHR call "open(...)"');
        } else if (callName === "fetch" || callName === "sendBeacon") {
          report(node, `disallowed network property call "${callName}(...)"`);
        }
      }
    } else if (ts.isNewExpression(node)) {
      const ctorName = resolveCallName(node.expression);
      if (ctorName && NETWORK_CONSTRUCTORS.has(ctorName)) {
        report(node, `disallowed network constructor "new ${ctorName}(...)"`);
      }
    }

    ts.forEachChild(node, visit);
  }

  function report(node, message) {
    const start = node.getStart(sourceFile);
    const pos = sourceFile.getLineAndCharacterOfPosition(start);
    issues.push({
      file: path.relative(ROOT, filePath),
      line: pos.line + 1,
      column: pos.character + 1,
      message,
    });
  }
}

function resolveCallName(expression) {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return null;
}

function isLikelyXmlHttpRequestOpen(expression) {
  if (!ts.isPropertyAccessExpression(expression)) return false;
  const left = expression.expression.getText();
  return /xmlhttprequest/i.test(left) || /\bxhr\b/i.test(left);
}
