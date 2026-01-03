import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const DISALLOWED = [/\bfetch\(/i, /http:\/\//i, /https:\/\//i];
const SCAN_DIRS = ["src"];
let violations = 0;

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  DISALLOWED.forEach((pattern) => {
    if (pattern.test(content)) {
      console.error(`lint: disallowed pattern ${pattern} in ${filePath}`);
      violations += 1;
    }
  });
}

function walk(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  entries.forEach((entry) => {
    if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "docs" || entry.name === "build-test") return;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else if (entry.isFile() && /\.(ts|tsx|js|jsx)$/i.test(entry.name)) {
      scanFile(full);
    }
  });
}

SCAN_DIRS.forEach((dir) => walk(path.join(ROOT, dir)));

if (violations > 0) {
  process.exitCode = 1;
} else {
  console.log("lint: no disallowed network calls detected");
}
