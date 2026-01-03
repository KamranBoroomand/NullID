import fs from "node:fs";
import path from "node:path";

const DIST_DIR = path.resolve("dist");

function fail(message) {
  console.error(message);
  process.exit(1);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

assert(fs.existsSync(DIST_DIR), `dist directory missing at ${DIST_DIR}`);

const indexPath = path.join(DIST_DIR, "index.html");
assert(fs.existsSync(indexPath), "dist/index.html missing");

const indexHtml = fs.readFileSync(indexPath, "utf8");
const assetMatches = [...indexHtml.matchAll(/<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']/g)]
  .map((match) => match[1])
  .filter((url) => /(^|\/)assets\//.test(url))
  .map((url) => path.basename(url.split("?")[0]));
if (assetMatches.length === 0) {
  console.error("No JS assets referenced in index.html. First lines:");
  console.error(indexHtml.split("\n").slice(0, 30).join("\n"));
  fail("No JS assets referenced in index.html");
}

assert(assetMatches.length > 0, "No JS assets referenced in index.html");

const guideHints = [/Guide/i, /\bguide\b/i];
const found = assetMatches.some((asset) => {
  const assetPath = path.join(DIST_DIR, "assets", asset);
  if (!fs.existsSync(assetPath)) {
    fail(`Referenced asset missing: ${assetPath}`);
  }
  const content = fs.readFileSync(assetPath, "utf8");
  return guideHints.some((pattern) => pattern.test(content));
});

assert(found, "Guide markers not found in built assets");

console.log("assert-guide: Guide markers present in build");
