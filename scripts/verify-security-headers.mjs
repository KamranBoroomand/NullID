import fs from "node:fs";
import path from "node:path";

const REQUIRED_HEADERS = [
  "Content-Security-Policy",
  "Referrer-Policy",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Permissions-Policy",
];

const ROOT = process.cwd();

function loadHeadersFile() {
  const file = path.join(ROOT, "public", "_headers");
  if (!fs.existsSync(file)) {
    throw new Error("Missing public/_headers security policy file");
  }
  return fs.readFileSync(file, "utf8");
}

function loadVercelConfig() {
  const file = path.join(ROOT, "vercel.json");
  if (!fs.existsSync(file)) {
    throw new Error("Missing vercel.json security header config");
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function ensureHeadersInText(content, sourceLabel) {
  const missing = REQUIRED_HEADERS.filter((header) => !content.includes(header));
  if (missing.length > 0) {
    throw new Error(`Missing ${missing.join(", ")} in ${sourceLabel}`);
  }
}

function ensureHeadersInVercel(config) {
  const entries = Array.isArray(config?.headers) ? config.headers : [];
  const keys = new Set(
    entries.flatMap((entry) => {
      if (!Array.isArray(entry?.headers)) return [];
      return entry.headers.map((item) => item?.key).filter(Boolean);
    }),
  );
  const missing = REQUIRED_HEADERS.filter((header) => !keys.has(header));
  if (missing.length > 0) {
    throw new Error(`Missing ${missing.join(", ")} in vercel.json`);
  }
}

try {
  const headersText = loadHeadersFile();
  const vercelConfig = loadVercelConfig();
  ensureHeadersInText(headersText, "public/_headers");
  ensureHeadersInVercel(vercelConfig);
  console.log("security headers: baseline config verified");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`security headers: ${message}`);
  process.exitCode = 1;
}
