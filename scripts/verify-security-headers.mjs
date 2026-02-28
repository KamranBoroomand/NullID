import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const REQUIRED_HEADERS = [
  "Content-Security-Policy",
  "Referrer-Policy",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
];

try {
  const headersText = loadHeadersFile();
  const vercelConfig = loadVercelConfig();

  const publicHeaders = parseHeaderPairs(headersText);
  const vercelHeaders = parseVercelHeaders(vercelConfig);

  validateHeaderMap(publicHeaders, "public/_headers");
  validateHeaderMap(vercelHeaders, "vercel.json");
  console.log("security headers: strict baseline config verified");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`security headers: ${message}`);
  process.exitCode = 1;
}

function loadHeadersFile() {
  const file = path.join(ROOT, "public", "_headers");
  if (!fs.existsSync(file)) throw new Error("Missing public/_headers security policy file");
  return fs.readFileSync(file, "utf8");
}

function loadVercelConfig() {
  const file = path.join(ROOT, "vercel.json");
  if (!fs.existsSync(file)) throw new Error("Missing vercel.json security header config");
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function parseHeaderPairs(content) {
  const map = new Map();
  const regex = /^\s*(?:\/\*+)?\s*([A-Za-z-]+)\s*:\s*(.+?)\s*(?:\*\/)?\s*$/gm;
  let match = regex.exec(content);
  while (match) {
    map.set(match[1], match[2]);
    match = regex.exec(content);
  }
  return map;
}

function parseVercelHeaders(config) {
  const map = new Map();
  const entries = Array.isArray(config?.headers) ? config.headers : [];
  for (const entry of entries) {
    const list = Array.isArray(entry?.headers) ? entry.headers : [];
    for (const header of list) {
      if (!header?.key || typeof header.value !== "string") continue;
      map.set(header.key, header.value);
    }
  }
  return map;
}

function validateHeaderMap(headers, sourceLabel) {
  const missing = REQUIRED_HEADERS.filter((name) => !headers.has(name));
  if (missing.length > 0) {
    throw new Error(`Missing ${missing.join(", ")} in ${sourceLabel}`);
  }

  validateCsp(headers.get("Content-Security-Policy"), sourceLabel);
  assertExact(headers.get("Referrer-Policy"), "no-referrer", "Referrer-Policy", sourceLabel);
  assertExact(headers.get("X-Content-Type-Options"), "nosniff", "X-Content-Type-Options", sourceLabel);
  assertExact(headers.get("X-Frame-Options"), "DENY", "X-Frame-Options", sourceLabel);
  assertExact(headers.get("Cross-Origin-Opener-Policy"), "same-origin", "Cross-Origin-Opener-Policy", sourceLabel);
  validatePermissionsPolicy(headers.get("Permissions-Policy"), sourceLabel);
}

function validateCsp(rawValue, sourceLabel) {
  const value = normalize(rawValue);
  const directives = parseCsp(value);

  requireDirectiveToken(directives, "default-src", "'self'", sourceLabel);
  requireDirectiveToken(directives, "script-src", "'self'", sourceLabel);
  requireDirectiveToken(directives, "style-src", "'self'", sourceLabel);
  requireDirectiveToken(directives, "style-src", "'unsafe-inline'", sourceLabel);
  requireDirectiveToken(directives, "img-src", "'self'", sourceLabel);
  requireDirectiveToken(directives, "img-src", "blob:", sourceLabel);
  requireDirectiveToken(directives, "img-src", "data:", sourceLabel);
  requireDirectiveToken(directives, "font-src", "'self'", sourceLabel);
  requireDirectiveToken(directives, "connect-src", "'self'", sourceLabel);
  requireDirectiveToken(directives, "worker-src", "'self'", sourceLabel);
  requireDirectiveToken(directives, "base-uri", "'none'", sourceLabel);
  requireDirectiveToken(directives, "object-src", "'none'", sourceLabel);
  requireDirectiveToken(directives, "frame-ancestors", "'none'", sourceLabel);
  requireDirectiveToken(directives, "form-action", "'self'", sourceLabel);
}

function validatePermissionsPolicy(rawValue, sourceLabel) {
  const value = normalize(rawValue);
  const required = ["camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"];
  const missing = required.filter((token) => !value.includes(token));
  if (missing.length > 0) {
    throw new Error(`Permissions-Policy missing ${missing.join(", ")} in ${sourceLabel}`);
  }
}

function parseCsp(value) {
  const map = new Map();
  for (const segment of value.split(";")) {
    const trimmed = segment.trim();
    if (!trimmed) continue;
    const [name, ...tokens] = trimmed.split(/\s+/);
    map.set(name, tokens);
  }
  return map;
}

function requireDirectiveToken(cspMap, directive, token, sourceLabel) {
  const tokens = cspMap.get(directive);
  if (!tokens || !tokens.includes(token)) {
    throw new Error(`CSP directive ${directive} missing token ${token} in ${sourceLabel}`);
  }
}

function assertExact(actualValue, expected, headerName, sourceLabel) {
  const actual = normalize(actualValue);
  if (actual !== expected) {
    throw new Error(`${headerName} must be "${expected}" in ${sourceLabel} (received "${actual}")`);
  }
}

function normalize(value) {
  return String(value ?? "").trim();
}
