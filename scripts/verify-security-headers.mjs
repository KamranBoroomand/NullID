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
  const headersBlocks = parseHeadersFile(loadHeadersFile());
  const vercelBlocks = parseVercelHeaders(loadVercelConfig());

  validateHeaderBlocks(headersBlocks, "public/_headers");
  validateHeaderBlocks(vercelBlocks, "vercel.json");
  console.log("security headers: strict baseline config verified");
} catch (error) {
  const message = error instanceof Error ? error.message : "header verification failed";
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

function parseHeadersFile(content) {
  const blocks = [];
  let current = null;
  content.split(/\r?\n/).forEach((line) => {
    if (!line.trim()) return;
    if (/^\S/.test(line) && !line.includes(":")) {
      current = { source: line.trim(), headers: [] };
      blocks.push(current);
      return;
    }
    const match = line.match(/^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$/);
    if (!match || !current) return;
    current.headers.push({ key: match[1], value: match[2] });
  });
  return blocks;
}

function parseVercelHeaders(config) {
  const entries = Array.isArray(config?.headers) ? config.headers : [];
  return entries.map((entry) => ({
    source: typeof entry?.source === "string" ? entry.source : "",
    headers: Array.isArray(entry?.headers)
      ? entry.headers
          .filter((header) => typeof header?.key === "string" && typeof header.value === "string")
          .map((header) => ({ key: header.key, value: header.value }))
      : [],
  }));
}

function validateHeaderBlocks(blocks, sourceLabel) {
  const catchAllBlocks = blocks.filter((block) => isCatchAllRoute(block.source));
  if (catchAllBlocks.length !== 1) {
    throw new Error(`${sourceLabel} must define exactly one catch-all header route`);
  }
  const headers = toHeaderMap(catchAllBlocks[0], sourceLabel);
  validateHeaderMap(headers, sourceLabel);
}

function toHeaderMap(block, sourceLabel) {
  const map = new Map();
  block.headers.forEach((header) => {
    const existing = map.get(header.key);
    if (existing !== undefined && normalize(existing) !== normalize(header.value)) {
      throw new Error(`Conflicting ${header.key} definitions in ${sourceLabel} route ${block.source}`);
    }
    if (existing !== undefined) {
      throw new Error(`Duplicate ${header.key} definition in ${sourceLabel} route ${block.source}`);
    }
    map.set(header.key, header.value);
  });
  return map;
}

function validateHeaderMap(headers, sourceLabel) {
  const missing = REQUIRED_HEADERS.filter((name) => !headers.has(name));
  if (missing.length > 0) {
    throw new Error(`Missing ${missing.join(", ")} in catch-all route for ${sourceLabel}`);
  }

  validateCsp(headers.get("Content-Security-Policy"), sourceLabel);
  assertExact(headers.get("Referrer-Policy"), "no-referrer", "Referrer-Policy", sourceLabel);
  assertExact(headers.get("X-Content-Type-Options"), "nosniff", "X-Content-Type-Options", sourceLabel);
  assertExact(headers.get("X-Frame-Options"), "DENY", "X-Frame-Options", sourceLabel);
  assertExact(headers.get("Cross-Origin-Opener-Policy"), "same-origin", "Cross-Origin-Opener-Policy", sourceLabel);
  validatePermissionsPolicy(headers.get("Permissions-Policy"), sourceLabel);
}

function validateCsp(rawValue, sourceLabel) {
  const directives = parseCsp(normalize(rawValue));

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
    if (map.has(name)) throw new Error(`Duplicate CSP directive ${name}`);
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

function isCatchAllRoute(source) {
  return source === "/*" || source === "/(.*)" || source === "/**";
}

function normalize(value) {
  return String(value ?? "").trim();
}
