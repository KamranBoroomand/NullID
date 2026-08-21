export const DOCUMENT_CACHE_CONTROL = "public, max-age=0, must-revalidate, no-transform";

export const INDEXABLE_DOCUMENT_ROUTES = [
  "/",
  "/tools/",
  "/offline-file-encryption/",
  "/metadata-privacy/",
  "/local-redaction/",
  "/file-sanitization/",
  "/hash-and-verify/",
  "/secret-scanner/",
  "/password-generator/",
  "/safe-share/",
  "/package-verification/",
  "/privacy/",
  "/faq/",
];

export const REQUIRED_SECURITY_HEADERS = [
  "Content-Security-Policy",
  "Referrer-Policy",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
];

const APP_SHELL_DOCUMENT_ROUTES = ["/index.html"];
const DIRECT_NOT_FOUND_DOCUMENT_ROUTES = ["/404.html"];
const UNKNOWN_NOT_FOUND_DOCUMENT_ROUTES = ["/this-page-definitely-does-not-exist-9f47d"];
const NO_TRANSFORM_DOCUMENT_ROUTES = [
  ...INDEXABLE_DOCUMENT_ROUTES,
  ...APP_SHELL_DOCUMENT_ROUTES,
  ...DIRECT_NOT_FOUND_DOCUMENT_ROUTES,
  ...UNKNOWN_NOT_FOUND_DOCUMENT_ROUTES,
];

const STATIC_ASSET_CACHE_DETACHMENT_PROBES = [
  "/.vite/manifest.json",
  "/SHA256SUMS",
  "/assets/index-probe.js",
  "/assets/styles-probe.css",
  "/brand/nullid-mark-light.svg",
  "/build.json",
  "/deploy-manifest.json",
  "/favicon.svg",
  "/icons/favicon-32.png",
  "/manifest.webmanifest",
  "/nullid-precache-manifest.json",
  "/nullid-preview.png",
  "/robots.txt",
  "/sbom.json",
  "/site.css",
  "/sitemap.xml",
  "/sw.js",
];

export function parseHeadersFile(content) {
  const blocks = [];
  let current = null;
  content.split(/\r?\n/).forEach((line) => {
    if (!line.trim()) return;
    if (/^\s*#/u.test(line)) return;
    if (/^\S/.test(line) && !line.includes(":")) {
      current = { source: line.trim(), headers: [] };
      blocks.push(current);
      return;
    }
    const detachMatch = line.match(/^\s*!\s*([A-Za-z-]+)\s*$/u);
    if (detachMatch && current) {
      current.headers.push({ key: detachMatch[1], value: "", detach: true });
      return;
    }
    const match = line.match(/^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$/);
    if (!match || !current) return;
    current.headers.push({ key: match[1], value: match[2], detach: false });
  });
  return blocks;
}

export function validateStaticHostHeaderPolicy(blocks, sourceLabel, options = {}) {
  validateSecurityHeaderBaseline(blocks, sourceLabel);
  validateHtmlNoTransformPolicy(blocks, sourceLabel);
  validateStaticAssetCacheDetachment(blocks, sourceLabel, options.staticAssetPaths ?? []);
}

export function validateSecurityHeaderBaseline(blocks, sourceLabel) {
  const catchAllBlocks = blocks.filter((block) => isCatchAllRoute(block.source));
  if (catchAllBlocks.length !== 1) {
    throw new Error(`${sourceLabel} must define exactly one catch-all header route`);
  }
  const headers = toHeaderMap(catchAllBlocks[0], sourceLabel);
  validateSecurityHeaderMap(headers, sourceLabel);
}

export function validateHtmlNoTransformPolicy(blocks, sourceLabel) {
  for (const route of NO_TRANSFORM_DOCUMENT_ROUTES) {
    const headers = resolveHeadersForRequestPath(blocks, route, sourceLabel);
    assertExact(headers.get("Cache-Control"), DOCUMENT_CACHE_CONTROL, "Cache-Control", sourceLabel);
  }

  for (const assetPath of STATIC_ASSET_CACHE_DETACHMENT_PROBES) {
    const headers = resolveHeadersForRequestPath(blocks, assetPath, sourceLabel);
    if (headers.has("Cache-Control")) {
      throw new Error(`${sourceLabel} must detach Cache-Control for static asset path ${assetPath}`);
    }
  }
}

export function validateStaticAssetCacheDetachment(blocks, sourceLabel, assetPaths) {
  for (const assetPath of assetPaths) {
    const headers = resolveHeadersForRequestPath(blocks, assetPath, sourceLabel);
    if (headers.has("Cache-Control")) {
      throw new Error(`${sourceLabel} applies document Cache-Control to static asset ${assetPath}`);
    }
  }
}

export function resolveHeadersForRequestPath(blocks, requestPath, sourceLabel = "headers") {
  const map = new Map();
  for (const block of blocks) {
    if (!matchesHeaderRule(block.source, requestPath)) continue;
    for (const header of block.headers) {
      if (header.detach) {
        map.delete(header.key);
        continue;
      }
      const existing = map.get(header.key);
      if (existing !== undefined) {
        throw new Error(`Duplicate ${header.key} applies to ${requestPath} in ${sourceLabel}`);
      }
      map.set(header.key, header.value);
    }
  }
  return map;
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

function validateSecurityHeaderMap(headers, sourceLabel) {
  const missing = REQUIRED_SECURITY_HEADERS.filter((name) => !headers.has(name));
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

function matchesHeaderRule(source, requestPath) {
  if (source === requestPath) return true;
  if (!source.includes("*")) return false;
  const pattern = source
    .split("*")
    .map((segment) => segment.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"))
    .join(".*");
  return new RegExp(`^${pattern}$`, "u").test(requestPath);
}

function normalize(value) {
  return String(value ?? "").trim();
}
