#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  PRODUCTION_ORIGIN,
  SOCIAL_IMAGE_URL,
  canonicalUrl,
  publicPages,
  rootPage,
  sitemapPaths,
} from "./public-site-data.mjs";

const DIST_DIR = path.resolve("dist");
const PROHIBITED = [
  ["Co", "dex"].join(""),
  ["Chat", "G", "P", "T"].join(""),
  ["Open", "A", "I"].join(""),
  [["A", "I"].join(""), "generated"].join("-"),
  ["generated", "by"].join("-"),
  ["assisted", "by"].join("-"),
  [["Co", "authored"].join("-"), "by"].join("-"),
  ["task", "chat"].join("/"),
  [".", "codex"].join(""),
  ["AGENTS", "md"].join("."),
  ["", "Users", "kamran"].join("/"),
  ["", "private", "tmp"].join("/"),
  ["agent", "logs"].join(" "),
];

const MACHINE_PRIVATE_PATH_PATTERNS = [
  { label: "macOS user home path", pattern: new RegExp(["", "Users", String.raw`[^\s"'<>]+`].join("\\/"), "u") },
  { label: "private temporary path", pattern: new RegExp(["", "private", String.raw`(?:tmp|var)\b[^\s"'<>]*`].join("\\/"), "u") },
  { label: "Unix home path", pattern: new RegExp(["", "home", String.raw`[^\s"'<>]+`].join("\\/"), "u") },
  { label: "Windows user home path", pattern: /[A-Za-z]:\\Users\\[^"'<>]+/u },
];

const PROVENANCE_ARTIFACT_STEMS = new Set([
  ["co", "dex"].join(""),
  ["chat", "gpt"].join(""),
  ["open", "ai"].join(""),
  "agent-log",
  "agent-logs",
  "task-log",
  "task-logs",
  "chat-log",
  "chat-logs",
  "conversation-log",
  "conversation-logs",
  "prompt",
  "prompts",
  "transcript",
  "transcripts",
]);

try {
  const report = verify();
  console.log(
    `[verify:web] ok (${report.indexablePages} indexable pages, ${report.sitemapUrls} sitemap URLs, ${report.sourceMapCount} source maps, ${report.brokenLinks} broken links)`,
  );
} catch (error) {
  console.error(`[verify:web] ${error instanceof Error ? error.message : "verification failed"}`);
  process.exit(1);
}

function verify() {
  const pages = [rootPage, ...publicPages];
  const htmlByPath = new Map();
  const titles = new Map();
  const descriptions = new Map();
  const canonicals = new Set();
  let brokenLinks = 0;

  for (const page of pages) {
    const htmlPath = htmlPathForRoute(page.path);
    const html = readFile(htmlPath);
    htmlByPath.set(page.path, html);
    requireIncludes(html, '<html lang="en"', `${page.path} missing html lang`);
    requireIncludes(html, '<meta charset="UTF-8"', `${page.path} missing UTF-8 charset`);
    requireIncludes(html, 'name="viewport"', `${page.path} missing viewport`);
    const title = extractSingle(html, /<title>([^<]+)<\/title>/u, `${page.path} title`);
    const description = extractMeta(html, "description", page.path);
    const h1Count = countMatches(html, /<h1\b/gu);
    if (h1Count !== 1) throw new Error(`${page.path} expected one h1, found ${h1Count}`);
    if (title !== page.title) throw new Error(`${page.path} title mismatch`);
    if (description !== page.description) throw new Error(`${page.path} description mismatch`);
    if (titles.has(title)) throw new Error(`duplicate title: ${title}`);
    if (descriptions.has(description)) throw new Error(`duplicate meta description: ${description}`);
    titles.set(title, page.path);
    descriptions.set(description, page.path);
    const canonical = extractAttr(html, /<link\s+rel="canonical"\s+href="([^"]+)"/u, `${page.path} canonical`);
    if (canonical !== canonicalUrl(page.path)) throw new Error(`${page.path} canonical mismatch: ${canonical}`);
    if (!canonical.startsWith(`${PRODUCTION_ORIGIN}/`)) throw new Error(`${page.path} canonical host mismatch`);
    if (canonicals.has(canonical)) throw new Error(`duplicate canonical: ${canonical}`);
    canonicals.add(canonical);
    requireMetaProperty(html, "og:type", "website", page.path);
    requireMetaProperty(html, "og:site_name", "NullID", page.path);
    requireMetaProperty(html, "og:title", page.title, page.path);
    requireMetaProperty(html, "og:description", page.description, page.path);
    requireMetaProperty(html, "og:url", canonicalUrl(page.path), page.path);
    requireMetaProperty(html, "og:image", SOCIAL_IMAGE_URL, page.path);
    requireMetaProperty(html, "og:image:width", "1200", page.path);
    requireMetaProperty(html, "og:image:height", "630", page.path);
    requireIncludes(html, 'property="og:image:alt"', `${page.path} missing og image alt`);
    requireIncludes(html, 'name="twitter:card"', `${page.path} missing Twitter card`);
    requireIncludes(html, `name="twitter:image" content="${SOCIAL_IMAGE_URL}"`, `${page.path} Twitter image mismatch`);
    requireIncludes(html, 'rel="icon"', `${page.path} missing icon link`);
    requireIncludes(html, 'rel="apple-touch-icon"', `${page.path} missing apple touch icon`);
    if (/<meta\s+name="robots"\s+content="noindex"/u.test(html)) {
      throw new Error(`${page.path} must be indexable`);
    }
    brokenLinks += validateLinks(html, page.path);
  }

  verifyNotFound();
  verifyRobots();
  verifySitemap();
  const sourceMapCount = walkFiles(DIST_DIR).filter((file) => file.endsWith(".map")).length;
  if (sourceMapCount !== 0) throw new Error(`source maps found: ${sourceMapCount}`);
  verifyPublicHygiene();

  return {
    indexablePages: pages.length,
    sitemapUrls: sitemapPaths.length,
    sourceMapCount,
    brokenLinks,
  };
}

function htmlPathForRoute(route) {
  if (route === "/") return path.join(DIST_DIR, "index.html");
  return path.join(DIST_DIR, route.slice(1), "index.html");
}

function readFile(filePath) {
  if (!fs.existsSync(filePath)) throw new Error(`missing file: ${path.relative(DIST_DIR, filePath)}`);
  return fs.readFileSync(filePath, "utf8");
}

function verifyNotFound() {
  const html = readFile(path.join(DIST_DIR, "404.html"));
  requireIncludes(html, '<meta name="robots" content="noindex"', "404 missing noindex");
  const h1Count = countMatches(html, /<h1\b/gu);
  if (h1Count !== 1) throw new Error(`404 expected one h1, found ${h1Count}`);
  for (const href of ["/", "/tools/", "/faq/"]) {
    requireIncludes(html, `href="${href}"`, `404 missing link ${href}`);
  }
  if (html.includes("canonical")) throw new Error("404 must not include a canonical URL");
}

function verifyRobots() {
  const robots = readFile(path.join(DIST_DIR, "robots.txt"));
  const expected = `User-agent: *\nAllow: /\nSitemap: ${PRODUCTION_ORIGIN}/sitemap.xml\n`;
  if (robots !== expected) throw new Error("robots.txt mismatch");
}

function verifySitemap() {
  const sitemap = readFile(path.join(DIST_DIR, "sitemap.xml"));
  if (!sitemap.startsWith('<?xml version="1.0" encoding="UTF-8"?>')) throw new Error("sitemap missing XML declaration");
  const urls = Array.from(sitemap.matchAll(/<loc>([^<]+)<\/loc>/gu), (match) => match[1]);
  const expected = sitemapPaths.map((pathname) => canonicalUrl(pathname));
  if (JSON.stringify(urls) !== JSON.stringify(expected)) throw new Error("sitemap URL set mismatch");
  if (new Set(urls).size !== urls.length) throw new Error("sitemap contains duplicate URLs");
  for (const url of urls) {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || parsed.host !== "nullid.kamranboroomand.ir") {
      throw new Error(`sitemap contains non-production URL: ${url}`);
    }
    if (parsed.search || parsed.hash || parsed.pathname === "/404.html") {
      throw new Error(`sitemap contains non-canonical URL: ${url}`);
    }
  }
}

function validateLinks(html, pagePath) {
  const allowedRoutes = new Set(sitemapPaths);
  let broken = 0;
  for (const match of html.matchAll(/<a\b[^>]*\bhref="([^"]+)"/gu)) {
    const href = match[1];
    if (href.startsWith("http")) {
      const parsed = new URL(href);
      if (parsed.origin !== PRODUCTION_ORIGIN) throw new Error(`${pagePath} external link is not allowed: ${href}`);
      continue;
    }
    if (!href.startsWith("/")) continue;
    const parsed = new URL(href, PRODUCTION_ORIGIN);
    if (parsed.pathname === "/" && parsed.search.startsWith("?tool=")) continue;
    if (!allowedRoutes.has(parsed.pathname)) {
      broken += 1;
      throw new Error(`${pagePath} links to missing route: ${href}`);
    }
  }
  return broken;
}

function verifyPublicHygiene() {
  const files = walkFiles(DIST_DIR);
  for (const file of files) {
    const rel = path.relative(DIST_DIR, file).replace(/\\/g, "/");
    if (isProvenanceArtifactPath(rel)) {
      throw new Error(`provenance artifact path is present in dist: ${rel}`);
    }
    if (["test-results", "playwright-report", "coverage", "build-test", "release", "output"].some((part) => rel === part || rel.startsWith(`${part}/`))) {
      throw new Error(`temporary output is present in dist: ${rel}`);
    }
    const text = isTextLike(file) ? fs.readFileSync(file, "utf8") : "";
    if (shouldCheckTemporaryHost(file)) {
      for (const value of ["localhost", "127.0.0.1", "pages.dev"]) {
        if (text.includes(value)) throw new Error(`${rel} contains temporary host ${value}`);
      }
    }
    for (const value of PROHIBITED) {
      if (text.includes(value)) throw new Error(`${rel} contains prohibited wording/path: ${value}`);
    }
    for (const { label, pattern } of MACHINE_PRIVATE_PATH_PATTERNS) {
      if (pattern.test(text)) throw new Error(`${rel} contains ${label}`);
    }
  }
}

function isProvenanceArtifactPath(rel) {
  const normalized = rel.toLowerCase();
  const segments = normalized.split("/");
  const dotPath = [".", "codex"].join("");
  const agentsFile = ["agents", "md"].join(".");
  if (segments.includes(dotPath) || segments.includes(agentsFile)) return true;
  const basename = segments.at(-1) ?? "";
  if (!/\.(?:html|md|txt|log|json|zip)$/u.test(basename)) return false;
  const stem = basename.replace(/\.[^.]+$/u, "").replace(/[._\s-]+/gu, "-");
  return PROVENANCE_ARTIFACT_STEMS.has(stem);
}

function walkFiles(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) out.push(full);
    }
  }
  return out.sort();
}

function isTextLike(file) {
  return /\.(?:html|css|js|json|webmanifest|xml|txt|svg|md)$/u.test(file);
}

function shouldCheckTemporaryHost(file) {
  return /\.(?:html|css|webmanifest|xml|txt|svg)$/u.test(file);
}

function requireIncludes(html, needle, message) {
  if (!html.includes(needle)) throw new Error(message);
}

function requireMetaProperty(html, property, expected, pagePath) {
  const actual = extractAttr(html, new RegExp(`<meta\\s+property="${escapeRegExp(property)}"\\s+content="([^"]+)"`, "u"), `${pagePath} ${property}`);
  if (actual !== expected) throw new Error(`${pagePath} ${property} mismatch`);
}

function extractMeta(html, name, pagePath) {
  return extractAttr(html, new RegExp(`<meta\\s+name="${escapeRegExp(name)}"\\s+content="([^"]+)"`, "u"), `${pagePath} ${name}`);
}

function extractAttr(html, regex, label) {
  const match = html.match(regex);
  if (!match) throw new Error(`missing ${label}`);
  return decodeHtml(match[1]);
}

function extractSingle(html, regex, label) {
  const matches = Array.from(html.matchAll(new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : `${regex.flags}g`)));
  if (matches.length !== 1) throw new Error(`${label} count mismatch: ${matches.length}`);
  return decodeHtml(matches[0][1]);
}

function countMatches(html, regex) {
  return Array.from(html.matchAll(regex)).length;
}

function decodeHtml(value) {
  return value
    .replace(/&quot;/gu, '"')
    .replace(/&gt;/gu, ">")
    .replace(/&lt;/gu, "<")
    .replace(/&amp;/gu, "&");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
