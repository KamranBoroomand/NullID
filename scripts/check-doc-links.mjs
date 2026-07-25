#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const LINK_RE = /!?\[[^\]\n]*]\(([^)\s]+(?:\s+"[^"]*")?)\)/g;
const HEADING_RE = /^(#{1,6})\s+(.+?)\s*#*\s*$/gm;
const SKIP_SCHEMES = /^(?:https?:|mailto:|tel:|ftp:|data:|javascript:)/i;

const trackedFiles = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" })
  .split("\n")
  .filter(Boolean);
const trackedSet = new Set(trackedFiles.map((file) => normalizePath(file)));
const markdownFiles = trackedFiles.filter((file) => /\.md$/i.test(file) || isRootMarkdownDocument(file));
const issues = [];

for (const markdownFile of markdownFiles) {
  const source = fs.readFileSync(path.join(ROOT, markdownFile), "utf8");
  const anchors = collectAnchors(source);
  const seen = new Set();
  for (const match of source.matchAll(LINK_RE)) {
    const rawTarget = match[1].trim();
    const target = stripTitle(rawTarget);
    if (!target || shouldSkipTarget(target)) continue;
    const issueKey = `${markdownFile}\0${target}\0${match.index}`;
    if (seen.has(issueKey)) continue;
    seen.add(issueKey);
    validateTarget(markdownFile, target, anchors);
  }
}

if (issues.length > 0) {
  console.error(`docs:links found ${issues.length} issue(s)`);
  for (const issue of issues) {
    console.error(`- ${issue}`);
  }
  process.exit(1);
}

console.log(`docs:links ok (${markdownFiles.length} tracked Markdown files checked)`);

function isRootMarkdownDocument(file) {
  return ["CHANGELOG", "CODE_OF_CONDUCT", "CONTRIBUTING", "README", "SECURITY", "SUPPORT"].includes(path.basename(file));
}

function stripTitle(target) {
  const titleIndex = target.search(/\s+"/);
  return titleIndex === -1 ? target : target.slice(0, titleIndex);
}

function shouldSkipTarget(target) {
  return target.startsWith("<") || SKIP_SCHEMES.test(target);
}

function validateTarget(sourceFile, target, sourceAnchors) {
  const [pathPart, hashPart = ""] = target.split("#");
  if (!pathPart) {
    validateAnchor(sourceFile, target, hashPart, sourceAnchors);
    return;
  }

  const decodedPath = decodeURIComponent(pathPart);
  const resolvedRelative = normalizePath(
    path.relative(ROOT, path.resolve(path.dirname(path.join(ROOT, sourceFile)), decodedPath)),
  );

  if (!trackedSet.has(resolvedRelative)) {
    issues.push(`${sourceFile}: missing target ${target}`);
    return;
  }

  if (hashPart && /\.md$/i.test(resolvedRelative)) {
    const targetSource = fs.readFileSync(path.join(ROOT, resolvedRelative), "utf8");
    validateAnchor(sourceFile, target, hashPart, collectAnchors(targetSource));
  }
}

function validateAnchor(sourceFile, target, hashPart, anchors) {
  const decodedAnchor = decodeURIComponent(hashPart).toLowerCase();
  if (!anchors.has(decodedAnchor)) {
    issues.push(`${sourceFile}: missing anchor ${target}`);
  }
}

function collectAnchors(source) {
  const anchors = new Set();
  const counts = new Map();
  for (const match of source.matchAll(HEADING_RE)) {
    const base = slugify(match[2]);
    const count = counts.get(base) ?? 0;
    counts.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  return anchors;
}

function slugify(value) {
  return value
    .replace(/`([^`]+)`/g, "$1")
    .replace(/<[^>]+>/g, "")
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/\s+/g, "-");
}

function normalizePath(value) {
  return value.split(path.sep).join("/");
}
