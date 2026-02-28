import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const SRC_ROOT = path.join(ROOT, "src");
const I18N_FILE = path.join(SRC_ROOT, "i18n.tsx");
const GUIDE_TRANSLATIONS_FILE = path.join(SRC_ROOT, "content", "guidePhraseTranslations.ts");

const sourceFiles = walk(SRC_ROOT).filter((file) => file !== I18N_FILE);
const i18nText = fs.readFileSync(I18N_FILE, "utf8");
const guidePhraseText = fs.readFileSync(GUIDE_TRANSLATIONS_FILE, "utf8");

const tUsage = collectUsage(sourceFiles, /\bt\(\s*"([^"]+)"/g);
const trUsage = collectUsage(sourceFiles, /\btr\(\s*"([^"]+)"/g);

const missingT = [];
for (const [key, files] of tUsage.entries()) {
  if (!hasKeyTranslation(key, i18nText)) {
    missingT.push({ key, files: Array.from(files).sort() });
  }
}

const missingTr = [];
for (const [phrase, files] of trUsage.entries()) {
  if (!hasPhraseTranslation(phrase, i18nText, guidePhraseText)) {
    missingTr.push({ phrase, files: Array.from(files).sort() });
  }
}

if (missingT.length === 0 && missingTr.length === 0) {
  console.log(`i18n coverage: ok (${tUsage.size} t() keys, ${trUsage.size} tr() literals)`);
  process.exit(0);
}

if (missingT.length > 0) {
  console.error(`i18n coverage: missing t() keys (${missingT.length})`);
  for (const issue of missingT) {
    console.error(`- "${issue.key}" :: ${issue.files.join(", ")}`);
  }
}

if (missingTr.length > 0) {
  console.error(`i18n coverage: missing tr() phrase translations (${missingTr.length})`);
  for (const issue of missingTr) {
    console.error(`- "${issue.phrase}" :: ${issue.files.join(", ")}`);
  }
}

process.exit(1);

function walk(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(fullPath));
      continue;
    }
    if (!entry.isFile()) continue;
    if (!/\.(ts|tsx|js|jsx)$/i.test(entry.name)) continue;
    out.push(fullPath);
  }
  return out;
}

function collectUsage(files, pattern) {
  const usage = new Map();
  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    pattern.lastIndex = 0;
    let match = pattern.exec(text);
    while (match) {
      const key = match[1];
      if (!usage.has(key)) usage.set(key, new Set());
      usage.get(key).add(path.relative(ROOT, file));
      match = pattern.exec(text);
    }
  }
  return usage;
}

function hasPhraseTranslation(phrase, i18nSource, guideSource) {
  const escaped = escapeRegex(phrase);
  const quoted = new RegExp(`["']${escaped}["']\\s*:`);
  if (quoted.test(i18nSource) || quoted.test(guideSource)) return true;
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(phrase)) {
    const bare = new RegExp(`(?:^|[,{\\s])${escaped}\\s*:`);
    if (bare.test(i18nSource)) return true;
  }
  return false;
}

function hasKeyTranslation(key, i18nSource) {
  const escaped = escapeRegex(key);
  const quoted = new RegExp(`["']${escaped}["']\\s*:`);
  if (quoted.test(i18nSource)) return true;
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)) {
    const bare = new RegExp(`(?:^|[,{\\s])${escaped}\\s*:`);
    if (bare.test(i18nSource)) return true;
  }
  return false;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
