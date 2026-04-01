import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const ROOT = process.cwd();
const SRC_ROOT = path.join(ROOT, "src");
const CONTENT_ROOT = path.join(SRC_ROOT, "content");
const I18N_FILE = path.join(SRC_ROOT, "i18n.tsx");
const UI_FILE_PATTERN = /(^|[/\\])src([/\\])(App\.tsx|views[/\\].+\.tsx|components[/\\].+\.tsx)$/;
const USER_VISIBLE_ATTRS = new Set(["aria-label", "placeholder", "title", "alt"]);
const IGNORED_LITERAL_VALUES = new Set(["WIPE"]);
const SUPPORTED_LOCALES = ["en", "fa", "ru"];
const STRICT_PHRASE_COVERAGE = process.env.STRICT_I18N_PHRASES === "1";

const sourceFiles = walk(SRC_ROOT).filter((file) => file !== I18N_FILE);
const phraseTranslationFiles = walk(CONTENT_ROOT).filter((file) => /PhraseTranslations\.ts$/.test(path.basename(file)));
const i18nText = fs.readFileSync(I18N_FILE, "utf8");
const phraseTranslationTexts = phraseTranslationFiles.map((file) => fs.readFileSync(file, "utf8"));
const phraseTranslationSources = [i18nText, ...phraseTranslationTexts];

const { tUsage, trUsage, pushUsage, hardcodedUiLiterals } = scanSourceFiles(sourceFiles);
const messagesByLocale = extractMessageKeysByLocale(i18nText);

const missingT = [];
for (const [key, files] of tUsage.entries()) {
  const missingLocales = SUPPORTED_LOCALES.filter((locale) => !messagesByLocale[locale]?.has(key));
  if (missingLocales.length > 0) {
    missingT.push({ key, files: Array.from(files).sort(), missingLocales });
  }
}

const localeKeyParityIssues = collectLocaleKeyParityIssues(messagesByLocale);

const missingTr = [];
for (const [phrase, files] of trUsage.entries()) {
  if (!hasPhraseTranslation(phrase, phraseTranslationSources)) {
    missingTr.push({ phrase, files: Array.from(files).sort() });
  }
}

const missingPush = [];
for (const [phrase, files] of pushUsage.entries()) {
  if (!hasPhraseTranslation(phrase, phraseTranslationSources)) {
    missingPush.push({ phrase, files: Array.from(files).sort() });
  }
}

const phraseCoverageFailed = STRICT_PHRASE_COVERAGE && (missingTr.length > 0 || missingPush.length > 0);
if (missingT.length === 0 && localeKeyParityIssues.length === 0 && hardcodedUiLiterals.length === 0 && !phraseCoverageFailed) {
  console.log(
    `i18n coverage: ok (${tUsage.size} t() keys, ${trUsage.size} tr() literals, ${pushUsage.size} push() literals checked)`,
  );
  if (!STRICT_PHRASE_COVERAGE && (missingTr.length > 0 || missingPush.length > 0)) {
    console.warn(
      `i18n coverage: advisory (${missingTr.length} tr() + ${missingPush.length} push() phrases missing translations). Set STRICT_I18N_PHRASES=1 to enforce.`,
    );
  }
  process.exit(0);
}

if (missingT.length > 0) {
  console.error(`i18n coverage: missing t() key translations (${missingT.length})`);
  for (const issue of missingT) {
    console.error(`- "${issue.key}" missing in [${issue.missingLocales.join(", ")}] :: ${issue.files.join(", ")}`);
  }
}

if (localeKeyParityIssues.length > 0) {
  console.error(`i18n coverage: locale key parity issues (${localeKeyParityIssues.length})`);
  for (const issue of localeKeyParityIssues) {
    console.error(`- ${issue}`);
  }
}

if (missingTr.length > 0) {
  const log = STRICT_PHRASE_COVERAGE ? console.error : console.warn;
  log(`i18n coverage: missing tr() phrase translations (${missingTr.length})`);
  for (const issue of missingTr) {
    log(`- "${issue.phrase}" :: ${issue.files.join(", ")}`);
  }
}

if (missingPush.length > 0) {
  const log = STRICT_PHRASE_COVERAGE ? console.error : console.warn;
  log(`i18n coverage: missing push() toast phrase translations (${missingPush.length})`);
  for (const issue of missingPush) {
    log(`- "${issue.phrase}" :: ${issue.files.join(", ")}`);
  }
}

if (hardcodedUiLiterals.length > 0) {
  console.error(`i18n coverage: hardcoded user-visible UI literals (${hardcodedUiLiterals.length})`);
  for (const issue of hardcodedUiLiterals) {
    console.error(`- ${issue.file}:${issue.line} ${issue.kind}: "${issue.value}"`);
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

function scanSourceFiles(files) {
  const tUsage = new Map();
  const trUsage = new Map();
  const pushUsage = new Map();
  const hardcodedUiLiterals = [];

  for (const file of files) {
    const source = fs.readFileSync(file, "utf8");
    const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const relative = path.relative(ROOT, file);
    const isUiFile = UI_FILE_PATTERN.test(relative.replace(/\\/g, "/"));

    const visit = (node) => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
        const callName = node.expression.text;
        const literal = extractStringLiteral(node.arguments[0]);
        if (literal) {
          if (callName === "t") addUsage(tUsage, literal, relative);
          if (callName === "tr") addUsage(trUsage, literal, relative);
          if (callName === "push" && isUiFile) addUsage(pushUsage, literal, relative);
        }
      }

      if (isUiFile && ts.isJsxAttribute(node)) {
        const attrName = node.name.text;
        if (USER_VISIBLE_ATTRS.has(attrName)) {
          const literal = extractJsxAttributeString(node.initializer);
          if (literal && shouldReportHardcodedLiteral(literal)) {
            hardcodedUiLiterals.push({
              file: relative,
              line: getLineNumber(sourceFile, node),
              kind: `attr:${attrName}`,
              value: literal,
            });
          }
        }
      }

      if (isUiFile && ts.isJsxText(node)) {
        const normalized = node.text.replace(/\s+/g, " ").trim();
        if (normalized && shouldReportHardcodedLiteral(normalized)) {
          hardcodedUiLiterals.push({
            file: relative,
            line: getLineNumber(sourceFile, node),
            kind: "text",
            value: normalized,
          });
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  return { tUsage, trUsage, pushUsage, hardcodedUiLiterals };
}

function extractMessageKeysByLocale(i18nSourceText) {
  const sourceFile = ts.createSourceFile(I18N_FILE, i18nSourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const out = { en: new Set(), fa: new Set(), ru: new Set() };

  const visit = (node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === "messages" &&
      node.initializer &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      for (const localeProp of node.initializer.properties) {
        if (!ts.isPropertyAssignment(localeProp)) continue;
        const localeName = getPropertyName(localeProp.name);
        if (!localeName || !SUPPORTED_LOCALES.includes(localeName)) continue;
        if (!ts.isObjectLiteralExpression(localeProp.initializer)) continue;
        for (const messageProp of localeProp.initializer.properties) {
          if (!ts.isPropertyAssignment(messageProp) && !ts.isShorthandPropertyAssignment(messageProp)) continue;
          const messageKey = getPropertyName(messageProp.name);
          if (messageKey) out[localeName].add(messageKey);
        }
      }
    }
    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return out;
}

function collectLocaleKeyParityIssues(messagesByLocale) {
  const issues = [];
  const enKeys = messagesByLocale.en ?? new Set();

  for (const locale of SUPPORTED_LOCALES) {
    if (!messagesByLocale[locale]) {
      issues.push(`locale "${locale}" is missing from messages`);
      continue;
    }
    if (locale === "en") continue;

    const localeKeys = messagesByLocale[locale];
    const missing = Array.from(enKeys).filter((key) => !localeKeys.has(key));
    const extra = Array.from(localeKeys).filter((key) => !enKeys.has(key));

    if (missing.length > 0) {
      issues.push(`locale "${locale}" is missing ${missing.length} key(s): ${missing.slice(0, 6).join(", ")}${missing.length > 6 ? ", ..." : ""}`);
    }
    if (extra.length > 0) {
      issues.push(`locale "${locale}" has ${extra.length} extra key(s): ${extra.slice(0, 6).join(", ")}${extra.length > 6 ? ", ..." : ""}`);
    }
  }

  return issues;
}

function hasPhraseTranslation(phrase, sources) {
  const escaped = escapeRegex(phrase);
  const quoted = new RegExp(`["']${escaped}["']\\s*:`);
  if (sources.some((source) => quoted.test(source))) return true;

  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(phrase)) {
    const bare = new RegExp(`(?:^|[,{\\s])${escaped}\\s*:`);
    if (sources.some((source) => bare.test(source))) return true;
  }

  return false;
}

function shouldReportHardcodedLiteral(value) {
  if (!/\p{L}/u.test(value)) return false;
  if (IGNORED_LITERAL_VALUES.has(value)) return false;
  if (/^:[a-z0-9_-]+$/i.test(value)) return false;
  if (/^[A-Z0-9:+/._ -]+$/.test(value)) return false;
  return true;
}

function extractStringLiteral(node) {
  if (!node) return null;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

function extractJsxAttributeString(initializer) {
  if (!initializer) return null;
  if (ts.isStringLiteral(initializer)) return initializer.text;
  return null;
}

function getPropertyName(nameNode) {
  if (ts.isIdentifier(nameNode) || ts.isStringLiteral(nameNode) || ts.isNumericLiteral(nameNode)) return nameNode.text;
  return null;
}

function addUsage(map, key, file) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(file);
}

function getLineNumber(sourceFile, node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
