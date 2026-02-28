#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import os from "node:os";

const ENVELOPE_PREFIX = "NULLID:ENC:1";
const ENVELOPE_AAD = Buffer.from("nullid:enc:v1", "utf8");
const sanitizeFormats = new Set(["auto", "text", "json", "ndjson", "csv", "xml", "yaml"]);
const sensitiveKeys = new Set([
  "token",
  "authorization",
  "password",
  "secret",
  "apikey",
  "api_key",
  "session",
  "cookie",
  "bearer",
  "aws_secret_access_key",
  "access_token",
  "refresh_token",
]);

const command = process.argv[2];
const args = process.argv.slice(3);

function main() {
  if (!command || command === "help" || command === "--help" || command === "-h") {
    printUsage();
    process.exit(0);
  }

  try {
    switch (command) {
      case "hash":
        runHash(args);
        break;
      case "sanitize":
        runSanitize(args);
        break;
      case "sanitize-dir":
        runSanitizeDir(args);
        break;
      case "bundle":
        runBundle(args);
        break;
      case "redact":
        runRedact(args);
        break;
      case "enc":
        runEncrypt(args);
        break;
      case "dec":
        runDecrypt(args);
        break;
      case "pwgen":
        runPwgen(args);
        break;
      case "meta":
        runMeta(args);
        break;
      case "pdf-clean":
        runPdfClean(args);
        break;
      case "office-clean":
        runOfficeClean(args);
        break;
      case "archive-sanitize":
        runArchiveSanitize(args);
        break;
      case "precommit":
        runPrecommit(args);
        break;
      case "policy-init":
        runPolicyInit(args);
        break;
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  } catch (error) {
    console.error(`[nullid-cli] ${(error instanceof Error ? error.message : String(error)).trim()}`);
    process.exit(1);
  }
}

function runHash(argv) {
  const input = argv[0];
  if (!input) throw new Error("Usage: hash <input-file> [--algo sha256|sha512|sha1]");
  const algo = (getOption(argv, "--algo") || "sha256").toLowerCase();
  if (!["sha256", "sha512", "sha1"].includes(algo)) {
    throw new Error(`Unsupported hash algorithm: ${algo}`);
  }
  const buffer = fs.readFileSync(path.resolve(input));
  const hex = crypto.createHash(algo).update(buffer).digest("hex");
  console.log(JSON.stringify({ file: input, bytes: buffer.length, algorithm: algo, sha: hex }, null, 2));
}

function runSanitize(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error(
      "Usage: sanitize <input-file> <output-file> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--baseline <nullid.policy.json>] [--merge-mode strict-override|prefer-stricter] [--json-aware true|false] [--format auto|text|json|ndjson|csv|xml|yaml]",
    );
  }

  const input = fs.readFileSync(path.resolve(inputPath), "utf8");
  const options = parseSanitizeOptions(argv);
  const result = sanitizeWithOptions(input, options);
  fs.writeFileSync(path.resolve(outputPath), result.output, "utf8");
  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        detectedFormat: result.detectedFormat,
        linesAffected: result.linesAffected,
        appliedRules: result.applied,
        report: result.report,
      },
      null,
      2,
    ),
  );
}

function runSanitizeDir(argv) {
  const inputDir = argv[0];
  const outputDir = argv[1];
  if (!inputDir || !outputDir) {
    throw new Error(
      "Usage: sanitize-dir <input-dir> <output-dir> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--baseline <nullid.policy.json>] [--merge-mode strict-override|prefer-stricter] [--json-aware true|false] [--format auto|text|json|ndjson|csv|xml|yaml] [--ext .log,.txt,.json]",
    );
  }

  const sourceRoot = path.resolve(inputDir);
  const targetRoot = path.resolve(outputDir);
  if (!fs.existsSync(sourceRoot) || !fs.statSync(sourceRoot).isDirectory()) {
    throw new Error(`Input directory does not exist: ${sourceRoot}`);
  }
  ensureDir(targetRoot);

  const options = parseSanitizeOptions(argv);
  const extOption = getOption(argv, "--ext");
  const extFilter = extOption
    ? new Set(
        extOption
          .split(",")
          .map((value) => value.trim().toLowerCase())
          .filter(Boolean),
      )
    : null;

  const files = walkFiles(sourceRoot);
  const processed = [];
  const skipped = [];
  const failed = [];

  files.forEach((filePath) => {
    const rel = path.relative(sourceRoot, filePath);
    const ext = path.extname(filePath).toLowerCase();
    if (extFilter && !extFilter.has(ext)) {
      skipped.push({ file: rel, reason: "extension-filter" });
      return;
    }

    const buffer = fs.readFileSync(filePath);
    if (looksBinary(buffer)) {
      skipped.push({ file: rel, reason: "binary" });
      return;
    }

    try {
      const input = buffer.toString("utf8");
      const result = sanitizeWithOptions(input, options);
      const outPath = path.join(targetRoot, rel);
      ensureDir(path.dirname(outPath));
      fs.writeFileSync(outPath, result.output, "utf8");
      processed.push({
        file: rel,
        output: rel,
        detectedFormat: result.detectedFormat,
        linesAffected: result.linesAffected,
      });
    } catch (error) {
      failed.push({ file: rel, error: error instanceof Error ? error.message : String(error) });
    }
  });

  const reportPath = getOption(argv, "--report");
  const summary = {
    inputDir: sourceRoot,
    outputDir: targetRoot,
    counts: {
      scanned: files.length,
      processed: processed.length,
      skipped: skipped.length,
      failed: failed.length,
    },
    processed,
    skipped,
    failed,
  };
  if (reportPath) {
    fs.writeFileSync(path.resolve(reportPath), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  }
  console.log(JSON.stringify(summary, null, 2));
}

function runBundle(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error(
      "Usage: bundle <input-file> <output-json> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--baseline <nullid.policy.json>] [--merge-mode strict-override|prefer-stricter] [--json-aware true|false] [--format auto|text|json|ndjson|csv|xml|yaml]",
    );
  }
  const input = fs.readFileSync(path.resolve(inputPath), "utf8");
  const options = parseSanitizeOptions(argv);
  const result = sanitizeWithOptions(input, options);
  const bundle = {
    schemaVersion: 1,
    kind: "nullid-safe-share",
    createdAt: new Date().toISOString(),
    tool: "sanitize",
    sourceFile: inputPath,
    detectedFormat: result.detectedFormat,
    policy: options.policy,
    input: {
      bytes: Buffer.byteLength(input, "utf8"),
      sha256: sha256Hex(input),
    },
    output: {
      bytes: Buffer.byteLength(result.output, "utf8"),
      sha256: sha256Hex(result.output),
      text: result.output,
    },
    summary: {
      linesAffected: result.linesAffected,
      appliedRules: result.applied,
      report: result.report,
    },
  };
  fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  console.log(
    JSON.stringify(
      {
        output: outputPath,
        detectedFormat: result.detectedFormat,
        sha256: bundle.output.sha256,
        linesAffected: result.linesAffected,
      },
      null,
      2,
    ),
  );
}

function runRedact(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error(
      "Usage: redact <input-file> <output-file> [--mode full|partial] [--detectors email,phone,token,ip,id,iban,card,ipv6,awskey,awssecret,github,slack,privatekey]",
    );
  }

  const text = fs.readFileSync(path.resolve(inputPath), "utf8");
  const mode = (getOption(argv, "--mode") || "full").toLowerCase();
  if (mode !== "full" && mode !== "partial") {
    throw new Error(`Unsupported redact mode: ${mode}`);
  }

  const detectors = buildRedactDetectors();
  const selectedKeys = (getOption(argv, "--detectors") || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const selected = selectedKeys.length > 0 ? detectors.filter((detector) => selectedKeys.includes(detector.key)) : detectors;

  const findings = scanRedaction(text, selected);
  const output = applyRedaction(text, findings.matches, mode);
  fs.writeFileSync(path.resolve(outputPath), output, "utf8");

  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        mode,
        enabledDetectors: selected.map((detector) => detector.key),
        findingCount: findings.total,
        severity: findings.overall,
        byType: findings.counts,
      },
      null,
      2,
    ),
  );
}

function runEncrypt(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error(
      "Usage: enc <input-file> <output-envelope-file> [--pass <passphrase>|--pass-env <VAR>] [--profile compat|strong|paranoid] [--iterations <n>] [--kdf-hash sha256|sha512] [--name <name>] [--mime <mime>]",
    );
  }

  const passphrase = resolvePassphrase(argv);
  const data = fs.readFileSync(path.resolve(inputPath));
  const profile = resolveKdfProfile(getOption(argv, "--profile"));
  const overrideIterations = getOption(argv, "--iterations");
  const overrideHash = getOption(argv, "--kdf-hash");
  const kdf = resolveKdfSettings(profile, overrideIterations, overrideHash);
  const mime = getOption(argv, "--mime") || detectMimeFromPath(inputPath);
  const name = getOption(argv, "--name") || path.basename(inputPath);

  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(Buffer.from(passphrase, "utf8"), salt, kdf.iterations, 32, kdf.nodeHash);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(ENVELOPE_AAD);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);

  const header = {
    version: 1,
    algo: "AES-GCM",
    kdf: {
      name: "PBKDF2",
      iterations: kdf.iterations,
      hash: kdf.headerHash,
      salt: toBase64Url(salt),
    },
    iv: toBase64Url(iv),
    mime,
    name,
  };

  const payload = {
    header,
    ciphertext: toBase64Url(ciphertext),
  };
  const blob = `${ENVELOPE_PREFIX}.${toBase64Url(Buffer.from(JSON.stringify(payload), "utf8"))}`;
  fs.writeFileSync(path.resolve(outputPath), `${blob}\n`, "utf8");

  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        bytes: data.length,
        envelopePrefix: ENVELOPE_PREFIX,
        kdf: {
          profile: kdf.profile,
          iterations: kdf.iterations,
          hash: kdf.headerHash,
        },
      },
      null,
      2,
    ),
  );
}

function runDecrypt(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error("Usage: dec <input-envelope-file> <output-file> [--pass <passphrase>|--pass-env <VAR>]");
  }

  const passphrase = resolvePassphrase(argv);
  const blob = fs.readFileSync(path.resolve(inputPath), "utf8").trim();
  const normalized = blob.replace(/\s+/g, "");
  if (!normalized.startsWith(`${ENVELOPE_PREFIX}.`)) {
    throw new Error("Unsupported envelope prefix");
  }

  const encoded = normalized.slice(`${ENVELOPE_PREFIX}.`.length);
  const envelopePayload = fromBase64Url(encoded);
  let envelope;
  try {
    envelope = JSON.parse(envelopePayload.toString("utf8"));
  } catch {
    throw new Error("Invalid envelope format");
  }

  if (!envelope?.header || envelope.header.version !== 1 || envelope.header.algo !== "AES-GCM") {
    throw new Error("Unsupported envelope version");
  }
  if (!envelope.header.kdf || envelope.header.kdf.name !== "PBKDF2") {
    throw new Error("Unsupported envelope kdf");
  }

  const nodeHash = normalizeKdfHash(envelope.header.kdf.hash).nodeHash;
  const iterations = normalizeIterations(envelope.header.kdf.iterations);
  const salt = fromBase64Url(envelope.header.kdf.salt);
  const iv = fromBase64Url(envelope.header.iv);
  const ciphertextWithTag = fromBase64Url(envelope.ciphertext);
  if (ciphertextWithTag.length < 17) {
    throw new Error("Invalid envelope ciphertext");
  }
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);

  const key = crypto.pbkdf2Sync(Buffer.from(passphrase, "utf8"), salt, iterations, 32, nodeHash);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(ENVELOPE_AAD);
  decipher.setAuthTag(authTag);

  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("Decrypt failed: bad passphrase or envelope integrity failure");
  }

  fs.writeFileSync(path.resolve(outputPath), plaintext);
  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        bytes: plaintext.length,
        mime: envelope.header.mime || "application/octet-stream",
        name: envelope.header.name || path.basename(outputPath),
      },
      null,
      2,
    ),
  );
}

function runPwgen(argv) {
  const kind = (getOption(argv, "--kind") || "password").toLowerCase();
  if (kind !== "password" && kind !== "passphrase") {
    throw new Error(`Unsupported pwgen kind: ${kind}`);
  }

  if (kind === "password") {
    const settings = {
      length: clampInt(getOption(argv, "--length"), 8, 128, 20),
      upper: parseBoolean(getOption(argv, "--upper"), true),
      lower: parseBoolean(getOption(argv, "--lower"), true),
      digits: parseBoolean(getOption(argv, "--digits"), true),
      symbols: parseBoolean(getOption(argv, "--symbols"), true),
      avoidAmbiguity: parseBoolean(getOption(argv, "--avoid-ambiguous"), true),
      enforceMix: parseBoolean(getOption(argv, "--enforce-mix"), true),
    };
    const value = generatePassword(settings);
    const entropy = estimatePasswordEntropy(settings);
    console.log(JSON.stringify({ kind, value, entropyBits: entropy, settings }, null, 2));
    return;
  }

  const settings = {
    words: clampInt(getOption(argv, "--words"), 3, 12, 5),
    separator: getOption(argv, "--separator") || "-",
    randomCase: parseBoolean(getOption(argv, "--random-case"), true),
    appendNumber: parseBoolean(getOption(argv, "--append-number"), true),
    appendSymbol: parseBoolean(getOption(argv, "--append-symbol"), true),
  };
  const wordlist = buildWordlist();
  const value = generatePassphrase(settings, wordlist);
  const entropy = estimatePassphraseEntropy(settings, wordlist.length);
  console.log(JSON.stringify({ kind, value, entropyBits: entropy, settings }, null, 2));
}

function runMeta(argv) {
  const inputPath = argv[0];
  if (!inputPath) {
    throw new Error("Usage: meta <input-file>");
  }

  const fullPath = path.resolve(inputPath);
  const data = fs.readFileSync(fullPath);
  const format = detectFileFormat(data);
  const ext = path.extname(fullPath).toLowerCase();
  const digest = crypto.createHash("sha256").update(data).digest("hex");
  const exifHint = data.includes(Buffer.from("Exif\u0000\u0000", "binary"));

  const summary = {
    file: inputPath,
    bytes: data.length,
    sha256: digest,
    extension: ext || "(none)",
    detectedFormat: format,
    metadataHints: {
      exifMarker: exifHint,
      browserCleanExportFriendly: ["jpeg", "png", "webp", "avif", "gif", "bmp", "tiff"].includes(format),
      knownHardBlock: format === "heic" || format === "heif",
    },
  };

  console.log(JSON.stringify(summary, null, 2));
}

function runPdfClean(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error("Usage: pdf-clean <input.pdf> <output.pdf>");
  }

  const fullInput = path.resolve(inputPath);
  const fullOutput = path.resolve(outputPath);
  const buffer = fs.readFileSync(fullInput);
  if (!buffer.subarray(0, 5).toString("ascii").startsWith("%PDF-")) {
    throw new Error("Input file is not a PDF");
  }

  const text = buffer.toString("latin1");
  const report = [];
  let output = text;

  const rewrite = (regex, transform, label) => {
    const result = replaceSameLength(output, regex, transform);
    output = result.output;
    if (result.count > 0) report.push(`${label}:${result.count}`);
  };

  rewrite(
    /(\/(?:Author|Creator|Producer|Title|Subject|Keywords)\s*)(\((?:\\.|[^()])*\)|<[^>]*>)/g,
    (_match, prefix, value) => `${prefix}${maskPdfValue(value, "redacted")}`,
    "info-fields",
  );
  rewrite(
    /(\/(?:CreationDate|ModDate)\s*)(\((?:\\.|[^()])*\)|<[^>]*>)/g,
    (_match, prefix, value) => `${prefix}${maskPdfValue(value, "D:19700101000000Z")}`,
    "date-fields",
  );
  rewrite(/(<x:xmpmeta[\s\S]*?<\/x:xmpmeta>)/g, (match) => " ".repeat(match.length), "xmp-blocks");
  rewrite(/(<\?xpacket[\s\S]*?\?>)/g, (match) => " ".repeat(match.length), "xpacket-blocks");
  rewrite(/(\/Metadata\s+)(\d+\s+\d+\s+R)/g, (_match, prefix, ref) => `${prefix}${maskPdfRef(ref)}`, "metadata-refs");

  fs.mkdirSync(path.dirname(fullOutput), { recursive: true });
  fs.writeFileSync(fullOutput, Buffer.from(output, "latin1"));
  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        bytes: buffer.length,
        actions: report.length > 0 ? report : ["no-visible-metadata-found"],
      },
      null,
      2,
    ),
  );
}

function runOfficeClean(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error("Usage: office-clean <input.docx|input.xlsx|input.pptx> <output-file>");
  }

  const fullInput = path.resolve(inputPath);
  const fullOutput = path.resolve(outputPath);
  const ext = path.extname(fullInput).toLowerCase();
  if (![".docx", ".xlsx", ".pptx"].includes(ext)) {
    throw new Error("Office clean supports .docx, .xlsx, and .pptx only");
  }
  ensureZipTooling();

  const summary = withTempDir("nullid-office-", (extractDir) => {
    unzipArchive(fullInput, extractDir);
    const marker = path.join(extractDir, "[Content_Types].xml");
    if (!fs.existsSync(marker)) {
      throw new Error("Input does not look like an Office Open XML package");
    }

    let rewritten = 0;
    let removed = 0;

    const corePath = path.join(extractDir, "docProps", "core.xml");
    if (fs.existsSync(corePath)) {
      fs.writeFileSync(corePath, buildOfficeCoreXml(), "utf8");
      rewritten += 1;
    }

    const appPath = path.join(extractDir, "docProps", "app.xml");
    if (fs.existsSync(appPath)) {
      fs.writeFileSync(appPath, buildOfficeAppXml(), "utf8");
      rewritten += 1;
    }

    const customPath = path.join(extractDir, "docProps", "custom.xml");
    if (fs.existsSync(customPath)) {
      fs.rmSync(customPath, { force: true });
      removed += 1;
    }

    const personPath = path.join(extractDir, "docProps", "person.xml");
    if (fs.existsSync(personPath)) {
      fs.rmSync(personPath, { force: true });
      removed += 1;
    }

    fs.mkdirSync(path.dirname(fullOutput), { recursive: true });
    if (fs.existsSync(fullOutput)) fs.rmSync(fullOutput, { force: true });
    zipDirectory(extractDir, fullOutput);
    return { rewritten, removed };
  });

  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        rewrittenXmlFiles: summary.rewritten,
        removedFiles: summary.removed,
      },
      null,
      2,
    ),
  );
}

function runArchiveSanitize(argv) {
  const inputPath = argv[0];
  const outputPath = argv[1];
  if (!inputPath || !outputPath) {
    throw new Error(
      "Usage: archive-sanitize <input-dir|input.zip> <output.zip> [--policy <policy-json>] [--baseline <nullid.policy.json>] [--merge-mode strict-override|prefer-stricter] [--sanitize-text true|false] [--max-bytes <n>] [--include-ext .txt,.json]",
    );
  }
  ensureZipTooling();

  const fullInput = path.resolve(inputPath);
  const fullOutput = path.resolve(outputPath);
  const options = parseSanitizeOptions(argv);
  const sanitizeText = parseBoolean(getOption(argv, "--sanitize-text"), true);
  const maxBytes = clampInt(getOption(argv, "--max-bytes"), 1024, 100_000_000, 2_000_000);
  const includeExt = parseExtFilter(
    getOption(argv, "--include-ext") ||
      ".log,.txt,.json,.ndjson,.csv,.xml,.yaml,.yml,.md,.env,.ini,.cfg,.conf,.toml,.properties,.js,.ts,.tsx,.jsx,.py,.sh,.sql",
  );

  const sourceIsZip = fs.existsSync(fullInput) && fs.statSync(fullInput).isFile() && path.extname(fullInput).toLowerCase() === ".zip";
  const sourceIsDir = fs.existsSync(fullInput) && fs.statSync(fullInput).isDirectory();
  if (!sourceIsZip && !sourceIsDir) {
    throw new Error("archive-sanitize input must be a directory or .zip file");
  }

  const summary = withTempDir("nullid-archive-", (workspace) => {
    const sourceRoot = path.join(workspace, "source");
    const stageRoot = path.join(workspace, "stage");
    fs.mkdirSync(sourceRoot, { recursive: true });
    fs.mkdirSync(stageRoot, { recursive: true });

    if (sourceIsZip) {
      unzipArchive(fullInput, sourceRoot);
    } else {
      copyDirectory(fullInput, sourceRoot);
    }

    const files = walkFiles(sourceRoot);
    const entries = [];
    let sanitizedCount = 0;
    let findingTotal = 0;
    const severityTotals = { high: 0, medium: 0, low: 0 };

    files.forEach((sourceFile) => {
      const rel = path.relative(sourceRoot, sourceFile);
      const targetFile = path.join(stageRoot, rel);
      fs.mkdirSync(path.dirname(targetFile), { recursive: true });

      const sourceBuffer = fs.readFileSync(sourceFile);
      const ext = path.extname(sourceFile).toLowerCase();
      const beforeHash = sha256Hex(sourceBuffer);
      let outputBuffer = sourceBuffer;
      let sanitized = false;
      const isTextExt = includeExt.has(ext);
      const withinMaxBytes = sourceBuffer.length <= maxBytes;
      const isBinary = looksBinary(sourceBuffer);
      const canScanText = sanitizeText && isTextExt && withinMaxBytes && !isBinary;
      let findings = {
        scanned: false,
        reason: !sanitizeText
          ? "sanitize-text-disabled"
          : !isTextExt
            ? "extension-filter"
            : !withinMaxBytes
              ? "max-bytes"
              : isBinary
                ? "binary"
                : "not-scanned",
        total: 0,
        highestSeverity: null,
        bySeverity: { high: 0, medium: 0, low: 0 },
        byType: {},
      };

      if (canScanText) {
        const text = sourceBuffer.toString("utf8");
        const scan = scanRedaction(text, buildRedactDetectors());
        const bySeverity = severityCounts(scan.matches);
        findings = {
          scanned: true,
          reason: null,
          total: scan.total,
          highestSeverity: scan.total > 0 ? scan.overall : null,
          bySeverity,
          byType: scan.counts,
        };
        findingTotal += scan.total;
        severityTotals.high += bySeverity.high;
        severityTotals.medium += bySeverity.medium;
        severityTotals.low += bySeverity.low;
        const result = sanitizeWithOptions(text, options);
        outputBuffer = Buffer.from(result.output, "utf8");
        sanitized = outputBuffer.toString("utf8") !== text;
      }

      fs.writeFileSync(targetFile, outputBuffer);
      if (sanitized) sanitizedCount += 1;
      entries.push({
        path: rel,
        bytesBefore: sourceBuffer.length,
        bytesAfter: outputBuffer.length,
        sha256Before: beforeHash,
        sha256After: sha256Hex(outputBuffer),
        sanitized,
        findings,
      });
    });

    const manifest = {
      schemaVersion: 2,
      kind: "nullid-archive-manifest",
      createdAt: new Date().toISOString(),
      source: {
        input: inputPath,
        sourceType: sourceIsZip ? "zip" : "directory",
      },
      policy: {
        mergeMode: options.mergeMode,
        baseline: options.baselinePath ? path.relative(process.cwd(), options.baselinePath) : null,
      },
      summary: {
        fileCount: entries.length,
        sanitizedCount,
        findingTotal,
        severityTotals,
      },
      files: entries,
    };
    fs.writeFileSync(path.join(stageRoot, "nullid-archive-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

    fs.mkdirSync(path.dirname(fullOutput), { recursive: true });
    if (fs.existsSync(fullOutput)) fs.rmSync(fullOutput, { force: true });
    zipDirectory(stageRoot, fullOutput);
    return manifest.summary;
  });

  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        files: summary.fileCount,
        sanitized: summary.sanitizedCount,
      },
      null,
      2,
    ),
  );
}

function runPolicyInit(argv) {
  const outputPath = path.resolve(argv[0] || "nullid.policy.json");
  if (fs.existsSync(outputPath) && !hasFlag(argv, "--force")) {
    throw new Error(`Policy file already exists: ${outputPath} (use --force to overwrite)`);
  }
  const preset = getOption(argv, "--preset") || "nginx";
  const mergeMode = normalizeMergeMode(getOption(argv, "--merge-mode") || "strict-override");
  const config = buildPolicyFromPreset(preset, true);

  const payload = {
    schemaVersion: 1,
    kind: "nullid-policy-baseline",
    sanitize: {
      mergeMode,
      defaultConfig: config,
      packs: [
        {
          name: "workspace-default",
          createdAt: new Date().toISOString(),
          config,
        },
      ],
    },
  };
  fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  console.log(
    JSON.stringify(
      {
        output: path.relative(process.cwd(), outputPath),
        preset,
        mergeMode,
      },
      null,
      2,
    ),
  );
}

function runPrecommit(argv) {
  const options = parseSanitizeOptions(argv);
  const applySanitize = hasFlag(argv, "--apply-sanitize");
  const threshold = normalizeSeverity(getOption(argv, "--threshold") || "high");
  const files = resolvePrecommitFiles(argv);
  const extFilter = parseExtFilter(getOption(argv, "--ext"));

  const violations = [];
  const sanitized = [];
  const skipped = [];

  files.forEach((file) => {
    const fullPath = path.resolve(file);
    if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
      skipped.push({ file, reason: "missing" });
      return;
    }
    const ext = path.extname(file).toLowerCase();
    if (extFilter && !extFilter.has(ext)) {
      skipped.push({ file, reason: "extension-filter" });
      return;
    }

    const buffer = fs.readFileSync(fullPath);
    if (looksBinary(buffer)) {
      skipped.push({ file, reason: "binary" });
      return;
    }

    const text = buffer.toString("utf8");
    let findings = scanRedaction(text, buildRedactDetectors());
    let triggered = findings.matches.filter((match) => severityRank(match.severity) >= severityRank(threshold));
    if (triggered.length === 0) return;

    let changed = false;
    if (applySanitize) {
      const result = sanitizeWithOptions(text, options);
      if (result.output !== text) {
        fs.writeFileSync(fullPath, result.output, "utf8");
        changed = true;
        sanitized.push(file);
        findings = scanRedaction(result.output, buildRedactDetectors());
        triggered = findings.matches.filter((match) => severityRank(match.severity) >= severityRank(threshold));
        if (triggered.length === 0) {
          return;
        }
      }
    }

    const byType = triggered.reduce((acc, match) => {
      acc[match.label] = (acc[match.label] || 0) + 1;
      return acc;
    }, {});

    violations.push({
      file,
      total: triggered.length,
      highest: triggered
        .map((match) => match.severity)
        .sort((a, b) => severityRank(b) - severityRank(a))[0],
      byType,
      sanitized: changed,
    });
  });

  if (applySanitize && sanitized.length > 0 && hasFlag(argv, "--staged")) {
    runGit(["add", ...sanitized]);
  }

  const summary = {
    threshold,
    scanned: files.length,
    violations: violations.length,
    sanitized: sanitized.length,
    skipped,
    files: violations,
  };
  console.log(JSON.stringify(summary, null, 2));

  if (violations.length > 0) {
    throw new Error("precommit enforcement failed");
  }
}

function printUsage() {
  console.log(
    `
NullID local CLI (offline, no servers)

Commands:
  hash <input-file> [--algo sha256|sha512|sha1]
  sanitize <input-file> <output-file> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--baseline <nullid.policy.json>] [--merge-mode strict-override|prefer-stricter] [--json-aware true|false] [--format auto|text|json|ndjson|csv|xml|yaml]
  sanitize-dir <input-dir> <output-dir> [--preset ...|--policy ...|--baseline ...] [--format auto|text|json|ndjson|csv|xml|yaml] [--ext .log,.txt,.json] [--report <json-file>]
  bundle <input-file> <output-json> [--preset ...|--policy ...|--baseline ...] [--format auto|text|json|ndjson|csv|xml|yaml]
  redact <input-file> <output-file> [--mode full|partial] [--detectors email,phone,token,ip,id,iban,card,ipv6,awskey,awssecret,github,slack,privatekey]
  enc <input-file> <output-envelope-file> [--pass <passphrase>|--pass-env <VAR>] [--profile compat|strong|paranoid] [--iterations <n>] [--kdf-hash sha256|sha512]
  dec <input-envelope-file> <output-file> [--pass <passphrase>|--pass-env <VAR>]
  pwgen [--kind password|passphrase] [...options]
  meta <input-file>
  pdf-clean <input.pdf> <output.pdf>
  office-clean <input.docx|input.xlsx|input.pptx> <output-file>
  archive-sanitize <input-dir|input.zip> <output.zip> [--baseline <nullid.policy.json>] [--sanitize-text true|false]
  precommit [--staged|--git-range <range>|--files a,b] [--threshold high|medium|low] [--baseline <nullid.policy.json>] [--apply-sanitize]
  policy-init [output-file] [--preset nginx|apache|auth|json] [--merge-mode strict-override|prefer-stricter] [--force]

Examples:
  node scripts/nullid-local.mjs hash ./server.log --algo sha512
  node scripts/nullid-local.mjs sanitize ./raw.ndjson ./clean.ndjson --format ndjson --preset json
  node scripts/nullid-local.mjs sanitize-dir ./logs ./logs-clean --ext .log,.json --report ./sanitize-report.json
  node scripts/nullid-local.mjs redact ./incident.txt ./incident.redacted.txt --mode partial
  node scripts/nullid-local.mjs pdf-clean ./report.pdf ./report.clean.pdf
  node scripts/nullid-local.mjs office-clean ./incident.docx ./incident.clean.docx
  node scripts/nullid-local.mjs archive-sanitize ./evidence ./evidence-sanitized.zip --baseline ./nullid.policy.json
  node scripts/nullid-local.mjs precommit --staged --baseline ./nullid.policy.json --threshold high
  node scripts/nullid-local.mjs policy-init ./nullid.policy.json --preset nginx
  NULLID_PASSPHRASE='dev-secret' node scripts/nullid-local.mjs enc ./backup.tar ./backup.tar.nullid --profile strong
  NULLID_PASSPHRASE='dev-secret' node scripts/nullid-local.mjs dec ./backup.tar.nullid ./backup.tar
  node scripts/nullid-local.mjs pwgen --kind passphrase --words 6 --separator _
  node scripts/nullid-local.mjs meta ./photo.jpg
`.trim(),
  );
}

function parseSanitizeOptions(argv) {
  const preset = getOption(argv, "--preset") || "nginx";
  const policyPath = getOption(argv, "--policy");
  const baselinePath = resolveBaselinePath(getOption(argv, "--baseline"));
  const mergeMode = normalizeMergeMode(getOption(argv, "--merge-mode") || "strict-override");
  const jsonAware = parseBoolean(getOption(argv, "--json-aware"), true);
  const format = (getOption(argv, "--format") || "auto").toLowerCase();
  if (!sanitizeFormats.has(format)) {
    throw new Error(`Unsupported sanitize format: ${format}`);
  }

  let policy = policyPath ? loadPolicy(path.resolve(policyPath)) : buildPolicyFromPreset(preset, jsonAware);
  if (baselinePath) {
    const baseline = loadBaselineConfig(baselinePath);
    if (baseline) {
      policy = mergePolicyConfigs(policy, baseline, mergeMode);
    }
  }
  return { preset, policy, jsonAware: policy.jsonAware, format, mergeMode, baselinePath };
}

function sanitizeWithOptions(input, options) {
  return applySanitize(input, {
    policy: options.policy,
    jsonAware: options.jsonAware,
    format: options.format,
  });
}

const presetRules = {
  nginx: [
    "maskIp",
    "maskIpv6",
    "stripCookies",
    "dropUA",
    "scrubJwt",
    "maskBearer",
    "maskUser",
    "normalizeTs",
    "maskAwsKey",
    "maskAwsSecret",
    "maskGithubToken",
    "maskSlackToken",
    "stripPrivateKeyBlock",
    "maskCard",
    "maskIban",
  ],
  apache: [
    "maskIp",
    "maskIpv6",
    "maskEmail",
    "scrubJwt",
    "maskBearer",
    "normalizeTs",
    "maskGithubToken",
    "maskSlackToken",
    "stripPrivateKeyBlock",
    "maskCard",
    "maskIban",
  ],
  auth: ["maskIp", "maskIpv6", "maskUser", "maskGithubToken", "maskSlackToken", "stripPrivateKeyBlock"],
  json: [
    "maskIp",
    "maskIpv6",
    "stripJsonSecrets",
    "maskUser",
    "maskAwsKey",
    "maskAwsSecret",
    "maskGithubToken",
    "maskSlackToken",
    "stripPrivateKeyBlock",
    "maskCard",
    "maskIban",
  ],
};

const allRuleKeys = [
  "maskIp",
  "maskIpv6",
  "maskEmail",
  "scrubJwt",
  "maskBearer",
  "maskCard",
  "maskIban",
  "maskAwsKey",
  "maskAwsSecret",
  "maskGithubToken",
  "maskSlackToken",
  "stripPrivateKeyBlock",
  "stripCookies",
  "dropUA",
  "normalizeTs",
  "maskUser",
  "stripJsonSecrets",
];

function buildPolicyFromPreset(preset, jsonAware) {
  const selected = new Set(presetRules[preset] || presetRules.nginx);
  const rulesState = Object.fromEntries(allRuleKeys.map((key) => [key, selected.has(key)]));
  return { rulesState, jsonAware, customRules: [] };
}

function loadPolicy(policyPath) {
  const text = fs.readFileSync(policyPath, "utf8");
  const parsed = JSON.parse(text);
  const config = parsePolicyConfigPayload(parsed);
  if (!config) throw new Error("Invalid policy file: expected sanitize-policy-pack payload or direct policy config");
  return config;
}

function loadBaselineConfig(baselinePath) {
  const text = fs.readFileSync(path.resolve(baselinePath), "utf8");
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || parsed.kind !== "nullid-policy-baseline") {
    throw new Error("Invalid baseline file kind");
  }
  if (Number(parsed.schemaVersion) !== 1) {
    throw new Error(`Unsupported baseline schema: ${String(parsed.schemaVersion ?? "unknown")}`);
  }
  const sanitize = parsed.sanitize;
  if (!sanitize || typeof sanitize !== "object") {
    throw new Error("Baseline sanitize section missing");
  }
  const config = parsePolicyConfigPayload(sanitize.defaultConfig);
  if (!config) {
    throw new Error("Baseline defaultConfig invalid");
  }
  return config;
}

function parsePolicyConfigPayload(input) {
  const parsed = input && typeof input === "object" ? input : null;
  if (!parsed) return null;

  const packEntry = Array.isArray(parsed.packs) ? parsed.packs[0] : parsed.pack;
  if (packEntry && typeof packEntry === "object") {
    const config = normalizePolicyConfig(packEntry.config);
    if (config) return config;
  }

  if (parsed.kind === "nullid-policy-baseline" && parsed.sanitize && typeof parsed.sanitize === "object") {
    const baselineConfig = normalizePolicyConfig(parsed.sanitize.defaultConfig);
    if (baselineConfig) return baselineConfig;
  }

  return normalizePolicyConfig(parsed);
}

function normalizePolicyConfig(input) {
  if (!input || typeof input !== "object") return null;
  return {
    rulesState: normalizeRulesState(input.rulesState),
    jsonAware: Boolean(input.jsonAware),
    customRules: normalizeCustomRules(input.customRules),
  };
}

function mergePolicyConfigs(base, override, mode) {
  const rulesState = Object.fromEntries(
    allRuleKeys.map((key) => [key, mode === "prefer-stricter" ? Boolean(base.rulesState[key]) || Boolean(override.rulesState[key]) : Boolean(override.rulesState[key])]),
  );
  const customRules = mergeCustomRules(base.customRules, override.customRules);
  return {
    rulesState,
    jsonAware: mode === "prefer-stricter" ? Boolean(base.jsonAware) || Boolean(override.jsonAware) : Boolean(override.jsonAware),
    customRules,
  };
}

function mergeCustomRules(base, override) {
  const map = new Map();
  [...base, ...override].forEach((rule) => {
    const identity = `${rule.scope}::${rule.flags}::${rule.pattern}::${rule.replacement}`;
    map.set(identity, { ...rule, id: rule.id || crypto.randomUUID() });
  });
  return Array.from(map.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, rule]) => rule);
}

function resolveBaselinePath(explicitPath) {
  if (explicitPath) return path.resolve(explicitPath);
  const defaultPath = path.resolve("nullid.policy.json");
  return fs.existsSync(defaultPath) ? defaultPath : undefined;
}

function normalizeMergeMode(value) {
  return value === "prefer-stricter" ? "prefer-stricter" : "strict-override";
}

function normalizeRulesState(input) {
  const state = Object.fromEntries(allRuleKeys.map((key) => [key, false]));
  if (!input || typeof input !== "object") return state;
  allRuleKeys.forEach((key) => {
    if (typeof input[key] === "boolean") state[key] = input[key];
  });
  return state;
}

function normalizeCustomRules(input) {
  if (!Array.isArray(input)) return [];
  return input
    .map((rule) => {
      if (!rule || typeof rule !== "object") return null;
      if (typeof rule.pattern !== "string" || !rule.pattern.trim()) return null;
      const flags = typeof rule.flags === "string" ? rule.flags : "gi";
      try {
        // eslint-disable-next-line no-new
        new RegExp(rule.pattern, flags);
      } catch {
        return null;
      }
      return {
        id: typeof rule.id === "string" ? rule.id : crypto.randomUUID(),
        pattern: rule.pattern,
        replacement: typeof rule.replacement === "string" ? rule.replacement : "",
        flags,
        scope: rule.scope === "text" || rule.scope === "json" || rule.scope === "both" ? rule.scope : "both",
      };
    })
    .filter(Boolean);
}

function applySanitize(input, options) {
  const policy = options.policy;
  const report = [];
  const normalizedFormat = (options.format || "auto").toLowerCase();
  const detectedFormat = resolveSanitizeFormat(input, normalizedFormat, Boolean(options.jsonAware));
  report.push(`format:${detectedFormat}`);

  const structured = applyStructuredFormatSanitize(input, detectedFormat);
  let output = structured.output;
  if (structured.report.length) report.push(...structured.report);

  const applied = [];
  const applyRule = (enabled, label, fn) => {
    if (!enabled) return;
    const next = fn(output);
    if (next.count > 0) {
      output = next.output;
      report.push(`${label}: ${next.count}`);
      applied.push(label);
    }
  };

  applyRule(policy.rulesState.maskIp, "maskIp", (value) => replaceWithCount(value, /\b(\d{1,3}\.){3}\d{1,3}\b/g, "[ip]"));
  applyRule(policy.rulesState.maskIpv6, "maskIpv6", (value) => replaceWithCount(value, /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi, "[ipv6]"));
  applyRule(policy.rulesState.maskEmail, "maskEmail", (value) => replaceWithCount(value, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[email]"));
  applyRule(policy.rulesState.scrubJwt, "scrubJwt", (value) =>
    replaceWithCount(value, /(?:bearer\s+)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi, "[jwt]"),
  );
  applyRule(policy.rulesState.maskBearer, "maskBearer", (value) =>
    replaceWithCount(value, /\b(?:authorization[:=]\s*)?(?:bearer\s+)[A-Za-z0-9._-]{20,}\b/gi, "[token]"),
  );
  applyRule(policy.rulesState.maskAwsKey, "maskAwsKey", (value) => replaceWithCount(value, /\bAKIA[0-9A-Z]{16}\b/g, "[aws-key]"));
  applyRule(policy.rulesState.maskAwsSecret, "maskAwsSecret", (value) =>
    replaceWithCount(value, /\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b/gi, "aws_secret_access_key=[redacted]"),
  );
  applyRule(policy.rulesState.maskGithubToken, "maskGithubToken", (value) =>
    replaceWithCount(value, /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b/g, "[github-token]"),
  );
  applyRule(policy.rulesState.maskSlackToken, "maskSlackToken", (value) =>
    replaceWithCount(value, /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g, "[slack-token]"),
  );
  applyRule(policy.rulesState.stripPrivateKeyBlock, "stripPrivateKeyBlock", (value) =>
    replaceWithCount(
      value,
      /-----BEGIN (?:[A-Z0-9 ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]*?)PRIVATE KEY-----/g,
      "[private-key]",
    ),
  );
  applyRule(policy.rulesState.stripCookies, "stripCookies", (value) => replaceWithCount(value, /cookie=[^ ;\n]+/gi, "cookie=[stripped]"));
  applyRule(policy.rulesState.dropUA, "dropUA", (value) => replaceWithCount(value, /ua=[^\s]+|user-agent:[^\n]+/gi, "ua=[dropped]"));
  applyRule(policy.rulesState.normalizeTs, "normalizeTs", (value) =>
    replaceWithCount(value, /\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\]/g, "[timestamp]"),
  );
  applyRule(policy.rulesState.maskUser, "maskUser", (value) => replaceWithCount(value, /\buser=([A-Za-z0-9._-]+)\b/gi, "user=[user]"));
  applyRule(policy.rulesState.stripJsonSecrets, "stripJsonSecrets", (value) =>
    replaceWithCount(value, /\"(token|secret|password)\"\s*:\s*\"[^\"]+\"/gi, '"$1":"[redacted]"'),
  );
  applyRule(policy.rulesState.maskCard, "maskCard", replaceCardNumbers);
  applyRule(policy.rulesState.maskIban, "maskIban", replaceIban);

  const scope = detectedFormat === "json" || detectedFormat === "ndjson" ? "json" : "text";
  policy.customRules.forEach((rule) => {
    if (rule.scope !== "both" && rule.scope !== scope) return;
    const regex = new RegExp(rule.pattern, rule.flags);
    let count = 0;
    output = output.replace(regex, () => {
      count += 1;
      return rule.replacement;
    });
    if (count > 0) report.push(`custom:${rule.pattern}:${count}`);
  });

  const inputLines = input.split("\n");
  const outputLines = output.split("\n");
  const linesAffected = inputLines.reduce((count, line, index) => (line === outputLines[index] ? count : count + 1), 0);
  return { output, applied, report, linesAffected, detectedFormat };
}

function resolveSanitizeFormat(input, explicit, jsonAware) {
  if (explicit && explicit !== "auto") return explicit;

  const text = (input || "").trim();
  if (!text) return "text";

  if (jsonAware && (text.startsWith("{") || text.startsWith("["))) {
    try {
      JSON.parse(text);
      return "json";
    } catch {
      // Ignore and continue format heuristics.
    }
  }

  if (looksLikeNdjson(text)) return "ndjson";
  if (looksLikeCsv(text)) return "csv";
  if (looksLikeXml(text)) return "xml";
  if (looksLikeYaml(text)) return "yaml";
  return "text";
}

function looksLikeNdjson(text) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length < 2) return false;
  return lines.every((line) => {
    if (!(line.startsWith("{") || line.startsWith("["))) return false;
    try {
      JSON.parse(line);
      return true;
    } catch {
      return false;
    }
  });
}

function looksLikeCsv(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length < 2) return false;
  return lines[0].includes(",");
}

function looksLikeXml(text) {
  return /^\s*</.test(text) && /<[^>]+>/.test(text);
}

function looksLikeYaml(text) {
  return /^\s*[A-Za-z0-9_.-]+\s*:\s*.+/m.test(text);
}

function applyStructuredFormatSanitize(input, format) {
  if (format === "json") {
    try {
      const parsed = JSON.parse(input);
      const cleaned = jsonClean(parsed);
      return { output: JSON.stringify(cleaned, null, 2), report: ["json-aware-clean:1"] };
    } catch {
      return { output: input, report: ["json-aware-clean:0(parse-failed)"] };
    }
  }

  if (format === "ndjson") {
    const lines = input.split(/\r?\n/);
    let cleanedCount = 0;
    const outputLines = lines.map((line) => {
      if (!line.trim()) return line;
      try {
        const parsed = JSON.parse(line);
        const cleaned = jsonClean(parsed);
        cleanedCount += 1;
        return JSON.stringify(cleaned);
      } catch {
        return line;
      }
    });
    return {
      output: outputLines.join("\n"),
      report: [cleanedCount > 0 ? `ndjson-aware-clean:${cleanedCount}` : "ndjson-aware-clean:0"],
    };
  }

  if (format === "csv") {
    const rows = parseCsv(input);
    if (rows.length === 0) return { output: input, report: ["csv-redaction:0"] };
    const headers = rows[0].map((value) => normalizeHeader(value));
    const sensitiveColumns = headers.map((name) => isSensitiveHeader(name));
    let masked = 0;
    const nextRows = rows.map((row, rowIndex) => {
      if (rowIndex === 0) return row;
      return row.map((value, columnIndex) => {
        if (!sensitiveColumns[columnIndex]) return value;
        if (!value) return value;
        masked += 1;
        return "[redacted]";
      });
    });
    return { output: serializeCsv(nextRows), report: [masked > 0 ? `csv-redaction:${masked}` : "csv-redaction:0"] };
  }

  if (format === "xml") {
    let count = 0;
    const keyGroup = "token|authorization|password|secret|apikey|session|cookie|access_token|refresh_token";
    let output = input.replace(
      new RegExp(`(<\\s*(?:${keyGroup})\\b[^>]*>)[\\s\\S]*?(<\\/\\s*(?:${keyGroup})\\s*>)`, "gi"),
      (_match, open, close) => {
        count += 1;
        return `${open}[redacted]${close}`;
      },
    );
    output = output.replace(
      new RegExp(`(\\b(?:${keyGroup})\\b\\s*=\\s*[\"'])[^\"']*([\"'])`, "gi"),
      (_match, prefix, suffix) => {
        count += 1;
        return `${prefix}[redacted]${suffix}`;
      },
    );
    return { output, report: [count > 0 ? `xml-redaction:${count}` : "xml-redaction:0"] };
  }

  if (format === "yaml") {
    let count = 0;
    const output = input.replace(
      /^([ \t-]*)(token|authorization|password|secret|apikey|session|cookie|access_token|refresh_token)\s*:\s*.+$/gim,
      (_match, indent, key) => {
        count += 1;
        return `${indent}${key}: [redacted]`;
      },
    );
    return { output, report: [count > 0 ? `yaml-redaction:${count}` : "yaml-redaction:0"] };
  }

  return { output: input, report: [] };
}

function jsonClean(value) {
  if (Array.isArray(value)) return value.map((item) => jsonClean(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, sensitiveKeys.has(key.toLowerCase()) ? "[redacted]" : jsonClean(item)]),
    );
  }
  return value;
}

function parseCsv(input) {
  const lines = input.split(/\r?\n/);
  return lines.filter((line) => line.length > 0).map((line) => parseCsvLine(line));
}

function parseCsvLine(line) {
  const row = [];
  let value = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        value += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (char === "," && !inQuotes) {
      row.push(value);
      value = "";
      continue;
    }
    value += char;
  }
  row.push(value);
  return row;
}

function serializeCsv(rows) {
  return rows
    .map((row) =>
      row
        .map((cell) => {
          if (/[,"\n]/.test(cell)) {
            return `"${cell.replace(/"/g, '""')}"`;
          }
          return cell;
        })
        .join(","),
    )
    .join("\n");
}

function normalizeHeader(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "");
}

function isSensitiveHeader(value) {
  if (!value) return false;
  if (sensitiveKeys.has(value)) return true;
  return value.endsWith("token") || value.includes("password") || value.includes("secret");
}

function replaceWithCount(input, regex, replacement) {
  let count = 0;
  const output = input.replace(regex, () => {
    count += 1;
    return replacement;
  });
  return { output, count };
}

function replaceCardNumbers(input) {
  const regex = /\b(?:\d[ -]?){12,19}\b/g;
  let count = 0;
  const output = input.replace(regex, (match) => {
    if (passesLuhn(match)) {
      count += 1;
      return "[card]";
    }
    return match;
  });
  return { output, count };
}

function replaceIban(input) {
  const regex = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi;
  let count = 0;
  const output = input.replace(regex, (match) => {
    if (isValidIban(match)) {
      count += 1;
      return "[iban]";
    }
    return match;
  });
  return { output, count };
}

function passesLuhn(value) {
  const digits = value.replace(/[^0-9]/g, "");
  if (digits.length < 12 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = Number(digits[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function isValidIban(value) {
  const trimmed = value.replace(/\s+/g, "").toUpperCase();
  if (trimmed.length < 15 || trimmed.length > 34) return false;
  const rearranged = `${trimmed.slice(4)}${trimmed.slice(0, 4)}`;
  const converted = rearranged.replace(/[A-Z]/g, (ch) => `${ch.charCodeAt(0) - 55}`);
  let remainder = 0;
  for (let i = 0; i < converted.length; i += 1) {
    remainder = (remainder * 10 + Number(converted[i])) % 97;
  }
  return remainder === 1;
}

function buildRedactDetectors() {
  return [
    { key: "email", label: "Email", regex: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, severity: "medium", mask: "[email]" },
    { key: "phone", label: "Phone", regex: /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g, severity: "low", mask: "[phone]" },
    {
      key: "token",
      label: "Bearer / token",
      regex: /\b(?:authorization[:=]\s*)?(?:bearer\s+)?[A-Za-z0-9._-]{20,}\b/gi,
      severity: "high",
      mask: "[token]",
    },
    { key: "ip", label: "IP", regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, severity: "medium", mask: "[ip]" },
    { key: "id", label: "ID", regex: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "high", mask: "[id]" },
    {
      key: "iban",
      label: "IBAN",
      regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi,
      severity: "high",
      mask: "[iban]",
      validate: isValidIban,
    },
    {
      key: "card",
      label: "Credit card",
      regex: /\b(?:\d[ -]?){12,19}\b/g,
      severity: "high",
      mask: "[card]",
      validate: passesLuhn,
    },
    { key: "ipv6", label: "IPv6", regex: /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi, severity: "medium", mask: "[ipv6]" },
    { key: "awskey", label: "AWS key", regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high", mask: "[aws-key]" },
    {
      key: "awssecret",
      label: "AWS secret",
      regex: /\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b/gi,
      severity: "high",
      mask: "[aws-secret]",
    },
    {
      key: "github",
      label: "GitHub token",
      regex: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b/g,
      severity: "high",
      mask: "[github-token]",
    },
    {
      key: "slack",
      label: "Slack token",
      regex: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g,
      severity: "high",
      mask: "[slack-token]",
    },
    {
      key: "privatekey",
      label: "Private key block",
      regex: /-----BEGIN (?:[A-Z0-9 ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]*?)PRIVATE KEY-----/g,
      severity: "high",
      mask: "[private-key]",
    },
  ];
}

function scanRedaction(text, detectors) {
  const counts = {};
  const severityMap = {};
  const matches = [];

  detectors.forEach((detector) => {
    const regex = new RegExp(detector.regex, detector.regex.flags);
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      if (detector.validate && !detector.validate(value)) {
        if (!regex.global) break;
        continue;
      }
      counts[detector.label] = (counts[detector.label] || 0) + 1;
      severityMap[detector.label] = detector.severity;
      matches.push({
        start: match.index,
        end: match.index + value.length,
        label: detector.label,
        severity: detector.severity,
        mask: detector.mask,
      });
      if (!regex.global) break;
    }
  });

  const resolved = resolveOverlaps(matches);
  const total = Object.values(counts).reduce((sum, value) => sum + Number(value || 0), 0);
  const overall =
    resolved
      .map((match) => match.severity)
      .sort((a, b) => severityRank(b) - severityRank(a))[0] || "low";

  return { counts, severityMap, total, overall, matches: resolved };
}

function resolveOverlaps(matches) {
  if (matches.length === 0) return [];
  const byStart = [...matches].sort((a, b) => a.start - b.start);
  const resolved = [];
  let i = 0;
  while (i < byStart.length) {
    const group = [byStart[i]];
    let windowEnd = byStart[i].end;
    let j = i + 1;
    while (j < byStart.length && byStart[j].start < windowEnd) {
      group.push(byStart[j]);
      windowEnd = Math.max(windowEnd, byStart[j].end);
      j += 1;
    }
    const best = [...group].sort((a, b) => {
      const lenDiff = b.end - b.start - (a.end - a.start);
      if (lenDiff !== 0) return lenDiff;
      const sevDiff = severityRank(b.severity) - severityRank(a.severity);
      if (sevDiff !== 0) return sevDiff;
      return a.start - b.start;
    })[0];
    resolved.push(best);
    i = j;
  }
  return resolved.sort((a, b) => a.start - b.start);
}

function applyRedaction(text, matches, mode) {
  if (!matches.length) return text;
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  let cursor = 0;
  let output = "";
  sorted.forEach((match) => {
    output += text.slice(cursor, match.start);
    output += mode === "full" ? match.mask : partialMask(text.slice(match.start, match.end));
    cursor = match.end;
  });
  output += text.slice(cursor);
  return output;
}

function partialMask(value) {
  if (value.length <= 4) return "*".repeat(value.length);
  return "*".repeat(Math.max(0, value.length - 4)) + value.slice(-4);
}

function severityRank(value) {
  return value === "high" ? 3 : value === "medium" ? 2 : 1;
}

function severityCounts(matches) {
  const totals = { high: 0, medium: 0, low: 0 };
  matches.forEach((match) => {
    if (match.severity === "high") totals.high += 1;
    else if (match.severity === "medium") totals.medium += 1;
    else totals.low += 1;
  });
  return totals;
}

const kdfProfiles = {
  compat: { profile: "compat", iterations: 250_000, nodeHash: "sha256", headerHash: "SHA-256" },
  strong: { profile: "strong", iterations: 600_000, nodeHash: "sha512", headerHash: "SHA-512" },
  paranoid: { profile: "paranoid", iterations: 1_000_000, nodeHash: "sha512", headerHash: "SHA-512" },
};

function resolveKdfProfile(value) {
  const normalized = String(value || "compat").toLowerCase();
  if (!kdfProfiles[normalized]) {
    throw new Error(`Unsupported profile: ${value}`);
  }
  return kdfProfiles[normalized];
}

function resolveKdfSettings(profile, overrideIterations, overrideHash) {
  const normalizedHash = overrideHash ? normalizeKdfHash(overrideHash) : { nodeHash: profile.nodeHash, headerHash: profile.headerHash };
  return {
    profile: profile.profile,
    iterations: overrideIterations ? normalizeIterations(overrideIterations) : profile.iterations,
    nodeHash: normalizedHash.nodeHash,
    headerHash: normalizedHash.headerHash,
  };
}

function normalizeKdfHash(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "sha512" || normalized === "sha-512") {
    return { nodeHash: "sha512", headerHash: "SHA-512" };
  }
  if (normalized === "sha256" || normalized === "sha-256" || normalized === "") {
    return { nodeHash: "sha256", headerHash: "SHA-256" };
  }
  throw new Error(`Unsupported kdf hash: ${value}`);
}

function normalizeIterations(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 100_000 || parsed > 2_000_000) {
    throw new Error("KDF iterations must be between 100000 and 2000000");
  }
  return Math.floor(parsed);
}

function resolvePassphrase(argv) {
  const direct = getOption(argv, "--pass");
  if (direct) return direct;

  const passEnv = getOption(argv, "--pass-env");
  if (passEnv) {
    const value = process.env[passEnv];
    if (!value) {
      throw new Error(`Passphrase env variable not found: ${passEnv}`);
    }
    return value;
  }

  if (process.env.NULLID_PASSPHRASE) {
    return process.env.NULLID_PASSPHRASE;
  }

  throw new Error("Passphrase required: use --pass, --pass-env, or NULLID_PASSPHRASE");
}

function detectMimeFromPath(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const map = {
    ".txt": "text/plain",
    ".log": "text/plain",
    ".json": "application/json",
    ".csv": "text/csv",
    ".xml": "application/xml",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".md": "text/markdown",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".avif": "image/avif",
    ".pdf": "application/pdf",
  };
  return map[ext] || "application/octet-stream";
}

function detectFileFormat(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "jpeg";
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "png";
  if (buffer.length >= 6) {
    const sig = buffer.subarray(0, 6).toString("ascii");
    if (sig === "GIF87a" || sig === "GIF89a") return "gif";
  }
  if (buffer.length >= 12) {
    const riff = buffer.subarray(0, 4).toString("ascii");
    const webp = buffer.subarray(8, 12).toString("ascii");
    if (riff === "RIFF" && webp === "WEBP") return "webp";
  }
  if (buffer.length >= 12 && buffer.subarray(4, 8).toString("ascii") === "ftyp") {
    const brand = buffer.subarray(8, 12).toString("ascii").toLowerCase();
    if (brand.startsWith("avif") || brand.startsWith("avis")) return "avif";
    if (brand.startsWith("heic") || brand.startsWith("heif") || brand.startsWith("heix") || brand.startsWith("hevc")) return "heic";
    return "isobmff";
  }
  if (buffer.length >= 4 && buffer.subarray(0, 4).equals(Buffer.from([0x49, 0x49, 0x2a, 0x00]))) return "tiff";
  if (buffer.length >= 4 && buffer.subarray(0, 4).equals(Buffer.from([0x4d, 0x4d, 0x00, 0x2a]))) return "tiff";
  if (buffer.length >= 2 && buffer.subarray(0, 2).toString("ascii") === "BM") return "bmp";
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString("ascii") === "%PDF") return "pdf";
  return "unknown";
}

const symbols = "!@#$%^&*()-_=+[]{}<>?/|~";
const ambiguous = new Set(["l", "1", "I", "O", "0", "o"]);

function generatePassword(settings) {
  const pools = [];
  if (settings.upper) pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (settings.lower) pools.push("abcdefghijklmnopqrstuvwxyz");
  if (settings.digits) pools.push("0123456789");
  if (settings.symbols) pools.push(symbols);
  if (pools.length === 0) pools.push("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

  const filteredPools = settings.avoidAmbiguity ? pools.map((pool) => [...pool].filter((ch) => !ambiguous.has(ch)).join("")) : pools;
  const alphabet = filteredPools.join("");

  const baseline = [];
  if (settings.enforceMix) {
    filteredPools.forEach((pool) => {
      if (pool.length > 0) baseline.push(pool[randomIndex(pool.length)]);
    });
  }

  const remaining = Math.max(settings.length - baseline.length, 0);
  for (let i = 0; i < remaining; i += 1) {
    baseline.push(alphabet[randomIndex(alphabet.length)]);
  }

  return shuffle(baseline).join("");
}

function generatePassphrase(settings, wordlist) {
  const sep = settings.separator === "space" ? " " : settings.separator;
  const picks = [];

  for (let i = 0; i < settings.words; i += 1) {
    let word = wordlist[randomIndex(wordlist.length)];
    if (settings.randomCase) word = maybeCapitalize(word);
    picks.push(word);
  }

  if (settings.appendNumber) picks.push(String(randomIndex(10)));
  if (settings.appendSymbol) picks.push(symbols[randomIndex(symbols.length)]);

  return picks.join(sep);
}

function maybeCapitalize(value) {
  if (!value.length) return value;
  const mode = randomIndex(3);
  if (mode === 0) return value.toUpperCase();
  if (mode === 1) return value[0].toUpperCase() + value.slice(1);
  return value;
}

function estimatePasswordEntropy(settings) {
  const pools = [];
  if (settings.upper) pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (settings.lower) pools.push("abcdefghijklmnopqrstuvwxyz");
  if (settings.digits) pools.push("0123456789");
  if (settings.symbols) pools.push(symbols);
  const alphabet = (settings.avoidAmbiguity ? pools.map((pool) => [...pool].filter((ch) => !ambiguous.has(ch)).join("")) : pools).join("");
  const size = alphabet.length || 1;
  return Math.round(settings.length * Math.log2(size));
}

function estimatePassphraseEntropy(settings, wordlistSize) {
  const base = wordlistSize > 0 ? wordlistSize : 1;
  const wordEntropy = settings.words * Math.log2(base);
  const numberEntropy = settings.appendNumber ? Math.log2(10) : 0;
  const symbolEntropy = settings.appendSymbol ? Math.log2(symbols.length) : 0;
  const caseEntropy = settings.randomCase ? settings.words * Math.log2(3) : 0;
  return Math.round(wordEntropy + numberEntropy + symbolEntropy + caseEntropy);
}

function buildWordlist() {
  const syllables = ["amber", "bison", "cinder", "delta", "ember", "fable"];
  const list = [];
  for (let a = 0; a < 6; a += 1) {
    for (let b = 0; b < 6; b += 1) {
      for (let c = 0; c < 6; c += 1) {
        for (let d = 0; d < 6; d += 1) {
          for (let e = 0; e < 6; e += 1) {
            const word = `${syllables[a]}${syllables[b].slice(0, 2)}${syllables[c].slice(-2)}${syllables[d][0]}${syllables[e].slice(1, 3)}`;
            list.push(word);
          }
        }
      }
    }
  }
  return list;
}

function randomIndex(max) {
  if (max <= 0) throw new Error("max must be positive");
  return crypto.randomInt(0, max);
}

function shuffle(items) {
  const next = [...items];
  for (let i = next.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    [next[i], next[j]] = [next[j], next[i]];
  }
  return next;
}

function getOption(argv, flag) {
  const index = argv.findIndex((arg) => arg === flag);
  if (index < 0) return undefined;
  return argv[index + 1];
}

function hasFlag(argv, flag) {
  return argv.includes(flag);
}

function resolvePrecommitFiles(argv) {
  const filesArg = getOption(argv, "--files");
  if (filesArg) {
    return filesArg
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
  }
  if (hasFlag(argv, "--staged")) {
    return runGit(["diff", "--cached", "--name-only", "--diff-filter=ACM"]);
  }
  const gitRange = getOption(argv, "--git-range");
  if (gitRange) {
    return runGit(["diff", "--name-only", gitRange]);
  }
  return runGit(["ls-files"]);
}

function parseExtFilter(extOption) {
  if (!extOption) return new Set([".log", ".txt", ".json", ".ndjson", ".csv", ".xml", ".yaml", ".yml"]);
  return new Set(
    extOption
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

function normalizeSeverity(value) {
  const normalized = String(value || "high").toLowerCase();
  if (normalized === "medium" || normalized === "low" || normalized === "high") return normalized;
  throw new Error(`Unsupported severity threshold: ${value}`);
}

function runGit(args) {
  try {
    const output = execFileSync("git", args, { encoding: "utf8" });
    return output
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`git command failed: git ${args.join(" ")} (${detail})`);
  }
}

function replaceSameLength(input, regex, transform) {
  let count = 0;
  const output = input.replace(regex, (...args) => {
    count += 1;
    const match = args[0];
    const next = String(transform(...args));
    return fitToLength(next, match.length);
  });
  return { output, count };
}

function fitToLength(value, length, fillChar = " ") {
  if (value.length === length) return value;
  if (value.length > length) return value.slice(0, length);
  return value + fillChar.repeat(length - value.length);
}

function maskPdfValue(value, token) {
  if (value.startsWith("(") && value.endsWith(")") && value.length >= 2) {
    const inner = fitToLength(token, value.length - 2);
    return `(${inner})`;
  }
  if (value.startsWith("<") && value.endsWith(">") && value.length >= 2) {
    const hexToken = token.replace(/[^0-9a-f]/gi, "").toLowerCase() || "00";
    const evenLength = Math.max(2, (value.length - 2) % 2 === 0 ? value.length - 2 : value.length - 3);
    const inner = fitToLength(hexToken.repeat(Math.ceil(evenLength / Math.max(1, hexToken.length))), value.length - 2, "0");
    return `<${inner}>`;
  }
  return fitToLength(token, value.length);
}

function maskPdfRef(value) {
  return fitToLength("0 0 R", value.length);
}

function ensureZipTooling() {
  assertCommandAvailable("zip");
  assertCommandAvailable("unzip");
}

function assertCommandAvailable(command) {
  try {
    execFileSync("which", [command], { stdio: "ignore" });
  } catch {
    throw new Error(`${command} command not found; install it to use this workflow`);
  }
}

function unzipArchive(zipPath, outputDir) {
  fs.mkdirSync(outputDir, { recursive: true });
  try {
    execFileSync("unzip", ["-qq", zipPath, "-d", outputDir], { stdio: "pipe" });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`unzip failed for ${zipPath}: ${detail}`);
  }
}

function zipDirectory(sourceDir, outputZipPath) {
  try {
    execFileSync("zip", ["-qr", outputZipPath, "."], { cwd: sourceDir, stdio: "pipe" });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`zip failed for ${sourceDir}: ${detail}`);
  }
}

function withTempDir(prefix, action) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    return action(tempDir);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function copyDirectory(sourceDir, targetDir) {
  fs.cpSync(sourceDir, targetDir, { recursive: true });
}

function buildOfficeCoreXml() {
  return [
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">",
    "<dc:title></dc:title>",
    "<dc:subject></dc:subject>",
    "<dc:creator>redacted</dc:creator>",
    "<cp:keywords></cp:keywords>",
    "<dc:description></dc:description>",
    "<cp:lastModifiedBy>redacted</cp:lastModifiedBy>",
    "<dcterms:created xsi:type=\"dcterms:W3CDTF\">1970-01-01T00:00:00Z</dcterms:created>",
    "<dcterms:modified xsi:type=\"dcterms:W3CDTF\">1970-01-01T00:00:00Z</dcterms:modified>",
    "</cp:coreProperties>",
    "",
  ].join("\n");
}

function buildOfficeAppXml() {
  return [
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\" xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">",
    "<Application>NullID</Application>",
    "<DocSecurity>0</DocSecurity>",
    "<ScaleCrop>false</ScaleCrop>",
    "<LinksUpToDate>false</LinksUpToDate>",
    "<SharedDoc>false</SharedDoc>",
    "<HyperlinksChanged>false</HyperlinksChanged>",
    "<AppVersion>1.0</AppVersion>",
    "</Properties>",
    "",
  ].join("\n");
}

function parseBoolean(value, fallback) {
  if (value == null) return fallback;
  const normalized = String(value).toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  return fallback;
}

function clampInt(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function walkFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  entries.forEach((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(full));
      return;
    }
    if (entry.isFile()) files.push(full);
  });
  return files;
}

function looksBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8000));
  for (let i = 0; i < sample.length; i += 1) {
    if (sample[i] === 0) return true;
  }
  return false;
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function toBase64Url(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padLength), "base64");
}

main();
