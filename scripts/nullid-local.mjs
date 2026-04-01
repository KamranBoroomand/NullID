#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import os from "node:os";

const ENVELOPE_PREFIX = "NULLID:ENC:1";
const ENVELOPE_AAD = Buffer.from("nullid:enc:v1", "utf8");
const sanitizeFormats = new Set(["auto", "text", "json", "ndjson", "csv", "xml", "yaml"]);
const MAX_CUSTOM_PATTERN_LENGTH = 240;
const MAX_CUSTOM_REPLACEMENT_LENGTH = 2000;
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
const passwordHashSpec = JSON.parse(fs.readFileSync(new URL("../src/utils/passwordHashingSpec.json", import.meta.url), "utf8"));
const passwordHashAlgorithms = new Set(passwordHashSpec.algorithms);
const PASSWORD_HASH_MIN_SALT_BYTES = passwordHashSpec.saltBytes.min;
const PASSWORD_HASH_DEFAULT_SALT_BYTES = passwordHashSpec.saltBytes.default;
const PASSWORD_HASH_MAX_SALT_BYTES = passwordHashSpec.saltBytes.max;
const PASSWORD_HASH_DEFAULT_DERIVED_BYTES = passwordHashSpec.record.derivedBytes;
const PASSWORD_HASH_DEFAULT_DERIVED_BITS = passwordHashSpec.record.derivedBits;
const PASSWORD_HASH_ARGON2_VERSION = passwordHashSpec.record.argon2Version;

const PASSWORD_HASH_MIN_PBKDF2_ITERATIONS = passwordHashSpec.pbkdf2.iterations.min;
const PASSWORD_HASH_DEFAULT_PBKDF2_ITERATIONS = passwordHashSpec.pbkdf2.iterations.default;
const PASSWORD_HASH_MAX_PBKDF2_ITERATIONS = passwordHashSpec.pbkdf2.iterations.max;
const PASSWORD_HASH_PBKDF2_RECOMMENDED_MIN = passwordHashSpec.pbkdf2.iterations.recommendedMin;

const PASSWORD_HASH_MIN_ARGON2_MEMORY = passwordHashSpec.argon2.memory.min;
const PASSWORD_HASH_DEFAULT_ARGON2_MEMORY = passwordHashSpec.argon2.memory.default;
const PASSWORD_HASH_MAX_ARGON2_MEMORY = passwordHashSpec.argon2.memory.max;
const PASSWORD_HASH_ARGON2_MEMORY_RECOMMENDED_MIN = passwordHashSpec.argon2.memory.recommendedMin;

const PASSWORD_HASH_MIN_ARGON2_PASSES = passwordHashSpec.argon2.passes.min;
const PASSWORD_HASH_DEFAULT_ARGON2_PASSES = passwordHashSpec.argon2.passes.default;
const PASSWORD_HASH_MAX_ARGON2_PASSES = passwordHashSpec.argon2.passes.max;
const PASSWORD_HASH_ARGON2_PASSES_RECOMMENDED_MIN = passwordHashSpec.argon2.passes.recommendedMin;

const PASSWORD_HASH_MIN_ARGON2_PARALLELISM = passwordHashSpec.argon2.parallelism.min;
const PASSWORD_HASH_DEFAULT_ARGON2_PARALLELISM = passwordHashSpec.argon2.parallelism.default;
const PASSWORD_HASH_MAX_ARGON2_PARALLELISM = passwordHashSpec.argon2.parallelism.max;

const PASSWORD_HASH_B64_SEGMENT = passwordHashSpec.record.base64Segment;
const PASSWORD_HASH_B64_SEGMENT_RE = new RegExp(`^${PASSWORD_HASH_B64_SEGMENT}$`, "u");
const PASSWORD_HASH_WARNINGS = passwordHashSpec.warnings;
const PASSWORD_HASH_ERRORS = passwordHashSpec.errors;
const NULLID_APP_NAME = "NullID";
const NULLID_VERSION = readNullIdVersion();
const WORKFLOW_PACKAGE_SCHEMA_VERSION = 1;
const WORKFLOW_PACKAGE_KIND = "nullid-workflow-package";
const SAFE_SHARE_BUNDLE_SCHEMA_VERSION = 2;
const SAFE_SHARE_BUNDLE_KIND = "nullid-safe-share";
const LEGACY_SAFE_SHARE_BUNDLE_SCHEMA_VERSION = 1;
const WORKFLOW_UNSIGNED_NOTES = [
  "Unsigned package. Sender identity is not asserted.",
  "SHA-256 manifest entries help detect changes to listed artifacts, but they are not a signature.",
];
const SAFE_SHARE_WORKFLOW_PRESETS = {
  "general-safe-share": {
    label: "General safe share",
    description: "Balanced disclosure reduction for routine sharing of text snippets and locally cleanable files.",
  },
  "support-ticket": {
    label: "Support ticket / bug report",
    description: "Removes obvious secrets while keeping enough operational context for debugging.",
  },
  "external-minimum": {
    label: "External share / minimum disclosure",
    description: "Aggressively reduces context and avoids packaging original references by default.",
  },
  "internal-investigation": {
    label: "Internal investigation package",
    description: "Preserves responder context for internal analysis while still scrubbing obvious secrets and tokens.",
  },
  "incident-handoff": {
    label: "Incident artifact handoff",
    description: "Preserves enough context for another responder while still scrubbing obvious secrets.",
  },
  "evidence-archive": {
    label: "Evidence archive / preserve context",
    description: "Preserves context more conservatively and allows original file packaging when needed.",
  },
};

const command = process.argv[2];
const args = process.argv.slice(3);
let passwordHashArgon2SupportCache = null;

async function main() {
  if (!command || command === "help" || command === "--help" || command === "-h") {
    printUsage();
    return;
  }

  switch (command) {
    case "hash":
      runHash(args);
      return;
    case "sanitize":
      runSanitize(args);
      return;
    case "sanitize-dir":
      runSanitizeDir(args);
      return;
    case "bundle":
      runBundle(args);
      return;
    case "package-inspect":
      runPackageInspect(args);
      return;
    case "redact":
      runRedact(args);
      return;
    case "enc":
      runEncrypt(args);
      return;
    case "dec":
      runDecrypt(args);
      return;
    case "pwgen":
      runPwgen(args);
      return;
    case "pw-hash":
      await runPasswordHash(args);
      return;
    case "pw-verify":
      await runPasswordVerify(args);
      return;
    case "meta":
      runMeta(args);
      return;
    case "pdf-clean":
      runPdfClean(args);
      return;
    case "office-clean":
      runOfficeClean(args);
      return;
    case "archive-sanitize":
      runArchiveSanitize(args);
      return;
    case "precommit":
      runPrecommit(args);
      return;
    case "policy-init":
      runPolicyInit(args);
      return;
    default:
      throw new Error(`Unknown command: ${command}`);
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
      "Usage: bundle <input-file> <output-json> [--preset nginx|apache|auth|json] [--workflow general-safe-share|support-ticket|external-minimum|internal-investigation|incident-handoff|evidence-archive] [--title <incident-title>] [--purpose <text>] [--case-ref <id>] [--recipient <scope>] [--policy <policy-json>] [--baseline <nullid.policy.json>] [--merge-mode strict-override|prefer-stricter] [--json-aware true|false] [--format auto|text|json|ndjson|csv|xml|yaml]",
    );
  }
  const input = fs.readFileSync(path.resolve(inputPath), "utf8");
  const options = parseSanitizeOptions(argv);
  const workflowPreset = resolveSafeShareWorkflowPresetCli(getOption(argv, "--workflow"));
  const incidentMeta = {
    title: getOption(argv, "--title") || "",
    purpose: getOption(argv, "--purpose") || "",
    caseReference: getOption(argv, "--case-ref") || "",
    recipientScope: getOption(argv, "--recipient") || "",
  };
  const result = sanitizeWithOptions(input, options);
  const bundle = createSanitizeSafeShareBundleCli({
    inputPath,
    options,
    workflowPreset,
    incidentMeta,
    result,
    input,
  });
  fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  console.log(
    JSON.stringify(
      {
        output: outputPath,
        schemaVersion: bundle.schemaVersion,
        workflowType: bundle.workflowPackage.workflowType,
        workflowPreset: bundle.workflowPackage.workflowPreset?.id || null,
        detectedFormat: result.detectedFormat,
        sha256: bundle.output.sha256,
        linesAffected: result.linesAffected,
      },
      null,
      2,
    ),
  );
}

function runPackageInspect(argv) {
  const inputPath = argv[0];
  if (!inputPath) {
    throw new Error("Usage: package-inspect <input-file> [--pass <passphrase>|--pass-env <VAR>] [--verify-pass <passphrase>|--verify-pass-env <VAR>]");
  }

  const file = path.resolve(inputPath);
  const raw = fs.readFileSync(file, "utf8");
  const normalized = raw.trim().replace(/\s+/g, "");
  let payloadText = raw;
  let envelope = null;
  let decrypted = false;

  if (normalized.startsWith(`${ENVELOPE_PREFIX}.`)) {
    const envelopeInspect = inspectEnvelopeBlob(raw);
    envelope = {
      prefix: ENVELOPE_PREFIX,
      mime: envelopeInspect.header.mime || null,
      name: envelopeInspect.header.name || null,
      ciphertextBytes: envelopeInspect.ciphertextBytes,
      kdf: {
        name: envelopeInspect.header.kdf.name,
        iterations: envelopeInspect.header.kdf.iterations,
        hash: envelopeInspect.header.kdf.hash,
      },
    };

    const passphrase = resolveOptionalPassphrase(argv);
    if (!passphrase) {
      console.log(
        JSON.stringify(
          {
            file: inputPath,
            artifactType: "envelope",
            artifactKindLabel: "Encrypted envelope",
            title: envelope.name ? `Encrypted envelope (${envelope.name})` : "Encrypted envelope",
            verificationState: "verification-required",
            verificationLabel: "Passphrase required",
            envelope,
            trustBasis: [
              "Envelope header is inspectable locally.",
              "The inner payload and AES-GCM integrity cannot be checked without the passphrase.",
            ],
            verifiedChecks: ["Envelope header parsed successfully."],
            unverifiedChecks: ["Inner payload type is unknown until the envelope is decrypted."],
            warnings: [],
            limitations: ["Provide the envelope passphrase to inspect the inner payload."],
            facts: [],
            artifacts: [],
            transforms: [],
            policySummary: [],
            failure: "Passphrase required to inspect inner payload",
          },
          null,
          2,
        ),
      );
      return;
    }

    const decryptedEnvelope = decryptEnvelopeBlob(passphrase, raw);
    payloadText = decryptedEnvelope.plaintext.toString("utf8");
    decrypted = true;
  }

  let parsed;
  try {
    parsed = JSON.parse(payloadText);
  } catch {
    console.log(
      JSON.stringify(
        {
          file: inputPath,
          artifactType: decrypted ? "unsupported" : "malformed",
          artifactKindLabel: decrypted ? "Unsupported decrypted payload" : "Malformed artifact",
          title: decrypted ? "Unsupported decrypted payload" : "Malformed artifact",
          verificationState: decrypted ? "unsupported" : "malformed",
          verificationLabel: decrypted ? "Unsupported" : "Malformed",
          envelope,
          trustBasis: decrypted ? ["Envelope decryption succeeded locally."] : [],
          verifiedChecks: decrypted ? ["Envelope decrypted successfully."] : [],
          unverifiedChecks: [
            decrypted
              ? "The decrypted payload is not one of the supported JSON artifact types in this verifier."
              : "The content is not valid JSON and is not a NULLID:ENC:1 envelope.",
          ],
          warnings: [],
          limitations: [],
          facts: [],
          artifacts: [],
          transforms: [],
          policySummary: [],
          failure: decrypted ? "Unsupported decrypted payload" : "Malformed JSON or unsupported artifact encoding",
        },
        null,
        2,
      ),
    );
    return;
  }

  const inspected = inspectParsedArtifactCli(parsed, {
    verificationPassphrase: resolveOptionalVerificationPassphrase(argv),
  });
  const trustBasis = decrypted
    ? ["NULLID:ENC:1 envelope decrypted locally.", ...inspected.trustBasis]
    : inspected.trustBasis;
  const verifiedChecks = decrypted
    ? ["Envelope decrypted successfully.", ...inspected.verifiedChecks]
    : inspected.verifiedChecks;
  console.log(
    JSON.stringify(
      {
        file: inputPath,
        envelope,
        ...inspected,
        trustBasis,
        verifiedChecks,
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
  const blob = fs.readFileSync(path.resolve(inputPath), "utf8");
  const { plaintext, header } = decryptEnvelopeBlob(passphrase, blob);

  fs.writeFileSync(path.resolve(outputPath), plaintext);
  console.log(
    JSON.stringify(
      {
        input: inputPath,
        output: outputPath,
        bytes: plaintext.length,
        mime: header.mime || "application/octet-stream",
        name: header.name || path.basename(outputPath),
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

async function runPasswordHash(argv) {
  const algorithm = (getOption(argv, "--algo") || "argon2id").toLowerCase();
  if (!passwordHashAlgorithms.has(algorithm)) {
    throw new Error(`Unsupported password hash algorithm: ${algorithm}`);
  }

  const secret = resolvePasswordSecret(argv);
  const options = {
    algorithm,
    saltBytes: clampInt(getOption(argv, "--salt-bytes"), PASSWORD_HASH_MIN_SALT_BYTES, PASSWORD_HASH_MAX_SALT_BYTES, PASSWORD_HASH_DEFAULT_SALT_BYTES),
    pbkdf2Iterations: clampInt(
      getOption(argv, "--pbkdf2-iterations"),
      PASSWORD_HASH_MIN_PBKDF2_ITERATIONS,
      PASSWORD_HASH_MAX_PBKDF2_ITERATIONS,
      PASSWORD_HASH_DEFAULT_PBKDF2_ITERATIONS,
    ),
    argon2Memory: clampInt(
      getOption(argv, "--argon2-memory"),
      PASSWORD_HASH_MIN_ARGON2_MEMORY,
      PASSWORD_HASH_MAX_ARGON2_MEMORY,
      PASSWORD_HASH_DEFAULT_ARGON2_MEMORY,
    ),
    argon2Passes: clampInt(
      getOption(argv, "--argon2-passes"),
      PASSWORD_HASH_MIN_ARGON2_PASSES,
      PASSWORD_HASH_MAX_ARGON2_PASSES,
      PASSWORD_HASH_DEFAULT_ARGON2_PASSES,
    ),
    argon2Parallelism: clampInt(
      getOption(argv, "--argon2-parallelism"),
      PASSWORD_HASH_MIN_ARGON2_PARALLELISM,
      PASSWORD_HASH_MAX_ARGON2_PARALLELISM,
      PASSWORD_HASH_DEFAULT_ARGON2_PARALLELISM,
    ),
  };
  const result = await generatePasswordHashRecord(secret, options);
  console.log(
    JSON.stringify(
      {
        algorithm: result.algorithm,
        record: result.record,
        safety: result.assessment.safety,
        warnings: result.assessment.warnings,
      },
      null,
      2,
    ),
  );
}

async function runPasswordVerify(argv) {
  const record = resolvePasswordHashRecord(argv);
  const secret = resolvePasswordSecret(argv);
  const parsed = parsePasswordHashRecord(record);
  const match = await verifyPasswordHashRecord(secret, record);
  console.log(
    JSON.stringify(
      {
        algorithm: parsed.algorithm,
        match,
      },
      null,
      2,
    ),
  );
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

function createSanitizeSafeShareBundleCli({ inputPath, options, workflowPreset, incidentMeta, result, input }) {
  const createdAt = new Date().toISOString();
  const producer = {
    app: NULLID_APP_NAME,
    surface: "cli",
    module: "sanitize",
    version: NULLID_VERSION,
    buildId: null,
  };
  const workflowPackage = createSanitizeWorkflowPackageCli({
    createdAt,
    producer,
    sourceFile: inputPath,
    detectedFormat: result.detectedFormat,
    policy: options.policy,
    preset: options.preset,
    baselinePath: options.baselinePath || null,
    workflowPreset,
    incidentMeta,
    inputText: input,
    outputText: result.output,
    summary: {
      linesAffected: result.linesAffected,
      appliedRules: result.applied,
      report: result.report,
    },
  });

  return {
    schemaVersion: SAFE_SHARE_BUNDLE_SCHEMA_VERSION,
    kind: SAFE_SHARE_BUNDLE_KIND,
    createdAt,
    tool: "sanitize",
    producer,
    sourceFile: inputPath,
    detectedFormat: result.detectedFormat,
    policy: cloneJson(options.policy),
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
    warnings: [...workflowPackage.warnings],
    limitations: [...workflowPackage.limitations],
    workflowPackage,
  };
}

function createSanitizeWorkflowPackageCli({
  createdAt,
  producer,
  sourceFile,
  detectedFormat,
  policy,
  preset,
  baselinePath,
  workflowPreset,
  incidentMeta,
  inputText,
  outputText,
  summary,
}) {
  if (workflowPreset) {
    const classification = classifyTextForSafeShareCli(inputText);
    const sourceHash = sha256Hex(inputText);
    const outputHash = sha256Hex(outputText);
    const policyJson = JSON.stringify(policy);
    const resolvedTitle = sanitizeInlineCli(incidentMeta?.title) || `${workflowPreset.label} package`;
    const resolvedPurpose = sanitizeInlineCli(incidentMeta?.purpose) || `Prepare text content for ${workflowPreset.label.toLowerCase()}.`;
    const resolvedCaseReference = sanitizeInlineCli(incidentMeta?.caseReference);
    const resolvedRecipientScope = sanitizeInlineCli(incidentMeta?.recipientScope);
    const assistantReport = {
      mode: "text",
      workflowPreset: workflowPreset.id,
      classification,
      findings: Array.isArray(summary.report)
        ? summary.report
            .map((line) => {
              const match = String(line).match(/^(.*?):\s*(\d+)$/);
              if (!match) return null;
              return { label: match[1], count: Number(match[2]) };
            })
            .filter(Boolean)
        : [],
      linesAffected: summary.linesAffected,
      appliedRules: Array.isArray(summary.appliedRules) ? [...summary.appliedRules] : [],
      protectAtExport: false,
    };
    const assistantReportJson = JSON.stringify(assistantReport);
    const warnings = [
      ...(Array.isArray(summary.appliedRules) && summary.appliedRules.length === 0
        ? ["No sanitize rules triggered; review the output manually before sharing."]
        : []),
      ...WORKFLOW_UNSIGNED_NOTES,
    ];
    const limitations = [
      "Review sanitized output before sharing outside the intended trust boundary.",
      "Without an outer NULLID:ENC:1 envelope, the exported package remains readable JSON on disk.",
    ];
    const includedLabels = [
      ...(sourceFile ? [`Original input reference (${sourceFile})`] : []),
      "Shared output",
      "Sanitize policy snapshot",
      "Safe Share report",
    ];

    return {
      schemaVersion: WORKFLOW_PACKAGE_SCHEMA_VERSION,
      kind: WORKFLOW_PACKAGE_KIND,
      packageType: "bundle",
      workflowType: "safe-share-assistant",
      producedAt: createdAt,
      producer: cloneJson(producer),
      workflowPreset: {
        id: workflowPreset.id,
        label: workflowPreset.label,
        summary: workflowPreset.description,
      },
      summary: {
        title: resolvedTitle,
        description: "Safe Share Assistant export for text-based content.",
        highlights: [
          `Share class: ${formatSafeShareClassCli(classification)}`,
          `Applied rules: ${Array.isArray(summary.appliedRules) ? summary.appliedRules.length : 0}`,
          ...(resolvedCaseReference ? [`Case reference: ${resolvedCaseReference}`] : []),
          "Protection: none",
        ],
      },
      report: {
        purpose: resolvedPurpose,
        audience: resolvedRecipientScope,
        includedArtifacts: includedLabels,
        transformedArtifacts: ["Safe Share review", "Sanitize transformation"],
        preservedArtifacts: sourceFile ? ["Original input reference only"] : [],
        receiverCanVerify: [
          "Workflow package structure and schema version.",
          "SHA-256 manifest entries for included inline artifacts and references.",
        ],
        receiverCannotVerify: [
          "Sender identity or authorship.",
          "Whether omitted context outside the included artifacts was complete.",
        ],
      },
      trust: {
        identity: "not-asserted",
        packageSignature: {
          method: "none",
        },
        artifactManifest: {
          algorithm: "sha256",
          entryCount: sourceFile ? 4 : 3,
        },
        encryptedPayload: {
          method: "none",
        },
        notes: [...WORKFLOW_UNSIGNED_NOTES],
      },
      artifacts: [
        {
          id: "source-input",
          role: "input",
          label: sourceFile ? `Original input (${sourceFile})` : "Original input",
          kind: "reference",
          mediaType: "text/plain",
          included: false,
          bytes: Buffer.byteLength(inputText, "utf8"),
          sha256: sourceHash,
          filename: sourceFile || undefined,
        },
        {
          id: "shared-output",
          role: "output",
          label: "Shared output",
          kind: "text",
          mediaType: "text/plain;charset=utf-8",
          included: true,
          bytes: Buffer.byteLength(outputText, "utf8"),
          sha256: outputHash,
          text: outputText,
        },
        {
          id: "sanitize-policy",
          role: "policy",
          label: "Sanitize policy snapshot",
          kind: "json",
          mediaType: "application/json",
          included: true,
          bytes: Buffer.byteLength(policyJson, "utf8"),
          sha256: sha256Hex(policyJson),
          json: cloneJson(policy),
        },
        {
          id: "safe-share-report",
          role: "report",
          label: "Safe Share report",
          kind: "json",
          mediaType: "application/json",
          included: true,
          bytes: Buffer.byteLength(assistantReportJson, "utf8"),
          sha256: sha256Hex(assistantReportJson),
          json: assistantReport,
        },
      ],
      policy: {
        type: "sanitize",
        config: cloneJson(policy),
        preset: preset || undefined,
        baseline: baselinePath,
      },
      transforms: [
        {
          id: "safe-share-review",
          type: "safe-share",
          label: "Safe Share review",
          summary: `${workflowPreset.label} preset prepared a text safe-share package.`,
          report: [
            `classification:${classification}`,
            `findings:${assistantReport.findings.length}`,
            `source-reference:${sourceFile ? "included" : "omitted"}`,
          ],
          metadata: {
            workflowPreset: workflowPreset.id,
          },
        },
        {
          id: "sanitize-transform",
          type: "sanitize",
          label: "Sanitize transformation",
          summary: `Sanitized output ready (${summary.linesAffected} line${summary.linesAffected === 1 ? "" : "s"} changed).`,
          applied: Array.isArray(summary.appliedRules) ? [...summary.appliedRules] : [],
          report: Array.isArray(summary.report) ? [...summary.report] : [],
          metadata: {
            classification,
            detectedFormat: detectedFormat || "text",
          },
        },
      ],
      warnings,
      limitations,
    };
  }

  return {
    schemaVersion: WORKFLOW_PACKAGE_SCHEMA_VERSION,
    kind: WORKFLOW_PACKAGE_KIND,
    packageType: "bundle",
    workflowType: "sanitize-safe-share",
    producedAt: createdAt,
    producer: cloneJson(producer),
    summary: {
      title: "Sanitized safe-share package",
      description: "Portable local package containing sanitized output, policy snapshot, and SHA-256 manifest entries.",
      highlights: [
        `Detected format: ${detectedFormat || "text"}`,
        `Lines affected: ${summary.linesAffected}`,
        `Applied rules: ${Array.isArray(summary.appliedRules) ? summary.appliedRules.length : 0}`,
      ],
    },
    report: {
      purpose: "Prepare sanitized text for local safe sharing.",
      includedArtifacts: [
        "Original input reference",
        "Sanitized output",
        "Sanitize policy snapshot",
      ],
      transformedArtifacts: ["Sanitize transformation"],
      preservedArtifacts: ["Original input reference only"],
      receiverCanVerify: [
        "Workflow package structure and schema version.",
        "SHA-256 manifest entries for the original input reference and sanitized output.",
      ],
      receiverCannotVerify: [
        "Sender identity or authorship.",
        "Whether omitted source context outside the included artifacts was complete.",
      ],
    },
    trust: {
      identity: "not-asserted",
      packageSignature: {
        method: "none",
      },
      artifactManifest: {
        algorithm: "sha256",
        entryCount: 2,
      },
      encryptedPayload: {
        method: "none",
      },
      notes: [...WORKFLOW_UNSIGNED_NOTES],
    },
    artifacts: [
      {
        id: "source-input",
        role: "input",
        label: sourceFile ? `Original input (${sourceFile})` : "Original input",
        kind: "reference",
        mediaType: "text/plain",
        included: false,
        bytes: Buffer.byteLength(inputText, "utf8"),
        sha256: sha256Hex(inputText),
        filename: sourceFile || undefined,
      },
      {
        id: "sanitized-output",
        role: "output",
        label: "Sanitized output",
        kind: "text",
        mediaType: "text/plain;charset=utf-8",
        included: true,
        bytes: Buffer.byteLength(outputText, "utf8"),
        sha256: sha256Hex(outputText),
        text: outputText,
      },
      {
        id: "sanitize-policy",
        role: "policy",
        label: "Sanitize policy snapshot",
        kind: "json",
        mediaType: "application/json",
        included: true,
        bytes: Buffer.byteLength(JSON.stringify(policy), "utf8"),
        json: cloneJson(policy),
      },
    ],
    policy: {
      type: "sanitize",
      config: cloneJson(policy),
      preset: preset || undefined,
      baseline: baselinePath,
    },
    transforms: [
      {
        id: "sanitize-transform",
        type: "sanitize",
        label: "Sanitize transformation",
        summary: `Sanitized output ready (${summary.linesAffected} line${summary.linesAffected === 1 ? "" : "s"} changed).`,
        applied: Array.isArray(summary.appliedRules) ? [...summary.appliedRules] : [],
        report: Array.isArray(summary.report) ? [...summary.report] : [],
        metadata: {
          detectedFormat: detectedFormat || "text",
        },
      },
    ],
    warnings: [...WORKFLOW_UNSIGNED_NOTES],
    limitations: [
      "Sanitized output should still be reviewed before sharing outside the intended trust boundary.",
      "Policy metadata is included for reproducibility; NullID does not claim public-key identity for this package.",
    ],
  };
}

function inspectParsedArtifactCli(payload, options = {}) {
  if (looksLikeWorkflowArtifactCli(payload)) {
    try {
      return verifyWorkflowPayloadCli(payload);
    } catch (error) {
      return invalidWorkflowPayloadResultCli(payload, error);
    }
  }
  if (looksLikePolicyPackCli(payload)) {
    return verifyPolicyPackPayloadCli(payload, options);
  }
  if (looksLikeProfileCli(payload)) {
    return verifyProfilePayloadCli(payload, options);
  }
  if (looksLikeVaultCli(payload)) {
    return verifyVaultPayloadCli(payload, options);
  }
  return {
    artifactType: "unsupported",
    artifactKindLabel: "Unsupported artifact",
    title: "Unsupported artifact",
    verificationState: "unsupported",
    verificationLabel: "Unsupported",
    trustBasis: [],
    verifiedChecks: [],
    unverifiedChecks: ["This JSON payload is not a supported NullID artifact type in this verifier."],
    warnings: [],
    limitations: ["Supported types in this step: workflow packages, safe-share bundles, sanitize policy packs, profile snapshots, vault snapshots, and NULLID envelopes."],
    facts: [],
    artifacts: [],
    transforms: [],
    policySummary: [],
  };
}

function invalidWorkflowPayloadResultCli(payload, error) {
  const sourceKind = payload && typeof payload === "object" && payload.kind === SAFE_SHARE_BUNDLE_KIND ? "safe-share" : "workflow-package";
  const schemaVersion = payload && typeof payload === "object" && typeof payload.schemaVersion === "number" ? payload.schemaVersion : 0;
  const failure = error instanceof Error ? error.message : "Invalid workflow package payload";
  return {
    artifactType: sourceKind === "safe-share" ? "safe-share-bundle" : "workflow-package",
    artifactKindLabel: sourceKind === "safe-share" ? "Safe-share bundle" : "Workflow package",
    title: "Invalid workflow package",
    verificationState: "invalid",
    verificationLabel: "Invalid",
    trustBasis: ["NullID recognized the workflow artifact type, but the payload could not be validated safely."],
    verifiedChecks: [],
    unverifiedChecks: ["No workflow-package integrity or authenticity guarantees could be established."],
    warnings: [failure],
    limitations: ["Workflow-package verification currently checks schema structure, manifest self-consistency, and honest trust metadata only."],
    facts: [
      { label: "Schema", value: String(schemaVersion) },
      { label: "Source", value: sourceKind },
    ],
    artifacts: [],
    transforms: [],
    policySummary: [],
    failure,
  };
}

function verifyWorkflowPayloadCli(payload) {
  const match = resolveWorkflowPayloadCli(payload);
  const workflowPackage = match.workflowPackage;
  const artifactChecks = Array.isArray(workflowPackage.artifacts) ? workflowPackage.artifacts.map((artifact) => verifyWorkflowArtifactCli(artifact)) : [];
  const manifestEntryCount = Array.isArray(workflowPackage.artifacts)
    ? workflowPackage.artifacts.filter((artifact) => typeof artifact.sha256 === "string").length
    : 0;
  const manifestCountMatches =
    workflowPackage.trust &&
    workflowPackage.trust.artifactManifest &&
    Number(workflowPackage.trust.artifactManifest.entryCount) === manifestEntryCount;
  const mismatchArtifacts = artifactChecks.filter((artifact) => artifact.status === "mismatch");
  const verifiedArtifacts = artifactChecks.filter((artifact) => artifact.status === "verified");
  const referenceArtifacts = artifactChecks.filter((artifact) => artifact.status === "reference");
  const unverifiableArtifacts = artifactChecks.filter((artifact) => artifact.status === "unverified");
  const signatureMethod =
    workflowPackage.trust &&
    workflowPackage.trust.packageSignature &&
    workflowPackage.trust.packageSignature.method === "shared-secret-hmac"
      ? "shared-secret-hmac"
      : "none";
  let verificationState = "unsigned";
  let verificationLabel = "Unsigned";
  let failure;

  if (signatureMethod !== "none") {
    verificationState = "invalid";
    verificationLabel = "Invalid";
    failure = "Package declares shared-secret verification, but no verifiable package signature is available in the current workflow package contract.";
  } else if (!manifestCountMatches || mismatchArtifacts.length > 0) {
    verificationState = "mismatch";
    verificationLabel = "Mismatch";
    failure = mismatchArtifacts.length > 0
      ? `${mismatchArtifacts.length} artifact hash mismatch(es) detected.`
      : "Manifest entry count mismatch.";
  } else if (verifiedArtifacts.length > 0 || manifestCountMatches) {
    verificationState = "integrity-checked";
    verificationLabel = "Integrity checked";
  }

  return {
    artifactType: match.sourceKind === "safe-share" ? "safe-share-bundle" : "workflow-package",
    artifactKindLabel: match.sourceKind === "safe-share" ? "Safe-share bundle" : "Workflow package",
    title:
      workflowPackage.summary && typeof workflowPackage.summary.title === "string" && workflowPackage.summary.title
        ? workflowPackage.summary.title
        : "Workflow package",
    verificationState,
    verificationLabel,
    trustBasis: [
      signatureMethod === "none" ? "Unsigned workflow package." : `Declared trust basis: ${signatureMethod}.`,
      manifestCountMatches
        ? `SHA-256 manifest entry count matches (${manifestEntryCount}).`
        : `SHA-256 manifest entry count mismatch (${workflowPackage.trust?.artifactManifest?.entryCount ?? "unknown"} declared vs ${manifestEntryCount} present).`,
    ],
    verifiedChecks: [
      `Workflow package schema ${Number(workflowPackage.schemaVersion) || 0} parsed successfully.`,
      ...(verifiedArtifacts.length > 0 ? [`Verified SHA-256 for ${verifiedArtifacts.length} included artifact(s).`] : []),
    ],
    unverifiedChecks: [
      "Sender identity is not asserted by this package format.",
      ...(referenceArtifacts.length > 0
        ? [`${referenceArtifacts.length} referenced artifact(s) were listed but not included, so their bytes could not be verified locally.`]
        : []),
      ...(unverifiableArtifacts.length > 0
        ? [`${unverifiableArtifacts.length} included artifact(s) lacked inline content needed for local hash verification.`]
        : []),
    ],
    warnings: [
      ...(Array.isArray(workflowPackage.warnings) ? workflowPackage.warnings : []),
      ...(!manifestCountMatches ? ["Manifest metadata does not match the number of hashed artifact entries."] : []),
      ...(signatureMethod !== "none"
        ? ["Package declares shared-secret HMAC trust, but the current workflow package contract does not carry a verifiable package signature."]
        : []),
    ],
    limitations: Array.isArray(workflowPackage.limitations) ? workflowPackage.limitations : [],
    facts: [
      { label: "Workflow", value: typeof workflowPackage.workflowType === "string" ? workflowPackage.workflowType : "unknown" },
      { label: "Package type", value: typeof workflowPackage.packageType === "string" ? workflowPackage.packageType : "unknown" },
      { label: "Schema", value: String(Number(workflowPackage.schemaVersion) || 0) },
      { label: "Source", value: match.sourceKind },
      ...(workflowPackage.workflowPreset && typeof workflowPackage.workflowPreset === "object" && typeof workflowPackage.workflowPreset.label === "string"
        ? [{ label: "Workflow preset", value: workflowPackage.workflowPreset.label }]
        : []),
      ...(typeof workflowPackage.producedAt === "string" ? [{ label: "Produced at", value: workflowPackage.producedAt }] : []),
      ...(workflowPackage.producer && typeof workflowPackage.producer === "object"
        ? [{ label: "Producer", value: `${workflowPackage.producer.app || NULLID_APP_NAME} / ${workflowPackage.producer.surface || "unknown"}` }]
        : []),
    ],
    artifacts: artifactChecks,
    transforms: Array.isArray(workflowPackage.transforms)
      ? workflowPackage.transforms.map((transform) => ({ label: transform.label, value: transform.summary }))
      : [],
    policySummary: summarizeWorkflowPolicyCli(workflowPackage.policy),
    workflowReport: summarizeWorkflowReportCli(workflowPackage.report),
    failure,
  };
}

function verifyWorkflowArtifactCli(artifact) {
  const base = {
    id: artifact.id,
    role: artifact.role,
    label: artifact.label,
    detail: "No local verification performed.",
    status: "unverified",
    included: Boolean(artifact.included),
    kind: artifact.kind,
    mediaType: artifact.mediaType,
    bytes: artifact.bytes,
    sha256: artifact.sha256,
  };

  if (!artifact.sha256) {
    return {
      ...base,
      detail: "No SHA-256 manifest entry recorded for this artifact.",
    };
  }
  if (!artifact.included) {
    return {
      ...base,
      status: "reference",
      detail: "Artifact was referenced but not included, so local byte verification was not possible.",
    };
  }
  if (artifact.kind === "text" && typeof artifact.text === "string") {
    const computed = sha256Hex(artifact.text);
    return {
      ...base,
      status: computed === artifact.sha256 ? "verified" : "mismatch",
      detail: computed === artifact.sha256 ? "SHA-256 matches the included text payload." : "SHA-256 does not match the included text payload.",
    };
  }
  if (artifact.kind === "json" && artifact.json !== undefined) {
    const computed = sha256Hex(JSON.stringify(artifact.json));
    return {
      ...base,
      status: computed === artifact.sha256 ? "verified" : "mismatch",
      detail: computed === artifact.sha256 ? "SHA-256 matches the included JSON payload." : "SHA-256 does not match the included JSON payload.",
    };
  }
  if (artifact.kind === "binary" && typeof artifact.base64 === "string") {
    const computed = sha256Hex(decodeBase64StrictCli(artifact.base64, "Invalid binary artifact base64 payload"));
    return {
      ...base,
      status: computed === artifact.sha256 ? "verified" : "mismatch",
      detail: computed === artifact.sha256 ? "SHA-256 matches the included binary payload." : "SHA-256 does not match the included binary payload.",
    };
  }
  return {
    ...base,
    detail: "Artifact includes a manifest hash, but no inline payload was available for local verification.",
  };
}

function resolveWorkflowPayloadCli(payload) {
  if (isWorkflowPackageLike(payload)) {
    return {
      workflowPackage: payload,
      legacy: false,
      sourceKind: "workflow-package",
    };
  }

  if (payload && typeof payload === "object" && payload.kind === SAFE_SHARE_BUNDLE_KIND) {
    if (isWorkflowPackageLike(payload.workflowPackage)) {
      return {
        workflowPackage: payload.workflowPackage,
        legacy: false,
        sourceKind: "safe-share",
      };
    }

    const legacy = mapLegacySafeShareBundleCli(payload);
    if (legacy) {
      return {
        workflowPackage: legacy,
        legacy: true,
        sourceKind: "safe-share",
      };
    }
  }

  throw new Error(describeWorkflowPayloadFailureCli(payload));
}

function isWorkflowPackageLike(value) {
  return Boolean(value) && typeof value === "object" && value.kind === WORKFLOW_PACKAGE_KIND && Number(value.schemaVersion) === WORKFLOW_PACKAGE_SCHEMA_VERSION;
}

function mapLegacySafeShareBundleCli(payload) {
  if (!payload || typeof payload !== "object" || payload.kind !== SAFE_SHARE_BUNDLE_KIND) {
    return null;
  }
  if (Number(payload.schemaVersion) !== LEGACY_SAFE_SHARE_BUNDLE_SCHEMA_VERSION && Number(payload.schemaVersion) !== SAFE_SHARE_BUNDLE_SCHEMA_VERSION) {
    return null;
  }
  if (!payload.input || !payload.output || typeof payload.output.text !== "string") {
    return null;
  }

  const policy = normalizePolicyConfig(payload.policy) || undefined;
  const summary = payload.summary && typeof payload.summary === "object" ? payload.summary : {};
  const producer =
    payload.producer && typeof payload.producer === "object"
      ? {
          app: NULLID_APP_NAME,
          surface: payload.producer.surface === "web" || payload.producer.surface === "cli" ? payload.producer.surface : "unknown",
          module: typeof payload.producer.module === "string" ? payload.producer.module : "sanitize",
          version: typeof payload.producer.version === "string" ? payload.producer.version : null,
          buildId: typeof payload.producer.buildId === "string" ? payload.producer.buildId : null,
        }
      : {
          app: NULLID_APP_NAME,
          surface: "unknown",
          module: "sanitize",
          version: null,
          buildId: null,
        };

  return {
    schemaVersion: WORKFLOW_PACKAGE_SCHEMA_VERSION,
    kind: WORKFLOW_PACKAGE_KIND,
    packageType: "bundle",
    workflowType: "sanitize-safe-share",
    producedAt: typeof payload.createdAt === "string" ? payload.createdAt : new Date(0).toISOString(),
    producer,
    summary: {
      title: "Sanitized safe-share package",
      description: "Compatibility-mapped safe-share bundle.",
      highlights: [
        `Lines affected: ${typeof summary.linesAffected === "number" ? summary.linesAffected : 0}`,
        `Applied rules: ${Array.isArray(summary.appliedRules) ? summary.appliedRules.length : 0}`,
      ],
    },
    trust: {
      identity: "not-asserted",
      packageSignature: {
        method: "none",
      },
      artifactManifest: {
        algorithm: "sha256",
        entryCount: 2,
      },
      encryptedPayload: {
        method: "none",
      },
      notes: [...WORKFLOW_UNSIGNED_NOTES],
    },
    artifacts: [
      {
        id: "source-input",
        role: "input",
        label: typeof payload.sourceFile === "string" ? `Original input (${payload.sourceFile})` : "Original input",
        kind: "reference",
        mediaType: "text/plain",
        included: false,
        bytes: typeof payload.input.bytes === "number" ? payload.input.bytes : undefined,
        sha256: typeof payload.input.sha256 === "string" ? payload.input.sha256 : undefined,
        filename: typeof payload.sourceFile === "string" ? payload.sourceFile : undefined,
      },
      {
        id: "sanitized-output",
        role: "output",
        label: "Sanitized output",
        kind: "text",
        mediaType: "text/plain;charset=utf-8",
        included: true,
        bytes: typeof payload.output.bytes === "number" ? payload.output.bytes : undefined,
        sha256: typeof payload.output.sha256 === "string" ? payload.output.sha256 : undefined,
        text: payload.output.text,
      },
      {
        id: "sanitize-policy",
        role: "policy",
        label: "Sanitize policy snapshot",
        kind: "json",
        mediaType: "application/json",
        included: true,
        bytes: policy ? Buffer.byteLength(JSON.stringify(policy), "utf8") : undefined,
        json: policy,
      },
    ],
    policy: policy
      ? {
          type: "sanitize",
          config: policy,
        }
      : undefined,
    transforms: [
      {
        id: "sanitize-transform",
        type: "sanitize",
        label: "Sanitize transformation",
        summary: "Compatibility-mapped sanitize report.",
        applied: Array.isArray(summary.appliedRules) ? [...summary.appliedRules] : [],
        report: Array.isArray(summary.report) ? [...summary.report] : [],
        metadata: {
          detectedFormat: typeof payload.detectedFormat === "string" ? payload.detectedFormat : "text",
        },
      },
    ],
    warnings: [...WORKFLOW_UNSIGNED_NOTES],
    limitations: Array.isArray(payload.limitations) ? [...payload.limitations] : [],
  };
}

function describeWorkflowPayloadFailureCli(payload) {
  if (!payload || typeof payload !== "object") {
    return "Unsupported workflow package payload";
  }
  if (payload.kind === WORKFLOW_PACKAGE_KIND) {
    if (Number(payload.schemaVersion) !== WORKFLOW_PACKAGE_SCHEMA_VERSION) {
      return `Unsupported workflow package schema: ${String(payload.schemaVersion ?? "unknown")}`;
    }
    return "Invalid workflow package payload";
  }
  if (payload.kind === SAFE_SHARE_BUNDLE_KIND) {
    const schemaVersion = Number(payload.schemaVersion);
    if (schemaVersion !== LEGACY_SAFE_SHARE_BUNDLE_SCHEMA_VERSION && schemaVersion !== SAFE_SHARE_BUNDLE_SCHEMA_VERSION) {
      return `Unsupported safe-share bundle schema: ${String(payload.schemaVersion ?? "unknown")}`;
    }
    if (payload.workflowPackage && typeof payload.workflowPackage === "object" && payload.workflowPackage.kind === WORKFLOW_PACKAGE_KIND) {
      if (Number(payload.workflowPackage.schemaVersion) !== WORKFLOW_PACKAGE_SCHEMA_VERSION) {
        return `Unsupported embedded workflow package schema: ${String(payload.workflowPackage.schemaVersion ?? "unknown")}`;
      }
      return "Invalid embedded workflow package payload";
    }
    return "Invalid safe-share bundle payload";
  }
  return "Unsupported workflow package payload";
}

function looksLikeWorkflowArtifactCli(value) {
  return Boolean(value) && typeof value === "object" && (value.kind === WORKFLOW_PACKAGE_KIND || value.kind === SAFE_SHARE_BUNDLE_KIND);
}

function looksLikePolicyPackCli(value) {
  return Boolean(value) && typeof value === "object" && value.kind === "sanitize-policy-pack";
}

function looksLikeProfileCli(value) {
  return Boolean(value) && typeof value === "object" && (value.kind === "profile" || (value.entries && value.schemaVersion !== undefined));
}

function looksLikeVaultCli(value) {
  return Boolean(value) && typeof value === "object" && (value.kind === "vault" || value.vault || value.notes || value.meta);
}

function summarizeWorkflowPolicyCli(policy) {
  if (!policy || typeof policy !== "object") return [];
  const facts = [];
  if (policy.type) facts.push({ label: "Policy type", value: String(policy.type) });
  if (policy.preset) facts.push({ label: "Preset", value: String(policy.preset) });
  if (policy.packName) facts.push({ label: "Pack", value: String(policy.packName) });
  if (policy.baseline) facts.push({ label: "Baseline", value: String(policy.baseline) });
  if (policy.config && typeof policy.config === "object" && policy.config.rulesState && typeof policy.config.rulesState === "object") {
    const enabledRules = Object.values(policy.config.rulesState).filter(Boolean).length;
    facts.push({ label: "Enabled rules", value: String(enabledRules) });
    facts.push({ label: "JSON aware", value: policy.config.jsonAware ? "yes" : "no" });
    facts.push({ label: "Custom rules", value: String(Array.isArray(policy.config.customRules) ? policy.config.customRules.length : 0) });
  }
  return facts;
}

function summarizeWorkflowReportCli(report) {
  if (!report || typeof report !== "object") return null;
  return {
    purpose: typeof report.purpose === "string" ? report.purpose : undefined,
    audience: typeof report.audience === "string" ? report.audience : undefined,
    includedArtifacts: Array.isArray(report.includedArtifacts) ? report.includedArtifacts.map(String) : [],
    transformedArtifacts: Array.isArray(report.transformedArtifacts) ? report.transformedArtifacts.map(String) : [],
    preservedArtifacts: Array.isArray(report.preservedArtifacts) ? report.preservedArtifacts.map(String) : [],
    receiverCanVerify: Array.isArray(report.receiverCanVerify) ? report.receiverCanVerify.map(String) : [],
    receiverCannotVerify: Array.isArray(report.receiverCannotVerify) ? report.receiverCannotVerify.map(String) : [],
  };
}

function verifyPolicyPackPayloadCli(payload, options = {}) {
  const descriptor = {
    schemaVersion: typeof payload.schemaVersion === "number" ? payload.schemaVersion : 0,
    packCount: Array.isArray(payload.packs) ? payload.packs.length : payload.pack ? 1 : 0,
    keyHint: payload.signature && typeof payload.signature === "object" && typeof payload.signature.keyHint === "string" ? payload.signature.keyHint : undefined,
  };
  if (payload.kind !== "sanitize-policy-pack") {
    return invalidSnapshotResultCli("policy-pack", "Sanitize policy pack", descriptor, "Invalid policy payload kind");
  }

  if (Number(payload.schemaVersion) === 1) {
    const source = Array.isArray(payload.packs) ? payload.packs : payload.pack ? [payload.pack] : [];
    const packNames = source
      .filter((entry) => entry && typeof entry === "object" && typeof entry.name === "string")
      .map((entry) => entry.name.trim())
      .filter(Boolean);
    return {
      artifactType: "policy-pack",
      artifactKindLabel: "Sanitize policy pack",
      title: "Sanitize policy pack",
      verificationState: "unsigned",
      verificationLabel: "Unsigned",
      trustBasis: ["Legacy policy pack with no integrity metadata."],
      verifiedChecks: [`Parsed ${packNames.length} policy pack(s) from the legacy payload.`],
      unverifiedChecks: ["Legacy policy packs do not include payload hashing or HMAC verification metadata."],
      warnings: [],
      limitations: ["Policy pack verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(descriptor.schemaVersion) },
        { label: "Pack count", value: String(packNames.length) },
        ...(typeof payload.exportedAt === "string" ? [{ label: "Exported at", value: payload.exportedAt }] : []),
      ],
      artifacts: packNames.map((name) => ({ id: name, role: "pack", label: name, detail: "Policy pack entry", status: "unverified" })),
    };
  }

  if (Number(payload.schemaVersion) !== 2) {
    return invalidSnapshotResultCli("policy-pack", "Sanitize policy pack", descriptor, `Unsupported policy schema: ${String(payload.schemaVersion ?? "unknown")}`);
  }

  const packs = (Array.isArray(payload.packs) ? payload.packs : [])
    .map((entry) => {
      if (!entry || typeof entry !== "object") return null;
      const name = typeof entry.name === "string" ? entry.name.trim() : "";
      const config = normalizePolicyConfig(entry.config);
      if (!name || !config) return null;
      return {
        name,
        createdAt: typeof entry.createdAt === "string" ? entry.createdAt : new Date(0).toISOString(),
        config,
      };
    })
    .filter(Boolean);
  try {
    const verification = verifySnapshotIntegrityCli({
      subject: "Policy pack",
      countKey: "packCount",
      actualCount: packs.length,
      payload: {
        schemaVersion: 2,
        kind: "sanitize-policy-pack",
        exportedAt: payload.exportedAt,
        packs: packs.map((entry) => ({ name: entry.name, createdAt: entry.createdAt, config: entry.config })),
      },
      integrity: payload.integrity,
      signature: payload.signature,
      verificationPassphrase: options.verificationPassphrase,
      missingIntegrityMessage: "Policy integrity metadata missing",
      invalidIntegrityMessage: "Invalid policy integrity metadata",
      countMismatchMessage: "Policy integrity mismatch (count)",
      hashMismatchMessage: "Policy integrity mismatch (hash)",
      invalidSignatureMessage: "Invalid policy signature metadata",
      verificationRequiredMessage: "Policy pack is signed; verification passphrase required",
      verificationFailedMessage: "Policy signature verification failed",
    });
    const signed = verification.signed;
    const verificationState = signed ? "verified" : "integrity-checked";
    return {
      artifactType: "policy-pack",
      artifactKindLabel: "Sanitize policy pack",
      title: "Sanitize policy pack",
      verificationState,
      verificationLabel: signed ? "HMAC verified" : "Integrity checked",
      trustBasis: signed
        ? ["Shared-secret HMAC verification succeeded.", "Payload hash and pack count matched the signed metadata."]
        : ["Payload hash and pack count matched the embedded integrity metadata.", "No sender identity is asserted."],
      verifiedChecks: [`Policy pack count matched (${packs.length}).`, "Payload hash matched the embedded integrity metadata."],
      unverifiedChecks: signed ? ["Shared-secret verification proves tamper detection for holders of the same secret, not public-key identity."] : [],
      warnings: [],
      limitations: ["Policy pack verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(descriptor.schemaVersion) },
        { label: "Pack count", value: String(packs.length) },
        ...(typeof payload.exportedAt === "string" ? [{ label: "Exported at", value: payload.exportedAt }] : []),
        ...(descriptor.keyHint ? [{ label: "Key hint", value: descriptor.keyHint }] : []),
      ],
      artifacts: packs.map((entry) => ({
        id: entry.name,
        role: "pack",
        label: entry.name,
        detail: "Policy pack entry",
        status: snapshotArtifactStatusCli(verificationState),
      })),
    };
  } catch (error) {
    return snapshotErrorResultCli(
      "policy-pack",
      "Sanitize policy pack",
      descriptor,
      error,
      packs.map((entry) => entry.name),
      payload.exportedAt,
      { role: "pack", detail: "Policy pack entry" },
    );
  }
}

function verifyProfilePayloadCli(payload, options = {}) {
  const descriptor = {
    schemaVersion: typeof payload.schemaVersion === "number" ? payload.schemaVersion : 0,
    entryCount: payload.entries && typeof payload.entries === "object" ? Object.keys(payload.entries).length : 0,
    keyHint: payload.signature && typeof payload.signature === "object" && typeof payload.signature.keyHint === "string" ? payload.signature.keyHint : undefined,
    legacy: Number(payload.schemaVersion) === 1,
  };
  if (Number(payload.schemaVersion) === 1) {
    if (!payload.entries || typeof payload.entries !== "object" || Array.isArray(payload.entries)) {
      return invalidSnapshotResultCli("profile", "Profile snapshot", descriptor, "Invalid legacy profile payload");
    }
    if (!Object.values(payload.entries).every(isSupportedProfileValueCli)) {
      return invalidSnapshotResultCli("profile", "Profile snapshot", descriptor, "Legacy profile contains unsupported value types");
    }
    const sampleKeys = sampleEntryKeysCli(payload.entries);
    return {
      artifactType: "profile",
      artifactKindLabel: "Profile snapshot",
      title: "Profile snapshot",
      verificationState: "unsigned",
      verificationLabel: "Unsigned",
      trustBasis: ["Legacy profile payload with no integrity metadata."],
      verifiedChecks: [`Parsed ${Object.keys(payload.entries).length} profile entr${Object.keys(payload.entries).length === 1 ? "y" : "ies"}.`],
      unverifiedChecks: ["Legacy profile payloads do not carry payload hashing or HMAC verification metadata."],
      warnings: [],
      limitations: ["Profile verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(descriptor.schemaVersion) },
        { label: "Entry count", value: String(Object.keys(payload.entries).length) },
        ...(typeof payload.exportedAt === "string" ? [{ label: "Exported at", value: payload.exportedAt }] : []),
      ],
      artifacts: sampleKeys.map((key) => ({ id: key, role: "entry", label: key, detail: "Profile entry key", status: "unverified" })),
    };
  }
  if (Number(payload.schemaVersion) !== 2) {
    return invalidSnapshotResultCli("profile", "Profile snapshot", descriptor, `Unsupported profile schema: ${String(payload.schemaVersion ?? "unknown")}`);
  }
  if (payload.kind && payload.kind !== "profile") {
    return invalidSnapshotResultCli("profile", "Profile snapshot", descriptor, "Invalid profile payload kind");
  }
  if (!payload.entries || typeof payload.entries !== "object" || Array.isArray(payload.entries)) {
    return invalidSnapshotResultCli("profile", "Profile snapshot", descriptor, "Invalid profile payload");
  }
  if (!Object.values(payload.entries).every(isSupportedProfileValueCli)) {
    return invalidSnapshotResultCli("profile", "Profile snapshot", descriptor, "Profile payload contains unsupported value types");
  }
  try {
    const verification = verifySnapshotIntegrityCli({
      subject: "Profile",
      countKey: "entryCount",
      actualCount: Object.keys(payload.entries).length,
      payload: {
        schemaVersion: 2,
        exportedAt: payload.exportedAt,
        entries: payload.entries,
      },
      integrity: payload.integrity,
      signature: payload.signature,
      verificationPassphrase: options.verificationPassphrase,
      missingIntegrityMessage: "Profile integrity metadata missing",
      invalidIntegrityMessage: "Invalid profile integrity metadata",
      countMismatchMessage: "Profile integrity mismatch (entry count)",
      hashMismatchMessage: "Profile integrity mismatch (hash)",
      invalidSignatureMessage: "Invalid profile signature metadata",
      verificationRequiredMessage: "Profile is signed; verification passphrase required",
      verificationFailedMessage: "Profile signature verification failed",
    });
    const signed = verification.signed;
    const sampleKeys = sampleEntryKeysCli(payload.entries);
    const verificationState = signed ? "verified" : "integrity-checked";
    return {
      artifactType: "profile",
      artifactKindLabel: "Profile snapshot",
      title: "Profile snapshot",
      verificationState,
      verificationLabel: signed ? "HMAC verified" : "Integrity checked",
      trustBasis: signed
        ? ["Shared-secret HMAC verification succeeded.", "Payload hash and entry count matched the embedded metadata."]
        : ["Payload hash and entry count matched the embedded integrity metadata.", "No sender identity is asserted."],
      verifiedChecks: [`Profile entry count matched (${Object.keys(payload.entries).length}).`, "Payload hash matched the embedded integrity metadata."],
      unverifiedChecks: signed ? ["Shared-secret verification proves tamper detection for holders of the same secret, not public-key identity."] : [],
      warnings: [],
      limitations: ["Profile verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(descriptor.schemaVersion) },
        { label: "Entry count", value: String(Object.keys(payload.entries).length) },
        ...(typeof payload.exportedAt === "string" ? [{ label: "Exported at", value: payload.exportedAt }] : []),
        ...(descriptor.keyHint ? [{ label: "Key hint", value: descriptor.keyHint }] : []),
      ],
      artifacts: sampleKeys.map((key) => ({
        id: key,
        role: "entry",
        label: key,
        detail: "Profile entry key",
        status: snapshotArtifactStatusCli(verificationState),
      })),
    };
  } catch (error) {
    return snapshotErrorResultCli(
      "profile",
      "Profile snapshot",
      descriptor,
      error,
      sampleEntryKeysCli(payload.entries),
      payload.exportedAt,
      { role: "entry", detail: "Profile entry key" },
    );
  }
}

function verifyVaultPayloadCli(payload, options = {}) {
  const descriptor = {
    schemaVersion: typeof payload.schemaVersion === "number" ? payload.schemaVersion : 0,
    noteCount:
      payload.integrity && typeof payload.integrity === "object" && typeof payload.integrity.noteCount === "number"
        ? payload.integrity.noteCount
        : Array.isArray(payload.notes)
          ? payload.notes.length
          : payload.vault && Array.isArray(payload.vault.notes)
            ? payload.vault.notes.length
            : 0,
    keyHint: payload.signature && typeof payload.signature === "object" && typeof payload.signature.keyHint === "string" ? payload.signature.keyHint : undefined,
    legacy: Number(payload.schemaVersion) !== 2,
  };

  const snapshotContainer = payload.vault && typeof payload.vault === "object" ? payload.vault : payload;
  let snapshot;
  try {
    snapshot = normalizeVaultSnapshotCli(snapshotContainer);
  } catch (error) {
    return invalidSnapshotResultCli("vault", "Vault snapshot", descriptor, error instanceof Error ? error.message : "Invalid vault snapshot payload");
  }

  if (Number(payload.schemaVersion) !== 2) {
    return {
      artifactType: "vault",
      artifactKindLabel: "Vault snapshot",
      title: "Vault snapshot",
      verificationState: "unsigned",
      verificationLabel: "Unsigned",
      trustBasis: ["Legacy vault snapshot with no integrity metadata."],
      verifiedChecks: [`Parsed ${snapshot.notes.length} vault note entr${snapshot.notes.length === 1 ? "y" : "ies"}.`],
      unverifiedChecks: ["Legacy vault snapshots do not carry payload hashing or HMAC verification metadata."],
      warnings: [],
      limitations: ["Vault verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(descriptor.schemaVersion) },
        { label: "Note count", value: String(snapshot.notes.length) },
        ...(typeof payload.exportedAt === "string" ? [{ label: "Exported at", value: payload.exportedAt }] : []),
        { label: "Legacy", value: "yes" },
      ],
      artifacts: snapshot.notes.slice(0, 6).map((note) => ({ id: note.id, role: "note", label: note.id, detail: "Vault note id", status: "unverified" })),
    };
  }

  if (payload.kind && payload.kind !== "vault") {
    return invalidSnapshotResultCli("vault", "Vault snapshot", descriptor, "Invalid vault snapshot kind");
  }
  try {
    const verification = verifySnapshotIntegrityCli({
      subject: "Vault snapshot",
      countKey: "noteCount",
      actualCount: snapshot.notes.length,
      payload: {
        schemaVersion: 2,
        exportedAt: payload.exportedAt,
        vault: snapshot,
      },
      integrity: payload.integrity,
      signature: payload.signature,
      verificationPassphrase: options.verificationPassphrase,
      missingIntegrityMessage: "Vault integrity metadata missing",
      invalidIntegrityMessage: "Invalid vault integrity metadata",
      countMismatchMessage: "Vault integrity mismatch (note count)",
      hashMismatchMessage: "Vault integrity mismatch (hash)",
      invalidSignatureMessage: "Invalid vault signature metadata",
      verificationRequiredMessage: "Vault snapshot is signed; verification passphrase required",
      verificationFailedMessage: "Vault signature verification failed",
    });
    const signed = verification.signed;
    const verificationState = signed ? "verified" : "integrity-checked";
    return {
      artifactType: "vault",
      artifactKindLabel: "Vault snapshot",
      title: "Vault snapshot",
      verificationState,
      verificationLabel: signed ? "HMAC verified" : "Integrity checked",
      trustBasis: signed
        ? ["Shared-secret HMAC verification succeeded.", "Payload hash and note count matched the embedded metadata."]
        : ["Payload hash and note count matched the embedded integrity metadata.", "No sender identity is asserted."],
      verifiedChecks: [`Vault note count matched (${snapshot.notes.length}).`, "Payload hash matched the embedded integrity metadata."],
      unverifiedChecks: signed ? ["Shared-secret verification proves tamper detection for holders of the same secret, not public-key identity."] : [],
      warnings: [],
      limitations: ["Vault verification checks payload integrity and optional shared-secret HMAC metadata only."],
      facts: [
        { label: "Schema", value: String(descriptor.schemaVersion) },
        { label: "Note count", value: String(snapshot.notes.length) },
        ...(typeof payload.exportedAt === "string" ? [{ label: "Exported at", value: payload.exportedAt }] : []),
        ...(descriptor.keyHint ? [{ label: "Key hint", value: descriptor.keyHint }] : []),
      ],
      artifacts: snapshot.notes.slice(0, 6).map((note) => ({
        id: note.id,
        role: "note",
        label: note.id,
        detail: "Vault note id",
        status: snapshotArtifactStatusCli(verificationState),
      })),
    };
  } catch (error) {
    return snapshotErrorResultCli(
      "vault",
      "Vault snapshot",
      descriptor,
      error,
      snapshot.notes.slice(0, 6).map((note) => note.id),
      payload.exportedAt,
      { role: "note", detail: "Vault note id" },
    );
  }
}

class PackageInspectVerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function verifySnapshotIntegrityCli(options) {
  if (!options.integrity || typeof options.integrity !== "object") {
    throw new PackageInspectVerificationError("integrity-missing", options.missingIntegrityMessage);
  }
  const countValue = options.integrity[options.countKey];
  const payloadHash = options.integrity.payloadHash;
  if (typeof countValue !== "number" || !Number.isInteger(countValue) || countValue < 0 || typeof payloadHash !== "string" || payloadHash.length < 16) {
    throw new PackageInspectVerificationError("integrity-invalid", options.invalidIntegrityMessage);
  }
  if (countValue !== options.actualCount) {
    throw new PackageInspectVerificationError("integrity-count-mismatch", options.countMismatchMessage);
  }
  const computedHash = sha256Base64UrlCli(options.payload);
  if (computedHash !== payloadHash) {
    throw new PackageInspectVerificationError("integrity-hash-mismatch", options.hashMismatchMessage);
  }
  if (options.signature !== undefined) {
    if (
      !options.signature ||
      typeof options.signature !== "object" ||
      options.signature.algorithm !== "HMAC-SHA-256" ||
      typeof options.signature.value !== "string" ||
      (options.signature.keyHint !== undefined && typeof options.signature.keyHint !== "string")
    ) {
      throw new PackageInspectVerificationError("signature-invalid", options.invalidSignatureMessage);
    }
    if (!options.verificationPassphrase) {
      throw new PackageInspectVerificationError("verification-required", options.verificationRequiredMessage);
    }
    if (!verifyHashSignatureCli(payloadHash, options.signature.value, options.verificationPassphrase)) {
      throw new PackageInspectVerificationError("verification-failed", options.verificationFailedMessage);
    }
    return { signed: true, verified: true, keyHint: options.signature.keyHint };
  }
  return { signed: false, verified: false };
}

function invalidSnapshotResultCli(artifactType, artifactKindLabel, descriptor, failure) {
  return {
    artifactType,
    artifactKindLabel,
    title: artifactKindLabel,
    verificationState: "invalid",
    verificationLabel: "Invalid",
    trustBasis: [`NullID could not validate the structure of this ${artifactKindLabel.toLowerCase()} payload.`],
    verifiedChecks: [],
    unverifiedChecks: ["No integrity or authenticity guarantees could be established."],
    warnings: [failure],
    limitations: [],
    facts: [
      ...(descriptor.schemaVersion !== undefined ? [{ label: "Schema", value: String(descriptor.schemaVersion) }] : []),
      ...(descriptor.entryCount !== undefined ? [{ label: "Entry count", value: String(descriptor.entryCount) }] : []),
      ...(descriptor.packCount !== undefined ? [{ label: "Pack count", value: String(descriptor.packCount) }] : []),
      ...(descriptor.noteCount !== undefined ? [{ label: "Note count", value: String(descriptor.noteCount) }] : []),
    ],
    artifacts: [],
    failure,
  };
}

function snapshotErrorResultCli(artifactType, artifactKindLabel, descriptor, error, artifactLabels = [], exportedAt, artifactMeta = { role: "entry", detail: "Logical entry" }) {
  const failure = error instanceof Error ? error.message : `${artifactKindLabel} verification failed`;
  const base = {
    artifactType,
    artifactKindLabel,
    title: artifactKindLabel,
    facts: [
      ...(descriptor.schemaVersion !== undefined ? [{ label: "Schema", value: String(descriptor.schemaVersion) }] : []),
      ...(descriptor.entryCount !== undefined ? [{ label: "Entry count", value: String(descriptor.entryCount) }] : []),
      ...(descriptor.packCount !== undefined ? [{ label: "Pack count", value: String(descriptor.packCount) }] : []),
      ...(descriptor.noteCount !== undefined ? [{ label: "Note count", value: String(descriptor.noteCount) }] : []),
      ...(exportedAt ? [{ label: "Exported at", value: exportedAt }] : []),
      ...(descriptor.keyHint ? [{ label: "Key hint", value: descriptor.keyHint }] : []),
    ],
    artifacts: artifactLabels.map((label) => ({
      id: label,
      role: artifactMeta.role,
      label,
      detail: artifactMeta.detail,
      status: snapshotArtifactStatusCli("verification-required"),
    })),
  };

  if (error instanceof PackageInspectVerificationError) {
    if (error.code === "verification-required") {
      return {
        ...base,
        verificationState: "verification-required",
        verificationLabel: "Verification required",
        trustBasis: ["Shared-secret HMAC metadata is present."],
        verifiedChecks: [],
        unverifiedChecks: ["A verification passphrase is required before authenticity can be checked."],
        warnings: descriptor.keyHint ? [`Expected key hint: ${descriptor.keyHint}`] : [],
        limitations: [],
        failure,
      };
    }
    if (error.code === "verification-failed" || error.code === "integrity-count-mismatch" || error.code === "integrity-hash-mismatch") {
      return {
        ...base,
        verificationState: "mismatch",
        verificationLabel: "Mismatch",
        trustBasis: [`${artifactKindLabel} integrity metadata was present, but verification did not succeed.`],
        verifiedChecks: [],
        unverifiedChecks: ["The payload may be tampered, incomplete, or paired with the wrong shared secret."],
        warnings: [failure],
        limitations: [],
        artifacts: artifactLabels.map((label) => ({
          id: label,
          role: artifactMeta.role,
          label,
          detail: artifactMeta.detail,
          status: snapshotArtifactStatusCli("mismatch"),
        })),
        failure,
      };
    }
  }
  return {
    ...base,
    verificationState: "invalid",
    verificationLabel: "Invalid",
    trustBasis: [`NullID could not validate the structure of this ${artifactKindLabel.toLowerCase()} payload.`],
    verifiedChecks: [],
    unverifiedChecks: ["No integrity or authenticity guarantees could be established."],
    warnings: [failure],
    limitations: [],
    failure,
  };
}

function snapshotArtifactStatusCli(state) {
  if (state === "verified" || state === "integrity-checked") return "verified";
  if (state === "mismatch") return "mismatch";
  return "unverified";
}

function stableStringifyCli(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringifyCli(entry)).join(",")}]`;
  }
  const entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${stableStringifyCli(child)}`).join(",")}}`;
}

function sha256Base64UrlCli(value) {
  const payload = typeof value === "string" ? value : stableStringifyCli(value);
  return toBase64Url(crypto.createHash("sha256").update(payload).digest());
}

function verifyHashSignatureCli(hashBase64Url, signatureBase64Url, secret) {
  const expected = toBase64Url(crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(hashBase64Url).digest());
  const expectedBytes = Buffer.from(expected, "utf8");
  const actualBytes = Buffer.from(String(signatureBase64Url), "utf8");
  if (expectedBytes.length !== actualBytes.length) return false;
  return crypto.timingSafeEqual(expectedBytes, actualBytes);
}

function sampleEntryKeysCli(entries) {
  return Object.keys(entries).sort().slice(0, 6);
}

function isSupportedProfileValueCli(value) {
  if (value === null) return true;
  const valueType = typeof value;
  if (valueType === "string" || valueType === "number" || valueType === "boolean") return true;
  if (Array.isArray(value)) return value.every(isSupportedProfileValueCli);
  if (valueType === "object") return Object.values(value).every(isSupportedProfileValueCli);
  return false;
}

function normalizeVaultSnapshotCli(value) {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid vault snapshot payload");
  }
  const notes = Array.isArray(value.notes)
    ? value.notes.map((note, index) => {
        if (!note || typeof note !== "object") throw new Error(`Invalid vault note at index ${index}`);
        if (typeof note.id !== "string" || !note.id.trim()) throw new Error(`Invalid vault note id at index ${index}`);
        if (typeof note.ciphertext !== "string") throw new Error(`Invalid vault note ciphertext at index ${index}`);
        if (typeof note.iv !== "string") throw new Error(`Invalid vault note iv at index ${index}`);
        if (typeof note.updatedAt !== "number" || !Number.isFinite(note.updatedAt) || note.updatedAt <= 0) {
          throw new Error(`Invalid vault note timestamp at index ${index}`);
        }
        if (fromBase64Url(note.iv).length !== 12) throw new Error(`Invalid vault note iv at index ${index}`);
        if (fromBase64Url(note.ciphertext).length < 16) throw new Error(`Invalid vault note ciphertext at index ${index}`);
        return {
          id: note.id,
          ciphertext: note.ciphertext,
          iv: note.iv,
          updatedAt: note.updatedAt,
        };
      })
    : [];
  const meta = value.meta == null
    ? null
    : (() => {
        if (!value.meta || typeof value.meta !== "object") throw new Error("Invalid vault meta payload");
        if (typeof value.meta.salt !== "string") throw new Error("Invalid vault meta salt");
        if (typeof value.meta.iterations !== "number" || !Number.isInteger(value.meta.iterations) || value.meta.iterations < 10_000 || value.meta.iterations > 2_000_000) {
          throw new Error("Invalid vault meta iterations");
        }
        if (fromBase64Url(value.meta.salt).length < 8) throw new Error("Invalid vault meta salt");
        return {
          salt: value.meta.salt,
          iterations: value.meta.iterations,
          version: typeof value.meta.version === "number" ? value.meta.version : undefined,
          lockedAt: typeof value.meta.lockedAt === "number" ? value.meta.lockedAt : undefined,
        };
      })();
  const canary = value.canary == null
    ? null
    : (() => {
        if (!value.canary || typeof value.canary !== "object" || typeof value.canary.ciphertext !== "string" || typeof value.canary.iv !== "string") {
          throw new Error("Invalid vault canary payload");
        }
        if (fromBase64Url(value.canary.iv).length !== 12 || fromBase64Url(value.canary.ciphertext).length < 16) {
          throw new Error("Invalid vault canary payload");
        }
        return {
          ciphertext: value.canary.ciphertext,
          iv: value.canary.iv,
        };
      })();
  return { meta, notes, canary };
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function sanitizeInlineCli(value) {
  if (typeof value !== "string") return "";
  return value.trim();
}

function resolveSafeShareWorkflowPresetCli(value) {
  if (!value) return null;
  const normalized = String(value).trim();
  if (!normalized) return null;
  const preset = SAFE_SHARE_WORKFLOW_PRESETS[normalized];
  if (!preset) {
    throw new Error(`Unsupported safe-share workflow preset: ${normalized}`);
  }
  return {
    id: normalized,
    ...preset,
  };
}

function classifyTextForSafeShareCli(input) {
  const trimmed = String(input || "").trim();
  if (!trimmed) return "freeform-text";
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      JSON.parse(trimmed);
      return "json-text";
    } catch {
      // Fall through to log-ish heuristics.
    }
  }
  if (/(?:\b\d{1,3}(?:\.\d{1,3}){3}\b|\buser=|\bcookie=|\btoken=|\[[0-9]{1,2}\/[A-Za-z]{3}\/[0-9]{4})/i.test(trimmed)) {
    return "structured-log";
  }
  return "freeform-text";
}

function formatSafeShareClassCli(value) {
  if (value === "structured-log") return "structured log";
  if (value === "json-text") return "JSON text";
  if (value === "freeform-text") return "freeform text";
  return String(value || "unknown");
}

function printUsage() {
  console.log(
    `
NullID local CLI (offline, no servers)

Commands:
  hash <input-file> [--algo sha256|sha512|sha1]
  sanitize <input-file> <output-file> [--preset nginx|apache|auth|json] [--policy <policy-json>] [--baseline <nullid.policy.json>] [--merge-mode strict-override|prefer-stricter] [--json-aware true|false] [--format auto|text|json|ndjson|csv|xml|yaml]
  sanitize-dir <input-dir> <output-dir> [--preset ...|--policy ...|--baseline ...] [--format auto|text|json|ndjson|csv|xml|yaml] [--ext .log,.txt,.json] [--report <json-file>]
  bundle <input-file> <output-json> [--preset ...|--workflow general-safe-share|support-ticket|external-minimum|internal-investigation|incident-handoff|evidence-archive] [--title ...] [--purpose ...] [--case-ref ...] [--recipient ...] [--policy ...|--baseline ...] [--format auto|text|json|ndjson|csv|xml|yaml]
  package-inspect <input-file> [--pass <passphrase>|--pass-env <VAR>] [--verify-pass <passphrase>|--verify-pass-env <VAR>]
  redact <input-file> <output-file> [--mode full|partial] [--detectors email,phone,token,ip,id,iban,card,ipv6,awskey,awssecret,github,slack,privatekey]
  enc <input-file> <output-envelope-file> [--pass <passphrase>|--pass-env <VAR>] [--profile compat|strong|paranoid] [--iterations <n>] [--kdf-hash sha256|sha512]
  dec <input-envelope-file> <output-file> [--pass <passphrase>|--pass-env <VAR>]
  pwgen [--kind password|passphrase] [...options]
  pw-hash [--algo argon2id|pbkdf2-sha256|sha512|sha256] [--password <value>|--password-env <VAR>|--password-file <path>|--password-stdin] [--salt-bytes <n>] [--pbkdf2-iterations <n>] [--argon2-memory <KiB>] [--argon2-passes <n>] [--argon2-parallelism <n>]
  pw-verify [--record <hash-record>|--record-file <path>|--record-stdin] [--password <value>|--password-env <VAR>|--password-file <path>|--password-stdin]
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
  node scripts/nullid-local.mjs bundle ./raw.log ./nullid-safe-share-bundle.json --preset nginx
  node scripts/nullid-local.mjs bundle ./raw.log ./nullid-safe-share-bundle.json --preset nginx --workflow support-ticket
  node scripts/nullid-local.mjs package-inspect ./nullid-safe-share-bundle.json
  node scripts/nullid-local.mjs package-inspect ./signed-policy.json --verify-pass-env NULLID_VERIFY_PASSPHRASE
  node scripts/nullid-local.mjs redact ./incident.txt ./incident.redacted.txt --mode partial
  node scripts/nullid-local.mjs pdf-clean ./report.pdf ./report.clean.pdf
  node scripts/nullid-local.mjs office-clean ./incident.docx ./incident.clean.docx
  node scripts/nullid-local.mjs archive-sanitize ./evidence ./evidence-sanitized.zip --baseline ./nullid.policy.json
  node scripts/nullid-local.mjs precommit --staged --baseline ./nullid.policy.json --threshold high
  node scripts/nullid-local.mjs policy-init ./nullid.policy.json --preset nginx
  NULLID_PASSPHRASE='dev-secret' node scripts/nullid-local.mjs enc ./backup.tar ./backup.tar.nullid --profile strong
  NULLID_PASSPHRASE='dev-secret' node scripts/nullid-local.mjs dec ./backup.tar.nullid ./backup.tar
  node scripts/nullid-local.mjs pwgen --kind passphrase --words 6 --separator _
  NULLID_PASSWORD='correct horse battery staple' node scripts/nullid-local.mjs pw-hash --password-env NULLID_PASSWORD --algo pbkdf2-sha256
  NULLID_PASSWORD='correct horse battery staple' node scripts/nullid-local.mjs pw-verify --record '$pbkdf2-sha256$i=600000$...' --password-env NULLID_PASSWORD
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
  "maskIranNationalId",
  "maskPhoneIntl",
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

  if (parsed.kind === "sanitize-policy-pack" && Array.isArray(parsed.packs) && parsed.packs.length > 1) {
    throw new Error("Policy file contains multiple packs; CLI sanitize requires a single-pack export or a direct policy config");
  }

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
  return input.map((rule) => normalizeCustomRule(rule)).filter(Boolean);
}

// Keep CLI custom-rule safety aligned with src/utils/sanitizeEngine.ts.
function normalizeCustomRule(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const id = typeof value.id === "string" && value.id.trim() ? value.id : crypto.randomUUID();
  const pattern = typeof value.pattern === "string" ? value.pattern : "";
  const replacement = typeof value.replacement === "string" ? value.replacement.slice(0, MAX_CUSTOM_REPLACEMENT_LENGTH) : "";
  const flags = typeof value.flags === "string" ? value.flags : "gi";
  const scope = value.scope === "text" || value.scope === "json" || value.scope === "both" ? value.scope : "both";
  if (!pattern.trim()) return null;
  if (pattern.length > MAX_CUSTOM_PATTERN_LENGTH) return null;
  if (isUnsafeCustomRegexPattern(pattern)) return null;
  try {
    // eslint-disable-next-line no-new
    new RegExp(pattern, flags);
  } catch {
    return null;
  }
  return { id, pattern, replacement, flags, scope };
}

function isUnsafeCustomRegexPattern(pattern) {
  const cleaned = pattern.replace(/\\./g, "_");
  if (cleaned.length > MAX_CUSTOM_PATTERN_LENGTH) return true;
  if (/(^|[^\\])\\[1-9]/.test(pattern)) return true;
  if (/\((?:\?:)?[^()]{0,120}(?:\+|\*|\{[0-9,\s]+\})[^()]{0,120}\)\s*(?:\+|\*)/.test(cleaned)) return true;
  if (/(?:\.\*|\.\+)\s*(?:\+|\*)/.test(cleaned)) return true;
  return false;
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
  applyRule(policy.rulesState.maskIranNationalId, "maskIranNationalId", replaceIranNationalIds);
  applyRule(policy.rulesState.maskPhoneIntl, "maskPhoneIntl", replaceInternationalPhoneNumbers);
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

function replaceInternationalPhoneNumbers(input) {
  const regex = /(?:\+|00)?[0-9\u06F0-\u06F9\u0660-\u0669][0-9\u06F0-\u06F9\u0660-\u0669().\-\s]{7,18}[0-9\u06F0-\u06F9\u0660-\u0669]/g;
  let count = 0;
  const output = input.replace(regex, (match) => {
    const digits = toAsciiDigits(match).replace(/[^0-9]/g, "");
    if (digits.length >= 10 && digits.length <= 15) {
      count += 1;
      return "[phone]";
    }
    return match;
  });
  return { output, count };
}

function replaceIranNationalIds(input) {
  const regex = /(^|[^0-9\u06F0-\u06F9\u0660-\u0669])([0-9\u06F0-\u06F9\u0660-\u0669]{10})(?=$|[^0-9\u06F0-\u06F9\u0660-\u0669])/g;
  let count = 0;
  const output = input.replace(regex, (match, prefix, candidate) => {
    if (isValidIranNationalId(candidate)) {
      count += 1;
      return `${prefix}[iran-id]`;
    }
    return match;
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

function isValidIranNationalId(value) {
  const digits = toAsciiDigits(value).replace(/[^0-9]/g, "");
  if (!/^\d{10}$/.test(digits)) return false;
  if (/^(\d)\1{9}$/.test(digits)) return false;
  const check = Number(digits[9]);
  const sum = digits
    .slice(0, 9)
    .split("")
    .reduce((acc, ch, index) => acc + Number(ch) * (10 - index), 0);
  const remainder = sum % 11;
  return (remainder < 2 && check === remainder) || (remainder >= 2 && check === 11 - remainder);
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

function toAsciiDigits(value) {
  return value
    .replace(/[۰-۹]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1728))
    .replace(/[٠-٩]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 1584));
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
  const resolved = resolveOptionalPassphrase(argv);
  if (resolved) return resolved;
  throw new Error("Passphrase required: use --pass, --pass-env, or NULLID_PASSPHRASE");
}

function resolveOptionalPassphrase(argv) {
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

  return null;
}

function resolveOptionalVerificationPassphrase(argv) {
  const direct = getOption(argv, "--verify-pass");
  if (direct) return direct;

  const passEnv = getOption(argv, "--verify-pass-env");
  if (passEnv) {
    const value = process.env[passEnv];
    if (!value) {
      throw new Error(`Verification passphrase env variable not found: ${passEnv}`);
    }
    return value;
  }

  if (process.env.NULLID_VERIFY_PASSPHRASE) {
    return process.env.NULLID_VERIFY_PASSPHRASE;
  }

  return null;
}

function resolvePasswordSecret(argv) {
  const direct = getOption(argv, "--password");
  if (direct != null) return direct;

  const passwordFile = getOption(argv, "--password-file");
  if (passwordFile) {
    return trimSingleTrailingNewline(fs.readFileSync(path.resolve(passwordFile), "utf8"));
  }

  const passwordEnv = getOption(argv, "--password-env");
  if (passwordEnv) {
    const value = process.env[passwordEnv];
    if (value == null) {
      throw new Error(`Password env variable not found: ${passwordEnv}`);
    }
    return value;
  }

  if (hasFlag(argv, "--password-stdin")) {
    return trimSingleTrailingNewline(readStdinText());
  }

  if (process.env.NULLID_PASSWORD != null) {
    return process.env.NULLID_PASSWORD;
  }

  throw new Error(
    "Password required: use --password, --password-env, --password-file, --password-stdin, or NULLID_PASSWORD",
  );
}

function resolvePasswordHashRecord(argv) {
  const direct = getOption(argv, "--record");
  if (direct) return direct.trim();

  const recordFile = getOption(argv, "--record-file");
  if (recordFile) {
    return fs.readFileSync(path.resolve(recordFile), "utf8").trim();
  }

  if (hasFlag(argv, "--record-stdin")) {
    return readStdinText().trim();
  }

  const positional = argv[0];
  if (positional && !positional.startsWith("--")) return positional.trim();

  throw new Error("Password hash record required: use --record, --record-file, or --record-stdin");
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

function assessPasswordHashChoice(options) {
  const warnings = [];
  if (options.algorithm === "argon2id") {
    const memory = clampInt(
      options.argon2Memory,
      PASSWORD_HASH_MIN_ARGON2_MEMORY,
      PASSWORD_HASH_MAX_ARGON2_MEMORY,
      PASSWORD_HASH_DEFAULT_ARGON2_MEMORY,
    );
    const passes = clampInt(
      options.argon2Passes,
      PASSWORD_HASH_MIN_ARGON2_PASSES,
      PASSWORD_HASH_MAX_ARGON2_PASSES,
      PASSWORD_HASH_DEFAULT_ARGON2_PASSES,
    );
    if (memory < PASSWORD_HASH_ARGON2_MEMORY_RECOMMENDED_MIN) warnings.push(PASSWORD_HASH_WARNINGS.argon2MemoryBelowRecommended);
    if (passes < PASSWORD_HASH_ARGON2_PASSES_RECOMMENDED_MIN) warnings.push(PASSWORD_HASH_WARNINGS.argon2PassesBelowRecommended);
    return { safety: warnings.length > 0 ? "fair" : "strong", warnings };
  }

  if (options.algorithm === "pbkdf2-sha256") {
    const iterations = clampInt(
      options.pbkdf2Iterations,
      PASSWORD_HASH_MIN_PBKDF2_ITERATIONS,
      PASSWORD_HASH_MAX_PBKDF2_ITERATIONS,
      PASSWORD_HASH_DEFAULT_PBKDF2_ITERATIONS,
    );
    if (iterations < PASSWORD_HASH_PBKDF2_RECOMMENDED_MIN) warnings.push(PASSWORD_HASH_WARNINGS.pbkdf2IterationsBelowRecommended);
    return { safety: warnings.length > 0 ? "fair" : "strong", warnings };
  }

  warnings.push(PASSWORD_HASH_WARNINGS.legacyFastSha);
  warnings.push(PASSWORD_HASH_WARNINGS.preferSlowKdf);
  return { safety: "weak", warnings };
}

function derivePasswordHashPbkdf2(secret, salt, iterations) {
  return crypto.pbkdf2Sync(Buffer.from(secret, "utf8"), salt, iterations, PASSWORD_HASH_DEFAULT_DERIVED_BYTES, "sha256");
}

async function derivePasswordHashArgon2id(secret, salt, options) {
  const subtle = crypto.webcrypto?.subtle;
  if (!subtle) {
    throw new Error(PASSWORD_HASH_ERRORS.argon2Unavailable);
  }
  const keyMaterial = await subtle.importKey("raw-secret", Buffer.from(secret, "utf8"), "Argon2id", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "Argon2id",
      nonce: salt,
      memory: options.memory,
      passes: options.passes,
      parallelism: options.parallelism,
    },
    keyMaterial,
    PASSWORD_HASH_DEFAULT_DERIVED_BITS,
  );
  return Buffer.from(bits);
}

function derivePasswordHashSha(secret, salt, algorithm) {
  return crypto.createHash(algorithm).update(Buffer.concat([salt, Buffer.from(secret, "utf8")])).digest();
}

async function supportsPasswordHashArgon2() {
  if (passwordHashArgon2SupportCache !== null) return passwordHashArgon2SupportCache;
  try {
    const subtle = crypto.webcrypto?.subtle;
    if (!subtle) {
      throw new Error("WebCrypto subtle unavailable");
    }
    const key = await subtle.importKey("raw-secret", Buffer.from("probe", "utf8"), "Argon2id", false, ["deriveBits"]);
    await subtle.deriveBits(
      {
        name: "Argon2id",
        nonce: crypto.randomBytes(16),
        memory: PASSWORD_HASH_MIN_ARGON2_MEMORY,
        passes: 1,
        parallelism: 1,
      },
      key,
      128,
    );
    passwordHashArgon2SupportCache = true;
  } catch {
    passwordHashArgon2SupportCache = false;
  }
  return passwordHashArgon2SupportCache;
}

async function generatePasswordHashRecord(secret, options) {
  if (!secret) {
    throw new Error(PASSWORD_HASH_ERRORS.passwordRequired);
  }

  const saltBytes = clampInt(
    options.saltBytes,
    PASSWORD_HASH_MIN_SALT_BYTES,
    PASSWORD_HASH_MAX_SALT_BYTES,
    PASSWORD_HASH_DEFAULT_SALT_BYTES,
  );
  const salt = crypto.randomBytes(saltBytes);
  const assessment = assessPasswordHashChoice(options);

  if (options.algorithm === "argon2id") {
    if (!(await supportsPasswordHashArgon2())) {
      throw new Error(PASSWORD_HASH_ERRORS.argon2Unavailable);
    }
    const memory = clampInt(
      options.argon2Memory,
      PASSWORD_HASH_MIN_ARGON2_MEMORY,
      PASSWORD_HASH_MAX_ARGON2_MEMORY,
      PASSWORD_HASH_DEFAULT_ARGON2_MEMORY,
    );
    const passes = clampInt(
      options.argon2Passes,
      PASSWORD_HASH_MIN_ARGON2_PASSES,
      PASSWORD_HASH_MAX_ARGON2_PASSES,
      PASSWORD_HASH_DEFAULT_ARGON2_PASSES,
    );
    const parallelism = clampInt(
      options.argon2Parallelism,
      PASSWORD_HASH_MIN_ARGON2_PARALLELISM,
      PASSWORD_HASH_MAX_ARGON2_PARALLELISM,
      PASSWORD_HASH_DEFAULT_ARGON2_PARALLELISM,
    );
    const digest = await derivePasswordHashArgon2id(secret, salt, { memory, passes, parallelism });
    return {
      algorithm: options.algorithm,
      record: `$argon2id$v=${PASSWORD_HASH_ARGON2_VERSION}$m=${memory},t=${passes},p=${parallelism}$${toBase64Url(salt)}$${toBase64Url(digest)}`,
      assessment,
    };
  }

  if (options.algorithm === "pbkdf2-sha256") {
    const iterations = clampInt(
      options.pbkdf2Iterations,
      PASSWORD_HASH_MIN_PBKDF2_ITERATIONS,
      PASSWORD_HASH_MAX_PBKDF2_ITERATIONS,
      PASSWORD_HASH_DEFAULT_PBKDF2_ITERATIONS,
    );
    const digest = derivePasswordHashPbkdf2(secret, salt, iterations);
    return {
      algorithm: options.algorithm,
      record: `$pbkdf2-sha256$i=${iterations}$${toBase64Url(salt)}$${toBase64Url(digest)}`,
      assessment,
    };
  }

  const digest = derivePasswordHashSha(secret, salt, options.algorithm);
  return {
    algorithm: options.algorithm,
    record: `$${options.algorithm}$s=${toBase64Url(salt)}$${toBase64Url(digest)}`,
    assessment,
  };
}

function decodePasswordHashSegment(value, errorMessage) {
  if (!PASSWORD_HASH_B64_SEGMENT_RE.test(value)) {
    throw new Error(errorMessage);
  }
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const hasPadding = normalized.includes("=");
  if (hasPadding && normalized.length % 4 !== 0) {
    throw new Error(errorMessage);
  }
  if (!hasPadding && normalized.length % 4 === 1) {
    throw new Error(errorMessage);
  }
  const padded = hasPadding ? normalized : normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const bytes = Buffer.from(padded, "base64");
  if (bytes.toString("base64") !== padded) {
    throw new Error(errorMessage);
  }
  return bytes;
}

function validatePasswordHashSaltLength(salt) {
  if (salt.length < PASSWORD_HASH_MIN_SALT_BYTES || salt.length > PASSWORD_HASH_MAX_SALT_BYTES) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidSaltLength);
  }
}

function validatePasswordHashDigestLength(algorithm, digest) {
  const expectedLength = algorithm === "sha512" ? 64 : PASSWORD_HASH_DEFAULT_DERIVED_BYTES;
  if (digest.length !== expectedLength) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidDigestLength);
  }
}

function validatePasswordHashPbkdf2Iterations(iterations) {
  if (!Number.isSafeInteger(iterations) || iterations < PASSWORD_HASH_MIN_PBKDF2_ITERATIONS || iterations > PASSWORD_HASH_MAX_PBKDF2_ITERATIONS) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidPbkdf2Iterations);
  }
}

function validatePasswordHashArgon2Params(memory, passes, parallelism) {
  const params = [memory, passes, parallelism];
  if (!params.every((value) => Number.isSafeInteger(value))) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidArgon2Params);
  }
  if (
    memory < PASSWORD_HASH_MIN_ARGON2_MEMORY ||
    memory > PASSWORD_HASH_MAX_ARGON2_MEMORY ||
    passes < PASSWORD_HASH_MIN_ARGON2_PASSES ||
    passes > PASSWORD_HASH_MAX_ARGON2_PASSES ||
    parallelism < PASSWORD_HASH_MIN_ARGON2_PARALLELISM ||
    parallelism > PASSWORD_HASH_MAX_ARGON2_PARALLELISM
  ) {
    throw new Error(PASSWORD_HASH_ERRORS.invalidArgon2Params);
  }
}

function parsePasswordHashRecord(record) {
  const argonMatch = record.match(
    new RegExp(
      `^\\$argon2id\\$v=${PASSWORD_HASH_ARGON2_VERSION}\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$(${PASSWORD_HASH_B64_SEGMENT})\\$(${PASSWORD_HASH_B64_SEGMENT})$`,
      "u",
    ),
  );
  if (argonMatch) {
    const argon2Memory = Number(argonMatch[1]);
    const argon2Passes = Number(argonMatch[2]);
    const argon2Parallelism = Number(argonMatch[3]);
    validatePasswordHashArgon2Params(argon2Memory, argon2Passes, argon2Parallelism);
    const salt = decodePasswordHashSegment(argonMatch[4], PASSWORD_HASH_ERRORS.invalidSaltEncoding);
    validatePasswordHashSaltLength(salt);
    const digest = decodePasswordHashSegment(argonMatch[5], PASSWORD_HASH_ERRORS.invalidDigestEncoding);
    validatePasswordHashDigestLength("argon2id", digest);
    return {
      algorithm: "argon2id",
      argon2Memory,
      argon2Passes,
      argon2Parallelism,
      salt,
      digest,
    };
  }

  const pbkdf2Match = record.match(
    new RegExp(`^\\$pbkdf2-sha256\\$i=(\\d+)\\$(${PASSWORD_HASH_B64_SEGMENT})\\$(${PASSWORD_HASH_B64_SEGMENT})$`, "u"),
  );
  if (pbkdf2Match) {
    const pbkdf2Iterations = Number(pbkdf2Match[1]);
    validatePasswordHashPbkdf2Iterations(pbkdf2Iterations);
    const salt = decodePasswordHashSegment(pbkdf2Match[2], PASSWORD_HASH_ERRORS.invalidSaltEncoding);
    validatePasswordHashSaltLength(salt);
    const digest = decodePasswordHashSegment(pbkdf2Match[3], PASSWORD_HASH_ERRORS.invalidDigestEncoding);
    validatePasswordHashDigestLength("pbkdf2-sha256", digest);
    return {
      algorithm: "pbkdf2-sha256",
      pbkdf2Iterations,
      salt,
      digest,
    };
  }

  const shaMatch = record.match(
    new RegExp(`^\\$(sha256|sha512)\\$s=(${PASSWORD_HASH_B64_SEGMENT})\\$(${PASSWORD_HASH_B64_SEGMENT})$`, "u"),
  );
  if (shaMatch) {
    const algorithm = shaMatch[1];
    const salt = decodePasswordHashSegment(shaMatch[2], PASSWORD_HASH_ERRORS.invalidSaltEncoding);
    validatePasswordHashSaltLength(salt);
    const digest = decodePasswordHashSegment(shaMatch[3], PASSWORD_HASH_ERRORS.invalidDigestEncoding);
    validatePasswordHashDigestLength(algorithm, digest);
    return {
      algorithm,
      salt,
      digest,
    };
  }

  throw new Error(PASSWORD_HASH_ERRORS.unsupportedFormat);
}

async function verifyPasswordHashRecord(secret, record) {
  if (!secret) return false;
  const parsed = parsePasswordHashRecord(record);

  if (parsed.algorithm === "argon2id") {
    if (!(await supportsPasswordHashArgon2())) {
      throw new Error(PASSWORD_HASH_ERRORS.argon2UnavailableVerify);
    }
    const digest = await derivePasswordHashArgon2id(secret, parsed.salt, {
      memory: parsed.argon2Memory ?? PASSWORD_HASH_DEFAULT_ARGON2_MEMORY,
      passes: parsed.argon2Passes ?? PASSWORD_HASH_DEFAULT_ARGON2_PASSES,
      parallelism: parsed.argon2Parallelism ?? PASSWORD_HASH_DEFAULT_ARGON2_PARALLELISM,
    });
    return equalPasswordHashBytes(digest, parsed.digest);
  }

  if (parsed.algorithm === "pbkdf2-sha256") {
    const digest = derivePasswordHashPbkdf2(
      secret,
      parsed.salt,
      parsed.pbkdf2Iterations ?? PASSWORD_HASH_DEFAULT_PBKDF2_ITERATIONS,
    );
    return equalPasswordHashBytes(digest, parsed.digest);
  }

  const digest = derivePasswordHashSha(secret, parsed.salt, parsed.algorithm);
  return equalPasswordHashBytes(digest, parsed.digest);
}

function equalPasswordHashBytes(left, right) {
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
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

function readStdinText() {
  return fs.readFileSync(0, "utf8");
}

function trimSingleTrailingNewline(value) {
  return value.replace(/\r?\n$/u, "");
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

function readNullIdVersion() {
  try {
    const raw = fs.readFileSync(new URL("../package.json", import.meta.url), "utf8");
    const parsed = JSON.parse(raw);
    return typeof parsed.version === "string" ? parsed.version : null;
  } catch {
    return null;
  }
}

function inspectEnvelopeBlob(blob) {
  const envelope = parseEnvelopeBlob(blob);
  return {
    header: envelope.header,
    ciphertextBytes: fromBase64Url(envelope.ciphertext).length,
  };
}

function decryptEnvelopeBlob(passphrase, blob) {
  const envelope = parseEnvelopeBlob(blob);
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

  try {
    return {
      plaintext: Buffer.concat([decipher.update(ciphertext), decipher.final()]),
      header: envelope.header,
    };
  } catch {
    throw new Error("Decrypt failed: bad passphrase or envelope integrity failure");
  }
}

function parseEnvelopeBlob(blob) {
  const normalized = String(blob || "").trim().replace(/\s+/g, "");
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
  return envelope;
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

function decodeBase64StrictCli(value, errorMessage) {
  const trimmed = String(value || "").trim();
  if (!trimmed || !/^[A-Za-z0-9+/]+=*$/u.test(trimmed)) {
    throw new Error(errorMessage);
  }
  const buffer = Buffer.from(trimmed, "base64");
  const normalized = buffer.toString("base64");
  const expected = trimmed.padEnd(trimmed.length + ((4 - (trimmed.length % 4)) % 4), "=");
  if (normalized !== expected) {
    throw new Error(errorMessage);
  }
  return buffer;
}

main().catch((error) => {
  console.error(`[nullid-cli] ${(error instanceof Error ? error.message : String(error)).trim()}`);
  process.exit(1);
});
