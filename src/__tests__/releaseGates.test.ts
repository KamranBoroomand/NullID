import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

describe("release and deployment E2E gates", () => {
  it("makes production offline and upgrade E2E mandatory", () => {
    const pkg = JSON.parse(fs.readFileSync("package.json", "utf8")) as { scripts: Record<string, string> };

    for (const script of ["test:e2e:app", "test:e2e:offline", "test:e2e:upgrade", "test:e2e:production"]) {
      assert.equal(typeof pkg.scripts[script], "string", `${script} script is required`);
    }
    assert.match(pkg.scripts.validate, /test:e2e:production/);
    assert.match(fs.readFileSync("scripts/release-dry-run.mjs", "utf8"), /test:e2e:production|validate/);

    const workflows = [
      ".github/workflows/quality-gates.yml",
      ".github/workflows/pages.yml",
      ".github/workflows/release-dry-run.yml",
      ".github/workflows/release-signed.yml",
    ];
    for (const workflow of workflows) {
      assert.match(fs.readFileSync(workflow, "utf8"), /test:e2e:production/, workflow);
    }
  });

  it("keeps the network lint gate authoritative for service-worker install fetches", () => {
    const output = execFileSync(process.execPath, ["scripts/lint.js"], { encoding: "utf8" });

    assert.match(output, /no disallowed network calls detected/);
  });

  it("launches CycloneDX SBOM generation through the portable Node entrypoint", () => {
    const source = fs.readFileSync("scripts/generate-sbom.mjs", "utf8");
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-sbom-"));
    const outputPath = path.join(tempDir, "sbom.json");
    let outputExisted = false;
    let sbom: {
      bomFormat?: string;
      specVersion?: string;
      components?: Array<{ group?: string; name?: string; version?: string }>;
      metadata?: { tools?: { components?: Array<{ type?: string; name?: string; version?: string }> } };
    } | undefined;

    assert.doesNotMatch(source, /cyclonedx-npm\.cmd/u);
    assert.match(source, /process\.execPath/u);
    assert.doesNotMatch(source, /shell\s*:\s*true/u);
    assert.doesNotMatch(source, /normalizeEnvironmentDerivedSbomFields/u);

    try {
      const output = execFileSync(process.execPath, ["scripts/generate-sbom.mjs", outputPath], { encoding: "utf8" });
      sbom = JSON.parse(fs.readFileSync(outputPath, "utf8")) as typeof sbom;

      outputExisted = fs.existsSync(outputPath);
      assert.match(output, /\[sbom\] wrote CycloneDX/u);
      assert.equal(sbom?.bomFormat, "CycloneDX");
      assert.equal(sbom?.specVersion, "1.6");
      assert.equal(Array.isArray(sbom?.components), true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }

    assert.equal(outputExisted, true);
    assert.equal(fs.existsSync(outputPath), false);

    const npmTool = sbom?.metadata?.tools?.components?.find((component) => component.type === "application" && component.name === "npm");
    assert.ok(npmTool, "SBOM should keep the npm tool identity");
    assert.equal(typeof npmTool.version, "string", "SBOM should keep the npm tool version emitted by CycloneDX");
    assert.notEqual(npmTool.version, "");

    assert.equal(hasComponent(sbom?.components, undefined, "react", "18.3.1"), true);
    assert.equal(hasComponent(sbom?.components, "@noble", "hashes", "1.8.0"), true);
    assert.equal(hasComponent(sbom?.components, "@cyclonedx", "cyclonedx-npm", "5.0.0"), true);
  });

  it("skips visual regression for test-only source paths before broad src matches", () => {
    const workflow = fs.readFileSync(".github/workflows/visual-regression.yml", "utf8");

    assert.ok(
      workflow.indexOf("src/__tests__/*|src/__tests__/**)") < workflow.indexOf("src/*|src/**)"),
      "test-only src exclusion must appear before the broad src match",
    );
    assert.doesNotMatch(workflow, /src\/\*\*tests\*\*/u);
    assert.match(workflow, /workflow_dispatch[\s\S]+should_run=true/u);

    assert.equal(visualRegressionShouldRun(workflow, "src/__tests__/releaseGates.test.ts"), false);
    assert.equal(visualRegressionShouldRun(workflow, "src/contestResults/View.tsx"), true);
    assert.equal(visualRegressionShouldRun(workflow, "src/App.tsx"), true);
    assert.equal(visualRegressionShouldRun(workflow, "src/styles/global.css"), true);
    assert.equal(visualRegressionShouldRun(workflow, "public/nullid-preview.png"), true);
    assert.equal(visualRegressionShouldRun(workflow, "tests/e2e/app.spec.ts-snapshots/app-chromium-darwin.png"), true);
  });

  it("rejects duplicate physical/logical sources in a coverage evidence scope", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-coverage-duplicates-"));
    writeCoverageSummary(tempDir, "core", {
      "build-test/utils/archiveReferencePolicy.js": coverageMetric(),
      "src/utils/archiveReferencePolicy.js": coverageMetric(),
    });
    writeCoverageSummary(tempDir, "scripts", {
      "scripts/lint.js": coverageMetric(),
    });
    writeCoverageSummary(tempDir, "combined", {
      "build-test/utils/archiveReferencePolicy.js": coverageMetric(),
      "src/utils/archiveReferencePolicy.js": coverageMetric(),
      "scripts/lint.js": coverageMetric(),
    });

    assert.throws(
      () => execFileSync(process.execPath, [path.resolve("scripts/coverage-evidence.mjs")], { cwd: tempDir, encoding: "utf8" }),
      /duplicate|logical|physical|source/i,
    );
  });

  it("records the canonical Node and V8 runtime in coverage evidence", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-coverage-runtime-"));
    writeCoverageSummary(tempDir, "core", { "build-test/utils/profile.js": coverageMetric() });
    writeCoverageSummary(tempDir, "scripts", { "scripts/lint.js": coverageMetric() });
    writeCoverageSummary(tempDir, "combined", {
      "build-test/utils/profile.js": coverageMetric(),
      "scripts/lint.js": coverageMetric(),
    });
    const evidencePath = path.join(tempDir, "coverage", "evidence-summary.json");

    execFileSync(process.execPath, [path.resolve("scripts/coverage-evidence.mjs"), "--write", evidencePath], { cwd: tempDir, encoding: "utf8" });

    const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8")) as {
      version?: number;
      runtime?: { node?: string; v8?: string; canonicalNode?: string; kind?: string; isCanonical?: boolean };
      canonicalRuntime?: { node?: string; v8?: string; canonicalNode?: string; kind?: string; isCanonical?: boolean };
    };
    const expectedKind = process.version === "v20.19.0" ? "canonical" : "noncanonical";
    assert.equal(evidence.version, 3);
    assert.equal(evidence.runtime?.node, process.version);
    assert.equal(evidence.runtime?.v8, process.versions.v8);
    assert.equal(evidence.runtime?.canonicalNode, "v20.19.0");
    assert.equal(evidence.runtime?.kind, expectedKind);
    assert.equal(evidence.runtime?.isCanonical, expectedKind === "canonical");
    assert.deepEqual(evidence.canonicalRuntime, evidence.runtime);
  });

  it("keeps combined coverage informational while preserving core and script thresholds", () => {
    const core = JSON.parse(fs.readFileSync("scripts/coverage-app.c8.json", "utf8")) as Record<string, unknown>;
    const scripts = JSON.parse(fs.readFileSync("scripts/coverage-scripts.c8.json", "utf8")) as Record<string, unknown>;
    const combined = JSON.parse(fs.readFileSync("scripts/coverage-combined.c8.json", "utf8")) as Record<string, unknown>;

    assert.equal(core["check-coverage"], true);
    assert.equal(core.lines, 75);
    assert.equal(core.statements, 75);
    assert.equal(core.functions, 75);
    assert.equal(core.branches, 60);

    assert.equal(scripts["check-coverage"], true);
    assert.equal(scripts.lines, 45);
    assert.equal(scripts.statements, 45);
    assert.equal(scripts.functions, 65);
    assert.equal(scripts.branches, 50);

    assert.equal(combined["check-coverage"], undefined);
    for (const key of ["lines", "statements", "functions", "branches"]) {
      assert.equal(combined[key], undefined, key);
    }
    assert.deepEqual(combined.reporter, ["text", "json-summary"]);
  });

  it("rejects false canonical coverage runtime claims", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-coverage-canonical-"));
    writeCoverageSummary(tempDir, "core", { "build-test/utils/profile.js": coverageMetric() });
    writeCoverageSummary(tempDir, "scripts", { "scripts/lint.js": coverageMetric() });
    writeCoverageSummary(tempDir, "combined", {
      "build-test/utils/profile.js": coverageMetric(),
      "scripts/lint.js": coverageMetric(),
    });
    const evidencePath = path.join(tempDir, "coverage", "evidence-summary.json");

    execFileSync(process.execPath, [path.resolve("scripts/coverage-evidence.mjs"), "--write", evidencePath], { cwd: tempDir, encoding: "utf8" });
    const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8")) as {
      runtime: { v8: string };
      canonicalRuntime: { v8: string };
    };
    evidence.runtime.v8 = "false-v8-claim";
    evidence.canonicalRuntime.v8 = "false-v8-claim";
    fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);

    assert.throws(
      () => execFileSync(process.execPath, [path.resolve("scripts/coverage-evidence.mjs"), "--verify", evidencePath], { cwd: tempDir, encoding: "utf8" }),
      /diverges|runtime|coverage/i,
    );
  });

  it("asserts canonical coverage only on Node 20.19.0", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-coverage-assert-canonical-"));
    writeCoverageSummary(tempDir, "core", { "build-test/utils/profile.js": coverageMetric() });
    writeCoverageSummary(tempDir, "scripts", { "scripts/lint.js": coverageMetric() });
    writeCoverageSummary(tempDir, "combined", {
      "build-test/utils/profile.js": coverageMetric(),
      "scripts/lint.js": coverageMetric(),
    });
    const evidencePath = path.join(tempDir, "coverage", "evidence-summary.json");
    const args = [path.resolve("scripts/coverage-evidence.mjs"), "--write", evidencePath, "--verify", evidencePath, "--assert-canonical"];

    if (process.version === "v20.19.0") {
      assert.doesNotThrow(() => execFileSync(process.execPath, args, { cwd: tempDir, encoding: "utf8" }));
    } else {
      assert.throws(
        () => execFileSync(process.execPath, args, { cwd: tempDir, encoding: "utf8" }),
        /canonical release evidence requires Node v20\.19\.0/i,
      );
    }
  });

  it("pins canonical coverage and tests supported Node lines in CI workflows", () => {
    const quality = fs.readFileSync(".github/workflows/quality-gates.yml", "utf8");
    const releaseDryRun = fs.readFileSync(".github/workflows/release-dry-run.yml", "utf8");
    const releaseSigned = fs.readFileSync(".github/workflows/release-signed.yml", "utf8");
    const reproducibility = fs.readFileSync(".github/workflows/reproducibility.yml", "utf8");

    assert.match(quality, /node-version:\s*20\.19\.0/);
    assert.match(quality, /coverage:assert-canonical/);
    for (const version of ["20.19.0", "22.x", "24.x"]) {
      assert.match(quality, new RegExp(`version:\\s*${version.replace(".", "\\.")}`), version);
    }
    assert.match(quality, /coverage:core/);
    assert.match(quality, /coverage:scripts/);
    assert.match(quality, /coverage:combined/);

    assert.match(releaseDryRun, /node-version:\s*20\.19\.0/);
    assert.match(releaseDryRun, /coverage:assert-canonical/);
    assert.match(releaseSigned, /node-version:\s*20\.19\.0/);
    assert.match(releaseSigned, /coverage:assert-canonical/);
    for (const version of ["20.19.0", "22.x", "24.x"]) {
      assert.match(reproducibility, new RegExp(`version:\\s*${version.replace(".", "\\.")}`), version);
    }
  });

  it("pins every third-party workflow action to a full commit SHA", () => {
    const workflowPaths = [
      ...discoverWorkflowYaml(".github/workflows"),
      ...discoverWorkflowYaml(".github/workflow-templates"),
    ];
    const mutableRefs: string[] = [];

    assert.ok(workflowPaths.length > 0);
    assert.equal(workflowPaths.includes(".github/workflows/desktop-tauri-smoke.yml"), true);

    for (const workflowPath of workflowPaths) {
      const source = fs.readFileSync(workflowPath, "utf8");
      for (const match of source.matchAll(/uses:\s*([^\s#]+@([^\s#]+))/g)) {
        const ref = match[2] ?? "";
        if (!/^[a-f0-9]{40}$/iu.test(ref)) {
          mutableRefs.push(`${workflowPath}: ${match[1]}`);
        }
      }
    }

    assert.deepEqual(mutableRefs, []);
  });

  it("keeps write-token release permissions out of dependency and build jobs", () => {
    for (const workflowPath of [".github/workflows/pages.yml", ".github/workflows/release-signed.yml"]) {
      const source = fs.readFileSync(workflowPath, "utf8");
      assert.doesNotMatch(workflowLevelPermissions(source), /(?:contents|pages|id-token|attestations):\s*write/u, workflowPath);
      for (const [jobName, body] of workflowJobs(source)) {
        if (/npm ci|npm run|node scripts|vite build/u.test(body)) {
          assert.doesNotMatch(jobPermissions(body), /(?:contents|pages|id-token|attestations):\s*write/u, `${workflowPath}:${jobName}`);
        }
      }
    }
  });
});

function writeCoverageSummary(tempDir: string, scope: string, files: Record<string, ReturnType<typeof coverageMetric>>) {
  const dir = path.join(tempDir, "coverage", scope);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "coverage-summary.json"),
    `${JSON.stringify({ total: coverageMetric(), ...files }, null, 2)}\n`,
  );
}

function coverageMetric() {
  return {
    lines: { total: 10, covered: 9, skipped: 0, pct: 90 },
    statements: { total: 10, covered: 9, skipped: 0, pct: 90 },
    functions: { total: 10, covered: 9, skipped: 0, pct: 90 },
    branches: { total: 10, covered: 8, skipped: 0, pct: 80 },
  };
}

function hasComponent(
  components: Array<{ group?: string; name?: string; version?: string }> | undefined,
  group: string | undefined,
  name: string,
  version: string,
) {
  return components?.some((component) => component.group === group && component.name === name && component.version === version) === true;
}

function visualRegressionShouldRun(workflow: string, file: string) {
  for (const rule of visualRegressionRules(workflow)) {
    if (rule.patterns.some((pattern) => shellCasePatternMatches(pattern, file))) {
      return rule.shouldRun;
    }
  }
  return false;
}

function visualRegressionRules(workflow: string) {
  const caseStart = workflow.indexOf('case "$file" in');
  const caseEnd = workflow.indexOf("esac", caseStart);
  assert.ok(caseStart >= 0 && caseEnd > caseStart, "visual workflow should classify changed files with a shell case statement");

  const lines = workflow.slice(caseStart, caseEnd).split("\n").slice(1);
  const rules: Array<{ patterns: string[]; shouldRun: boolean }> = [];
  for (let index = 0; index < lines.length;) {
    const trimmed = lines[index]?.trim() ?? "";
    if (trimmed.length === 0) {
      index += 1;
      continue;
    }

    const patternLines: string[] = [];
    while (index < lines.length) {
      const line = lines[index]?.trim() ?? "";
      patternLines.push(line);
      index += 1;
      if (line.endsWith(")")) break;
    }

    const actionLines: string[] = [];
    while (index < lines.length) {
      const line = lines[index]?.trim() ?? "";
      index += 1;
      if (line === ";;") break;
      actionLines.push(line);
    }

    const patterns = patternLines
      .join("")
      .replace(/\)$/, "")
      .replaceAll("\\", "")
      .split("|")
      .filter(Boolean);
    rules.push({ patterns, shouldRun: actionLines.includes("should_run=true") });
  }

  return rules;
}

function shellCasePatternMatches(pattern: string, file: string) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/gu, "\\$&").replaceAll("*", ".*").replaceAll("?", ".");
  return new RegExp(`^${escaped}$`, "u").test(file);
}

function workflowLevelPermissions(source: string) {
  const match = source.match(/^permissions:\n(?<body>(?: {2}.+\n)+)/mu);
  return match?.groups?.body ?? "";
}

function workflowJobs(source: string) {
  const jobsStart = source.search(/^jobs:\s*$/mu);
  if (jobsStart < 0) return [] as Array<[string, string]>;
  const jobsSource = source.slice(jobsStart);
  const matches = Array.from(jobsSource.matchAll(/^ {2}([A-Za-z0-9_-]+):\s*$/gmu));
  return matches.map((match, index) => {
    const start = (match.index ?? 0) + match[0].length;
    const end = index + 1 < matches.length ? (matches[index + 1].index ?? jobsSource.length) : jobsSource.length;
    return [match[1], jobsSource.slice(start, end)] as [string, string];
  });
}

function jobPermissions(jobBody: string) {
  const match = jobBody.match(/^ {4}permissions:\n(?<body>(?: {6}.+\n)+)/mu);
  return match?.groups?.body ?? "";
}

function discoverWorkflowYaml(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const paths = entries.flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return discoverWorkflowYaml(fullPath);
    return /\.ya?ml$/iu.test(entry.name) ? [fullPath] : [];
  });
  return paths.map((item) => item.replaceAll(path.sep, "/")).sort();
}
