import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

type AuditModule = {
  evaluateAuditReports(input: {
    productionAudit: AuditReport;
    fullAudit: AuditReport;
    policy: AuditPolicy;
    lockfile: Lockfile;
    now?: Date;
  }): { ok: boolean; output: string; failures: string[] };
  parseAuditJson(raw: string, label?: string): unknown;
};

type AuditReport = {
  auditReportVersion: number;
  vulnerabilities: Record<string, AuditVulnerability>;
  metadata: { vulnerabilities: Record<string, number> };
};

type AuditVulnerability = {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | AuditAdvisory>;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable?: boolean | { name: string; version: string; isSemVerMajor: boolean };
};

type AuditAdvisory = {
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: string;
  range: string;
};

type AuditPolicy = {
  exceptions: Array<{
    advisoryId: string;
    advisoryUrl: string;
    packageName: string;
    permittedVulnerableVersions: string[];
    permittedNodePaths: string[];
    permittedDependencyFamilies: Array<{ name: string; rootPackages: string[] }>;
    devOnly: boolean;
    expires: string;
  }>;
};

type Lockfile = {
  packages: Record<string, { name?: string; version?: string; dev?: boolean; optional?: boolean; dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> }>;
};

const moduleUrl = pathToFileURL(path.resolve("scripts/audit-dependencies.mjs")).href;
const advisoryOrigin = ["https:", "", "github.com"].join("/");

describe("dependency audit policy", () => {
  it("accepts a completely clean audit when no temporary exception is configured", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit: cleanAudit(),
      policy: { exceptions: [] },
      lockfile: baseLockfile(),
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, true);
    assert.match(result.output, /production tree clean/);
  });

  it("accepts only the exact approved dev-tool advisory", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit: approvedAudit(),
      policy: basePolicy(),
      lockfile: baseLockfile(),
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, true);
    assert.match(result.output, /approved temporary dev-tool exception GHSA-mh99-v99m-4gvg/);
    assert.match(result.output, /no unapproved high or critical findings/);
  });

  it("rejects an unexpected advisory", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const fullAudit = approvedAudit();
    fullAudit.vulnerabilities.postcss = vulnerability("postcss", "high", [postcssAdvisory()], ["node_modules/postcss"]);
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit,
      policy: basePolicy(),
      lockfile: baseLockfile(),
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, false);
    assert.match(result.output, /unapproved high advisory GHSA-r28c-9q8g-f849/);
  });

  it("rejects a critical advisory even when the advisory id matches", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const fullAudit = approvedAudit();
    fullAudit.vulnerabilities["brace-expansion"].severity = "critical";
    fullAudit.vulnerabilities["brace-expansion"].via = [braceExpansionAdvisory("critical")];
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit,
      policy: basePolicy(),
      lockfile: baseLockfile(),
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, false);
    assert.match(result.output, /critical advisory GHSA-mh99-v99m-4gvg/);
  });

  it("rejects a wrong vulnerable package version", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const lockfile = baseLockfile();
    lockfile.packages["node_modules/brace-expansion"].version = "1.1.17";
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit: approvedAudit(),
      policy: basePolicy(),
      lockfile,
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, false);
    assert.match(result.output, /expected one of 1\.1\.16, 2\.1\.2/);
  });

  it("rejects an additional vulnerable node", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const fullAudit = approvedAudit();
    fullAudit.vulnerabilities["brace-expansion"].nodes.push("node_modules/other/node_modules/brace-expansion");
    const lockfile = baseLockfile();
    lockfile.packages["node_modules/other"] = { version: "1.0.0", dev: true, dependencies: { "brace-expansion": "^1.1.7" } };
    lockfile.packages["node_modules/other/node_modules/brace-expansion"] = { version: "1.1.16", dev: true };
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit,
      policy: basePolicy(),
      lockfile,
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, false);
    assert.match(result.output, /unapproved vulnerable node/);
  });

  it("rejects a production-reachable vulnerable node", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const lockfile = baseLockfile();
    lockfile.packages[""].dependencies = { "eslint-plugin-jsx-a11y": "^6.10.2" };
    lockfile.packages[""].devDependencies = {};
    lockfile.packages["node_modules/brace-expansion"].dev = false;
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit: approvedAudit(),
      policy: basePolicy(),
      lockfile,
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, false);
    assert.match(result.output, /non-dev node/);
  });

  it("rejects an expired exception", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit: approvedAudit(),
      policy: basePolicy(),
      lockfile: baseLockfile(),
      now: new Date("2026-08-27T00:00:00.000Z"),
    });

    assert.equal(result.ok, false);
    assert.match(result.output, /expired on 2026-08-26/);
  });

  it("rejects malformed npm audit output", async () => {
    const { parseAuditJson } = await loadAuditModule();

    assert.throws(() => parseAuditJson("not json", "full npm audit"), /could not be parsed as JSON/);
  });

  it("rejects a stale exception after upstream remediation", async () => {
    const { evaluateAuditReports } = await loadAuditModule();
    const result = evaluateAuditReports({
      productionAudit: cleanAudit(),
      fullAudit: cleanAudit(),
      policy: basePolicy(),
      lockfile: baseLockfile(),
      now: new Date("2026-07-26T12:00:00.000Z"),
    });

    assert.equal(result.ok, false);
    assert.match(result.output, /exception is stale/);
  });
});

async function loadAuditModule(): Promise<AuditModule> {
  return (await import(moduleUrl)) as AuditModule;
}

function cleanAudit(): AuditReport {
  return {
    auditReportVersion: 2,
    vulnerabilities: {},
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
  };
}

function approvedAudit(): AuditReport {
  return {
    auditReportVersion: 2,
    vulnerabilities: {
      "brace-expansion": vulnerability("brace-expansion", "high", [braceExpansionAdvisory("high")], [
        "node_modules/brace-expansion",
        "node_modules/glob/node_modules/brace-expansion",
      ]),
      minimatch: vulnerability("minimatch", "high", ["brace-expansion"], ["node_modules/minimatch", "node_modules/glob/node_modules/minimatch"]),
      eslint: vulnerability("eslint", "high", ["minimatch"], ["node_modules/eslint"]),
      glob: vulnerability("glob", "high", ["minimatch"], ["node_modules/glob"]),
      "@cyclonedx/cyclonedx-npm": vulnerability("@cyclonedx/cyclonedx-npm", "high", ["glob"], ["node_modules/@cyclonedx/cyclonedx-npm"]),
    },
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 5, critical: 0, total: 5 } },
  };
}

function vulnerability(name: string, severity: string, via: Array<string | AuditAdvisory>, nodes: string[]): AuditVulnerability {
  return {
    name,
    severity,
    isDirect: false,
    via,
    effects: [],
    range: "",
    nodes,
    fixAvailable: false,
  };
}

function braceExpansionAdvisory(severity: string): AuditAdvisory {
  return {
    name: "brace-expansion",
    dependency: "brace-expansion",
    title: "brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash",
    url: advisoryUrl("GHSA-mh99-v99m-4gvg"),
    severity,
    range: "<=5.0.7",
  };
}

function postcssAdvisory(): AuditAdvisory {
  return {
    name: "postcss",
    dependency: "postcss",
    title: "PostCSS: Path Traversal in Previous Source Map Auto-Loading (sourceMappingURL) leads to Arbitrary .map File Disclosure",
    url: advisoryUrl("GHSA-r28c-9q8g-f849"),
    severity: "high",
    range: "<=8.5.17",
  };
}

function advisoryUrl(advisoryId: string): string {
  return `${advisoryOrigin}/advisories/${advisoryId}`;
}

function basePolicy(): AuditPolicy {
  return {
    exceptions: [
      {
        advisoryId: "GHSA-mh99-v99m-4gvg",
        advisoryUrl: advisoryUrl("GHSA-mh99-v99m-4gvg"),
        packageName: "brace-expansion",
        permittedVulnerableVersions: ["1.1.16", "2.1.2"],
        permittedNodePaths: ["node_modules/brace-expansion", "node_modules/glob/node_modules/brace-expansion"],
        permittedDependencyFamilies: [
          { name: "ESLint lint tooling", rootPackages: ["eslint", "eslint-plugin-jsx-a11y", "eslint-plugin-react-hooks", "typescript-eslint"] },
          { name: "CycloneDX SBOM tooling", rootPackages: ["@cyclonedx/cyclonedx-npm"] },
        ],
        devOnly: true,
        expires: "2026-08-26",
      },
    ],
  };
}

function baseLockfile(): Lockfile {
  return {
    packages: {
      "": {
        name: "nullid",
        version: "0.1.0",
        devDependencies: {
          eslint: "^9.39.4",
          "eslint-plugin-jsx-a11y": "^6.10.2",
          "@cyclonedx/cyclonedx-npm": "^5.0.0",
        },
      },
      "node_modules/eslint": { version: "9.39.4", dev: true, dependencies: { minimatch: "^3.1.5" } },
      "node_modules/eslint-plugin-jsx-a11y": { version: "6.10.2", dev: true, dependencies: { minimatch: "^3.1.5" } },
      "node_modules/minimatch": { version: "3.1.5", dev: true, dependencies: { "brace-expansion": "^1.1.7" } },
      "node_modules/brace-expansion": { version: "1.1.16", dev: true },
      "node_modules/@cyclonedx/cyclonedx-npm": { version: "5.0.0", dev: true, dependencies: { glob: "^10.5.0" } },
      "node_modules/glob": { version: "10.5.0", dev: true, optional: true, dependencies: { minimatch: "^9.0.4" } },
      "node_modules/glob/node_modules/minimatch": { version: "9.0.9", dev: true, optional: true, dependencies: { "brace-expansion": "^2.0.2" } },
      "node_modules/glob/node_modules/brace-expansion": { version: "2.1.2", dev: true, optional: true },
      "node_modules/postcss": { version: "8.5.23", dev: true },
    },
  };
}
