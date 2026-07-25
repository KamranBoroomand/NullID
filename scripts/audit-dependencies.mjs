#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = process.cwd();
const DEFAULT_POLICY_PATH = path.join(ROOT, "security", "dependency-audit-policy.json");
const DEFAULT_LOCKFILE_PATH = path.join(ROOT, "package-lock.json");
const HIGH_OR_CRITICAL = new Set(["high", "critical"]);

export function parseAuditJson(raw, label = "npm audit") {
  try {
    return JSON.parse(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${label} output could not be parsed as JSON: ${detail}`);
  }
}

export function evaluateAuditReports({ productionAudit, fullAudit, policy, lockfile, now = new Date() }) {
  const messages = [];
  const accepted = [];
  const failures = [];
  const exceptions = Array.isArray(policy?.exceptions) ? policy.exceptions : [];
  const activeExceptions = exceptions.map(normalizeException);

  assertProductionAuditClean(productionAudit, failures);
  if (failures.length === 0) {
    messages.push("dependency audit: production tree clean");
  }

  const fullVulnerabilities = fullAudit?.vulnerabilities && typeof fullAudit.vulnerabilities === "object" ? fullAudit.vulnerabilities : {};
  const highOrCriticalEntries = Object.values(fullVulnerabilities).filter((entry) => HIGH_OR_CRITICAL.has(entry?.severity));
  const advisories = collectHighCriticalAdvisories(fullVulnerabilities);

  for (const exception of activeExceptions) {
    if (Date.parse(exception.expires) < startOfUtcDay(now).getTime()) {
      failures.push(`approved exception ${exception.advisoryId} expired on ${exception.expires}`);
    }
  }

  if (highOrCriticalEntries.length === 0) {
    if (activeExceptions.length > 0) {
      failures.push("dependency audit exception is stale: no high or critical advisory remains for the configured exception");
    } else if (failures.length === 0) {
      messages.push("dependency audit: no unapproved high or critical findings");
    }
    return finishResult({ ok: failures.length === 0, messages, failures, accepted });
  }

  for (const advisory of advisories) {
    const exception = activeExceptions.find((candidate) => candidate.advisoryUrl === advisory.url || candidate.advisoryId === advisory.id);
    if (!exception) {
      failures.push(`unapproved ${advisory.severity} advisory ${advisory.id || advisory.url || advisory.title}`);
      continue;
    }
    if (advisory.packageName !== exception.packageName) {
      failures.push(`advisory ${exception.advisoryId} affects ${advisory.packageName}, expected ${exception.packageName}`);
    }
    if (advisory.severity === "critical") {
      failures.push(`critical advisory ${exception.advisoryId} is not covered by the temporary exception`);
    }
  }

  for (const [name, vulnerability] of Object.entries(fullVulnerabilities)) {
    if (!HIGH_OR_CRITICAL.has(vulnerability?.severity)) continue;
    const advisoryChain = collectAdvisoriesForEntry(vulnerability, fullVulnerabilities);
    const exception = activeExceptions.find((candidate) =>
      advisoryChain.some((advisory) => advisory.url === candidate.advisoryUrl || advisory.id === candidate.advisoryId),
    );
    if (!exception) continue;

    validateVulnerabilityEntry({
      name,
      vulnerability,
      exception,
      lockfile,
      failures,
    });
  }

  for (const exception of activeExceptions) {
    const hasActiveAdvisory = advisories.some((advisory) => advisory.advisoryUrl === exception.advisoryUrl || advisory.url === exception.advisoryUrl);
    const hasActiveId = advisories.some((advisory) => advisory.id === exception.advisoryId);
    if (!hasActiveAdvisory && !hasActiveId) {
      failures.push(`dependency audit exception is stale: ${exception.advisoryId} is no longer reported at high or critical severity`);
    }
  }

  if (failures.length === 0) {
    for (const exception of activeExceptions) {
      accepted.push({
        advisoryId: exception.advisoryId,
        packageName: exception.packageName,
        nodes: exception.permittedNodePaths,
      });
      messages.push(`dependency audit: approved temporary dev-tool exception ${exception.advisoryId}`);
    }
    messages.push("dependency audit: no unapproved high or critical findings");
  }

  return finishResult({ ok: failures.length === 0, messages, failures, accepted });
}

function validateVulnerabilityEntry({ name, vulnerability, exception, lockfile, failures }) {
  const nodes = Array.isArray(vulnerability.nodes) ? vulnerability.nodes.filter(Boolean) : [];
  if (nodes.length === 0) {
    failures.push(`vulnerability entry ${name} has no concrete npm lockfile nodes`);
    return;
  }

  for (const nodePath of nodes) {
    const node = lockfile?.packages?.[nodePath];
    if (!node) {
      failures.push(`vulnerability entry ${name} references missing lockfile node ${nodePath}`);
      continue;
    }
    if (exception.devOnly && node.dev !== true) {
      failures.push(`approved advisory ${exception.advisoryId} reached non-dev node ${nodePath}`);
    }

    const chains = findDependencyChains(lockfile, nodePath);
    if (chains.length === 0) {
      failures.push(`approved advisory ${exception.advisoryId} has no dependency path to ${nodePath}`);
      continue;
    }
    const disallowedChains = chains.filter((chain) => !chainBelongsToPermittedFamily(chain, exception));
    if (disallowedChains.length > 0) {
      failures.push(`approved advisory ${exception.advisoryId} reached disallowed dependency path: ${formatChain(disallowedChains[0], lockfile)}`);
    }
  }

  if (name === exception.packageName) {
    for (const nodePath of nodes) {
      const node = lockfile?.packages?.[nodePath];
      if (!exception.permittedNodePaths.includes(nodePath)) {
        failures.push(`approved advisory ${exception.advisoryId} reached unapproved vulnerable node ${nodePath}`);
      }
      if (!exception.permittedVulnerableVersions.includes(node?.version)) {
        failures.push(`approved advisory ${exception.advisoryId} found ${nodePath}@${node?.version}, expected one of ${exception.permittedVulnerableVersions.join(", ")}`);
      }
    }
  }
}

function assertProductionAuditClean(productionAudit, failures) {
  const vulnerabilities = productionAudit?.vulnerabilities && typeof productionAudit.vulnerabilities === "object" ? productionAudit.vulnerabilities : {};
  const entries = Object.values(vulnerabilities).filter((entry) => HIGH_OR_CRITICAL.has(entry?.severity));
  const metadata = productionAudit?.metadata?.vulnerabilities ?? {};
  const count = Number(metadata.high ?? 0) + Number(metadata.critical ?? 0);
  if (entries.length > 0 || count > 0) {
    failures.push(`production dependency audit found ${entries.length || count} high or critical vulnerability entries`);
  }
}

function collectHighCriticalAdvisories(vulnerabilities) {
  const seen = new Map();
  for (const vulnerability of Object.values(vulnerabilities)) {
    if (!HIGH_OR_CRITICAL.has(vulnerability?.severity)) continue;
    for (const advisory of collectAdvisoriesForEntry(vulnerability, vulnerabilities)) {
      const key = advisory.url || advisory.id || advisory.title;
      if (!seen.has(key)) seen.set(key, advisory);
    }
  }
  return [...seen.values()];
}

function collectAdvisoriesForEntry(entry, vulnerabilities, stack = new Set()) {
  const advisories = [];
  for (const via of Array.isArray(entry?.via) ? entry.via : []) {
    if (typeof via === "string") {
      if (stack.has(via)) continue;
      stack.add(via);
      const child = vulnerabilities[via];
      if (child) advisories.push(...collectAdvisoriesForEntry(child, vulnerabilities, stack));
      continue;
    }
    advisories.push({
      id: advisoryIdFromUrl(via.url),
      title: via.title,
      url: via.url,
      severity: via.severity,
      packageName: via.dependency || via.name,
      range: via.range,
    });
  }
  return advisories;
}

function findDependencyChains(lockfile, targetPath) {
  const packages = lockfile?.packages ?? {};
  const edges = new Map();
  for (const packagePath of Object.keys(packages)) {
    edges.set(packagePath, dependencyNames(packages[packagePath]).map((name) => resolveDependency(packages, packagePath, name)).filter(Boolean));
  }

  const chains = [];
  const stack = [{ path: "", chain: [""], seen: new Set([""]) }];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const next of edges.get(current.path) ?? []) {
      const chain = [...current.chain, next];
      if (next === targetPath) chains.push(chain);
      if (!current.seen.has(next) && chain.length < 16) {
        const seen = new Set(current.seen);
        seen.add(next);
        stack.push({ path: next, chain, seen });
      }
    }
  }
  return chains;
}

function dependencyNames(node) {
  return Object.keys({
    ...(node?.dependencies ?? {}),
    ...(node?.devDependencies ?? {}),
    ...(node?.optionalDependencies ?? {}),
    ...(node?.peerDependencies ?? {}),
  });
}

function resolveDependency(packages, fromPath, dependencyName) {
  const candidates = [];
  if (fromPath) candidates.push(`${fromPath}/node_modules/${dependencyName}`);
  for (const base of ancestorPackagePaths(fromPath)) {
    candidates.push(base ? `${base}/node_modules/${dependencyName}` : `node_modules/${dependencyName}`);
  }
  return candidates.find((candidate) => packages[candidate]);
}

function ancestorPackagePaths(packagePath) {
  const paths = [];
  let current = packagePath;
  while (true) {
    paths.push(current);
    const index = current.lastIndexOf("/node_modules/");
    if (index < 0) {
      paths.push("");
      break;
    }
    current = current.slice(0, index);
    if (!current) {
      paths.push("");
      break;
    }
  }
  return paths;
}

function chainBelongsToPermittedFamily(chain, exception) {
  const rootPath = chain[1];
  const rootPackageName = packageNameFromPath(rootPath);
  return exception.permittedDependencyFamilies.some((family) => family.rootPackages.includes(rootPackageName));
}

function formatChain(chain, lockfile) {
  return chain.map((nodePath) => {
    const node = lockfile?.packages?.[nodePath];
    const name = nodePath === "" ? lockfile.packages[""].name : packageNameFromPath(nodePath);
    return `${name}@${node?.version ?? lockfile.packages[""].version}`;
  }).join(" > ");
}

function packageNameFromPath(packagePath) {
  if (!packagePath) return "";
  const marker = "node_modules/";
  const index = packagePath.lastIndexOf(marker);
  const tail = packagePath.slice(index + marker.length);
  const segments = tail.split("/");
  return segments[0].startsWith("@") ? `${segments[0]}/${segments[1]}` : segments[0];
}

function normalizeException(exception) {
  return {
    advisoryId: String(exception.advisoryId),
    advisoryUrl: String(exception.advisoryUrl),
    packageName: String(exception.packageName),
    permittedVulnerableVersions: arrayOfStrings(exception.permittedVulnerableVersions),
    permittedNodePaths: arrayOfStrings(exception.permittedNodePaths),
    permittedDependencyFamilies: Array.isArray(exception.permittedDependencyFamilies)
      ? exception.permittedDependencyFamilies.map((family) => ({
          name: String(family.name),
          rootPackages: arrayOfStrings(family.rootPackages),
        }))
      : [],
    devOnly: exception.devOnly === true,
    expires: String(exception.expires),
  };
}

function arrayOfStrings(value) {
  return Array.isArray(value) ? value.map(String) : [];
}

function advisoryIdFromUrl(url) {
  const match = String(url ?? "").match(/GHSA-[a-z0-9-]+/iu);
  return match?.[0] ?? "";
}

function startOfUtcDay(date) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function finishResult(result) {
  return {
    ...result,
    output: [...result.messages, ...result.failures.map((failure) => `dependency audit: ${failure}`)].join("\n"),
  };
}

function runNpmAudit(args) {
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  try {
    const stdout = execFileSync(npmCommand, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: process.env });
    return { status: 0, stdout };
  } catch (error) {
    const stdout = typeof error.stdout === "string" ? error.stdout : Buffer.isBuffer(error.stdout) ? error.stdout.toString("utf8") : "";
    const stderr = typeof error.stderr === "string" ? error.stderr : Buffer.isBuffer(error.stderr) ? error.stderr.toString("utf8") : "";
    return {
      status: typeof error.status === "number" ? error.status : 1,
      stdout,
      stderr,
    };
  }
}

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function main() {
  const policy = loadJson(DEFAULT_POLICY_PATH);
  const lockfile = loadJson(DEFAULT_LOCKFILE_PATH);

  const productionRun = runNpmAudit(["audit", "--omit=dev", "--omit=optional", "--audit-level=high", "--json"]);
  if (productionRun.status !== 0) {
    throw new Error(`production npm audit command failed with status ${productionRun.status}`);
  }
  const productionAudit = parseAuditJson(productionRun.stdout, "production npm audit");

  const fullRun = runNpmAudit(["audit", "--json"]);
  if (![0, 1].includes(fullRun.status)) {
    throw new Error(`full npm audit command failed with status ${fullRun.status}`);
  }
  const fullAudit = parseAuditJson(fullRun.stdout, "full npm audit");

  const result = evaluateAuditReports({ productionAudit, fullAudit, policy, lockfile });
  if (result.output) console.log(result.output);
  if (!result.ok) process.exitCode = 1;
}

const entryPoint = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : "";
if (import.meta.url === entryPoint || fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`dependency audit: ${message}`);
    process.exitCode = 1;
  }
}
