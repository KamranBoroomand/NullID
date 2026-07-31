#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const outputArg = process.argv[2] || "dist/sbom.json";
const outputPath = path.resolve(outputArg);
const require = createRequire(import.meta.url);
const CYCLONEDX_PACKAGE_NAME = "@cyclonedx/cyclonedx-npm";
const cyclonedxCliPath = resolveCycloneDxCliPath();

fs.mkdirSync(path.dirname(outputPath), { recursive: true });

execFileSync(
  process.execPath,
  [
    cyclonedxCliPath,
    "package.json",
    "--package-lock-only",
    "--output-reproducible",
    "--validate",
    "--spec-version",
    "1.6",
    "--output-format",
    "JSON",
    "--output-file",
    outputPath,
  ],
  { stdio: "inherit" },
);

const sbom = JSON.parse(fs.readFileSync(outputPath, "utf8"));
if (sbom.bomFormat !== "CycloneDX" || typeof sbom.specVersion !== "string" || !Array.isArray(sbom.components)) {
  console.error("[sbom] output file is not a CycloneDX JSON SBOM");
  process.exit(1);
}
for (const component of sbom.components) {
  if (typeof component.name !== "string" || component.name.includes("/node_modules/")) {
    console.error(`[sbom] invalid component name: ${String(component.name)}`);
    process.exit(1);
  }
}

console.log(`[sbom] wrote CycloneDX ${sbom.specVersion} SBOM with ${sbom.components.length} components to ${path.relative(process.cwd(), outputPath)}`);

function resolveCycloneDxCliPath() {
  const { packageDir, packageJson } = resolveCycloneDxPackage();
  const binEntry = packageJson?.bin?.["cyclonedx-npm"];
  if (typeof binEntry !== "string" || binEntry.length === 0 || path.isAbsolute(binEntry)) {
    fail("@cyclonedx/cyclonedx-npm bin.cyclonedx-npm is missing or malformed");
  }

  const cliPath = path.resolve(packageDir, binEntry);
  const relativeCliPath = path.relative(packageDir, cliPath);
  if (relativeCliPath.startsWith("..") || path.isAbsolute(relativeCliPath)) {
    fail("@cyclonedx/cyclonedx-npm CLI entrypoint escapes the package directory");
  }
  if (!fs.existsSync(cliPath)) {
    fail("@cyclonedx/cyclonedx-npm CLI entrypoint does not exist");
  }

  return cliPath;
}

function resolveCycloneDxPackage() {
  let entryPath;
  try {
    entryPath = require.resolve(CYCLONEDX_PACKAGE_NAME);
  } catch {
    fail("could not resolve @cyclonedx/cyclonedx-npm");
  }

  let directory = path.dirname(entryPath);
  while (true) {
    const packageJsonPath = path.join(directory, "package.json");
    if (fs.existsSync(packageJsonPath)) {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
      if (packageJson?.name === CYCLONEDX_PACKAGE_NAME) {
        return { packageDir: directory, packageJson };
      }
    }

    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }

  fail("could not resolve @cyclonedx/cyclonedx-npm/package.json");
}

function fail(message) {
  console.error(`[sbom] ${message}`);
  process.exit(1);
}
