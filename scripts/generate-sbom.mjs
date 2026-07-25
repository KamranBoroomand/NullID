#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const outputArg = process.argv[2] || "dist/sbom.json";
const outputPath = path.resolve(outputArg);
const command = process.platform === "win32" ? "cyclonedx-npm.cmd" : "cyclonedx-npm";

fs.mkdirSync(path.dirname(outputPath), { recursive: true });

execFileSync(
  command,
  [
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
