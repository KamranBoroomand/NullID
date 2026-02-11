#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const lockfilePath = path.resolve("package-lock.json");
const outputArg = process.argv[2] || "dist/sbom.json";
const outputPath = path.resolve(outputArg);

if (!fs.existsSync(lockfilePath)) {
  console.error(`[sbom] package-lock.json not found at ${lockfilePath}`);
  process.exit(1);
}

const lockfile = JSON.parse(fs.readFileSync(lockfilePath, "utf8"));
const packages = lockfile.packages && typeof lockfile.packages === "object" ? lockfile.packages : {};

const components = Object.entries(packages)
  .filter(([key]) => key.startsWith("node_modules/"))
  .map(([key, value]) => {
    const name = key.replace(/^node_modules\//, "");
    return {
      name,
      version: value.version || "0.0.0",
      resolved: value.resolved || null,
      integrity: value.integrity || null,
      license: value.license || null,
      dev: Boolean(value.dev),
    };
  })
  .sort((a, b) => a.name.localeCompare(b.name));

const sbom = {
  schemaVersion: 1,
  format: "nullid-sbom",
  packageManager: "npm",
  lockfileVersion: lockfile.lockfileVersion || null,
  root: {
    name: lockfile.name || "nullid",
    version: lockfile.version || "0.0.0",
  },
  componentCount: components.length,
  components,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(sbom, null, 2)}\n`, "utf8");
console.log(`[sbom] wrote ${components.length} components to ${path.relative(process.cwd(), outputPath)}`);
