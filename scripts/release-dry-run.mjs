#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const forwarded = process.argv.slice(2);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

for (const dir of ["dist", "release"]) {
  fs.rmSync(path.resolve(dir), { recursive: true, force: true });
}

runNpm(["ci"]);
runNpm(["run", "audit:deps"]);
runNpm(["run", "validate"]);
runNpm(["run", "release:bundle", ...(forwarded.length > 0 ? ["--", ...forwarded] : [])]);
runNpm(["run", "release:verify"]);

console.log("[release] dry-run checks passed");

function runNpm(args) {
  execFileSync(npmCommand, args, {
    stdio: "inherit",
    env: process.env,
  });
}
