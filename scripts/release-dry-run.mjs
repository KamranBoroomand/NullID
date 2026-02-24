#!/usr/bin/env node
import { execFileSync } from "node:child_process";

const forwarded = process.argv.slice(2);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

runNpm(["run", "release:bundle", ...(forwarded.length > 0 ? ["--", ...forwarded] : [])]);
runNpm(["run", "release:verify"]);

console.log("[release] dry-run checks passed");

function runNpm(args) {
  execFileSync(npmCommand, args, {
    stdio: "inherit",
    env: process.env,
  });
}
