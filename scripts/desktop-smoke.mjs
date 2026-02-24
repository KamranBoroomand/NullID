#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const argv = process.argv.slice(2);
const root = process.cwd();
const tauriRoot = path.resolve(root, "desktop", "tauri", "src-tauri");
const confPath = path.join(tauriRoot, "tauri.conf.json");
const cargoPath = path.join(tauriRoot, "Cargo.toml");
const mainPath = path.join(tauriRoot, "src", "main.rs");
const skipCargo = hasFlag(argv, "--skip-cargo");

assertFile(confPath);
assertFile(cargoPath);
assertFile(mainPath);

const conf = JSON.parse(fs.readFileSync(confPath, "utf8"));
const frontendDist = conf?.build?.frontendDist;
if (typeof frontendDist !== "string" || !frontendDist.trim()) {
  throw new Error("tauri.conf.json missing build.frontendDist");
}

const frontendDistPath = path.resolve(path.dirname(confPath), frontendDist);
if (!fs.existsSync(frontendDistPath) || !fs.statSync(frontendDistPath).isDirectory()) {
  throw new Error(`frontendDist directory missing: ${path.relative(root, frontendDistPath)}`);
}

if (!skipCargo) {
  try {
    execFileSync("cargo", ["check", "--manifest-path", cargoPath], { stdio: "inherit" });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      throw new Error("cargo not found in PATH (install Rust toolchain or run with --skip-cargo)");
    }
    throw error;
  }
}

const summary = {
  desktopRoot: path.relative(root, path.dirname(tauriRoot)),
  tauriConfig: path.relative(root, confPath),
  frontendDist: path.relative(root, frontendDistPath),
  cargoChecked: !skipCargo,
  runnerOs: process.platform,
};

console.log(JSON.stringify(summary, null, 2));

function assertFile(filePath) {
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    throw new Error(`required file missing: ${path.relative(root, filePath)}`);
  }
}

function hasFlag(args, flag) {
  return args.includes(flag);
}
