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

const bundleIcons = conf?.bundle?.icon;
if (!Array.isArray(bundleIcons) || bundleIcons.length === 0) {
  throw new Error("tauri.conf.json missing bundle.icon entries");
}
for (const iconEntry of bundleIcons) {
  if (typeof iconEntry !== "string" || !iconEntry.trim()) {
    throw new Error("tauri.conf.json contains invalid bundle.icon entry");
  }
  const iconPath = path.resolve(path.dirname(confPath), iconEntry);
  if (!fs.existsSync(iconPath) || !fs.statSync(iconPath).isFile()) {
    throw new Error(`bundle icon missing: ${path.relative(root, iconPath)}`);
  }
}

if (!skipCargo) {
  runCargoCheck(cargoPath);
}

const summary = {
  desktopRoot: path.relative(root, path.dirname(tauriRoot)),
  tauriConfig: path.relative(root, confPath),
  frontendDist: path.relative(root, frontendDistPath),
  cargoChecked: !skipCargo,
  runnerOs: process.platform,
  iconCount: bundleIcons.length,
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

function runCargoCheck(manifestPath) {
  const explicitCargo = process.env.CARGO;
  const commandCandidates = explicitCargo ? [explicitCargo] : ["cargo"];

  if (process.platform === "win32") {
    const windowsFallbacks = [];
    if (process.env.CARGO_HOME) {
      windowsFallbacks.push(path.join(process.env.CARGO_HOME, "bin", "cargo.exe"));
    }
    if (process.env.USERPROFILE) {
      windowsFallbacks.push(path.join(process.env.USERPROFILE, ".cargo", "bin", "cargo.exe"));
    }
    commandCandidates.push(...windowsFallbacks);
  }

  let lastError;
  for (const command of commandCandidates) {
    try {
      execFileSync(command, ["check", "--manifest-path", manifestPath], { stdio: "inherit" });
      return;
    } catch (error) {
      lastError = error;
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
        throw error;
      }
    }
  }

  throw new Error(
    `cargo not found in PATH (checked: ${commandCandidates.join(", ")}). Install Rust toolchain or run with --skip-cargo`,
  );
}
