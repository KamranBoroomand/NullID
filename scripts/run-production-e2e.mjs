#!/usr/bin/env node
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const args = process.argv.slice(2);
const suite = readOption("--suite") || "all";
const bases = readOptions("--base");
const basePaths = bases.length > 0 ? bases : ["/"];
const playwrightCommand = path.join(rootDir, "node_modules", ".bin", process.platform === "win32" ? "playwright.cmd" : "playwright");

if (!["all", "offline", "upgrade"].includes(suite)) {
  throw new Error(`Unsupported production E2E suite: ${suite}`);
}
if (!fs.existsSync(playwrightCommand)) {
  throw new Error("Playwright is not installed locally. Run `npm ci` first.");
}

for (const basePath of basePaths) {
  const normalizedBase = normalizeBasePath(basePath);
  const port = await findFreePort("127.0.0.1");
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-production-e2e-"));
  try {
    const versionADir = buildFixture(tempRoot, "version-a", normalizedBase, false);
    const versionBDir = suite === "offline" ? versionADir : buildFixture(tempRoot, "version-b", normalizedBase, true);
    execFileSync(
      playwrightCommand,
      ["test", "tests/e2e/production-pwa.spec.ts", "--project=chromium"],
      {
        cwd: rootDir,
        stdio: "inherit",
        env: {
          ...process.env,
          PLAYWRIGHT_SKIP_WEB_SERVER: "1",
          PLAYWRIGHT_BASE_URL: `http://127.0.0.1:${port}${normalizedBase}`,
          NULLID_PROD_E2E_PORT: String(port),
          NULLID_PROD_E2E_BASE: normalizedBase,
          NULLID_PROD_E2E_VERSION_A: versionADir,
          NULLID_PROD_E2E_VERSION_B: versionBDir,
          NULLID_PROD_E2E_SUITE: suite,
        },
      },
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

function buildFixture(tempRoot, label, basePath, mutateRuntime) {
  const workDir = path.join(tempRoot, `${label}-work`);
  fs.mkdirSync(workDir, { recursive: true });
  for (const entry of ["src", "public", "scripts"]) {
    fs.cpSync(path.join(rootDir, entry), path.join(workDir, entry), { recursive: true });
  }
  for (const file of ["index.html", "package.json", "package-lock.json", "tsconfig.json", "tsconfig.app.json", "tsconfig.node.json", "vite.config.ts"]) {
    fs.copyFileSync(path.join(rootDir, file), path.join(workDir, file));
  }
  fs.symlinkSync(path.join(rootDir, "node_modules"), path.join(workDir, "node_modules"), "dir");

  if (mutateRuntime) {
    const guideViewPath = path.join(workDir, "src", "views", "GuideView.tsx");
    const source = fs.readFileSync(guideViewPath, "utf8");
    fs.writeFileSync(guideViewPath, source.replaceAll("Guide overview", "Guide overview upgrade"), "utf8");
  }

  execFileSync("npm", ["run", "build"], {
    cwd: workDir,
    stdio: "inherit",
    env: {
      ...process.env,
      VITE_BASE: basePath,
      VITE_BUILD_ID: `production-e2e-${label}`,
      SOURCE_DATE_EPOCH: "1735689600",
    },
  });
  return path.join(workDir, "dist");
}

function readOption(name) {
  const index = args.indexOf(name);
  if (index === -1) return null;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
  return value;
}

function readOptions(name) {
  const values = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] !== name) continue;
    const value = args[i + 1];
    if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
    values.push(value);
    i += 1;
  }
  return values;
}

function normalizeBasePath(value) {
  const trimmed = String(value || "/").trim();
  const withLeading = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeading.endsWith("/") ? withLeading : `${withLeading}/`;
}

function findFreePort(host) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("could not resolve a local test port")));
        return;
      }
      const { port } = address;
      server.close((closeError) => {
        if (closeError) reject(closeError);
        else resolve(port);
      });
    });
  });
}
