#!/usr/bin/env node
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const forwardedArgs = process.argv.slice(2);
const env = { ...process.env };
const rootDir = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const playwrightCommand = resolveLocalPlaywrightCommand();

if (!env.NULLID_E2E_HOST) {
  env.NULLID_E2E_HOST = "127.0.0.1";
}

validatePort(env.NULLID_E2E_PORT);
await configureBaseUrl(env);
await verifyLocalPlaywrightInstall(playwrightCommand);
await verifyExternalBaseUrl(env.PLAYWRIGHT_BASE_URL);

const hasProjectArg = forwardedArgs.some((arg) => arg === "--project" || arg.startsWith("--project="));
const args = [
  "test",
  ...forwardedArgs,
  ...(hasProjectArg ? [] : ["--project=chromium"]),
];

try {
  execFileSync(playwrightCommand, args, {
    stdio: "inherit",
    env,
  });
} catch (error) {
  process.exit(error && typeof error === "object" && "status" in error && typeof error.status === "number" ? error.status : 1);
}

async function configureBaseUrl(targetEnv) {
  if (targetEnv.PLAYWRIGHT_BASE_URL?.trim()) {
    targetEnv.PLAYWRIGHT_BASE_URL = targetEnv.PLAYWRIGHT_BASE_URL.trim();
    return;
  }

  if (!targetEnv.NULLID_E2E_PORT) {
    targetEnv.NULLID_E2E_PORT = String(await findFreePort(targetEnv.NULLID_E2E_HOST));
  }
}

function resolveLocalPlaywrightCommand() {
  const executable = process.platform === "win32" ? "playwright.cmd" : "playwright";
  const command = path.join(rootDir, "node_modules", ".bin", executable);
  if (!fs.existsSync(command)) {
    failPreflight("Playwright is not installed locally. Run `npm ci` before `npm run e2e`.");
  }
  return command;
}

async function verifyLocalPlaywrightInstall(command) {
  try {
    execFileSync(command, ["--version"], { stdio: "ignore" });
  } catch {
    failPreflight("The local Playwright CLI could not start. Run `npm ci` and retry.");
  }

  let chromium;
  try {
    ({ chromium } = await import("@playwright/test"));
  } catch {
    failPreflight("@playwright/test is not installed locally. Run `npm ci` before `npm run e2e`.");
  }

  const executablePath = chromium.executablePath();
  if (!fs.existsSync(executablePath)) {
    failPreflight("Playwright Chromium is not installed for the pinned package. Run `npm run e2e:install` first.");
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (error) {
    const detail = error instanceof Error && error.message ? ` ${error.message.split("\n")[0]}` : "";
    failPreflight(`Playwright Chromium is installed but could not launch in this environment.${detail}`);
  } finally {
    await browser?.close().catch(() => undefined);
  }
}

async function verifyExternalBaseUrl(value) {
  if (!value) return;
  let url;
  try {
    url = new URL(value);
  } catch {
    failPreflight("PLAYWRIGHT_BASE_URL must be an absolute http(s) URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    failPreflight("PLAYWRIGHT_BASE_URL must use http or https.");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, { method: "GET", signal: controller.signal });
    if (!response.ok) {
      failPreflight(`PLAYWRIGHT_BASE_URL returned HTTP ${response.status}: ${url.toString()}`);
    }
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      failPreflight(`PLAYWRIGHT_BASE_URL did not respond within 5s: ${url.toString()}`);
    }
    failPreflight(`PLAYWRIGHT_BASE_URL is not reachable: ${url.toString()}`);
  } finally {
    clearTimeout(timer);
  }
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
        if (closeError) {
          reject(closeError);
          return;
        }
        resolve(port);
      });
    });
  });
}

function validatePort(value) {
  if (!value) return;
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535 || String(port) !== value) {
    failPreflight("NULLID_E2E_PORT must be an integer between 1 and 65535.");
  }
}

function failPreflight(message) {
  console.error(`[e2e] ${message}`);
  process.exit(1);
}
