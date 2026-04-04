#!/usr/bin/env node
import net from "node:net";
import { execFileSync } from "node:child_process";

const forwardedArgs = process.argv.slice(2);
const npmCommand = process.platform === "win32" ? "npx.cmd" : "npx";
const env = { ...process.env };

if (!env.NULLID_E2E_HOST) {
  env.NULLID_E2E_HOST = "127.0.0.1";
}

if (!env.PLAYWRIGHT_BASE_URL && !env.NULLID_E2E_PORT) {
  env.NULLID_E2E_PORT = String(await findFreePort(env.NULLID_E2E_HOST));
}

const hasProjectArg = forwardedArgs.some((arg) => arg === "--project" || arg.startsWith("--project="));
const args = [
  "playwright",
  "test",
  ...forwardedArgs,
  ...(hasProjectArg ? [] : ["--project=chromium"]),
];

try {
  execFileSync(npmCommand, args, {
    stdio: "inherit",
    env,
  });
} catch (error) {
  if (missingBrowserError(error)) {
    console.error("[e2e] Playwright Chromium is not installed. Run `npx playwright install --with-deps chromium` first.");
  }
  process.exit(error && typeof error === "object" && "status" in error && typeof error.status === "number" ? error.status : 1);
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

function missingBrowserError(error) {
  const text = error instanceof Error ? error.message : String(error);
  return /browser.+executable.+doesn'?t exist|playwright install/i.test(text);
}
