import type { PlaywrightTestConfig } from "@playwright/test";

const host = process.env.NULLID_E2E_HOST || "127.0.0.1";
const port = Number.parseInt(process.env.NULLID_E2E_PORT || "", 10) || 4173;
const baseURL = `http://${host}:${port}`;

const config: PlaywrightTestConfig = {
  timeout: 60_000,
  workers: process.env.CI ? 1 : undefined,
  use: {
    baseURL,
    viewport: { width: 1280, height: 800 },
  },
  webServer: {
    command: `npm run dev -- --host ${host} --port ${port} --strictPort`,
    port,
    reuseExistingServer: process.env.PW_REUSE_SERVER === "1",
    timeout: 60_000,
  },
  testDir: "tests/e2e",
};

export default config;
