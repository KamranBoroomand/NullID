import type { PlaywrightTestConfig } from "@playwright/test";

const config: PlaywrightTestConfig = {
  timeout: 60_000,
  use: {
    baseURL: "http://127.0.0.1:4173",
    viewport: { width: 1280, height: 800 },
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 4173 --strictPort",
    port: 4173,
    reuseExistingServer: process.env.PW_REUSE_SERVER === "1",
    timeout: 60_000,
  },
  testDir: "tests/e2e",
};

export default config;
