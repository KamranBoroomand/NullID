import { defineConfig } from "@playwright/test";

const host = process.env.NULLID_E2E_HOST || "127.0.0.1";
const port = Number.parseInt(process.env.NULLID_E2E_PORT || "", 10) || 4173;
const externalBaseURL = process.env.PLAYWRIGHT_BASE_URL?.trim() || "";
const baseURL = externalBaseURL || `http://${host}:${port}`;
const skipWebServer = process.env.PLAYWRIGHT_SKIP_WEB_SERVER === "1" || Boolean(externalBaseURL);

export default defineConfig({
  timeout: 60_000,
  retries: 0,
  workers: process.env.CI ? 1 : undefined,
  // Keep snapshot filenames stable across the standard Chromium-only setup so
  // the checked-in baselines match both local and CI runs.
  snapshotPathTemplate: "{testDir}/{testFilePath}-snapshots/{arg}-{platform}{ext}",
  use: {
    baseURL,
    viewport: { width: 1280, height: 800 },
  },
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
      },
    },
  ],
  webServer: skipWebServer ? undefined : {
    command: `npm run dev -- --host ${host} --port ${port} --strictPort`,
    port,
    reuseExistingServer: process.env.PW_REUSE_SERVER === "1" || !process.env.CI,
    timeout: 60_000,
  },
  testDir: "tests/e2e",
});
