import { test, expect, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

const shellModules = [
  { key: "hash", title: "Hash & Verify", marker: "Text to hash" },
  { key: "batch", title: "Batch Review", marker: "Batch review input" },
  { key: "share", title: "Safe Share", marker: "Safe Share overview" },
  { key: "incident", title: "Incident Workflow", marker: "Incident workflow overview" },
  { key: "secret", title: "Secret Scanner", marker: "Secret scanner input" },
  { key: "analyze", title: "Structured Analyzer", marker: "Structured analyzer input" },
  { key: "finance", title: "Financial Review", marker: "Financial review input" },
  { key: "paths", title: "Filename Privacy", marker: "Filename / path privacy input" },
  { key: "verify", title: "Verify Package", marker: "Verify package input" },
  { key: "redact", title: "Text Redaction", marker: "Redaction input" },
  { key: "sanitize", title: "Log Sanitizer", marker: "Sanitizer input" },
  { key: "meta", title: "Metadata Inspector", marker: "Metadata input" },
  { key: "enc", title: "Encrypt / Decrypt", marker: "Encrypt panel" },
  { key: "pw", title: "Password & Passphrase", marker: "Password generator" },
  { key: "vault", title: "Secure Notes", marker: "Vault controls" },
  { key: "selftest", title: "Self-test", marker: "Enable auto monitor" },
  { key: "guide", title: "Guide", marker: "Guide overview" },
] as const;

test("fresh production install precaches lazy modules and language chunks before offline use", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const failures: string[] = [];
  page.on("pageerror", (error) => failures.push(error.message));
  page.on("requestfailed", (request) => failures.push(`request failed: ${request.url()} ${request.failure()?.errorText ?? ""}`));
  page.on("console", (message) => {
    if (message.type() === "error") failures.push(message.text());
  });

  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:locale", "en");
    window.localStorage.setItem("nullid:last-module", "hash");
  });

  await page.goto("/");
  await waitForServiceWorkerControl(page);

  const cachedUrls = await page.evaluate(async () => {
    const cacheNames = await caches.keys();
    const appCacheName = cacheNames.find((name) => name.startsWith("nullid-cache-"));
    if (!appCacheName) return [];
    const cache = await caches.open(appCacheName);
    const requests = await cache.keys();
    return requests.map((request) => request.url);
  });
  const expectedRuntimeAssets = readExpectedRuntimeAssets();
  const missingRuntimeAssets = expectedRuntimeAssets.filter((asset) =>
    !cachedUrls.some((url) => new URL(url).pathname.endsWith(`/${asset}`)),
  );
  expect(missingRuntimeAssets).toEqual([]);

  await context.setOffline(true);

  for (const module of shellModules) {
    await page.locator(".frame-pane .module-button").filter({ hasText: `:${module.key}` }).click();
    await expect(ariaLabelInWorkspace(page, module.marker)).toBeVisible();
  }

  await page.locator(".action-row .header-locale-select").selectOption("fa");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await page.locator(".frame-pane .module-button").filter({ hasText: ":guide" }).click();
  await expect(page.locator(".workspace")).not.toBeEmpty();

  await page.locator(".action-row .header-locale-select").selectOption("ru");
  await expect(page.locator("html")).toHaveAttribute("lang", "ru-RU");
  await page.reload();
  await expect(page.locator(".workspace")).not.toBeEmpty();

  expect(failures.filter((failure) => /chunk|dynamic import|failed|unhandled|error/i.test(failure))).toEqual([]);
  await context.close();
});

async function waitForServiceWorkerControl(page: Page) {
  await page.evaluate(async () => {
    if (!("serviceWorker" in navigator)) {
      throw new Error("service workers are unavailable");
    }
    await navigator.serviceWorker.ready;
    if (navigator.serviceWorker.controller) return;
    await new Promise<void>((resolve) => {
      navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true });
    });
  });
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null);
}

function ariaLabelInWorkspace(page: Page, label: string) {
  return page.locator(".workspace").locator(`[aria-label=${JSON.stringify(label)}]`).first();
}

function readExpectedRuntimeAssets() {
  const manifestPath = path.resolve(process.cwd(), "dist/.vite/manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, {
    file?: string;
    css?: string[];
    assets?: string[];
  }>;
  const assets = new Set<string>();
  Object.values(manifest).forEach((entry) => {
    if (entry.file) assets.add(entry.file);
    entry.css?.forEach((asset) => assets.add(asset));
    entry.assets?.forEach((asset) => assets.add(asset));
  });
  return Array.from(assets).sort((left, right) => left.localeCompare(right));
}
