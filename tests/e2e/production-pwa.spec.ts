import { test, expect, type Page } from "@playwright/test";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const suite = process.env.NULLID_PROD_E2E_SUITE ?? "all";
const basePath = normalizeBasePath(process.env.NULLID_PROD_E2E_BASE ?? "/");
const port = Number.parseInt(process.env.NULLID_PROD_E2E_PORT ?? "", 10);
const versionADir = requiredEnv("NULLID_PROD_E2E_VERSION_A");
const versionBDir = requiredEnv("NULLID_PROD_E2E_VERSION_B");
const baseUrl = `http://127.0.0.1:${port}${basePath}`;

const shellModules = [
  { key: "hash", marker: "Text to hash" },
  { key: "batch", marker: "Batch review input" },
  { key: "share", marker: "Safe Share overview" },
  { key: "incident", marker: "Incident workflow overview" },
  { key: "secret", marker: "Secret scanner input" },
  { key: "analyze", marker: "Structured analyzer input" },
  { key: "finance", marker: "Financial review input" },
  { key: "paths", marker: "Filename / path privacy input" },
  { key: "verify", marker: "Verify package input" },
  { key: "redact", marker: "Redaction input" },
  { key: "sanitize", marker: "Sanitizer input" },
  { key: "meta", marker: "Metadata input" },
  { key: "enc", marker: "Encrypt panel" },
  { key: "pw", marker: "Password generator" },
  { key: "vault", marker: "Vault controls" },
  { key: "selftest", marker: "Enable auto monitor" },
  { key: "guide", marker: "Guide overview" },
] as const;

const publicPageChecks = [
  { route: "/tools/", h1: "Local-first privacy and security tools" },
  { route: "/offline-file-encryption/", h1: "Offline file encryption in your browser" },
  { route: "/metadata-privacy/", h1: "Metadata privacy before sharing files" },
  { route: "/local-redaction/", h1: "Redact sensitive information locally" },
  { route: "/file-sanitization/", h1: "Local file sanitization for logs and text" },
  { route: "/hash-and-verify/", h1: "Hash and verify files locally" },
  { route: "/secret-scanner/", h1: "Scan likely secrets before sharing" },
  { route: "/password-generator/", h1: "Generate passwords and passphrases locally" },
  { route: "/safe-share/", h1: "Prepare sensitive material before sharing" },
  { route: "/package-verification/", h1: "Verify NullID packages honestly" },
  { route: "/privacy/", h1: "Privacy Policy" },
  { route: "/faq/", h1: "NullID FAQ" },
] as const;

const publicPageViewports = [
  { label: "mobile", width: 390, height: 844 },
  { label: "short desktop", width: 1366, height: 700 },
  { label: "visual desktop", width: 1366, height: 900 },
] as const;

let activeVersion: "a" | "b" | "mixed-index" = "a";
let server: http.Server;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  server = http.createServer((request, response) => {
    serveStatic(request, response);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve());
  });
});

test.afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

(suite === "all" || suite === "offline" ? test : test.skip)(
  "fresh production install precaches lazy modules and language chunks before offline use",
  async ({ browser }) => {
    activeVersion = "a";
    const context = await browser.newContext();
    const page = await context.newPage();
    const failures = collectRuntimeFailures(page);
    await seedLocalState(page);

    await page.goto(baseUrl);
    await waitForServiceWorkerControl(page);
    await expectRuntimeAssetsCached(page, versionADir);

    await context.setOffline(true);
    for (const module of shellModules) {
      await page.locator(".frame-pane .module-button").filter({ hasText: `:${module.key}` }).click();
      await expect(ariaLabelInWorkspace(page, module.marker)).toBeVisible();
    }

    await page.locator(".action-row .header-locale-select").selectOption("fa");
    await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
    await page.locator(".action-row .header-locale-select").selectOption("ru");
    await expect(page.locator("html")).toHaveAttribute("lang", "ru-RU");
    await page.reload();
    await expect(page.locator(".workspace")).not.toBeEmpty();

    expect(relevantRuntimeFailures(failures)).toEqual([]);
    await context.close();
  },
);

(suite === "all" || suite === "upgrade" ? test : test.skip)(
  "production service-worker rejects a manifest update paired with stale stable-name shell bytes",
  async ({ browser }) => {
    activeVersion = "a";
    const manifestB = readPrecacheManifest(versionBDir);

    const context = await browser.newContext();
    const page = await context.newPage();
    await seedLocalState(page);
    await page.goto(baseUrl);
    await waitForServiceWorkerControl(page);

    activeVersion = "mixed-index";
    await triggerServiceWorkerUpdate(page);
    await expectNoWaitingWorker(page);
    await expectOldCacheRemoved(page, cacheNameForManifest(manifestB, basePath));

    await context.close();
  },
);

(suite === "all" || suite === "offline" ? test : test.skip)(
  "production service worker leaves static pages and 404 navigations alone",
  async ({ browser }) => {
    activeVersion = "a";
    const context = await browser.newContext();
    const page = await context.newPage();
    const failures = collectRuntimeFailures(page);
    await seedLocalState(page);

    for (const viewport of publicPageViewports) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });

      await page.goto(baseUrl);
      await waitForServiceWorkerControl(page);
      await expect(page.locator(".workspace")).not.toBeEmpty();
      await expect(page.locator("h1")).toHaveCount(1);
      await expectNoHorizontalOverflow(page, `root app at ${viewport.label}`);

      for (const { route, h1 } of publicPageChecks) {
        const response = await page.goto(urlForRoute(route));
        expect(response?.status(), `${route} status at ${viewport.label}`).toBe(200);
        await expect(page.locator("h1")).toHaveCount(1);
        await expect(page.getByRole("heading", { name: h1, level: 1 })).toBeVisible();
        await expect(page.getByLabel("Public navigation").getByRole("link", { name: "Tools", exact: true })).toBeVisible();
        await expect(page.locator(".site-actions .site-button").first()).toBeVisible();
        await expect(page.locator(".workspace")).toHaveCount(0);
        await expectNoHorizontalOverflow(page, `${route} at ${viewport.label}`);
      }

      const missingResponse = await page.goto(urlForRoute("/missing-static-page/"));
      expect(missingResponse?.status(), `404 status at ${viewport.label}`).toBe(404);
      await expect(page.locator("h1")).toHaveCount(1);
      await expect(page.getByRole("heading", { name: "Page not found", level: 1 })).toBeVisible();
      await expect(page.locator(".workspace")).toHaveCount(0);
      await expectNoHorizontalOverflow(page, `404 at ${viewport.label}`);
    }

    expect(relevantRuntimeFailures(failures)).toEqual([]);
    await context.close();
  },
);

(suite === "all" || suite === "upgrade" ? test : test.skip)(
  "production service-worker upgrade keeps old clients coherent until reload",
  async ({ browser }) => {
    activeVersion = "a";
    const manifestA = readPrecacheManifest(versionADir);
    const manifestB = readPrecacheManifest(versionBDir);
    expect(manifestA.contentHash).not.toEqual(manifestB.contentHash);

    const contextA = await browser.newContext();
    const pageA = await contextA.newPage();
    const failures = collectRuntimeFailures(pageA);
    await seedLocalState(pageA);
    await pageA.goto(baseUrl);
    await waitForServiceWorkerControl(pageA);
    await expectCachePresent(pageA, cacheNameForManifest(manifestA, basePath));

    activeVersion = "b";
    await triggerServiceWorkerUpdate(pageA);
    await expectWaitingWorker(pageA);

    await contextA.setOffline(true);
    await pageA.locator(".frame-pane .module-button").filter({ hasText: ":guide" }).click();
    await expect(ariaLabelInWorkspace(pageA, "Guide overview")).toBeVisible();
    await pageA.reload();
    await expect(pageA.locator(".workspace")).not.toBeEmpty();
    expect(relevantRuntimeFailures(failures)).toEqual([]);
    await contextA.close();

    const contextB = await browser.newContext();
    const pageB = await contextB.newPage();
    await seedLocalState(pageB);
    await pageB.goto(baseUrl);
    await waitForServiceWorkerControl(pageB);
    await expectCachePresent(pageB, cacheNameForManifest(manifestB, basePath));
    await expectOldCacheRemoved(pageB, cacheNameForManifest(manifestA, basePath));
    await contextB.setOffline(true);
    await pageB.reload();
    await expect(pageB.locator(".workspace")).not.toBeEmpty();
    await contextB.close();
  },
);

(suite === "all" || suite === "upgrade" ? test : test.skip)(
  "old active worker keeps new online navigations on its coherent runtime while the update waits",
  async ({ browser }) => {
    activeVersion = "a";
    const manifestA = readPrecacheManifest(versionADir);
    const manifestB = readPrecacheManifest(versionBDir);
    const entryScriptA = entryScriptPath(versionADir);
    const entryScriptB = entryScriptPath(versionBDir);
    expect(manifestA.contentHash).not.toEqual(manifestB.contentHash);
    expect(entryScriptA).not.toEqual(entryScriptB);

    const contextA = await browser.newContext();
    const pageA = await contextA.newPage();
    const pageAFailures = collectRuntimeFailures(pageA);
    await seedLocalState(pageA);
    await pageA.goto(baseUrl);
    await waitForServiceWorkerControl(pageA);
    await expectCachePresent(pageA, cacheNameForManifest(manifestA, basePath));

    activeVersion = "b";
    await triggerServiceWorkerUpdate(pageA);
    await expectWaitingWorker(pageA);

    const coherentPage = await contextA.newPage();
    const coherentFailures = collectRuntimeFailures(coherentPage);
    const coherentRequests = collectRequestPaths(coherentPage);
    await seedLocalState(coherentPage);
    await coherentPage.goto(`${baseUrl}?coherent-old-worker=1`);
    await waitForServiceWorkerControl(coherentPage);
    await expect(coherentPage.locator(".workspace")).not.toBeEmpty();
    expect(coherentRequests).toContain(entryScriptA);
    expect(coherentRequests).not.toContain(entryScriptB);

    await coherentPage.locator(".frame-pane .module-button").filter({ hasText: ":guide" }).click();
    await expect(ariaLabelInWorkspace(coherentPage, "Guide overview")).toBeVisible();
    await contextA.setOffline(true);
    await coherentPage.reload();
    await expect(coherentPage.locator(".workspace")).not.toBeEmpty();
    expect(relevantRuntimeFailures([...pageAFailures, ...coherentFailures])).toEqual([]);
    await contextA.close();

    const contextB = await browser.newContext();
    const pageB = await contextB.newPage();
    const pageBFailures = collectRuntimeFailures(pageB);
    await seedLocalState(pageB);
    await pageB.goto(baseUrl);
    await waitForServiceWorkerControl(pageB);
    await expectCachePresent(pageB, cacheNameForManifest(manifestB, basePath));
    await expectOldCacheRemoved(pageB, cacheNameForManifest(manifestA, basePath));
    await contextB.setOffline(true);
    await pageB.reload();
    await expect(pageB.locator(".workspace")).not.toBeEmpty();
    expect(relevantRuntimeFailures(pageBFailures)).toEqual([]);
    await contextB.close();
  },
);

function serveStatic(request: http.IncomingMessage, response: http.ServerResponse) {
  const requestUrl = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  if (!requestUrl.pathname.startsWith(basePath)) {
    response.writeHead(404).end("outside base path");
    return;
  }
  let relativePath = decodeURIComponent(requestUrl.pathname.slice(basePath.length));
  if (!relativePath || relativePath.endsWith("/")) relativePath = `${relativePath}index.html`;
  const rootDir = rootDirForRequest(relativePath);
  const filePath = path.resolve(rootDir, relativePath);
  if (!filePath.startsWith(path.resolve(rootDir))) {
    response.writeHead(403).end("forbidden");
    return;
  }
  fs.readFile(filePath, (error, data) => {
    if (error) {
      const notFoundPath = path.join(rootDir, "404.html");
      fs.readFile(notFoundPath, (notFoundError, notFoundData) => {
        if (notFoundError) {
          response.writeHead(404, { "Cache-Control": "no-store" }).end("not found");
          return;
        }
        response.writeHead(404, {
          "Cache-Control": "no-store",
          "Content-Type": "text/html; charset=UTF-8",
        });
        response.end(notFoundData);
      });
      return;
    }
    response.writeHead(200, {
      "Cache-Control": "no-store, must-revalidate",
      "Content-Type": contentType(filePath),
      ...(relativePath === "sw.js" ? { "Service-Worker-Allowed": basePath } : {}),
    });
    response.end(data);
  });
}

function rootDirForRequest(relativePath: string) {
  if (activeVersion === "a") return versionADir;
  if (activeVersion === "mixed-index" && relativePath === "index.html") return versionADir;
  return versionBDir;
}

async function seedLocalState(page: Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem("nullid:onboarding-complete", "true");
    window.localStorage.setItem("nullid:onboarding-step", "0");
    window.localStorage.setItem("nullid:locale", "en");
    window.localStorage.setItem("nullid:last-module", "hash");
  });
}

async function waitForServiceWorkerControl(page: Page) {
  await page.evaluate(async () => {
    if (!("serviceWorker" in navigator)) throw new Error("service workers are unavailable");
    await navigator.serviceWorker.ready;
  });
  if (await page.evaluate(() => navigator.serviceWorker.controller !== null)) return;
  await page.reload();
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null);
}

async function triggerServiceWorkerUpdate(page: Page) {
  await page.evaluate(async () => {
    const registration = await navigator.serviceWorker.getRegistration();
    if (!registration) throw new Error("service worker registration missing");
    await registration.update();
  });
}

async function expectWaitingWorker(page: Page) {
  await expect.poll(
    () => page.evaluate(async () => Boolean((await navigator.serviceWorker.getRegistration())?.waiting)),
    { timeout: 15_000 },
  ).toBe(true);
}

async function expectNoWaitingWorker(page: Page) {
  await expect.poll(
    () => page.evaluate(async () => Boolean((await navigator.serviceWorker.getRegistration())?.waiting)),
    { timeout: 5_000 },
  ).toBe(false);
}

async function expectRuntimeAssetsCached(page: Page, distDir: string) {
  const manifest = readPrecacheManifest(distDir);
  const cachedUrls = await page.evaluate(async () => {
    const urls: string[] = [];
    for (const cacheName of await caches.keys()) {
      const cache = await caches.open(cacheName);
      const requests = await cache.keys();
      urls.push(...requests.map((request) => request.url));
    }
    return urls;
  });
  const missing = manifest.assets.filter((asset) => !cachedUrls.some((url) => new URL(url).pathname.endsWith(`/${asset}`)));
  expect(missing).toEqual([]);
}

async function expectCachePresent(page: Page, cacheName: string) {
  await expect.poll(() => page.evaluate(() => caches.keys()), { timeout: 15_000 }).toContain(cacheName);
}

async function expectOldCacheRemoved(page: Page, cacheName: string) {
  await expect.poll(() => page.evaluate(() => caches.keys()), { timeout: 15_000 }).not.toContain(cacheName);
}

function readPrecacheManifest(distDir: string): { contentHash: string; assets: string[]; cacheVersion: string } {
  const manifest = JSON.parse(fs.readFileSync(path.join(distDir, "nullid-precache-manifest.json"), "utf8")) as { contentHash: string; assets: string[] };
  return { ...manifest, cacheVersion: readServiceWorkerCacheVersion(distDir) };
}

function cacheNameForManifest(manifest: { cacheVersion: string }, scopePath: string) {
  return `nullid-cache-${cacheScopeKey(scopePath)}-${manifest.cacheVersion}`;
}

function readServiceWorkerCacheVersion(distDir: string) {
  const source = fs.readFileSync(path.join(distDir, "sw.js"), "utf8");
  const match = source.match(/const CACHE_VERSION = "([^"]+)"/u);
  if (!match) throw new Error(`Cannot read service-worker cache version from ${distDir}`);
  return match[1];
}

function cacheScopeKey(scopePath: string) {
  return `p-${encodeURIComponent(normalizeBasePath(scopePath))}`;
}

function ariaLabelInWorkspace(page: Page, label: string) {
  return page.locator(".workspace").locator(`[aria-label=${JSON.stringify(label)}]`).first();
}

function urlForRoute(route: string) {
  return `${baseUrl}${route.replace(/^\//u, "")}`;
}

async function expectNoHorizontalOverflow(page: Page, label: string) {
  const overflow = await page.evaluate(() =>
    Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - window.innerWidth,
  );
  expect(overflow, `${label} horizontal overflow`).toBeLessThanOrEqual(2);
}

function collectRuntimeFailures(page: Page) {
  const failures: string[] = [];
  page.on("pageerror", (error) => failures.push(error.message));
  page.on("requestfailed", (request) => failures.push(`request failed: ${request.url()} ${request.failure()?.errorText ?? ""}`));
  page.on("response", (response) => {
    if (response.status() >= 400 && response.request().resourceType() !== "document") {
      failures.push(`resource failed: ${response.status()} ${response.url()}`);
    }
  });
  page.on("console", (message) => {
    if (message.type() === "error" && !message.text().startsWith("Failed to load resource: the server responded with a status of 404")) {
      failures.push(message.text());
    }
  });
  return failures;
}

function collectRequestPaths(page: Page) {
  const paths: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin === `http://127.0.0.1:${port}`) {
      paths.push(url.pathname.slice(basePath.length - 1));
    }
  });
  return paths;
}

function relevantRuntimeFailures(failures: string[]) {
  return failures.filter((failure) => /chunk|dynamic import|failed|unhandled|error/i.test(failure));
}

function requiredEnv(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function normalizeBasePath(value: string) {
  const withLeading = value.startsWith("/") ? value : `/${value}`;
  return withLeading.endsWith("/") ? withLeading : `${withLeading}/`;
}

function entryScriptPath(distDir: string) {
  const html = fs.readFileSync(path.join(distDir, "index.html"), "utf8");
  const scriptSources = Array.from(html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/gu), (match) => match[1]);
  const entryScript = scriptSources.find((source) => /(^|\/)assets\/index-[^/"]+\.js$/u.test(source));
  if (!entryScript) throw new Error(`entry script missing from ${distDir}`);
  const entryPath = new URL(entryScript, `http://127.0.0.1:${port}${basePath}`).pathname;
  if (!entryPath.startsWith(basePath)) throw new Error(`entry script outside base path in ${distDir}`);
  return entryPath.slice(basePath.length - 1);
}

function contentType(filePath: string) {
  if (filePath.endsWith(".html")) return "text/html; charset=UTF-8";
  if (filePath.endsWith(".js")) return "text/javascript; charset=UTF-8";
  if (filePath.endsWith(".css")) return "text/css; charset=UTF-8";
  if (filePath.endsWith(".json") || filePath.endsWith(".webmanifest")) return "application/json; charset=UTF-8";
  if (filePath.endsWith(".svg")) return "image/svg+xml";
  if (filePath.endsWith(".png")) return "image/png";
  if (filePath.endsWith(".ico")) return "image/x-icon";
  return "application/octet-stream";
}
