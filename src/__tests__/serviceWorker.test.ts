import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs, { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";

type Listener = (event: unknown) => void;
type RequestInput = RequestLike | string;

interface RequestLike {
  url: string;
  method: string;
  mode: string;
  destination: string;
}

const TEST_ORIGIN = `${"https"}://nullid.test`;
const TEST_SCOPE = `${TEST_ORIGIN}/app/`;
const MAX_PRECACHE_ASSET_BYTES = 16 * 1024 * 1024;

describe("service worker cache writes", () => {
  it("does not intercept or cache requests outside the exact service-worker scope", async () => {
    const { listeners, fetchUrls, cachePutCalls } = loadServiceWorker();
    const requests: RequestLike[] = [
      { url: `${TEST_ORIGIN}/private/account.json`, method: "GET", mode: "same-origin", destination: "" },
      { url: `${TEST_ORIGIN}/private/app.js`, method: "GET", mode: "same-origin", destination: "script" },
      { url: `${TEST_ORIGIN}/api/account.json`, method: "GET", mode: "same-origin", destination: "" },
      { url: `${"https"}://cdn.nullid.test/app/assets/app.js`, method: "GET", mode: "cors", destination: "script" },
    ];

    for (const request of requests) {
      const result = dispatchFetchMaybe(listeners, request);
      assert.equal(result.responded, false, request.url);
    }
    assert.deepEqual(fetchUrls, []);
    assert.deepEqual(cachePutCalls, []);
  });

  it("does not cache unknown in-scope requests by default", async () => {
    const { listeners, fetchUrls, cachePutCalls } = loadServiceWorker();
    const staticResponse = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}assets/unlisted.js`,
      method: "GET",
      mode: "same-origin",
      destination: "script",
    });
    assert.equal(await staticResponse.text(), "network");
    assert.deepEqual(fetchUrls, [`${TEST_SCOPE}assets/unlisted.js`]);
    assert.deepEqual(cachePutCalls, []);

    for (const request of [
      { url: `${TEST_SCOPE}api/status`, method: "GET", mode: "same-origin", destination: "" },
      { url: `${TEST_SCOPE}data/account.json`, method: "GET", mode: "same-origin", destination: "" },
    ] satisfies RequestLike[]) {
      const result = dispatchFetchMaybe(listeners, request);
      assert.equal(result.responded, false, request.url);
    }
    assert.deepEqual(cachePutCalls, []);
  });

  it("serves manifest-listed runtime assets from the canonical cache entry for query and hash variants", async () => {
    const manifest = runtimeShellManifestFromAssets([{ path: "assets/app.js", body: "console.log('app')", required: true }]);
    const { listeners, fetchUrls, cachePutCalls } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
    });

    await dispatchLifecycle(listeners, "install");
    const putsBeforeFetch = [...cachePutCalls];
    const fetchesBeforeFetch = [...fetchUrls];

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}assets/app.js?cachebust=1#local`,
      method: "GET",
      mode: "same-origin",
      destination: "script",
    });

    assert.equal(await response.text(), "console.log('app')");
    assert.deepEqual(cachePutCalls, putsBeforeFetch);
    assert.deepEqual(fetchUrls, fetchesBeforeFetch);
    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/app.js?cachebust=1#local`), false);
  });

  it("awaits install cache writes before completing verified app-shell install", async () => {
    const cacheWrites: Array<Deferred<void>> = [];
    const manifest = runtimeShellManifestFromAssets([{ path: "assets/app.js", body: "console.log('app')", required: true }]);
    const { listeners } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
      onCachePut() {
        const deferred = createDeferred<void>();
        cacheWrites.push(deferred);
        return deferred.promise;
      },
    });

    const installPromise = dispatchLifecycle(listeners, "install");
    await assertPromisePending(installPromise, "install");
    await waitForCondition(() => cacheWrites.length === 1, "manifest cache write");
    cacheWrites[0].resolve();
    await assertPromisePending(installPromise, "install asset");
    await waitForCondition(() => cacheWrites.length === 2, "asset cache write");
    cacheWrites[1].resolve();
    await installPromise;
  });

  it("serves current-version navigation HTML instead of newer network HTML while controlled by the old worker", async () => {
    const cachedBodies = new Map<string, string>();
    const { listeners, cachePutCalls, fetchUrls } = loadServiceWorker({
      initialCacheEntries: [[`${TEST_SCOPE}index.html`, "INDEX-A"]],
      fetchResponse() {
        return Promise.resolve(new Response("INDEX-B", { status: 200, headers: { "Content-Type": "text/html" } }));
      },
      onCachePut(input, response) {
        return response.clone().text().then((body) => {
          cachedBodies.set(requestUrl(input), body);
        });
      },
    });

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}?tool=vault&note=1`,
      method: "GET",
      mode: "navigate",
      destination: "document",
    });

    assert.equal(await response.text(), "INDEX-A");
    assert.deepEqual(fetchUrls, []);
    assert.deepEqual(cachePutCalls, []);
    assert.equal(cachedBodies.get(`${TEST_SCOPE}?tool=vault&note=1`), undefined);
  });

  it("rejects network navigation fallback HTML that is not verified against the current worker manifest", async () => {
    const manifestA = runtimeShellManifestFromAssets([{ path: "index.html", body: "INDEX-A", required: true }]);
    const manifestB = runtimeShellManifestFromAssets([{ path: "index.html", body: "INDEX-B", required: true }]);
    const { listeners } = loadServiceWorker({
      runtimeShellHash: manifestA.contentHash,
      onCachesOpen() {
        throw new Error("cache unavailable");
      },
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifestB), { status: 200 }));
        }
        return Promise.resolve(new Response("INDEX-B", { status: 200, headers: { "Content-Type": "text/html" } }));
      },
    });

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}?tool=vault`,
      method: "GET",
      mode: "navigate",
      destination: "document",
    });

    assert.equal(response.status, 503);
    assert.match(await response.text(), /offline|unavailable|cache/i);
  });

  it("fails install rather than preserving stale optional entries after a failed retry cleanup", async () => {
    for (const retryMode of ["missing", "changed"] as const) {
      let attempt = 1;
      const manifest = runtimeShellManifestFromAssets([
        { path: "assets/required.js", body: "required-ok", required: true },
        { path: "assets/optional.js", body: "optional-fresh", required: false },
      ]);
      const { listeners, cacheEntryUrls, cacheEntryText } = loadServiceWorker({
        runtimeShellHash: manifest.contentHash,
        onCachesDelete() {
          if (attempt === 1) throw new Error("delete blocked");
        },
        fetchResponse(input) {
          const url = requestUrl(input);
          if (url.endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
          }
          if (url.endsWith("/assets/optional.js")) {
            if (attempt === 1) return Promise.resolve(new Response("optional-fresh", { status: 200 }));
            if (retryMode === "changed") return Promise.resolve(new Response("optional-stale-different", { status: 200 }));
            return Promise.resolve(new Response("missing", { status: 404 }));
          }
          if (url.endsWith("/assets/required.js")) {
            return Promise.resolve(new Response(attempt === 1 ? "tampered" : "required-ok", { status: 200 }));
          }
          return Promise.resolve(new Response("not found", { status: 404 }));
        },
      });

      await assert.rejects(dispatchLifecycle(listeners, "install"), /delete blocked|runtime-shell|hash|byte|length/i);
      assert.equal(await cacheEntryText(`${TEST_SCOPE}assets/optional.js`), "optional-fresh", retryMode);
      attempt = 2;

      await dispatchLifecycle(listeners, "install");

      assert.equal(cacheEntryUrls().includes(`${TEST_SCOPE}assets/optional.js`), false, retryMode);
    }
  });

  it("fails install when cache inventory cannot be enumerated or stale entries cannot be removed", async () => {
    const manifest = runtimeShellManifestFromAssets([{ path: "assets/required.js", body: "required-ok", required: true }]);
    const cases: Array<{ label: string; options: Partial<ServiceWorkerHarnessOptions>; expected: RegExp }> = [
      {
        label: "enumeration failure",
        options: {
          onOpenedCacheKeys() {
            throw new Error("cache keys blocked");
          },
        },
        expected: /cache keys blocked|inventory|enumer/i,
      },
      {
        label: "removal failure",
        options: {
          initialCacheEntries: [[`${TEST_SCOPE}stale.txt`, "stale"]],
          onOpenedCacheDelete() {
            throw new Error("cache delete blocked");
          },
        },
        expected: /cache delete blocked|inventory|stale|remove/i,
      },
    ];

    for (const testCase of cases) {
      const { listeners } = loadServiceWorker({
        runtimeShellHash: manifest.contentHash,
        ...testCase.options,
        fetchResponse(input) {
          const url = requestUrl(input);
          if (url.endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
          }
          return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
        },
      });

      await assert.rejects(dispatchLifecycle(listeners, "install"), testCase.expected, testCase.label);
    }
  });

  it("proves successful install inventory is exact and old active caches stay untouched", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "assets/required.js", body: "required-ok", required: true },
      { path: "assets/optional.js", body: "optional-ok", required: false },
    ]);
    const oldCacheName = `nullid-cache-${expectedCacheScopeIdentity(TEST_SCOPE)}-old-active`;
    const { listeners, cacheEntryUrls, deletedCaches } = loadServiceWorker({
      cacheKeys: [oldCacheName],
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
    });

    await dispatchLifecycle(listeners, "install");

    assert.deepEqual(cacheEntryUrls().sort(), [
      `${TEST_SCOPE}assets/optional.js`,
      `${TEST_SCOPE}assets/required.js`,
      `${TEST_SCOPE}nullid-precache-manifest.json`,
    ].sort());
    assert.equal(deletedCaches.includes(oldCacheName), false);
  });

  it("awaits cache writes before resolving navigation cache repair", async () => {
    const cacheWrites: Array<Deferred<void>> = [];
    const manifest = runtimeShellManifestFromAssets([{ path: "index.html", body: "INDEX-A", required: true }]);
    const { listeners } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      onCachePut() {
        const deferred = createDeferred<void>();
        cacheWrites.push(deferred);
        return deferred.promise;
      },
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response("INDEX-A", { status: 200, headers: { "Content-Type": "text/html" } }));
      },
    });

    const responsePromise = dispatchFetch(listeners, {
      url: `${TEST_SCOPE}?tool=vault`,
      method: "GET",
      mode: "navigate",
      destination: "document",
    });
    await assertPromisePending(responsePromise, "navigation cache repair");
    await waitForCondition(() => cacheWrites.length === 1, "navigation cache write");
    cacheWrites[0].resolve();
    const response = (await responsePromise) as { ok: boolean };
    assert.equal(response.ok, true);
  });

  it("returns cache-first hits without network or cache writes", async () => {
    const manifest = runtimeShellManifestFromAssets([{ path: "assets/app.js", body: "cached", required: true }]);
    const { listeners, fetchUrls, cachePutCalls } = loadServiceWorker({
      initialCacheEntries: [
        [`${TEST_SCOPE}nullid-precache-manifest.json`, JSON.stringify(manifest)],
        [`${TEST_SCOPE}assets/app.js`, "cached"],
      ],
      runtimeShellHash: manifest.contentHash,
    });

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}assets/app.js`,
      method: "GET",
      mode: "same-origin",
      destination: "script",
    });

    assert.equal(await response.text(), "cached");
    assert.deepEqual(fetchUrls, []);
    assert.equal(cachePutCalls.length, 0);
  });

  it("does not satisfy cache-first requests from stale caches outside the current scope/version", async () => {
    const manifest = runtimeShellManifestFromAssets([{ path: "assets/app.js", body: "current-network", required: true }]);
    const staleResponse = new Response("stale-old-cache", { status: 200 });
    const { listeners, fetchUrls, cachePutCalls } = loadServiceWorker({
      initialCacheEntries: [[`${TEST_SCOPE}nullid-precache-manifest.json`, JSON.stringify(manifest)]],
      runtimeShellHash: manifest.contentHash,
      onGlobalCacheMatch(input) {
        return requestUrl(input).endsWith("/assets/app.js") ? staleResponse : undefined;
      },
      fetchResponse(input) {
        return Promise.resolve(new Response(assetBodyForUrl(manifest, requestUrl(input)), { status: 200 }));
      },
    });

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}assets/app.js`,
      method: "GET",
      mode: "same-origin",
      destination: "script",
    });

    assert.equal(await response.text(), "current-network");
    assert.deepEqual(fetchUrls, [`${TEST_SCOPE}assets/app.js`]);
    assert.deepEqual(cachePutCalls, [`${TEST_SCOPE}assets/app.js`]);
  });

  it("falls back to URL-string cache lookups for cached module requests", async () => {
    const manifest = runtimeShellManifestFromAssets([{ path: "assets/BatchReviewView.js", body: "cached-module", required: true }]);
    const { listeners, fetchUrls } = loadServiceWorker({
      initialCacheEntries: [
        [`${TEST_SCOPE}nullid-precache-manifest.json`, JSON.stringify(manifest)],
        [`${TEST_SCOPE}assets/BatchReviewView.js`, "cached-module"],
      ],
      runtimeShellHash: manifest.contentHash,
    });

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}assets/BatchReviewView.js`,
      method: "GET",
      mode: "cors",
      destination: "script",
    });

    assert.equal(await response.text(), "cached-module");
    assert.deepEqual(fetchUrls, []);
  });

  it("isolates rejected cache writes from successful runtime network responses", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "assets/app.js", body: "asset", required: true },
      { path: "index.html", body: "INDEX", required: true },
    ]);
    const { listeners, warnings } = loadServiceWorker({
      initialCacheEntries: [[`${TEST_SCOPE}nullid-precache-manifest.json`, JSON.stringify(manifest)]],
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        return Promise.resolve(new Response(assetBodyForUrl(manifest, requestUrl(input)), { status: 200 }));
      },
      onCachePut() {
        return Promise.reject(new Error("quota exceeded"));
      },
    });

    const cases: RequestLike[] = [
      { url: `${TEST_SCOPE}assets/app.js`, method: "GET", mode: "same-origin", destination: "script" },
      { url: `${TEST_SCOPE}?tool=vault`, method: "GET", mode: "navigate", destination: "document" },
    ];

    for (const request of cases) {
      const response = await dispatchFetch(listeners, request);
      assert.equal(response.status, 200, request.destination);
    }
    const apiResult = dispatchFetchMaybe(listeners, { url: `${TEST_SCOPE}api/status`, method: "GET", mode: "same-origin", destination: "" });
    assert.equal(apiResult.responded, false);
    assert.equal(warnings.length, 2);
  });

  it("returns successful cache-first network responses when cache match or open rejects", async () => {
    const cases: Array<{ label: string; options: ServiceWorkerHarnessOptions }> = [
      {
        label: "opened cache match rejection",
        options: {
          onOpenedCacheMatch() {
            throw new Error("opened match failed");
          },
        },
      },
      {
        label: "cache open rejection",
        options: {
          onCachesOpen() {
            throw new Error("cache open failed");
          },
        },
      },
    ];

    for (const testCase of cases) {
      const { listeners } = loadServiceWorker(testCase.options);
      const response = await dispatchFetch(listeners, {
        url: `${TEST_SCOPE}assets/app.js`,
        method: "GET",
        mode: "same-origin",
        destination: "script",
      });

      assert.equal(response.status, 200, testCase.label);
      assert.equal(await response.text(), "network", testCase.label);
    }
  });

  it("does not hijack unknown destination requests when cache open rejects", async () => {
    const { listeners } = loadServiceWorker({
      onCachesOpen() {
        throw new Error("cache open failed");
      },
    });

    const result = dispatchFetchMaybe(listeners, {
      url: `${TEST_SCOPE}api/status`,
      method: "GET",
      mode: "same-origin",
      destination: "",
    });

    assert.equal(result.responded, false);
  });

  it("does not use NullID caches for unknown in-scope API requests", async () => {
    const cachedResponse = new Response("cached-api", { status: 200 });
    const { listeners } = loadServiceWorker({
      fetchResponse() {
        return Promise.reject(new Error("offline"));
      },
      onOpenedCacheMatch(input) {
        return requestUrl(input).endsWith("/api/cached") ? cachedResponse : undefined;
      },
    });

    const cached = dispatchFetchMaybe(listeners, {
      url: `${TEST_SCOPE}api/cached`,
      method: "GET",
      mode: "same-origin",
      destination: "",
    });
    assert.equal(cached.responded, false);

    assert.equal(await cachedResponse.text(), "cached-api");
  });

  it("serves navigation fallbacks from the scoped cache when the network is unavailable", async () => {
    const indexFallback = new Response("app shell", { status: 200 });
    const { listeners } = loadServiceWorker({
      fetchResponse() {
        return Promise.reject(new Error("offline"));
      },
      onOpenedCacheMatch(input) {
        return requestUrl(input) === `${TEST_SCOPE}index.html` ? indexFallback : undefined;
      },
    });

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}?tool=vault&note=1`,
      method: "GET",
      mode: "navigate",
      destination: "document",
    });

    assert.equal(await response.text(), "app shell");
  });

  it("does not hijack real static document or unknown online navigations", () => {
    const { listeners } = loadServiceWorker();

    const staticDocument = dispatchFetchMaybe(listeners, {
      url: `${TEST_SCOPE}tools/`,
      method: "GET",
      mode: "navigate",
      destination: "document",
    });
    assert.equal(staticDocument.responded, false);

    const unknownDocument = dispatchFetchMaybe(listeners, {
      url: `${TEST_SCOPE}missing/`,
      method: "GET",
      mode: "navigate",
      destination: "document",
    });
    assert.equal(unknownDocument.responded, false);
  });

  it("returns an offline 503 navigation response when no app shell is cached", async () => {
    const { listeners } = loadServiceWorker({
      fetchResponse() {
        return Promise.reject(new Error("offline"));
      },
    });

    const response = await dispatchFetch(listeners, {
      url: `${TEST_SCOPE}?tool=vault`,
      method: "GET",
      mode: "navigate",
      destination: "document",
    });

    assert.equal(response.status, 503);
    assert.match(await response.text(), /offline/i);
  });

  it("keeps online navigation responses independent from cache API failures", async () => {
    const manifest = runtimeShellManifestFromAssets([{ path: "index.html", body: "INDEX", required: true }]);
    const cases: Array<{ label: string; options: ServiceWorkerHarnessOptions }> = [
      {
        label: "open rejection",
        options: {
          runtimeShellHash: manifest.contentHash,
          fetchResponse(input) {
            const url = requestUrl(input);
            if (url.endsWith("/nullid-precache-manifest.json")) {
              return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
            }
            return Promise.resolve(new Response("INDEX", { status: 200 }));
          },
          onCachesOpen() {
            throw new Error("cache open failed");
          },
        },
      },
      {
        label: "put rejection",
        options: {
          initialCacheEntries: [[`${TEST_SCOPE}nullid-precache-manifest.json`, JSON.stringify(manifest)]],
          runtimeShellHash: manifest.contentHash,
          fetchResponse() {
            return Promise.resolve(new Response("INDEX", { status: 200 }));
          },
          onCachePut() {
            throw new Error("cache put failed");
          },
        },
      },
    ];

    for (const testCase of cases) {
      const { listeners } = loadServiceWorker(testCase.options);
      const response = await dispatchFetch(listeners, {
        url: `${TEST_SCOPE}?tool=vault`,
        method: "GET",
        mode: "navigate",
        destination: "document",
      });

      assert.equal(response.status, 200, testCase.label);
      assert.equal(await response.text(), "INDEX", testCase.label);
    }
  });

  it("uses the terminal navigation fallback when both network and cache APIs fail", async () => {
    const cases: Array<{ label: string; options: ServiceWorkerHarnessOptions }> = [
      {
        label: "cache open rejection",
        options: {
          fetchResponse() {
            return Promise.reject(new Error("offline"));
          },
          onCachesOpen() {
            throw new Error("cache open failed");
          },
        },
      },
      {
        label: "opened-cache match rejection",
        options: {
          fetchResponse() {
            return Promise.reject(new Error("offline"));
          },
          onOpenedCacheMatch() {
            throw new Error("opened match failed");
          },
        },
      },
    ];

    for (const testCase of cases) {
      const { listeners } = loadServiceWorker(testCase.options);
      const response = await dispatchFetch(listeners, {
        url: `${TEST_SCOPE}?tool=vault`,
        method: "GET",
        mode: "navigate",
        destination: "document",
      });

      assert.equal(response.status, 503, testCase.label);
      assert.match(await response.text(), /offline/i, testCase.label);
    }
  });

  it("fails install when the required precache manifest cannot complete", async () => {
    const { listeners } = loadServiceWorker({
      fetchResponse(input) {
        if (requestUrl(input).endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response("missing", { status: 404 }));
        }
        return Promise.resolve(new Response("asset", { status: 200 }));
      },
    });

    await assert.rejects(dispatchLifecycle(listeners, "install"), /precache manifest/i);
  });

  it("fails install when the precache manifest is not authenticated by count, ordering and content hash", async () => {
    const validManifest = runtimeShellManifest(["assets/index.js"]);
    const duplicateEntries = [
      runtimeShellEntry("assets/index.js"),
      runtimeShellEntry("assets/index.js"),
    ];
    const unsortedEntries = [
      runtimeShellEntry("assets/z.js"),
      runtimeShellEntry("assets/a.js"),
    ];
    const invalidManifests = [
      { manifest: { ...validManifest, assetCount: 2 }, runtimeShellHash: validManifest.contentHash },
      { manifest: { ...validManifest, contentHash: "0".repeat(64) }, runtimeShellHash: validManifest.contentHash },
      {
        manifest: {
          schemaVersion: 2,
          kind: "nullid-runtime-shell-manifest",
          assetCount: duplicateEntries.length,
          contentHash: sha256Hex(JSON.stringify(duplicateEntries)),
          assets: duplicateEntries.map((entry) => entry.path),
          entries: duplicateEntries,
        },
      },
      {
        manifest: {
          schemaVersion: 2,
          kind: "nullid-runtime-shell-manifest",
          assetCount: unsortedEntries.length,
          contentHash: sha256Hex(JSON.stringify(unsortedEntries)),
          assets: unsortedEntries.map((entry) => entry.path),
          entries: unsortedEntries,
        },
      },
      { manifest: { ...validManifest, contentHash: "not-a-sha256" }, runtimeShellHash: validManifest.contentHash },
    ];

    for (const { manifest, runtimeShellHash } of invalidManifests) {
      const { listeners } = loadServiceWorker({
        runtimeShellHash: runtimeShellHash ?? (typeof manifest.contentHash === "string" ? manifest.contentHash : validManifest.contentHash),
        fetchResponse(input) {
          if (requestUrl(input).endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
          }
          return Promise.resolve(new Response("asset", { status: 200 }));
        },
      });

      await assert.rejects(dispatchLifecycle(listeners, "install"), /precache manifest/i);
    }
  });

  it("verifies exact runtime-shell bytes and caches only canonical scoped URLs", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "assets/index.js", body: "console.log('ok')", required: true },
      { path: "index.html", body: "<main>ok</main>", required: true },
      { path: "manifest.webmanifest", body: "{\"name\":\"NullID\"}", required: true },
      { path: "nullid-preview.png", body: "optional-preview", required: false },
    ]);
    const cacheBodies = new Map<string, string>();
    const { listeners, cachePutCalls } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      onCachePut(input, response) {
        return response.clone().text().then((body) => {
          cacheBodies.set(requestUrl(input), body);
        });
      },
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
    });

    await dispatchLifecycle(listeners, "install");

    assert.deepEqual(cachePutCalls.sort(), [
      `${TEST_SCOPE}assets/index.js`,
      `${TEST_SCOPE}index.html`,
      `${TEST_SCOPE}manifest.webmanifest`,
      `${TEST_SCOPE}nullid-precache-manifest.json`,
      `${TEST_SCOPE}nullid-preview.png`,
    ].sort());
    assert.equal(cacheBodies.get(`${TEST_SCOPE}assets/index.js`), "console.log('ok')");
    assert.equal(cacheBodies.get(`${TEST_SCOPE}index.html`), "<main>ok</main>");
    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}`), false);
  });

  it("strips transport encoding headers from reconstructed verified runtime-shell responses", async () => {
    const body = "console.log('decoded asset')";
    const manifest = runtimeShellManifestFromAssets([{ path: "assets/index.js", body, required: true }]);
    const cachedHeaders = new Map<string, string | null>();
    const { listeners } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      onCachePut(input, response) {
        if (requestUrl(input).endsWith("/assets/index.js")) {
          cachedHeaders.set("content-encoding", response.headers.get("content-encoding"));
          cachedHeaders.set("content-length", response.headers.get("content-length"));
          cachedHeaders.set("content-type", response.headers.get("content-type"));
        }
      },
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(
          new Response(body, {
            status: 200,
            headers: {
              "Content-Encoding": "gzip",
              "Content-Length": String(Buffer.byteLength(body, "utf8")),
              "Content-Type": "application/javascript",
            },
          }),
        );
      },
    });

    await dispatchLifecycle(listeners, "install");

    assert.equal(cachedHeaders.get("content-encoding"), null);
    assert.equal(cachedHeaders.get("content-length"), null);
    assert.equal(cachedHeaders.get("content-type"), "application/javascript");
  });

  it("rejects required runtime-shell assets whose downloaded bytes do not match the manifest", async () => {
    const cases: Array<{ label: string; responseBody: string | (() => string); expected: RegExp }> = [
      { label: "same length wrong content", responseBody: "B".repeat("expected".length), expected: /sha-?256|hash/i },
      { label: "wrong length", responseBody: "short", expected: /byte|length/i },
      { label: "truncated response", responseBody: "expec", expected: /byte|length/i },
      { label: "oversized response", responseBody: () => "x".repeat(MAX_PRECACHE_ASSET_BYTES + 1), expected: /too large|maximum|byte/i },
      { label: "stale stable-name index", responseBody: "version-a-index", expected: /sha-?256|hash|byte|length/i },
      { label: "stale manifest.webmanifest", responseBody: "version-a-manifest", expected: /sha-?256|hash|byte|length/i },
    ];

    for (const testCase of cases) {
      const assetPath = testCase.label === "stale manifest.webmanifest" ? "manifest.webmanifest" : "index.html";
      const expectedBody = testCase.label === "stale manifest.webmanifest" ? "version-b-manifest" : "expected";
      const manifest = runtimeShellManifestFromAssets([{ path: assetPath, body: expectedBody, required: true }]);
      const { listeners } = loadServiceWorker({
        runtimeShellHash: manifest.contentHash,
        fetchResponse(input) {
          const url = requestUrl(input);
          if (url.endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
          }
          const body = typeof testCase.responseBody === "function" ? testCase.responseBody() : testCase.responseBody;
          return Promise.resolve(new Response(body, { status: 200 }));
        },
      });

      await assert.rejects(dispatchLifecycle(listeners, "install"), testCase.expected, testCase.label);
    }
  });

  it("applies required versus optional runtime-shell asset failure policy during install", async () => {
    const cases: Array<{ label: string; required: boolean; mode: "404" | "network"; rejects: boolean }> = [
      { label: "required 404", required: true, mode: "404", rejects: true },
      { label: "optional 404", required: false, mode: "404", rejects: false },
      { label: "required network failure", required: true, mode: "network", rejects: true },
      { label: "optional network failure", required: false, mode: "network", rejects: false },
    ];

    for (const testCase of cases) {
      const manifest = runtimeShellManifestFromAssets([{ path: "assets/maybe.js", body: "asset", required: testCase.required }]);
      const { listeners, cachePutCalls, warnings } = loadServiceWorker({
        runtimeShellHash: manifest.contentHash,
        fetchResponse(input) {
          const url = requestUrl(input);
          if (url.endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
          }
          if (testCase.mode === "network") return Promise.reject(new Error("offline"));
          return Promise.resolve(new Response("missing", { status: 404 }));
        },
      });

      if (testCase.rejects) {
        await assert.rejects(dispatchLifecycle(listeners, "install"), /runtime-shell|asset|HTTP|offline/i, testCase.label);
      } else {
        await dispatchLifecycle(listeners, "install");
        assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/maybe.js`), false, testCase.label);
        assert.equal(warnings.length, 1, testCase.label);
      }
    }
  });

  it("rejects duplicate canonical runtime-shell URLs and scope escapes", async () => {
    const duplicateEntries = [
      runtimeShellEntryFromBody("assets/index.js", "asset-a", true),
      runtimeShellEntryFromBody("./assets/index.js", "asset-b", true),
    ];
    const duplicateManifest = manifestFromEntries(duplicateEntries);
    const scopeEscapeManifest = manifestFromEntries([
      runtimeShellEntryFromBody("../outside.js", "escape", true),
    ]);

    const cases = [
      { label: "duplicate canonical URL", manifest: duplicateManifest, expected: /duplicate|canonical/i },
      { label: "scope escape", manifest: scopeEscapeManifest, expected: /outside service-worker scope|scope/i },
    ];

    for (const testCase of cases) {
      const { listeners } = loadServiceWorker({
        runtimeShellHash: testCase.manifest.contentHash,
        fetchResponse(input) {
          if (requestUrl(input).endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(testCase.manifest), { status: 200 }));
          }
          return Promise.resolve(new Response("asset", { status: 200 }));
        },
      });

      await assert.rejects(dispatchLifecycle(listeners, "install"), testCase.expected, testCase.label);
    }
  });

  it("cleans incomplete runtime-shell caches after a required asset failure", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "assets/a-ok.js", body: "ok", required: true },
      { path: "assets/z-bad.js", body: "expected", required: true },
    ]);
    const { listeners, cachePutCalls, deletedCaches } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        if (url.endsWith("/assets/z-bad.js")) {
          return Promise.resolve(new Response("tampered", { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
    });

    await assert.rejects(dispatchLifecycle(listeners, "install"), /runtime-shell|hash|byte|length/i);

    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/a-ok.js`), true);
    assert.deepEqual(deletedCaches, [expectedCacheName(TEST_SCOPE)]);
  });

  it("installs successfully from root and subpath scopes", async () => {
    const cases = [
      { label: "root", scope: `${TEST_ORIGIN}/`, assetUrl: `${TEST_ORIGIN}/index.html` },
      { label: "subpath", scope: TEST_SCOPE, assetUrl: `${TEST_SCOPE}index.html` },
    ];

    for (const testCase of cases) {
      const manifest = runtimeShellManifestFromAssets([{ path: "index.html", body: "<main>ok</main>", required: true }]);
      const { listeners, cachePutCalls } = loadServiceWorker({
        scope: testCase.scope,
        runtimeShellHash: manifest.contentHash,
        fetchResponse(input) {
          const url = requestUrl(input);
          if (url.endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
          }
          return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
        },
      });

      await dispatchLifecycle(listeners, "install");
      assert.equal(cachePutCalls.includes(testCase.assetUrl), true, testCase.label);
    }
  });

  it("does not fail install when optional app-shell assets are unavailable", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "assets/index.js", body: "asset", required: true },
      { path: "favicon.svg", body: "<svg></svg>", required: true },
      { path: "index.html", body: "<main>ok</main>", required: true },
      { path: "manifest.webmanifest", body: "{\"name\":\"NullID\"}", required: true },
      { path: "nullid-preview.png", body: "preview", required: false },
    ]);
    const { listeners, cachePutCalls, warnings } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        if (url.endsWith("/nullid-preview.png")) {
          return Promise.resolve(new Response("missing", { status: 404 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
    });

    await dispatchLifecycle(listeners, "install");

    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}index.html`), true);
    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/index.js`), true);
    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}nullid-preview.png`), false);
    assert.equal(warnings.length, 1);
  });

  it("cleans old versioned caches while preserving the current scoped cache", async () => {
    const scopeIdentity = expectedCacheScopeIdentity(TEST_SCOPE);
    const { listeners, deletedCaches } = loadServiceWorker({
      cacheKeys: [
        `nullid-cache-${scopeIdentity}-old`,
        expectedCacheName(TEST_SCOPE),
        "other-cache",
      ],
    });

    await dispatchLifecycle(listeners, "activate");

    assert.deepEqual(deletedCaches, [`nullid-cache-${scopeIdentity}-old`]);
  });

  it("keeps a waiting worker install from mutating the active worker cache on worker-only updates", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "index.html", body: "INDEX-A", required: true },
      { path: "assets/app.js", body: "APP-A", required: true },
    ]);
    const activeWorker = stampServiceWorkerForTest(manifest, "active worker logic");
    const waitingWorker = stampServiceWorkerForTest(manifest, "waiting worker logic");
    const activeCacheName = expectedCacheName(TEST_SCOPE, activeWorker.cacheVersion);
    const waitingCacheName = expectedCacheName(TEST_SCOPE, waitingWorker.cacheVersion);
    const sharedCaches = createSharedCacheStorage({
      [activeCacheName]: [
        [`${TEST_SCOPE}nullid-precache-manifest.json`, JSON.stringify(manifest)],
        [`${TEST_SCOPE}index.html`, "INDEX-A"],
        [`${TEST_SCOPE}assets/app.js`, "APP-A"],
      ],
    });
    const activeSnapshot = await cacheSnapshot(sharedCaches, activeCacheName);

    const active = loadServiceWorker({
      cacheVersion: activeWorker.cacheVersion,
      fetchResponse: async () => new Response("offline", { status: 503 }),
      runtimeShellHash: manifest.contentHash,
      sharedCaches,
      source: activeWorker.source,
    });
    const cacheWrites: Deferred<void>[] = [];
    const waiting = loadServiceWorker({
      cacheVersion: waitingWorker.cacheVersion,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
      onCachePut() {
        const deferred = createDeferred<void>();
        cacheWrites.push(deferred);
        return deferred.promise;
      },
      runtimeShellHash: manifest.contentHash,
      sharedCaches,
      source: waitingWorker.source,
    });

    const installPromise = dispatchLifecycle(waiting.listeners, "install");
    await waitForCondition(() => cacheWrites.length === 1, "waiting worker manifest cache write");
    assert.deepEqual(await cacheSnapshot(sharedCaches, activeCacheName), activeSnapshot, "active cache changed before manifest write finished");
    assert.equal(await (await dispatchFetch(active.listeners, navigationRequest(`${TEST_SCOPE}?tool=vault`))).text(), "INDEX-A");
    assert.equal(await (await dispatchFetch(active.listeners, scriptRequest(`${TEST_SCOPE}assets/app.js`))).text(), "APP-A");

    cacheWrites[0].resolve();
    await waitForCondition(() => cacheWrites.length === 2, "waiting worker first asset cache write");
    assert.deepEqual(await cacheSnapshot(sharedCaches, activeCacheName), activeSnapshot, "active cache changed during first asset write");
    assert.equal(await (await dispatchFetch(active.listeners, navigationRequest(`${TEST_SCOPE}?tool=guide`))).text(), "INDEX-A");
    assert.equal(await (await dispatchFetch(active.listeners, scriptRequest(`${TEST_SCOPE}assets/app.js?lazy=1`))).text(), "APP-A");

    cacheWrites[1].resolve();
    await waitForCondition(() => cacheWrites.length === 3, "waiting worker partial asset cache write");
    assert.deepEqual(await cacheSnapshot(sharedCaches, activeCacheName), activeSnapshot, "active cache changed during partial waiting cache population");
    cacheWrites[2].resolve();
    await installPromise;

    assert.deepEqual(await cacheSnapshot(sharedCaches, activeCacheName), activeSnapshot, "active cache changed while worker is waiting");
    assert.deepEqual(await cacheSnapshot(sharedCaches, waitingCacheName), activeSnapshot, "waiting cache should contain the exact runtime shell");

    await dispatchLifecycle(waiting.listeners, "activate");

    assert.deepEqual(await cacheSnapshot(sharedCaches, activeCacheName), [], "active cache should be removed only after activation");
    assert.deepEqual(await cacheSnapshot(sharedCaches, waitingCacheName), activeSnapshot, "waiting cache should remain exact after activation");
  });

  it("cleans only caches that belong to the current service-worker scope", async () => {
    const scopeIdentity = expectedCacheScopeIdentity(TEST_SCOPE);
    const { listeners, deletedCaches } = loadServiceWorker({
      cacheKeys: [
        `nullid-cache-${scopeIdentity}-old-runtime`,
        "nullid-cache-other-scope-old-runtime",
        expectedCacheName(TEST_SCOPE),
        "other-cache",
      ],
    });

    await dispatchLifecycle(listeners, "activate");

    assert.deepEqual(deletedCaches, [`nullid-cache-${scopeIdentity}-old-runtime`]);
  });

  it("loads precache manifest assets relative to a scoped base path during install", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "assets/app.css", body: "body{}", required: true },
      { path: "assets/app.js", body: "console.log(1)", required: true },
    ]);
    const { listeners, cachePutCalls } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        if (requestUrl(input).endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, requestUrl(input)), { status: 200 }));
      },
    });

    await dispatchLifecycle(listeners, "install");

    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/app.css`), true);
    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/app.js`), true);
  });

  it("loads a generated precache manifest and caches lazy runtime chunks during install", async () => {
    const manifest = runtimeShellManifestFromAssets([
      { path: "assets/index.js", body: "index", required: true },
      { path: "assets/HashView.js", body: "hash", required: true },
      { path: "assets/runtimePhraseTranslations.js", body: "runtime phrases", required: true },
      { path: "assets/workflowPhraseTranslations.js", body: "workflow phrases", required: true },
    ]);
    const { listeners, cachePutCalls } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200, headers: { "Content-Type": "application/json" } }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
    });

    await dispatchLifecycle(listeners, "install");

    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/HashView.js`), true);
    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/runtimePhraseTranslations.js`), true);
    assert.equal(cachePutCalls.includes(`${TEST_SCOPE}assets/workflowPhraseTranslations.js`), true);
  });

  it("installs a new worker without forcing skipWaiting while old clients may exist", async () => {
    const manifest = runtimeShellManifest(["assets/index.js"]);
    const { listeners, skipWaitingCalls } = loadServiceWorker({
      runtimeShellHash: manifest.contentHash,
      fetchResponse(input) {
        const url = requestUrl(input);
        if (url.endsWith("/nullid-precache-manifest.json")) {
          return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
        }
        return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
      },
    });

    await dispatchLifecycle(listeners, "install");

    assert.equal(skipWaitingCalls.length, 0);
  });

  it("activates without claiming already-open clients", async () => {
    const scopeIdentity = expectedCacheScopeIdentity(TEST_SCOPE);
    const { listeners, clientsClaimCalls } = loadServiceWorker({
      cacheKeys: [`nullid-cache-${scopeIdentity}-old`, expectedCacheName(TEST_SCOPE)],
    });

    await dispatchLifecycle(listeners, "activate");

    assert.deepEqual(clientsClaimCalls, []);
  });

  it("does not fail activation when cache-key cleanup APIs reject", async () => {
    const cases: Array<{ label: string; options: ServiceWorkerHarnessOptions; deleted: string[] }> = [
      {
        label: "keys rejection",
        options: {
          onCachesKeys() {
            throw new Error("cache keys failed");
          },
        },
        deleted: [],
      },
      {
        label: "delete rejection",
        options: {
          cacheKeys: [`nullid-cache-${expectedCacheScopeIdentity(TEST_SCOPE)}-old`],
          onCachesDelete() {
            throw new Error("delete failed");
          },
        },
        deleted: [],
      },
    ];

    for (const testCase of cases) {
      const { listeners, deletedCaches } = loadServiceWorker(testCase.options);
      await dispatchLifecycle(listeners, "activate");
      assert.deepEqual(deletedCaches, testCase.deleted, testCase.label);
    }
  });

  it("uses collision-safe cache identities for arbitrary service-worker scopes", async () => {
    const scopes = [
      "/",
      "/a/b/",
      "/a-b/",
      "/a//b/",
      "/a--b/",
      "/scope/%C3%89/",
      "/scope/e%CC%81/",
      "/punct/a+b/",
      "/punct/a b/",
      `/${"long/".repeat(40)}`,
    ].map((path) => `${TEST_ORIGIN}${path}`);
    const openedCacheNames: string[] = [];

    for (const scope of scopes) {
      const manifest = runtimeShellManifestFromAssets([{ path: "index.html", body: `<main>${scope}</main>`, required: true }]);
      const { listeners } = loadServiceWorker({
        scope,
        runtimeShellHash: manifest.contentHash,
        onCachesOpen(name) {
          openedCacheNames.push(name);
        },
        fetchResponse(input) {
          const url = requestUrl(input);
          if (url.endsWith("/nullid-precache-manifest.json")) {
            return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
          }
          return Promise.resolve(new Response(assetBodyForUrl(manifest, url), { status: 200 }));
        },
      });
      await dispatchLifecycle(listeners, "install");
    }

    assert.equal(new Set(openedCacheNames).size, scopes.length);
    for (const [index, scope] of scopes.entries()) {
      assert.equal(openedCacheNames[index], expectedCacheName(scope));
    }
  });

  it("never deletes another deployment scope's caches during activation", async () => {
    const runtimeHash = "a".repeat(64);
    const scopeA = `${TEST_ORIGIN}/a/b/`;
    const scopeB = `${TEST_ORIGIN}/a-b/`;
    const scopeACache = expectedCacheName(scopeA);
    const scopeBOldCache = `nullid-cache-${expectedCacheScopeIdentity(scopeB)}-precache-${"b".repeat(32)}`;
    const { listeners, deletedCaches } = loadServiceWorker({
      scope: scopeA,
      runtimeShellHash: runtimeHash,
      cacheKeys: [
        scopeACache,
        `nullid-cache-${expectedCacheScopeIdentity(scopeA)}-precache-${"c".repeat(32)}`,
        scopeBOldCache,
      ],
    });

    await dispatchLifecycle(listeners, "activate");

    assert.deepEqual(deletedCaches, [`nullid-cache-${expectedCacheScopeIdentity(scopeA)}-precache-${"c".repeat(32)}`]);
    assert.equal(deletedCaches.includes(scopeBOldCache), false);
  });
});

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });
  return { promise, resolve };
}

async function assertPromisePending(promise: Promise<unknown>, label: string) {
  const status = await Promise.race([promise.then(() => "resolved"), new Promise<"pending">((resolve) => setTimeout(() => resolve("pending"), 0))]);
  assert.equal(status, "pending", label);
}

async function waitForCondition(predicate: () => boolean, label: string) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  assert.equal(predicate(), true, label);
}

interface ServiceWorkerHarnessOptions {
  cacheKeys?: string[];
  cacheVersion?: string;
  initialCacheEntries?: Array<[string, string]>;
  scope?: string;
  runtimeShellHash?: string;
  sharedCaches?: SharedCacheStorage;
  source?: string;
  fetchResponse?: (input: RequestInput, init?: RequestInit) => Promise<Response>;
  onCacheAddAll?: (urls: string[]) => unknown;
  onCachePut?: (input: RequestInput, response: Response) => unknown;
  onCachesDelete?: (key: string) => unknown;
  onCachesKeys?: () => string[] | Promise<string[]>;
  onCachesOpen?: (name: string) => unknown;
  onGlobalCacheMatch?: (input: RequestInput, options?: CacheQueryOptions) => Response | undefined | Promise<Response | undefined>;
  onOpenedCacheDelete?: (input: RequestInput) => unknown;
  onOpenedCacheKeys?: () => RequestInput[] | Promise<RequestInput[]>;
  onOpenedCacheMatch?: (input: RequestInput, options?: CacheQueryOptions) => Response | undefined | Promise<Response | undefined>;
}

function loadServiceWorker(options: ServiceWorkerHarnessOptions = {}) {
  const listeners: Record<string, Listener[]> = {};
  const fetchUrls: string[] = [];
  const cachePutCalls: string[] = [];
  const deletedCaches: string[] = [];
  const clientsClaimCalls: string[] = [];
  const skipWaitingCalls: string[] = [];
  const warnings: string[] = [];
  const scope = options.scope ?? TEST_SCOPE;
  const origin = new URL(scope).origin;
  const defaultCacheName = expectedCacheName(scope, options.cacheVersion);
  const cacheStores = options.sharedCaches ?? createSharedCacheStorage();
  if (options.initialCacheEntries) {
    cacheStores.set(defaultCacheName, responseMapFromEntries(options.initialCacheEntries));
  }
  if (!cacheStores.has(defaultCacheName)) {
    cacheStores.set(defaultCacheName, new Map());
  }
  let lastOpenedCacheName = defaultCacheName;
  const selfScope = {
    registration: { scope },
    location: { origin },
    clients: {
      claim: async () => {
        clientsClaimCalls.push("claim");
      },
    },
    skipWaiting: async () => {
      skipWaitingCalls.push("skipWaiting");
    },
    addEventListener(type: string, listener: Listener) {
      listeners[type] = [...(listeners[type] ?? []), listener];
    },
  };
  const context = vm.createContext({
    URL,
    Headers,
    Response,
    TextDecoder,
    TextEncoder,
    caches: {
      delete: async (key: string) => {
        await options.onCachesDelete?.(key);
        cacheStores.delete(key);
        deletedCaches.push(key);
        return true;
      },
      keys: async () => options.onCachesKeys ? options.onCachesKeys() : options.cacheKeys ?? Array.from(cacheStores.keys()),
      match: async (input: RequestInput, matchOptions?: CacheQueryOptions) => options.onGlobalCacheMatch?.(input, matchOptions),
      open: async (name: string) => {
        await options.onCachesOpen?.(name);
        lastOpenedCacheName = name;
        return openedCache(cacheStores, name, {
          cachePutCalls,
          onCacheAddAll: options.onCacheAddAll,
          onCachePut: options.onCachePut,
          onOpenedCacheDelete: options.onOpenedCacheDelete,
          onOpenedCacheKeys: options.onOpenedCacheKeys,
          onOpenedCacheMatch: options.onOpenedCacheMatch,
        });
      },
    },
    crypto: globalThis.crypto,
    console: {
      warn(message: unknown) {
        warnings.push(String(message));
      },
    },
    fetch: async (input: RequestInput, init?: RequestInit) => {
      fetchUrls.push(requestUrl(input));
      if (options.fetchResponse) {
        return options.fetchResponse(input, init);
      }
      return new Response("network", { status: 200 });
    },
    self: selfScope,
  });

  const source = (options.source ?? readFileSync("public/sw.js", "utf8"))
    .replaceAll("__NULLID_BUILD_ID__", options.cacheVersion ?? "__NULLID_BUILD_ID__")
    .replaceAll("__NULLID_RUNTIME_SHELL_HASH__", options.runtimeShellHash ?? "__NULLID_RUNTIME_SHELL_HASH__");
  vm.runInContext(source, context, { filename: "public/sw.js" });

  return {
    cacheEntryText: async (url: string, cacheName = lastOpenedCacheName) => cacheStores.get(cacheName)?.get(url)?.clone().text(),
    cacheEntryUrls: (cacheName = lastOpenedCacheName) => Array.from(cacheStores.get(cacheName)?.keys() ?? []),
    cachePutCalls,
    clientsClaimCalls,
    deletedCaches,
    fetchUrls,
    listeners,
    skipWaitingCalls,
    warnings,
  };
}

type SharedCacheStorage = Map<string, Map<string, Response>>;

interface OpenedCacheHooks {
  cachePutCalls: string[];
  onCacheAddAll?: (urls: string[]) => unknown;
  onCachePut?: (input: RequestInput, response: Response) => unknown;
  onOpenedCacheDelete?: (input: RequestInput) => unknown;
  onOpenedCacheKeys?: () => RequestInput[] | Promise<RequestInput[]>;
  onOpenedCacheMatch?: (input: RequestInput, options?: CacheQueryOptions) => Response | undefined | Promise<Response | undefined>;
}

function openedCache(cacheStores: SharedCacheStorage, cacheName: string, hooks: OpenedCacheHooks) {
  const cacheEntries = ensureCacheStore(cacheStores, cacheName);
  return {
    addAll: async (urls: string[]) => {
      await hooks.onCacheAddAll?.(urls);
    },
    delete: async (input: RequestInput) => {
      await hooks.onOpenedCacheDelete?.(input);
      return cacheEntries.delete(requestUrl(input));
    },
    keys: async () => {
      if (hooks.onOpenedCacheKeys) return hooks.onOpenedCacheKeys();
      return Array.from(cacheEntries.keys()).map((url) => requestLike(url));
    },
    match: async (input: RequestInput, matchOptions?: CacheQueryOptions) => {
      const matched = await hooks.onOpenedCacheMatch?.(input, matchOptions);
      if (matched) return matched;
      const cached = matchCacheEntry(cacheEntries, input, matchOptions);
      return cached ? cached.clone() : undefined;
    },
    put: async (input: RequestInput, response: Response) => {
      hooks.cachePutCalls.push(requestUrl(input));
      await hooks.onCachePut?.(input, response);
      cacheEntries.set(requestUrl(input), response.clone());
    },
  };
}

function createSharedCacheStorage(entries: Record<string, Array<[string, string]>> = {}): SharedCacheStorage {
  return new Map(Object.entries(entries).map(([cacheName, cacheEntries]) => [cacheName, responseMapFromEntries(cacheEntries)]));
}

function responseMapFromEntries(entries: Array<[string, string]>): Map<string, Response> {
  return new Map(entries.map(([url, body]) => [url, new Response(body, { status: 200 })]));
}

function ensureCacheStore(cacheStores: SharedCacheStorage, cacheName: string): Map<string, Response> {
  const existing = cacheStores.get(cacheName);
  if (existing) return existing;
  const created = new Map<string, Response>();
  cacheStores.set(cacheName, created);
  return created;
}

async function cacheSnapshot(cacheStores: SharedCacheStorage, cacheName: string) {
  const entries = Array.from(cacheStores.get(cacheName)?.entries() ?? []);
  const out = [];
  for (const [url, response] of entries) {
    out.push([url, await response.clone().text()]);
  }
  return out.sort(([left], [right]) => left.localeCompare(right));
}

function matchCacheEntry(cacheEntries: Map<string, Response>, input: RequestInput, options?: CacheQueryOptions): Response | undefined {
  const exact = cacheEntries.get(requestUrl(input));
  if (exact || !options?.ignoreSearch) return exact;
  const target = new URL(requestUrl(input));
  target.search = "";
  target.hash = "";
  for (const [url, response] of cacheEntries) {
    const candidate = new URL(url);
    candidate.search = "";
    candidate.hash = "";
    if (candidate.href === target.href) return response;
  }
  return undefined;
}

function dispatchFetch(listeners: Record<string, Listener[]>, request: RequestLike): Promise<Response> {
  const result = dispatchFetchMaybe(listeners, request);
  assert.ok(result.responsePromise, "fetch listener called respondWith");
  return result.responsePromise;
}

function dispatchFetchMaybe(listeners: Record<string, Listener[]>, request: RequestLike): { responded: boolean; responsePromise: Promise<Response> | null } {
  let responsePromise: Promise<Response> | null = null;
  const [listener] = listeners.fetch ?? [];
  assert.ok(listener, "service worker fetch listener registered");

  listener({
    request,
    respondWith(response: Promise<Response>) {
      responsePromise = Promise.resolve(response);
    },
  });

  return { responded: Boolean(responsePromise), responsePromise };
}

function dispatchLifecycle(listeners: Record<string, Listener[]>, type: "install" | "activate"): Promise<void> {
  let lifecyclePromise: Promise<void> | null = null;
  const [listener] = listeners[type] ?? [];
  assert.ok(listener, `service worker ${type} listener registered`);

  listener({
    waitUntil(promise: Promise<void>) {
      lifecyclePromise = Promise.resolve(promise);
    },
  });

  assert.ok(lifecyclePromise, `${type} listener called waitUntil`);
  return lifecyclePromise;
}

function navigationRequest(url: string): RequestLike {
  return { url, method: "GET", mode: "navigate", destination: "document" };
}

function scriptRequest(url: string): RequestLike {
  return { url, method: "GET", mode: "same-origin", destination: "script" };
}

function runtimeShellManifest(paths: string[]) {
  const entries = [...paths].sort().map((assetPath) => runtimeShellEntry(assetPath));
  return manifestFromEntries(entries);
}

function runtimeShellManifestFromAssets(assets: Array<{ path: string; body: string; required: boolean }>) {
  const entries = assets
    .map((asset) => runtimeShellEntryFromBody(asset.path, asset.body, asset.required))
    .sort((left, right) => left.path.localeCompare(right.path));
  return manifestFromEntries(entries);
}

function manifestFromEntries(entries: ReturnType<typeof runtimeShellEntry>[]) {
  return {
    schemaVersion: 2,
    kind: "nullid-runtime-shell-manifest",
    assetCount: entries.length,
    contentHash: sha256Hex(JSON.stringify(entries)),
    assets: entries.map((entry) => entry.path),
    entries,
  };
}

function runtimeShellEntry(assetPath: string) {
  return runtimeShellEntryFromBody(assetPath, `asset:${assetPath}`, true);
}

function runtimeShellEntryFromBody(assetPath: string, body: string, required: boolean) {
  const entry = {
    path: assetPath,
    bytes: Buffer.byteLength(body, "utf8"),
    sha256: sha256Hex(body),
    required,
  };
  ASSET_BODIES.set(`${entry.path}:${entry.sha256}`, body);
  return entry;
}

function sha256Hex(value: string) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function assetBodyForUrl(manifest: ReturnType<typeof runtimeShellManifest>, url: string) {
  const requestPath = new URL(url).pathname;
  const entry = manifest.entries.find((candidate) => requestPath.endsWith(`/${candidate.path.replace(/^\.\//u, "")}`));
  assert.ok(entry, `manifest entry for ${url}`);
  return ASSET_BODIES.get(`${entry.path}:${entry.sha256}`) ?? "";
}

const ASSET_BODIES = new Map<string, string>();

function expectedCacheScopeIdentity(scope: string) {
  const pathname = new URL(scope).pathname || "/";
  return `p-${encodeURIComponent(pathname)}`;
}

function expectedCacheName(scope: string, cacheVersion = "__NULLID_BUILD_ID__") {
  return `nullid-cache-${expectedCacheScopeIdentity(scope)}-${cacheVersion}`;
}

function stampServiceWorkerForTest(manifest: ReturnType<typeof runtimeShellManifest>, workerMarker: string) {
  const distDir = fs.mkdtempSync(path.join(os.tmpdir(), "nullid-sw-cache-isolation-"));
  try {
    fs.writeFileSync(path.join(distDir, "nullid-precache-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    fs.writeFileSync(path.join(distDir, "sw.js"), `${readFileSync("public/sw.js", "utf8")}\n// ${workerMarker}\n`, "utf8");
    execFileSync(process.execPath, ["scripts/write-build-info.mjs", distDir], {
      stdio: "pipe",
      env: { ...process.env, VITE_BUILD_ID: "metadata-only-change", SOURCE_DATE_EPOCH: "1735689600" },
    });
    const source = readFileSync(path.join(distDir, "sw.js"), "utf8");
    return { cacheVersion: extractCacheVersion(source), source };
  } finally {
    fs.rmSync(distDir, { recursive: true, force: true });
  }
}

function extractCacheVersion(source: string) {
  const match = source.match(/const CACHE_VERSION = "([^"]+)"/u);
  assert.ok(match, "stamped service-worker cache version");
  return match[1];
}

function requestLike(url: string): RequestLike {
  return { url, method: "GET", mode: "same-origin", destination: "" };
}

function requestUrl(input: RequestInput): string {
  return typeof input === "string" ? input : input.url;
}
