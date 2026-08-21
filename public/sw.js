const CACHE_VERSION = "__NULLID_BUILD_ID__";
const RUNTIME_SHELL_HASH = "__NULLID_RUNTIME_SHELL_HASH__";
const CACHE_SCOPE = cacheScopeKey(self.registration.scope);
const CACHE_PREFIX = `nullid-cache-${CACHE_SCOPE}-`;
const CACHE_NAME = `${CACHE_PREFIX}${CACHE_VERSION}`;
const PRECACHE_MANIFEST_FILE = "nullid-precache-manifest.json";
const PRECACHE_MANIFEST_KIND = "nullid-runtime-shell-manifest";
const PRECACHE_MANIFEST_SCHEMA_VERSION = 2;
const MAX_PRECACHE_ASSET_BYTES = 16 * 1024 * 1024;
const MAX_PRECACHE_MANIFEST_BYTES = 1024 * 1024;
const STATIC_RUNTIME_DESTINATIONS = new Set(["style", "script", "worker", "font", "image", "manifest"]);

let installedPrecacheManifest = null;

function scopedUrl(pathname) {
  return new URL(pathname, self.registration.scope).toString();
}

function cacheScopeKey(scope) {
  const pathname = new URL(scope).pathname || "/";
  return `p-${encodeURIComponent(pathname)}`;
}

async function addAppShellToCache() {
  const cache = await caches.open(CACHE_NAME);
  const verifiedUrls = new Set();
  try {
    const manifest = await getPrecacheManifest();
    await clearCacheEntries(cache);
    await cache.put(manifest.url, manifest.response);
    verifiedUrls.add(manifest.url);
    for (const entry of manifest.entries) {
      const cached = await cacheVerifiedManifestEntry(cache, entry);
      if (cached) verifiedUrls.add(entry.url);
    }
    await verifyExactCacheInventory(cache, verifiedUrls);
    installedPrecacheManifest = manifest;
  } catch (error) {
    await caches.delete(CACHE_NAME);
    throw error;
  }
}

async function getPrecacheManifest() {
  const manifestUrl = scopedUrl(PRECACHE_MANIFEST_FILE);
  const manifestResponse = await fetch(manifestUrl, { cache: "no-store" });
  if (!manifestResponse.ok) {
    throw new Error(`Cannot load required precache manifest: HTTP ${manifestResponse.status}`);
  }
  requireReadableSameOriginResponse(manifestResponse, { path: PRECACHE_MANIFEST_FILE });

  const manifestBytes = await readResponseBytes(manifestResponse, MAX_PRECACHE_MANIFEST_BYTES);
  const manifestText = new TextDecoder().decode(manifestBytes);
  const manifest = JSON.parse(manifestText);
  const entries = await validatePrecacheManifest(manifest);
  return {
    url: manifestUrl,
    response: new Response(manifestBytes, responseInitFrom(manifestResponse)),
    entries,
  };
}

async function cacheVerifiedManifestEntry(cache, entry) {
  try {
    const verifiedResponse = await fetchVerifiedManifestEntry(entry);
    await cache.put(entry.url, verifiedResponse);
    return true;
  } catch (error) {
    if (entry.required) {
      throw error;
    }
    reportCacheWriteFailure(`Optional runtime-shell asset skipped: ${entry.path}`, error);
    return false;
  }
}

async function fetchVerifiedManifestEntry(entry) {
  if (entry.bytes > MAX_PRECACHE_ASSET_BYTES) {
    throw new Error(`runtime-shell asset exceeds maximum size: ${entry.path}`);
  }
  const response = await fetch(entry.url, { cache: "no-store" });
  requireReadableSameOriginResponse(response, entry);
  const bytes = await readResponseBytes(response, MAX_PRECACHE_ASSET_BYTES);
  if (bytes.byteLength !== entry.bytes) {
    throw new Error(`runtime-shell asset byte length mismatch: ${entry.path}`);
  }
  const actualHash = await sha256Hex(bytes);
  if (actualHash !== entry.sha256) {
    throw new Error(`runtime-shell asset SHA-256 mismatch: ${entry.path}`);
  }
  return new Response(bytes, responseInitFrom(response));
}

async function clearCacheEntries(cache) {
  const keys = await cache.keys();
  for (const key of keys) {
    const deleted = await cache.delete(key);
    if (!deleted) {
      throw new Error(`Cannot establish clean install cache: failed to remove ${requestUrl(key)}`);
    }
  }
}

async function verifyExactCacheInventory(cache, expectedUrls) {
  const keys = await cache.keys();
  const actualUrls = keys.map((key) => requestUrl(key)).sort();
  const expected = Array.from(expectedUrls).sort();
  if (actualUrls.length !== expected.length) {
    throw new Error("Successful install cache inventory is not exact");
  }
  for (const [index, url] of actualUrls.entries()) {
    if (url !== expected[index]) {
      throw new Error("Successful install cache inventory contains stale or missing entries");
    }
  }
}

function requireReadableSameOriginResponse(response, entry) {
  if (response.type === "opaque" || response.type === "opaqueredirect") {
    throw new Error(`runtime-shell asset is not readable: ${entry.path}`);
  }
  if (!response.ok) {
    throw new Error(`runtime-shell asset HTTP ${response.status}: ${entry.path}`);
  }
  if (response.url) {
    const responseUrl = new URL(response.url);
    if (responseUrl.origin !== self.location.origin || !isWithinServiceWorkerScope(responseUrl)) {
      throw new Error(`runtime-shell asset response outside service-worker scope: ${entry.path}`);
    }
  }
}

function responseInitFrom(response) {
  const headers = new Headers(response.headers);
  headers.delete("content-encoding");
  headers.delete("content-length");
  headers.delete("content-range");
  headers.delete("transfer-encoding");
  return {
    status: response.status,
    statusText: response.statusText,
    headers,
  };
}

async function validatePrecacheManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("Cannot load required precache manifest: invalid schema");
  }
  if (manifest.schemaVersion !== PRECACHE_MANIFEST_SCHEMA_VERSION || manifest.kind !== PRECACHE_MANIFEST_KIND) {
    throw new Error("Cannot load required precache manifest: invalid schema");
  }
  if (typeof manifest.contentHash !== "string" || !/^[a-f0-9]{64}$/u.test(manifest.contentHash)) {
    throw new Error("Cannot load required precache manifest: invalid content hash");
  }
  if (manifest.contentHash !== RUNTIME_SHELL_HASH) {
    throw new Error("Cannot load required precache manifest: content hash does not match worker");
  }
  if (!Array.isArray(manifest.assets) || !Array.isArray(manifest.entries)) {
    throw new Error("Cannot load required precache manifest: invalid asset list");
  }
  if (!Number.isInteger(manifest.assetCount) || manifest.assetCount !== manifest.entries.length || manifest.assetCount !== manifest.assets.length) {
    throw new Error("Cannot load required precache manifest: invalid asset count");
  }

  const entries = [];
  const seenPaths = new Set();
  const seenUrls = new Set();
  for (const entry of manifest.entries) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("Cannot load required precache manifest: invalid entry");
    }
    const keys = Object.keys(entry).sort();
    if (JSON.stringify(keys) !== JSON.stringify(["bytes", "path", "required", "sha256"])) {
      throw new Error("Cannot load required precache manifest: invalid entry shape");
    }
    if (typeof entry.path !== "string" || !entry.path) {
      throw new Error("Cannot load required precache manifest: invalid asset path");
    }
    if (!Number.isInteger(entry.bytes) || entry.bytes < 0) {
      throw new Error("Cannot load required precache manifest: invalid asset bytes");
    }
    if (typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(entry.sha256)) {
      throw new Error("Cannot load required precache manifest: invalid asset hash");
    }
    if (typeof entry.required !== "boolean") {
      throw new Error("Cannot load required precache manifest: invalid required flag");
    }
    const url = resolveManifestAsset(entry.path);
    if (seenPaths.has(entry.path)) {
      throw new Error("Cannot load required precache manifest: duplicate asset path");
    }
    if (seenUrls.has(url)) {
      throw new Error("Cannot load required precache manifest: duplicate canonical asset URL");
    }
    seenPaths.add(entry.path);
    seenUrls.add(url);
    entries.push({ path: entry.path, url, bytes: entry.bytes, sha256: entry.sha256, required: entry.required });
  }

  const assetPaths = manifest.assets.map((asset) => {
    if (typeof asset !== "string") {
      throw new Error("Cannot load required precache manifest: invalid asset path");
    }
    return asset;
  });
  const sortedAssetPaths = [...assetPaths].sort();
  if (JSON.stringify(assetPaths) !== JSON.stringify(sortedAssetPaths)) {
    throw new Error("Cannot load required precache manifest: assets are not sorted");
  }
  if (new Set(assetPaths).size !== assetPaths.length) {
    throw new Error("Cannot load required precache manifest: duplicate assets");
  }
  if (JSON.stringify(assetPaths) !== JSON.stringify(entries.map((entry) => entry.path))) {
    throw new Error("Cannot load required precache manifest: assets do not match entries");
  }
  const computedHash = await sha256Hex(JSON.stringify(entries.map((entry) => ({
    path: entry.path,
    bytes: entry.bytes,
    sha256: entry.sha256,
    required: entry.required,
  }))));
  if (computedHash !== manifest.contentHash) {
    throw new Error("Cannot load required precache manifest: content hash does not match entries");
  }
  return entries;
}

function resolveManifestAsset(asset) {
  if (asset.startsWith("data:")) {
    throw new Error("Cannot load required precache manifest: invalid asset path");
  }
  const resolved = new URL(asset, self.registration.scope);
  if (resolved.origin !== self.location.origin || !isWithinServiceWorkerScope(resolved)) {
    throw new Error("Cannot load required precache manifest: asset outside service-worker scope");
  }
  return resolved.toString();
}

function isWithinServiceWorkerScope(url) {
  const scope = new URL(self.registration.scope);
  return url.href.startsWith(scope.href);
}

function scopedSameOriginUrl(request) {
  const requestUrlObject = new URL(request.url);
  if (requestUrlObject.origin !== self.location.origin || !isWithinServiceWorkerScope(requestUrlObject)) {
    return null;
  }
  return requestUrlObject;
}

function isRootAppNavigation(request) {
  const requestUrlObject = scopedSameOriginUrl(request);
  if (!requestUrlObject) return false;
  const scopePath = new URL(self.registration.scope).pathname || "/";
  const normalizedScopePath = scopePath.endsWith("/") ? scopePath : `${scopePath}/`;
  return requestUrlObject.pathname === normalizedScopePath;
}

function canonicalRuntimeAssetUrl(request) {
  const requestUrlObject = scopedSameOriginUrl(request);
  if (!requestUrlObject) return null;
  requestUrlObject.search = "";
  requestUrlObject.hash = "";
  return requestUrlObject.toString();
}

function requestUrl(input) {
  return typeof input === "string" ? input : input.url;
}

async function readResponseBytes(response, maxBytes) {
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) {
      throw new Error("runtime-shell asset exceeds maximum size");
    }
    return bytes;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("runtime-shell asset exceeds maximum size");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function sha256Hex(value) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function putCacheBestEffort(cache, request, response) {
  if (!cache) return;
  try {
    await cache.put(request, response);
  } catch (error) {
    reportCacheWriteFailure("Runtime cache write failed; continuing with network response.", error);
  }
}

async function openCacheBestEffort() {
  try {
    return await caches.open(CACHE_NAME);
  } catch (error) {
    reportCacheWriteFailure("Runtime cache open failed; continuing without cache.", error);
    return null;
  }
}

function normalizedSameOriginCacheUrl(request) {
  const requestUrl = new URL(typeof request === "string" ? request : request.url);
  if (requestUrl.origin !== self.location.origin || !isWithinServiceWorkerScope(requestUrl)) {
    return null;
  }
  requestUrl.search = "";
  requestUrl.hash = "";
  return requestUrl.toString();
}

async function matchCachedResponseBestEffort(cache, request, options) {
  const cached = await openedCacheMatchBestEffort(cache, request, options);
  if (cached) return cached;

  const normalizedUrl = normalizedSameOriginCacheUrl(request);
  if (!normalizedUrl || (typeof request === "string" && normalizedUrl === request)) {
    return undefined;
  }
  return openedCacheMatchBestEffort(cache, normalizedUrl, options);
}

async function openedCacheMatchBestEffort(cache, request, options) {
  if (!cache) return undefined;
  try {
    return await cache.match(request, options);
  } catch (error) {
    reportCacheWriteFailure("Runtime opened-cache match failed; continuing without cached response.", error);
    return undefined;
  }
}

async function cacheKeysBestEffort() {
  try {
    return await caches.keys();
  } catch (error) {
    reportCacheWriteFailure("Cache cleanup key enumeration failed; continuing activation.", error);
    return [];
  }
}

async function deleteCacheBestEffort(key) {
  try {
    await caches.delete(key);
  } catch (error) {
    reportCacheWriteFailure(`Cache cleanup delete failed for ${key}; continuing activation.`, error);
  }
}

function reportCacheWriteFailure(message, error) {
  if (typeof console !== "undefined" && typeof console.warn === "function") {
    console.warn(message, error);
  }
}

async function cleanOldCaches() {
  const keys = await cacheKeysBestEffort();
  const staleKeys = keys.filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME);
  await Promise.all(staleKeys.map((key) => deleteCacheBestEffort(key)));
}

async function readCachedPrecacheManifest(cache) {
  const cachedManifest = await openedCacheMatchBestEffort(cache, scopedUrl(PRECACHE_MANIFEST_FILE));
  if (!cachedManifest) return null;
  const manifestBytes = await readResponseBytes(cachedManifest, MAX_PRECACHE_MANIFEST_BYTES);
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  const entries = await validatePrecacheManifest(manifest);
  return {
    url: scopedUrl(PRECACHE_MANIFEST_FILE),
    response: new Response(manifestBytes, responseInitFrom(cachedManifest)),
    entries,
  };
}

async function getInstalledPrecacheManifest(cache) {
  if (installedPrecacheManifest) return installedPrecacheManifest;
  if (!cache) return null;
  installedPrecacheManifest = await readCachedPrecacheManifest(cache);
  return installedPrecacheManifest;
}

function findManifestEntryByUrl(manifest, url) {
  return manifest.entries.find((entry) => entry.url === url) || null;
}

async function runtimeAssetResponse(request) {
  const canonicalUrl = canonicalRuntimeAssetUrl(request);
  if (!canonicalUrl) {
    throw new Error("Runtime asset request outside service-worker scope.");
  }
  const cache = await openCacheBestEffort();
  const manifest = await getInstalledPrecacheManifest(cache);
  const entry = manifest ? findManifestEntryByUrl(manifest, canonicalUrl) : null;
  if (!entry) {
    return fetch(request);
  }

  const cached = await matchCachedResponseBestEffort(cache, canonicalUrl);
  if (cached) {
    return cached;
  }

  try {
    const verifiedResponse = await fetchVerifiedManifestEntry(entry);
    await putCacheBestEffort(cache, canonicalUrl, verifiedResponse.clone());
    return verifiedResponse;
  } catch (error) {
    reportCacheWriteFailure(`Verified runtime-shell response unavailable: ${entry.path}`, error);
    throw error;
  }
}

async function navigationFallback() {
  const cache = await openCacheBestEffort();
  const cachedPage = await openedCacheMatchBestEffort(cache, scopedUrl("index.html"));
  if (cachedPage) {
    return cachedPage;
  }

  try {
    const manifest = (await getInstalledPrecacheManifest(cache)) || (await getPrecacheManifest());
    const entry = findManifestEntryByUrl(manifest, scopedUrl("index.html"));
    if (!entry) {
      throw new Error("Current runtime-shell manifest does not contain index.html");
    }
    const verifiedResponse = await fetchVerifiedManifestEntry(entry);
    await putCacheBestEffort(cache, entry.url, verifiedResponse.clone());
    return verifiedResponse;
  } catch (error) {
    reportCacheWriteFailure("Verified navigation shell unavailable; returning offline response.", error);

    return new Response("NullID is offline. Reload once while online to cache this page.", {
      status: 503,
      statusText: "Service Unavailable",
      headers: { "Content-Type": "text/plain; charset=UTF-8" },
    });
  }
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    addAppShellToCache(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    cleanOldCaches(),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") {
    return;
  }

  if (!scopedSameOriginUrl(request)) {
    return;
  }

  if (request.mode === "navigate" && isRootAppNavigation(request)) {
    event.respondWith(navigationFallback());
    return;
  }

  if (STATIC_RUNTIME_DESTINATIONS.has(request.destination)) {
    event.respondWith(runtimeAssetResponse(request));
    return;
  }
});
