const CACHE_VERSION = "v2";
const CACHE_NAME = `nullid-cache-${CACHE_VERSION}`;
const APP_SHELL_FILES = [
  ".",
  "index.html",
  "manifest.webmanifest",
  "nullid-preview.png",
  "favicon.svg",
  "icons/favicon-16.png",
  "icons/favicon-32.png",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "icons/icon-512-maskable.png",
  "icons/apple-touch-icon.png",
];

function scopedUrl(pathname) {
  return new URL(pathname, self.registration.scope).toString();
}

async function addAppShellToCache() {
  const cache = await caches.open(CACHE_NAME);
  const shellUrls = APP_SHELL_FILES.map((file) => scopedUrl(file));
  const assetUrls = await getIndexAssetUrls();
  const urls = Array.from(new Set([...shellUrls, ...assetUrls]));
  await cache.addAll(urls);
}

async function getIndexAssetUrls() {
  try {
    const indexResponse = await fetch(scopedUrl("index.html"), { cache: "no-cache" });
    if (!indexResponse.ok) {
      return [];
    }

    const html = await indexResponse.text();
    const base = scopedUrl(".");
    const matches = html.matchAll(/(?:href|src)="([^"]+)"/g);
    const urls = [];

    for (const match of matches) {
      const rawPath = match[1];
      if (!rawPath || rawPath.startsWith("data:")) {
        continue;
      }

      const resolved = new URL(rawPath, base);
      if (resolved.origin === self.location.origin) {
        urls.push(resolved.toString());
      }
    }

    return urls;
  } catch {
    return [];
  }
}

async function cleanOldCaches() {
  const keys = await caches.keys();
  const staleKeys = keys.filter((key) => key.startsWith("nullid-cache-") && key !== CACHE_NAME);
  await Promise.all(staleKeys.map((key) => caches.delete(key)));
}

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) {
    return cached;
  }

  const response = await fetch(request);
  if (response.ok) {
    const cache = await caches.open(CACHE_NAME);
    cache.put(request, response.clone());
  }
  return response;
}

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    if (cached) {
      return cached;
    }
    throw new Error("Network request failed and no cache was found.");
  }
}

async function navigationFallback(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cache = await caches.open(CACHE_NAME);
    const cachedPage =
      (await cache.match(request, { ignoreSearch: true })) ||
      (await cache.match(scopedUrl("."))) ||
      (await cache.match(scopedUrl("index.html")));

    if (cachedPage) {
      return cachedPage;
    }

    return new Response("NullID is offline. Reload once while online to cache this page.", {
      status: 503,
      statusText: "Service Unavailable",
      headers: { "Content-Type": "text/plain; charset=UTF-8" },
    });
  }
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      await addAppShellToCache();
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      await cleanOldCaches();
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") {
    return;
  }

  const requestUrl = new URL(request.url);
  if (requestUrl.origin !== self.location.origin) {
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(navigationFallback(request));
    return;
  }

  const staticDestinations = new Set(["style", "script", "worker", "font", "image", "manifest"]);
  if (staticDestinations.has(request.destination)) {
    event.respondWith(cacheFirst(request));
    return;
  }

  event.respondWith(networkFirst(request));
});
