// Update this version to trigger a cache update (Format: YYYYMMDD-Revision)
const CACHE_NAME = "grindqrcoder-v20261020-3";
const urlsToCache = [
  "./",
  "./styles.css",
  "./main.js",
  "./icon-192.png",
  "./icon-512.png",
  "./grind-qrcoder.jpg",
  "./ICON_GOOGLE_MAPS.png",
  "./ICON_FACEBOOK.png",
  "./ICON_INSTAGRAM.png",
  "./ICON_TIKTOK.png",
  "./ICON_X.png",
  "./ICON_ZOOM.png",
  "./poster.jpg",
  "./card.png",
  "./manifest.json",
  "./assets/alpine.min.js",
  "./assets/alpine-collapse.min.js",
  "./assets/alpine-focus.min.js",
  "./assets/qr-code-styling.js",
  "./assets/fflate.min.js",
  "./assets/html5-qrcode.min.js",
  "./assets/purify.min.js"
];

// Create cache on install
// The new worker waits until the page asks for it (SKIP_WAITING) so a running page never mixes versions
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      console.log("Opened cache");
      await cache.addAll(urlsToCache.map((url) => new Request(url, { cache: "reload" })));
    }),
  );
});

self.addEventListener("message", (event) => {
  if (event.data === "SKIP_WAITING") self.skipWaiting();
});

// Delete old caches
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName.startsWith("grindqrcoder-") && cacheName !== CACHE_NAME) {
              console.log("Deleted old cache:", cacheName);
              return caches.delete(cacheName);
            }
          }),
        );
      })
      .then(() => self.clients.claim()),
  );
});

const offlineFallbackHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>QR Coder - Notification</title><style>body { font-family: sans-serif; background-color: #fafafa; color: #333; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; padding: 20px; } h1 { font-size: 20px; color: #111827; margin-bottom: 16px; font-weight: bold; } p { font-size: 15px; color: #4b5563; line-height: 1.6; margin-bottom: 24px; } .icon { font-size: 48px; margin-bottom: 16px; }</style></head><body><div class="icon">💡</div><h1>Browser cache seems to have been cleared.</h1><p>Your data is safely stored on your PC.<br><br>To use the app offline again, please connect to the internet and access it once.</p></body></html>`;

const precachedPaths = new Set(urlsToCache.map((url) => new URL(url, self.location).pathname));

function isHtmlRequest(request) {
  return request.mode === "navigate" || (request.headers.get("accept") || "").includes("text/html");
}

function offlineResponse(request) {
  if (isHtmlRequest(request)) {
    return new Response(offlineFallbackHtml, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  return Response.error();
}

self.addEventListener("fetch", (event) => {
  // Bypass cache for non-GET or non-HTTP requests
  if (event.request.method !== "GET" || !event.request.url.startsWith("http")) return;

  const url = new URL(event.request.url);
  const isPrecached = url.origin === self.location.origin && precachedPaths.has(url.pathname);

  if (isPrecached) {
    // App shell: served only from this version's cache (updated as a whole via CACHE_NAME)
    event.respondWith(
      caches.open(CACHE_NAME)
        .then((cache) => cache.match(event.request, { ignoreSearch: true }))
        .then((response) => response || fetch(event.request))
        .catch(() => offlineResponse(event.request)),
    );
    return;
  }

  // Everything else: stale-while-revalidate
  event.respondWith(
    caches.match(event.request, { ignoreSearch: true }).then((response) => {
      const fetchPromise = fetch(event.request)
        .then((networkResponse) => {
          // Do not cache requests with query parameters (e.g., Share Target) to avoid bloat
          if (networkResponse && networkResponse.ok && networkResponse.type === "basic" && !url.search) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseToCache));
          }
          return networkResponse;
        })
        .catch(() => offlineResponse(event.request));

      // Silently absorb errors from asynchronous fetchPromise
      fetchPromise.catch(() => {});
      return response || fetchPromise;
    }),
  );
});
