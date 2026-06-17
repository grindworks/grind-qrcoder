// Update this version to trigger a cache update (Format: YYYYMMDD-Revision)
const CACHE_NAME = "grindqrcoder-v20260617-11";
const urlsToCache = [
  "./",
  "./index.html",
  "./styles.css",
  "./main.js?v=clear-cache-2",
  "./icon-192.png",
  "./icon-512.png",
  "./icons-sprite.svg",
  "./ICON_GOOGLE_MAPS.png",
  "./ICON_FACEBOOK.png",
  "./ICON_INSTAGRAM.png",
  "./ICON_TIKTOK.png",
  "./ICON_X.png",
  "./ICON_ZOOM.png",
  "./poster.jpg",
  "./card.png",
  "./manifest.json"
];

const externalUrlsToCache = [
  "https://cdn.jsdelivr.net/npm/alpinejs@3.13.5/dist/cdn.min.js",
  "https://cdn.jsdelivr.net/npm/@alpinejs/collapse@3.13.5/dist/cdn.min.js",
  "https://cdn.jsdelivr.net/npm/@alpinejs/focus@3.13.5/dist/cdn.min.js",
  "https://unpkg.com/qr-code-styling@1.9.2/lib/qr-code-styling.js",
  "https://cdn.jsdelivr.net/npm/fflate@0.8.2/umd/index.js",
  "https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js",
  "https://cdn.jsdelivr.net/npm/dompurify@3.0.9/dist/purify.min.js",
  "https://grindsite.com/tools/footer.js"
];

// Create cache on install
self.addEventListener("install", (event) => {
  // Activate new Service Worker immediately
  self.skipWaiting();

  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      console.log("Opened cache");
      // Add local files to cache
      await cache.addAll(urlsToCache);
      // Add external CDN files individually with CORS
      for (const url of externalUrlsToCache) {
        try {
          const request = new Request(url, { mode: "cors" });
          const response = await fetch(request);
          // Prevent caching broken responses like 404 errors
          if (response.ok) {
            await cache.put(request, response);
          } else {
            console.error(
              "Skipped caching because external resource fetch failed:",
              response.status,
              url,
            );
          }
        } catch (error) {
          console.error("Failed to cache external resource:", url, error);
        }
      }
    }),
  );
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

// Return cache on fetch (Stale-while-revalidate strategy)
self.addEventListener("fetch", (event) => {
  // Bypass cache for non-GET requests
  if (event.request.method !== "GET") return;

  event.respondWith(
    // Ignore query parameters to ensure cache hits
    caches.match(event.request, { ignoreSearch: true }).then((response) => {
      // Fetch latest resources from network and update cache on success (background)
      const fetchPromise = fetch(event.request)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.ok && (networkResponse.type === "basic" || networkResponse.type === "cors")) {
            // Do not cache requests with query parameters (e.g., Share Target) to avoid bloat
            if (!event.request.url.includes("?")) {
              const responseToCache = networkResponse.clone();
              caches.open(CACHE_NAME).then((cache) => {
                cache.put(event.request, responseToCache);
              });
            }
          }
          return networkResponse;
        })
        .catch(() => {
          // Fallback when offline and not in cache (only for HTML requests)
          if (
            event.request.mode === "navigate" ||
            (event.request.headers.get("accept") && event.request.headers.get("accept").includes("text/html"))
          ) {
            const fallbackHtml = `\n            <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>QR Coder - Notification</title><style>body { font-family: sans-serif; background-color: #fafafa; color: #333; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; padding: 20px; } h1 { font-size: 20px; color: #111827; margin-bottom: 16px; font-weight: bold; } p { font-size: 15px; color: #4b5563; line-height: 1.6; margin-bottom: 24px; } .icon { font-size: 48px; margin-bottom: 16px; }</style></head><body><div class="icon">💡</div><h1>Browser cache seems to have been cleared.</h1><p>Your data is safely stored on your PC.<br><br>To use the app offline again, please connect to the internet and access it once.</p></body></html>\n          `;
            return new Response(fallbackHtml, {
              headers: { "Content-Type": "text/html; charset=utf-8" },
            });
          }
        });

      // Silently absorb errors from asynchronous fetchPromise
      fetchPromise.catch(() => {});

      // Return cache immediately if available, otherwise wait for fetchPromise
      return response || fetchPromise;
    }),
  );
});
