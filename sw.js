// 💡 アップデート時はここを書き換えることで更新が発火します
const CACHE_NAME = "grindqrcoder-v93";
const urlsToCache = [
  "./",
  "./index.html",
  "./styles.css",
  "./main.js",
  "./icon-192.png",
  "./icon-512.png",
  "./icons-sprite.svg",
  "./ICON_EMAIL.png",
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
  "https://unpkg.com/qr-code-styling@1.9.2/lib/qr-code-styling.js"
];

// インストール時にキャッシュを作成
self.addEventListener("install", (event) => {
  // 新しいService Workerを即座にアクティブにする
  self.skipWaiting();

  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      console.log("Opened cache");
      // ローカルファイルは通常通り一括追加
      await cache.addAll(urlsToCache);
      // 外部CDNファイルはCORS対応のため cors で個別に追加
      for (const url of externalUrlsToCache) {
        try {
          const request = new Request(url, { mode: "cors" });
          const response = await fetch(request);
          // 404エラーなどで壊れたキャッシュを保存しないための防波堤
          if (response.ok) {
            await cache.put(request, response);
          } else {
            console.error(
              "外部リソースの取得に失敗したためキャッシュをスキップしました:",
              response.status,
              url,
            );
          }
        } catch (error) {
          console.error("外部リソースのキャッシュに失敗しました:", url, error);
        }
      }
    }),
  );
});

// 古いキャッシュを削除
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== CACHE_NAME) {
              console.log("古いキャッシュを削除しました:", cacheName);
              return caches.delete(cacheName);
            }
          }),
        );
      })
      .then(() => self.clients.claim()),
  );
});

// fetchイベントでキャッシュを返す (Stale-while-revalidate 戦略に変更)
self.addEventListener("fetch", (event) => {
  // GETリクエスト以外はキャッシュ処理をバイパス
  if (event.request.method !== "GET") return;

  event.respondWith(
    // クエリパラメータを無視してWASMファイルなどを確実にキャッシュヒットさせる
    caches.match(event.request, { ignoreSearch: true }).then((response) => {
      // ネットワークから最新リソースをフェッチし、成功すればキャッシュを更新する（裏側で実行）
      const fetchPromise = fetch(event.request)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.ok && (networkResponse.type === "basic" || networkResponse.type === "cors")) {
            // クエリパラメータ付きのリクエスト（Share Target 等）はキャッシュを肥大化させるため保存しない
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
          // オフラインかつキャッシュにもない場合のフォールバック（HTMLへのアクセス時のみ）
          if (
            event.request.mode === "navigate" ||
            (event.request.headers.get("accept") && event.request.headers.get("accept").includes("text/html"))
          ) {
            const fallbackHtml = `\n            <!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>QR Coder - 通知</title><style>body { font-family: sans-serif; background-color: #fafafa; color: #333; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; padding: 20px; } h1 { font-size: 20px; color: #111827; margin-bottom: 16px; font-weight: bold; } p { font-size: 15px; color: #4b5563; line-height: 1.6; margin-bottom: 24px; } .icon { font-size: 48px; margin-bottom: 16px; }</style></head><body><div class="icon">💡</div><h1>ブラウザのキャッシュがクリアされたようです</h1><p>データはあなたのPCに安全に保存されています。<br><br>アプリを再びオフラインで使うには、一度インターネットに接続した状態でアクセスし直してください。</p></body></html>\n          `;
            return new Response(fallbackHtml, {
              headers: { "Content-Type": "text/html; charset=utf-8" },
            });
          }
        });

      // キャッシュがあれば即座に返し、なければ fetchPromise の結果を待つ
      return response || fetchPromise;
    }),
  );
});
