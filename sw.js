// ============================================================
//  RedCW — Service Worker (PWA)
// ============================================================
const CACHE_NAME = "redcw-v1";
const ASSETS_TO_CACHE = [
  "/",
  "/index.html",
  "/css/app.css",
  "/js/config.js",
  "/js/supabase.js",
  "/js/app.js",
  "/js/pages.js",
  "/js/auth.js",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=Fira+Sans:wght@300;400;500;600&display=swap",
];

// ── Install ─────────────────────────────────────────────────
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE.filter(u => !u.startsWith("http")));
    })
  );
  self.skipWaiting();
});

// ── Activate ─────────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── Fetch (Network first, fallback to cache) ─────────────────
self.addEventListener("fetch", (event) => {
  // Skip Supabase API calls — always go to network
  if (event.request.url.includes("supabase.co")) return;
  
  event.respondWith(
    fetch(event.request)
    .then((response) => {
      if (response && response.status === 200 && response.type === "basic") {
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
      }
      return response;
    })
    .catch(() => caches.match(event.request))
  );
});

// ── Push notifications (placeholder) ─────────────────────────
self.addEventListener("push", (event) => {
  const data = event.data?.json() || {};
  event.waitUntil(
    self.registration.showNotification(data.title || "RedCW", {
      body: data.body || "Nueva notificación",
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      data: data,
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(clients.openWindow("/"));
});