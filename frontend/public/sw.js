/* sw.js - Digi Samurai ASM Service Worker for Offline Caching */

const CACHE_NAME = 'digi-samurai-asm-v1';

// Routes and assets to pre-cache on installation
const PRECACHE_ASSETS = [
  '/',
  '/_not-found',
  '/login',
  '/dashboard',
  '/assets',
  '/recon',
  '/vulnerabilities',
  '/scans',
  '/scheduler',
  '/reports',
  '/settings',
  '/shannon',
  '/super-admin',
  '/super-admin/organizations',
  '/organization/users'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        // Pre-cache primary routes
        return cache.addAll(PRECACHE_ASSETS).catch(err => {
          console.warn("Failed to pre-cache some assets:", err);
        });
      })
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Network-First with Cache-Fallback Strategy
self.addEventListener('fetch', (event) => {
  const requestUrl = new URL(event.request.url);

  // Bypass API requests, non-GET requests, or webpack hot-reload assets
  if (
    requestUrl.pathname.startsWith('/api/') || 
    event.request.method !== 'GET' ||
    requestUrl.pathname.startsWith('/_next/webpack-hmr')
  ) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // If request succeeded, clone response and write it to cache
        if (response && response.status === 200 && response.type === 'basic') {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return response;
      })
      .catch(() => {
        // Network failed (offline). Search cache.
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }
          
          // Fallback to offline index for page navigation
          if (event.request.mode === 'navigate') {
            return caches.match('/dashboard') || caches.match('/');
          }
        });
      })
  );
});
