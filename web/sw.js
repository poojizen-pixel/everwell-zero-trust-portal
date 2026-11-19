'use strict';
// Service worker of the Everwell Health Portal (the interface of the Zero Trust hospital information system demonstration).
// It caches ONLY the public static shell (HTML, CSS, JS, icons, manifest, offline page) so that the app opens and shows an offline page
// without a connection. It never touches /api, /ctl or /admin, never stores a response to an authenticated request, and never sees a
// token: every protected request goes straight to the network (the service worker does not even call respondWith for it).
const VERSION = 'zt-shell-v4';      // bumped with the role-specific interfaces (v3: Everwell branding) so installed copies replace their cached shell, icons and names
const SHELL = ['/', '/index.html', '/styles.css', '/app.js', '/manifest.webmanifest', '/offline.html', '/favicon.png',
  '/icons/icon-192.png', '/icons/icon-512.png', '/icons/icon-maskable-512.png'];
const DYNAMIC = ['/api/', '/ctl/', '/admin/'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(VERSION)
      .then((cache) => cache.addAll(SHELL.map((url) => new Request(url, { cache: 'reload' }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== VERSION).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;                         // not ours
  if (DYNAMIC.some((prefix) => url.pathname.startsWith(prefix)) || request.headers.has('authorization')) return;   // protected: network only, never stored
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => caches.match('/offline.html')));
    return;
  }
  event.respondWith(
    caches.match(request).then((hit) => {
      const network = fetch(request).then((response) => {
        if (response.ok && SHELL.includes(url.pathname)) {
          const copy = response.clone();
          caches.open(VERSION).then((cache) => cache.put(request, copy));
        }
        return response;
      }).catch(() => hit);
      return hit || network;
    })
  );
});
