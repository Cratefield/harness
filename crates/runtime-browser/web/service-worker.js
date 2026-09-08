// Production ingress: intercept `fetch` of `/api/*` and serve it from the
// in-tab wasm venture instead of the network. Register with
// `navigator.serviceWorker.register('./service-worker.js', { type: 'module' })`.
//
// STATUS: written to the documented APIs; NOT yet run in a browser. Running
// wasm-bindgen ESM + sqlite-wasm inside a Service Worker is plausible but
// unverified — the demo page (index.html) drives the same `callHandle`
// contract directly, which is the path to try first. See web/README.md.

import init, * as wasm from './pkg/cratefield_runtime_browser_demo.js';
import { installSqliteBridge } from './sqlite_bridge.js';
import { callHandle } from './api.js';

const HARNESS_SECRET = 'browser-demo-secret-please-change-me-32b';
const ADMIN_TOKEN = 'demo-admin-token';

let ready;
async function boot() {
  await init();
  await installSqliteBridge();
  wasm.init(HARNESS_SECRET, ADMIN_TOKEN);
  await wasm.migrate();
}
function ensureReady() {
  ready = ready || boot();
  return ready;
}

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(ensureReady());
});
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith('/api/')) { return; }
  event.respondWith((async () => {
    await ensureReady();
    // Map `/api/<rest>` onto the harness path `/<rest>`.
    const path = url.pathname.replace(/^\/api/, '') + url.search;
    const headers = [...event.request.headers.entries()];
    const bodyBytes = new Uint8Array(await event.request.arrayBuffer());
    const res = await callHandle(wasm, event.request.method, self.location.origin + path, headers, bodyBytes);
    return new Response(res.bytes, { status: res.status, headers: res.headers });
  })());
});
