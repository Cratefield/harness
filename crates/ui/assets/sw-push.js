/* The reference push service worker (issue #183). Served at
 * /ui/sw-push.js with `Service-Worker-Allowed: /`, and meant to be
 * copied: a service worker can only be registered from the origin of the
 * page that registers it, and a venture's site is rarely the API origin.
 *
 *   cp sw-push.js <site root>/sw.js
 *   cf.push.subscribe()            // registers /sw.js by default
 *
 * A venture that already has a service worker pastes the three listeners
 * into it instead. They are independent of everything else a worker does.
 *
 * It reads the JSON `cratefield-adapter-webpush` sends — title, body,
 * icon, url, tag, silent, data — and nothing else. No analytics, no
 * fetch of its own, and nothing it stores is a credential: the only
 * thing kept is the venture's application server key, which is public by
 * definition, so that `pushsubscriptionchange` can re-subscribe with it.
 * The subscription endpoint itself is never stored, logged or messaged.
 */

const STORE = "cf-push-v1";
const KEY_URL = "/__cf-push-key";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

/** The page hands over the application server key at subscribe time.
 *  `pushsubscriptionchange` fires with no page open, so the worker has to
 *  hold its own copy: `event.oldSubscription.options` carries one in some
 *  browsers and in none of the others. */
self.addEventListener("message", (event) => {
  if (event.data?.type === "cf-push-key" && event.data.key) {
    event.waitUntil(remember(event.data.key));
  }
});

async function remember(key) {
  const cache = await caches.open(STORE);
  await cache.put(KEY_URL, new Response(key));
}

async function recall() {
  const cache = await caches.open(STORE);
  const stored = await cache.match(KEY_URL);
  return stored ? stored.text() : null;
}

/** base64url → Uint8Array. The same conversion cf.js does, because the
 *  worker re-subscribes without it. */
function keyBytes(key) {
  const padded = key.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (key.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** The adapter's payload, shown. A push that fails to display is a
 *  permission the browser takes away, so there is always a title. */
self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    // Not our JSON (a test send from another tool, say). Show what
    // there is rather than nothing, and never log the body.
    payload = { body: event.data ? event.data.text() : "" };
  }
  const options = {
    body: payload.body || "",
    icon: payload.icon,
    tag: payload.tag,
    silent: payload.silent === true,
    // `url` travels inside `data` because that is where the click
    // handler reads it back from; a caller's own `data` keeps its keys.
    data: { ...(payload.data || {}), url: payload.url },
  };
  event.waitUntil(self.registration.showNotification(payload.title || "Notification", options));
});

/** Focus the tab that is already showing it, rather than opening a
 *  second one. An exact match wins; failing that any window on this
 *  origin is focused and navigated. */
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(open(event.notification.data?.url));
});

async function open(url) {
  const target = new URL(url || "/", self.location.origin);
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  if (target.origin !== self.location.origin) {
    return self.clients.openWindow?.(target.href);
  }
  for (const client of windows) {
    if (client.url === target.href) return client.focus();
  }
  const first = windows[0];
  if (first?.navigate) {
    await first.focus();
    return first.navigate(target.href);
  }
  return self.clients.openWindow?.(target.href);
}

/** The event that silently kills a subscription if it is ignored: the
 *  browser has replaced this browser's subscription, and until the new
 *  one is registered every send goes to an endpoint that is gone.
 *
 *  Re-subscribing is the half only the worker can do. Re-registering
 *  needs an access token, which a worker has no business holding, so it
 *  wakes any open page and `cf.push.sync()` there does the PUT. With no
 *  page open the next visit repairs it — `cf.push.sync()` re-registers
 *  whatever subscription the browser holds — and the old endpoint
 *  answers `410 Gone`, which is the one status that prunes the row. */
self.addEventListener("pushsubscriptionchange", (event) => {
  event.waitUntil(resubscribe(event));
});

async function resubscribe(event) {
  let subscription = event.newSubscription || (await self.registration.pushManager.getSubscription());
  if (!subscription) {
    const key = event.oldSubscription?.options?.applicationServerKey || (await recall().then((k) => k && keyBytes(k)));
    if (!key) return;
    subscription = await self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: key,
    });
  }
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  // The signal only. The page reads the subscription from its own
  // `getSubscription()`, so the endpoint never travels in a message.
  for (const client of windows) client.postMessage({ type: "cf-push-resubscribed" });
}
