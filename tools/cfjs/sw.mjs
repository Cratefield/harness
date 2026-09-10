// The reference push service worker (issue #183), in a fake
// ServiceWorkerGlobalScope.
//
// A service worker is a script with a handful of globals, so it runs
// under `node:vm` with those globals faked and its events dispatched by
// hand. That covers the three listeners and the payload contract — what
// it cannot cover is a real browser actually delivering a push, which is
// the vendor-live leg (issue #186, needs-human).
import { readFileSync } from "node:fs";
import vm from "node:vm";

const ORIGIN = "https://site.example.test";
const KEY = "BMnoZrNHaWFZwLcli9rMtHS5Y7IMqsKZ4_gc9aCFGZ-hrjPdTHuYbdiXP5q5FoG6QoaJxJ1K9Ub6MZ5DCvd81qA";
const ENDPOINT = "https://push.example.test/subscription/a-secret-capability";

const source = readFileSync(new URL("../../crates/ui/assets/sw-push.js", import.meta.url), "utf8");

let failures = 0;
function assert(cond, message) {
  if (cond) {
    console.log(`ok: ${message}`);
  } else {
    failures += 1;
    console.error(`FAIL: ${message}`);
  }
}

/** A window this worker can see. `url` is what `client.url` reports. */
function client(url, id) {
  return {
    id,
    url,
    focused: false,
    navigatedTo: null,
    messages: [],
    focus() {
      this.focused = true;
      return this;
    },
    navigate(to) {
      this.navigatedTo = to;
      return this;
    },
    postMessage(message) {
      this.messages.push(message);
    },
  };
}

/** A fake `ServiceWorkerGlobalScope` with the worker evaluated in it. */
function worker(options = {}) {
  const listeners = new Map();
  const notifications = [];
  const opened = [];
  const cache = new Map();
  let subscription = options.subscription ?? null;
  const subscribeCalls = [];

  const self = {
    location: { origin: ORIGIN },
    skipWaiting: () => {},
    clients: {
      claim: async () => {},
      matchAll: async () => options.clients ?? [],
      openWindow: async (url) => {
        opened.push(url);
        return client(url, "opened");
      },
    },
    registration: {
      showNotification: async (title, init) => notifications.push({ title, ...init }),
      pushManager: {
        getSubscription: async () => subscription,
        subscribe: async (init) => {
          subscribeCalls.push(init);
          subscription = { endpoint: ENDPOINT };
          return subscription;
        },
      },
    },
    addEventListener: (type, handler) => listeners.set(type, handler),
  };

  const context = {
    self,
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
    Uint8Array,
    URL,
    Response: class {
      constructor(body) {
        this.body = body;
      }
      async text() {
        return this.body;
      }
    },
    caches: {
      open: async () => ({
        put: async (key, response) => cache.set(key, response),
        match: async (key) => cache.get(key),
      }),
    },
    console,
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "sw-push.js" });

  return {
    notifications,
    opened,
    cache,
    subscribeCalls,
    get subscription() {
      return subscription;
    },
    /** Dispatches one event and awaits whatever it held open. */
    async dispatch(type, event = {}) {
      const held = [];
      const handler = listeners.get(type);
      if (!handler) throw new Error(`the worker registers no ${type} listener`);
      handler({ ...event, waitUntil: (promise) => held.push(promise) });
      await Promise.all(held);
    },
    has: (type) => listeners.has(type),
  };
}

/** `event.data` the way the Push API hands over an encrypted payload. */
function payload(json) {
  return {
    json: () => JSON.parse(json),
    text: () => json,
  };
}

// ---------------------------------------------------------------------------

console.log("-- the adapter's payload");
{
  const w = worker();
  // Exactly what `build_payload` in `cratefield-adapter-webpush` emits.
  await w.dispatch("push", {
    data: payload(
      JSON.stringify({
        title: "Your room starts soon",
        body: "Studio 2, in ten minutes",
        icon: "/icon-192.png",
        url: "/rooms/17",
        tag: "room-17",
        silent: false,
        data: { room: "17" },
      }),
    ),
  });
  const shown = w.notifications[0];
  assert(shown.title === "Your room starts soon", "the title is the adapter's `title`");
  assert(shown.body === "Studio 2, in ten minutes", "the body is the adapter's `body`");
  assert(shown.icon === "/icon-192.png", "the icon is passed through");
  assert(shown.tag === "room-17", "`tag` is what the adapter maps `thread_id` to");
  assert(shown.silent === false, "`silent` is always present and is a boolean");
  assert(shown.data.room === "17", "a caller's own `data` keys survive");
  assert(shown.data.url === "/rooms/17", "and `url` joins them, which is where the click reads it");
}
{
  const w = worker();
  await w.dispatch("push", { data: payload(JSON.stringify({ body: "no title" })) });
  assert(
    typeof w.notifications[0].title === "string" && w.notifications[0].title.length > 0,
    "a payload with no title still shows one: a push that displays nothing costs the permission",
  );
}
{
  const w = worker();
  await w.dispatch("push", { data: { json: () => JSON.parse("{"), text: () => "not our json" } });
  assert(w.notifications.length === 1, "a payload that is not ours still shows a notification");
}
{
  const w = worker();
  await w.dispatch("push", { data: payload(JSON.stringify({ title: "t", badge: 4 })) });
  assert(
    w.notifications[0].badge === undefined,
    "`badge` is not forwarded — the port's is a count and the web's is an icon URL",
  );
}

console.log("-- notificationclick focuses rather than opening a second tab");
{
  const other = client(`${ORIGIN}/somewhere-else`, "a");
  const showing = client(`${ORIGIN}/rooms/17`, "b");
  const w = worker({ clients: [other, showing] });
  await w.dispatch("notificationclick", {
    notification: { close: () => {}, data: { url: "/rooms/17" } },
  });
  assert(showing.focused === true, "the tab already on that URL is focused");
  assert(other.focused === false, "and the other one is left alone");
  assert(w.opened.length === 0, "no second window is opened");
}
{
  const open = client(`${ORIGIN}/`, "a");
  const w = worker({ clients: [open] });
  await w.dispatch("notificationclick", {
    notification: { close: () => {}, data: { url: "/rooms/17" } },
  });
  assert(open.focused === true, "with no exact match an open window is focused");
  assert(open.navigatedTo === `${ORIGIN}/rooms/17`, "and navigated, rather than a second one opened");
  assert(w.opened.length === 0, "still no second window");
}
{
  const w = worker({ clients: [] });
  await w.dispatch("notificationclick", {
    notification: { close: () => {}, data: { url: "/rooms/17" } },
  });
  assert(w.opened[0] === `${ORIGIN}/rooms/17`, "with nothing open, a window is opened");
}
{
  const w = worker({ clients: [] });
  await w.dispatch("notificationclick", { notification: { close: () => {}, data: {} } });
  assert(w.opened[0] === `${ORIGIN}/`, "a notification with no url opens the site root");
}
{
  const open = client(`${ORIGIN}/`, "a");
  const w = worker({ clients: [open] });
  await w.dispatch("notificationclick", {
    notification: { close: () => {}, data: { url: "https://elsewhere.example/x" } },
  });
  assert(
    open.navigatedTo === null && w.opened[0] === "https://elsewhere.example/x",
    "a cross-origin target is opened, never navigated into (client.navigate refuses it)",
  );
}

console.log("-- pushsubscriptionchange");
{
  const w = worker();
  await w.dispatch("message", { data: { type: "cf-push-key", key: KEY } });
  assert(w.cache.size === 1, "the page's key is remembered, and it is the only thing stored");
  await w.dispatch("pushsubscriptionchange", { oldSubscription: null });
  assert(w.subscribeCalls.length === 1, "the worker re-subscribes on its own");
  const init = w.subscribeCalls[0];
  assert(init.userVisibleOnly === true, "with userVisibleOnly, as the first subscribe had");
  assert(init.applicationServerKey.length === 65, "and with the stored key, decoded to bytes");
  assert(init.applicationServerKey[0] === 0x04, "an uncompressed P-256 point");
}
{
  const page = client(`${ORIGIN}/`, "a");
  const w = worker({ clients: [page] });
  await w.dispatch("message", { data: { type: "cf-push-key", key: KEY } });
  await w.dispatch("pushsubscriptionchange", { oldSubscription: null });
  assert(page.messages[0]?.type === "cf-push-resubscribed", "an open page is told to re-register");
  const said = JSON.stringify(page.messages);
  assert(!said.includes(ENDPOINT), "the new endpoint never travels in the message — it is a credential");
  assert(!said.includes(KEY), "and neither does the key: the page has its own");
}
{
  // Chrome hands the old subscription's key back; the worker takes it
  // rather than insisting on the stored copy.
  const w = worker();
  await w.dispatch("pushsubscriptionchange", {
    oldSubscription: { options: { applicationServerKey: Uint8Array.from([4, 1, 2, 3]) } },
  });
  assert(w.subscribeCalls[0]?.applicationServerKey.length === 4, "the event's own key is used when it carries one");
}
{
  // Nothing stored and nothing on the event: re-subscribing would need a
  // key nobody has. It must not throw, or the event handler's rejection
  // is all that happens.
  const w = worker();
  await w.dispatch("pushsubscriptionchange", { oldSubscription: null });
  assert(w.subscribeCalls.length === 0, "with no key anywhere, it gives up quietly rather than throwing");
}
{
  // The browser already made the replacement: use it, do not make a
  // second one and orphan the first.
  const w = worker();
  await w.dispatch("pushsubscriptionchange", { newSubscription: { endpoint: ENDPOINT } });
  assert(w.subscribeCalls.length === 0, "a subscription the browser supplied is not replaced");
}

console.log("-- the three listeners exist at all");
for (const type of ["push", "notificationclick", "pushsubscriptionchange", "message", "install", "activate"]) {
  assert(worker().has(type), `the worker registers a ${type} listener`);
}

if (failures) {
  console.error(`sw-push.js: ${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("sw-push.js: all assertions passed");
