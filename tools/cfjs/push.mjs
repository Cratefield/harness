// The push half of cf.js (issue #183), against stubbed browser APIs.
//
// It runs the file that ships, byte for byte apart from the two edits
// `test.mjs` makes (the module origin, and the export line jsdom's
// classic-script eval cannot take). Nothing here needs a server, so it
// runs in the size-gate job rather than the wrangler one.
//
// A fresh JSDOM per case on purpose: cf.js caches the application server
// key for the life of a page, and a shared world would let one case's
// fetch answer another's.
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

const API = "https://api.example.test";
// A P-256 public point, uncompressed, base64url: 87 characters, 65 bytes.
const KEY = "BMnoZrNHaWFZwLcli9rMtHS5Y7IMqsKZ4_gc9aCFGZ-hrjPdTHuYbdiXP5q5FoG6QoaJxJ1K9Ub6MZ5DCvd81qA";
const ENDPOINT = "https://push.example.test/subscription/a-secret-capability";
const TOKEN = "an-access-token";

const source = readFileSync(new URL("../../crates/ui/assets/cf.js", import.meta.url), "utf8");
const script = source
  .replace("new URL(import.meta.url).origin", JSON.stringify(API))
  .replace(/^export .*$/m, "");

let failures = 0;
function assert(cond, message) {
  if (cond) {
    console.log(`ok: ${message}`);
  } else {
    failures += 1;
    console.error(`FAIL: ${message}`);
  }
}

async function rejects(promise, message) {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  failures += 1;
  console.error(`FAIL: ${message} (it resolved)`);
  return null;
}

/** A page with the push APIs stubbed. `options` decides what the browser
 *  looks like; everything the code did is recorded on the returned world. */
function world(options = {}) {
  const dom = new JSDOM("<!doctype html><body></body>", {
    url: "https://site.example.test/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const { window } = dom;
  const calls = [];
  const requests = [];

  if (options.userAgent) {
    Object.defineProperty(window.navigator, "userAgent", { value: options.userAgent });
  }
  if (options.installed) window.navigator.standalone = true;
  Object.defineProperty(window, "isSecureContext", { value: options.insecure !== true, configurable: true });

  const permission = { value: options.permission ?? "default" };
  window.Notification = class {};
  Object.defineProperty(window.Notification, "permission", { get: () => permission.value });
  window.Notification.requestPermission = async () => {
    calls.push("requestPermission");
    permission.value = options.grants ?? "granted";
    return permission.value;
  };

  const subscription = options.existingKey
    ? {
        options: { applicationServerKey: options.existingKey },
        toJSON: () => ({
          endpoint: ENDPOINT,
          expirationTime: null,
          keys: { p256dh: "old-p256dh", auth: "old-auth" },
        }),
        unsubscribe: async () => {
          calls.push("subscription.unsubscribe");
          return true;
        },
      }
    : null;
  const created = {
    toJSON: () => ({ endpoint: ENDPOINT, expirationTime: null, keys: { p256dh: "p256dh-value", auth: "auth-value" } }),
    unsubscribe: async () => {
      calls.push("subscription.unsubscribe");
      return true;
    },
  };
  const pushManager = {
    getSubscription: async () => {
      calls.push("getSubscription");
      return subscription;
    },
    subscribe: async (init) => {
      calls.push("pushManager.subscribe");
      world.lastInit = init;
      registration.lastInit = init;
      return created;
    },
  };
  const registration = {
    pushManager,
    active: {
      postMessage: (message) => calls.push(`postMessage:${message.type}:${message.key}`),
    },
  };
  if (options.noPushManager !== true) window.PushManager = class {};
  const listeners = [];
  window.navigator.serviceWorker = options.noServiceWorker
    ? undefined
    : {
        controller: null,
        register: async (url, init) => {
          calls.push(`register:${url}:${init?.scope ?? "-"}`);
          return registration;
        },
        getRegistration: async () => (options.registered === false ? undefined : registration),
        addEventListener: (type, handler) => listeners.push([type, handler]),
        get ready() {
          calls.push("ready");
          return Promise.resolve(registration);
        },
      };
  if (options.noServiceWorker) delete window.navigator.serviceWorker;

  window.fetch = async (url, init = {}) => {
    requests.push({ url: String(url), method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body });
    if (String(url).endsWith("/vapid-public-key")) {
      return options.noKey
        ? { ok: false, status: 404, json: async () => ({}) }
        : { ok: true, status: 200, json: async () => ({ public_key: KEY }) };
    }
    if (init.method === "PUT") return { ok: true, status: 200, json: async () => ({ id: "sub-42" }) };
    if (init.method === "DELETE") return { ok: true, status: 204, json: async () => ({}) };
    return { ok: false, status: 500, json: async () => ({}) };
  };

  window.eval(script);
  return {
    window,
    calls,
    requests,
    registration,
    listeners,
    push: window.cf.push,
    setAuth: (auth) => {
      window.cf.auth = auth;
    },
  };
}

function bytesOf(base64url) {
  const padded = base64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (base64url.length % 4)) % 4);
  return Uint8Array.from(Buffer.from(padded, "base64"));
}

// ---------------------------------------------------------------------------

console.log("-- support and state");
{
  const w = world();
  assert(w.push.supported().supported === true, "a secure page with the APIs is supported");
  assert(w.push.state() === "default", "state is the permission when supported");
}
{
  const w = world({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Safari/605.1.15" });
  const check = w.push.supported();
  assert(
    check.supported === false && check.reason === "ios-needs-homescreen",
    "iOS Safari in a tab reports the installable case, not a flat no",
  );
  assert(w.push.state() === "unsupported", "state collapses every unsupported reason");
}
{
  const w = world({
    userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Safari/605.1.15",
    installed: true,
  });
  assert(w.push.supported().supported === true, "the same iPhone, installed to the Home Screen, is supported");
}
{
  const w = world({ userAgent: "Mozilla/5.0 (Macintosh) Safari/605.1.15", installed: false });
  Object.defineProperty(w.window.navigator, "platform", { value: "MacIntel" });
  Object.defineProperty(w.window.navigator, "maxTouchPoints", { value: 5 });
  assert(
    w.push.supported().reason === "ios-needs-homescreen",
    "an iPad that reports itself as a Mac is still an iPad",
  );
}
{
  const w = world({ insecure: true });
  assert(w.push.supported().reason === "insecure-context", "http is its own reason");
}
{
  const w = world({ noPushManager: true });
  assert(w.push.supported().reason === "no-push", "a browser without the Push API says so");
}

console.log("-- the application server key");
{
  const w = world();
  w.setAuth(TOKEN);
  await w.push.subscribe();
  const init = w.registration.lastInit;
  const expected = bytesOf(KEY);
  assert(init.userVisibleOnly === true, "userVisibleOnly is set (every browser requires it)");
  assert(init.applicationServerKey instanceof w.window.Uint8Array || ArrayBuffer.isView(init.applicationServerKey),
    "applicationServerKey is bytes, not the base64url string");
  assert(init.applicationServerKey.length === 65, "65 bytes: an uncompressed P-256 point");
  assert(init.applicationServerKey[0] === 0x04, "the leading 0x04 of an uncompressed point survives");
  assert(
    Array.from(init.applicationServerKey).every((b, i) => b === expected[i]),
    "the conversion matches an independent base64url decode",
  );
  assert(
    w.requests.filter((r) => r.url.endsWith("/vapid-public-key")).length === 1,
    "the key is fetched once per page",
  );
}

console.log("-- the gesture");
{
  const w = world();
  w.setAuth(TOKEN);
  const pending = w.push.subscribe();
  // Checked before awaiting: nothing may have suspended yet, or the
  // user activation the browsers demand for `requestPermission` is gone.
  assert(
    w.calls[0] === "requestPermission",
    "permission is requested before the first await, so the click still counts",
  );
  await pending;
  assert(
    w.calls.indexOf("requestPermission") < w.calls.findIndex((c) => c.startsWith("register:")),
    "the service worker is registered after the prompt, not before it",
  );
}
{
  const w = world({ permission: "granted" });
  w.setAuth(TOKEN);
  await w.push.subscribe();
  assert(!w.calls.includes("requestPermission"), "an already-granted page is not prompted again");
}
{
  const w = world({ grants: "denied" });
  w.setAuth(TOKEN);
  const err = await rejects(w.push.subscribe(), "a refused prompt rejects");
  assert(/denied/.test(err?.message ?? ""), "the refusal says which permission state it saw");
  assert(w.requests.length === 0, "nothing is sent when permission was refused");
}

console.log("-- registration");
{
  const w = world();
  w.setAuth(async () => TOKEN);
  const answer = await w.push.subscribe({ appId: "example.test", appVersion: "1.2.3" });
  assert(answer.id === "sub-42", "subscribe answers with the venture's row id");
  const put = w.requests.find((r) => r.method === "PUT");
  assert(put.url === `${API}/v1/notifications/subscriptions`, "it PUTs the module's route");
  assert(put.headers.authorization === `Bearer ${TOKEN}`, "the bearer comes from cf.auth");
  const body = JSON.parse(put.body);
  assert(body.transport === "webpush", "the transport is the column's spelling");
  assert(
    Object.keys(body.recipient).length === 1 && body.recipient.web_push,
    "the recipient is the port's `web_push` tag, and only that",
  );
  assert(
    body.recipient.web_push.endpoint === ENDPOINT &&
      body.recipient.web_push.p256dh === "p256dh-value" &&
      body.recipient.web_push.auth === "auth-value",
    "`toJSON()`'s nested keys are flattened the way the route reads them",
  );
  assert(body.recipient.web_push.keys === undefined, "the `keys` object itself is not sent (deny_unknown_fields)");
  assert(body.app_id === "example.test" && body.app_version === "1.2.3", "app id and version travel");
  assert(
    w.calls.some((c) => c === `postMessage:cf-push-key:${KEY}`),
    "the worker is handed the key so it can re-subscribe on its own",
  );
}
{
  const w = world();
  const err = await rejects(w.push.subscribe(), "no cf.auth rejects");
  assert(/cf\.auth/.test(err?.message ?? ""), "the error names the seam the page has to fill");
  assert(
    !w.requests.some((r) => r.method === "PUT"),
    "no unauthenticated PUT is sent — a 401 would be the only possible answer",
  );
}
{
  const w = world({ permission: "granted", existingKey: bytesOf("BAAA" + KEY.slice(4)) });
  w.setAuth(TOKEN);
  await w.push.subscribe();
  assert(
    w.calls.includes("subscription.unsubscribe") && w.calls.includes("pushManager.subscribe"),
    "a subscription made with another application server key is replaced, not re-registered",
  );
}
{
  const w = world({ permission: "granted", existingKey: bytesOf(KEY) });
  w.setAuth(TOKEN);
  await w.push.subscribe();
  assert(
    !w.calls.includes("pushManager.subscribe"),
    "a subscription made with this key is kept — re-subscribing would change the endpoint for nothing",
  );
}
{
  const w = world({ noKey: true });
  w.setAuth(TOKEN);
  const err = await rejects(w.push.subscribe(), "a venture with no key rejects");
  assert(/404/.test(err?.message ?? ""), "the 404 is reported as a status");
  assert(!/api\.example/.test(err?.message ?? ""), "and no URL is quoted back");
}

console.log("-- unsubscribe");
{
  const w = world({ permission: "granted", existingKey: bytesOf(KEY) });
  w.setAuth(TOKEN);
  await w.push.subscribe();
  const before = w.requests.length;
  assert((await w.push.unsubscribe()) === true, "unsubscribe reports that there was something to undo");
  const del = w.requests.slice(before).find((r) => r.method === "DELETE");
  assert(w.calls.includes("subscription.unsubscribe"), "the browser's own subscription is undone");
  assert(del?.url === `${API}/v1/notifications/subscriptions/sub-42`, "the venture's row is deleted too");
  assert(del.headers.authorization === `Bearer ${TOKEN}`, "the delete carries the bearer");
  assert(w.window.localStorage.getItem("cf.push.id") === null, "the remembered id is forgotten");
}
{
  // Storage cleared between visits: the id is re-learned rather than
  // leaving a row nothing will ever delete.
  const w = world({ permission: "granted", existingKey: bytesOf(KEY) });
  w.setAuth(TOKEN);
  await w.push.unsubscribe();
  const methods = w.requests.map((r) => r.method);
  assert(
    methods.indexOf("PUT") >= 0 && methods.indexOf("PUT") < methods.indexOf("DELETE"),
    "with no remembered id, the upsert answers with one and the delete follows",
  );
}

console.log("-- sync, the pushsubscriptionchange repair");
{
  const w = world({ permission: "granted", existingKey: bytesOf(KEY) });
  w.setAuth(TOKEN);
  const answer = await w.push.sync();
  assert(answer?.id === "sub-42", "sync re-registers the subscription the browser already holds");
  assert(!w.calls.includes("requestPermission"), "sync never prompts, so it is safe on load");
  assert(!w.calls.includes("pushManager.subscribe"), "and never creates one");
}
{
  const w = world({ permission: "default" });
  w.setAuth(TOKEN);
  assert((await w.push.sync()) === null, "sync does nothing before permission is granted");
  assert(w.requests.length === 0, "and sends nothing");
}
{
  const w = world({ permission: "granted", existingKey: bytesOf(KEY) });
  w.setAuth(TOKEN);
  await w.push.sync();
  const [type, handler] = w.listeners.find(([t]) => t === "message") ?? [];
  assert(type === "message", "the page listens for the worker's re-subscribe ping");
  const before = w.requests.filter((r) => r.method === "PUT").length;
  await handler({ data: { type: "cf-push-resubscribed" } });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(
    w.requests.filter((r) => r.method === "PUT").length === before + 1,
    "the ping re-registers, which is what a pushsubscriptionchange needs from the page",
  );
}

console.log("-- <cf-push>");
{
  const w = world();
  w.setAuth(TOKEN);
  const { document } = w.window;
  document.body.innerHTML = "<cf-push></cf-push>";
  const element = document.querySelector("cf-push");
  assert(element.querySelector("button")?.textContent === "Turn notifications on", "the block renders its button");
  element.querySelector("button").click();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(
    w.calls[0] === "requestPermission",
    "the button's handler reaches the prompt inside the click, keeping the gesture",
  );
}
{
  const w = world({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Safari/605.1.15" });
  const { document } = w.window;
  document.body.innerHTML = `<cf-push install="Add us to your Home Screen."></cf-push>`;
  const element = document.querySelector("cf-push");
  assert(!element.querySelector("button"), "an iPhone in a tab gets no button it cannot honour");
  assert(element.textContent === "Add us to your Home Screen.", "and the copy is the page's own");
}
{
  const w = world({ permission: "denied" });
  const { document } = w.window;
  document.body.innerHTML = "<cf-push></cf-push>";
  assert(!document.querySelector("cf-push button"), "a blocked page gets no button either");
}

console.log("-- nothing that is a credential reaches an error");
{
  const w = world({ permission: "granted", existingKey: bytesOf(KEY) });
  w.setAuth(TOKEN);
  w.window.fetch = async (url, init = {}) => {
    if (String(url).endsWith("/vapid-public-key")) return { ok: true, status: 200, json: async () => ({ public_key: KEY }) };
    return { ok: false, status: 500, json: async () => ({}) };
  };
  const err = await rejects(w.push.sync(), "a failing PUT rejects");
  const message = err?.message ?? "";
  assert(!message.includes(ENDPOINT), "the subscription endpoint is never quoted (it is a bearer capability)");
  assert(!message.includes(TOKEN), "and neither is the access token");
  assert(/500/.test(message), "the status is what the caller gets");
}

if (failures) {
  console.error(`cf.js push: ${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("cf.js push: all assertions passed");
