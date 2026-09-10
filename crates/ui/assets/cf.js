/* cratefield-ui embed (ADR 0010, issue #73). Served at /ui/cf.js.
 *
 *   <script type="module" src="https://api.example.com/ui/cf.js"></script>
 *   <cf-form module="waitlist" action="join" product="kontinuum"></cf-form>
 *   <cf-status module="waitlist"></cf-status>
 *
 * An embed, not a renderer: every byte of markup comes from the harness.
 * <cf-form> fetches /ui/<module>/<action>?fragment=1 from the API origin
 * (the script's own origin unless `base` says otherwise), inserts it into
 * the light DOM, and turns the submit into a fetch of the same /ui route,
 * swapping the returned fragment (notice, or the form with its errors)
 * back in. Attributes that name a field pre-fill and hide it (sent as
 * `?field=value&hide=field`). When a
 * fragment carries a Turnstile widget, Turnstile's script is loaded once
 * and the widget rendered. <cf-status> is a <cf-form> whose action is a
 * GET, with `token` taken from the page URL. No dependencies, no shadow
 * DOM, no inline styles; style the cf-* classes.
 *
 * Events on the element: cf:loaded, cf:submitted (detail.status), cf:error.
 *
 * Browser push (issue #183) is the second half: `cf.push.subscribe()` and
 * <cf-push>. See the block below the elements.
 */
const ORIGIN = new URL(import.meta.url).origin;
const SKIP = new Set(["module", "action", "base", "class", "id", "style", "hidden", "slot"]);
const TURNSTILE = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
let turnstileLoading = null;

function loadTurnstile() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (!turnstileLoading) {
    turnstileLoading = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = TURNSTILE;
      s.async = true;
      s.onload = () => resolve(window.turnstile);
      s.onerror = () => reject(new Error("turnstile failed to load"));
      document.head.append(s);
    });
  }
  return turnstileLoading;
}

class CfForm extends HTMLElement {
  static get observedAttributes() {
    return ["module", "action"];
  }

  get action() {
    return this.getAttribute("action") || "join";
  }

  /** The /ui URL for this element, with field attributes as the query. */
  url(fragment) {
    const base = this.getAttribute("base") || ORIGIN;
    const u = new URL(`/ui/${this.getAttribute("module")}/${this.action}`, base);
    const hide = [];
    for (const { name, value } of this.attributes) {
      if (SKIP.has(name)) continue;
      u.searchParams.set(name, value);
      hide.push(name);
    }
    for (const [k, v] of this.extraParams()) u.searchParams.set(k, v);
    if (hide.length) u.searchParams.set("hide", hide.join(","));
    if (fragment) u.searchParams.set("fragment", "1");
    return u;
  }

  /** Overridden by <cf-status>: parameters read from the page URL. */
  extraParams() {
    return [];
  }

  connectedCallback() {
    if (!this.getAttribute("module")) return;
    this.load();
  }

  attributeChangedCallback(_name, was, now) {
    if (was !== null && was !== now && this.isConnected) this.load();
  }

  fallback(text) {
    const a = document.createElement("a");
    a.className = "cf-embed-link";
    a.href = this.url(false);
    a.textContent = text;
    this.replaceChildren(a);
  }

  async load() {
    this.fallback("Open the form");
    try {
      const res = await fetch(this.url(true), { headers: { Accept: "text/html" } });
      await this.swap(res);
      this.dispatchEvent(new CustomEvent("cf:loaded", { detail: { status: res.status } }));
    } catch (err) {
      this.fallback("Open the form (could not load it here)");
      this.dispatchEvent(new CustomEvent("cf:error", { detail: { error: err } }));
    }
  }

  /** Replaces the content with the response's fragment and wires it. */
  async swap(res) {
    if (res.redirected) {
      window.location.assign(res.url);
      return;
    }
    const html = await res.text();
    const tpl = document.createElement("template");
    tpl.innerHTML = html;
    this.replaceChildren(tpl.content);
    const form = this.querySelector("form.cf-form");
    if (form) form.addEventListener("submit", (e) => this.submit(e, form));
    const widget = this.querySelector(".cf-turnstile");
    if (widget) {
      loadTurnstile()
        .then((t) => t.render(widget, { sitekey: widget.dataset.sitekey }))
        .catch(() => {});
    }
  }

  async submit(event, form) {
    event.preventDefault();
    const button = form.querySelector(".cf-submit");
    if (button) button.disabled = true;
    // Post to the form's own /ui route, keeping this element's switches
    // (hidden fields stay hidden on a re-render).
    const target = this.url(true);
    try {
      const res = await fetch(target, {
        method: "POST",
        body: new URLSearchParams(new FormData(form)),
        headers: { Accept: "text/html" },
      });
      await this.swap(res);
      this.dispatchEvent(new CustomEvent("cf:submitted", { detail: { status: res.status } }));
    } catch (err) {
      if (button) button.disabled = false;
      this.dispatchEvent(new CustomEvent("cf:error", { detail: { error: err } }));
    }
  }
}

class CfStatus extends CfForm {
  get action() {
    return this.getAttribute("action") || "status";
  }

  extraParams() {
    const page = new URLSearchParams(window.location.search);
    const token = this.getAttribute("token") || page.get("token");
    return token ? [["token", token]] : [];
  }

  fallback(text) {
    super.fallback(text.replace("the form", "the status page"));
  }

  /** No token on the page: say so instead of fetching a 400. */
  load() {
    if (this.extraParams().length === 0) {
      const p = document.createElement("p");
      p.className = "cf-help cf-status-empty";
      p.textContent = this.getAttribute("empty") || "Open the link from your email to see your status.";
      this.replaceChildren(p);
      this.dispatchEvent(new CustomEvent("cf:loaded", { detail: { status: 0 } }));
      return Promise.resolve();
    }
    return super.load();
  }
}

/* Browser push (issue #183) -------------------------------------------
 *
 *   <script>window.cf = { auth: () => session.accessToken };</script>
 *   <script type="module" src="https://api.example.com/ui/cf.js"></script>
 *   <cf-push></cf-push>            <!-- or call cf.push.* yourself -->
 *
 * The auth seam is `cf.auth`: an access token, or a function returning
 * one (it may be async). It is read once per request and never stored —
 * refresh and storage stay with the page, and this file keeps no
 * credential of its own. The routes it calls take a bearer token and
 * nothing else, so without `cf.auth` a subscribe throws here rather than
 * sending a request that can only be a 401.
 *
 * The five things a push client gets wrong, and where each is handled:
 * base64url → Uint8Array (`keyBytes`), permission only on a gesture
 * (`subscribe` asks before its first `await`), re-registering after
 * `pushsubscriptionchange` (the service worker pings, `sync` re-PUTs),
 * iOS Safari needing an installed web app (`supported`, reported as its
 * own reason), and deleting the server-side row (`unsubscribe`).
 */
const cf = (window.cf ||= {});
const SUBS = "/v1/notifications/subscriptions";
const ID_KEY = "cf.push.id";
let serverKeyPromise = null;
let listening = false;

/** The API origin: the script's own, unless the page named another. */
function apiBase() {
  return cf.base || ORIGIN;
}

/** The one auth seam. Read per request, never cached, never stored. */
async function authHeaders() {
  const token = typeof cf.auth === "function" ? await cf.auth() : cf.auth;
  if (!token) throw new Error("cf.auth is not set: the page must supply an access token");
  return { authorization: `Bearer ${token}`, "content-type": "application/json" };
}

/** base64url → Uint8Array, the only form `applicationServerKey` takes. */
function keyBytes(key) {
  const padded = key.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (key.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function sameKey(a, b) {
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

/** iOS and iPadOS, including the iPad that reports itself as a Mac. */
function isIos() {
  return (
    /iP(hone|ad|od)/.test(navigator.userAgent || "") ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)
  );
}

function isInstalled() {
  return navigator.standalone === true || window.matchMedia?.("(display-mode: standalone)").matches === true;
}

/** Why push is, or is not, available here.
 *
 * `ios-needs-homescreen` is deliberately not folded into the flat no:
 * iOS and iPadOS 16.4+ do support this, only from a web app the user has
 * added to the Home Screen, so the page can ask for that instead of
 * telling somebody their phone cannot do it. */
function supported() {
  if (!window.isSecureContext) return { supported: false, reason: "insecure-context" };
  if (isIos() && !isInstalled()) return { supported: false, reason: "ios-needs-homescreen" };
  if (!("serviceWorker" in navigator)) return { supported: false, reason: "no-service-worker" };
  if (!("PushManager" in window)) return { supported: false, reason: "no-push" };
  if (!("Notification" in window)) return { supported: false, reason: "no-notifications" };
  return { supported: true };
}

/** granted | denied | default | unsupported. */
function state() {
  return supported().supported ? Notification.permission : "unsupported";
}

/** The venture's `applicationServerKey`, fetched once per page. */
function serverKey() {
  serverKeyPromise ||= fetch(`${apiBase()}/v1/notifications/vapid-public-key`)
    .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`no application server key (${res.status})`))))
    .then((body) => body.public_key)
    .catch((err) => {
      serverKeyPromise = null;
      throw err;
    });
  return serverKeyPromise;
}

/** Registers the subscription with the venture. The route upserts, so
 *  this is also the repair for a subscription the browser replaced. */
async function put(subscription, options = {}) {
  const json = subscription.toJSON();
  const body = {
    transport: "webpush",
    recipient: { web_push: { endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth } },
  };
  if (options.appId) body.app_id = options.appId;
  if (options.appVersion) body.app_version = options.appVersion;
  const res = await fetch(apiBase() + SUBS, {
    method: "PUT",
    headers: await authHeaders(),
    body: JSON.stringify(body),
  });
  // A subscription endpoint is a bearer capability: statuses, never URLs.
  if (!res.ok) throw new Error(`registering for notifications failed (${res.status})`);
  const { id } = await res.json();
  try {
    localStorage.setItem(ID_KEY, id);
  } catch {}
  return { id };
}

/** The service worker's re-subscribe ping. It never holds a token, so a
 *  `pushsubscriptionchange` with a page open is re-registered from here. */
function listen() {
  if (listening || !("serviceWorker" in navigator)) return;
  listening = true;
  navigator.serviceWorker.addEventListener("message", (event) => {
    if (event.data?.type === "cf-push-resubscribed" && cf.auth) sync().catch(() => {});
  });
}

/** Ask, subscribe, register. Call it from a click handler: permission is
 *  requested before the first `await`, because an `await` spends the user
 *  activation the browsers require for it. */
async function subscribe(options = {}) {
  const check = supported();
  if (!check.supported) throw new Error(`browser push is unavailable here: ${check.reason}`);
  if (Notification.permission === "default") await Notification.requestPermission();
  if (Notification.permission !== "granted") throw new Error(`notification permission is ${Notification.permission}`);

  listen();
  const registration = await navigator.serviceWorker.register(
    options.swUrl || "/sw.js",
    options.scope ? { scope: options.scope } : undefined,
  );
  await navigator.serviceWorker.ready;
  const key = await serverKey();
  const bytes = keyBytes(key);
  let subscription = await registration.pushManager.getSubscription();
  // A rotated VAPID key leaves a subscription nothing can push to and
  // nothing about it looks wrong from here. Replace it rather than
  // re-registering a recipient every send will fail against.
  if (subscription && !sameKey(subscription.options?.applicationServerKey || bytes, bytes)) {
    await subscription.unsubscribe();
    subscription = null;
  }
  subscription ||= await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: bytes });
  // The worker keeps the key so it can re-subscribe on its own. Public by
  // definition, and the only thing it is told.
  registration.active?.postMessage({ type: "cf-push-key", key });
  return put(subscription, options);
}

/** Both halves: the browser's subscription and the venture's row. */
async function unsubscribe() {
  const registration = await navigator.serviceWorker?.getRegistration();
  const subscription = registration && (await registration.pushManager.getSubscription());
  let id = null;
  try {
    id = localStorage.getItem(ID_KEY);
  } catch {}
  // No remembered id: the PUT upserts and answers with the row's own, so
  // the delete works on a browser whose storage was cleared.
  if (!id && subscription) id = (await put(subscription)).id;
  if (subscription) await subscription.unsubscribe();
  if (id) {
    const res = await fetch(`${apiBase()}${SUBS}/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: await authHeaders(),
    });
    if (!res.ok && res.status !== 404) throw new Error(`turning notifications off failed (${res.status})`);
  }
  try {
    localStorage.removeItem(ID_KEY);
  } catch {}
  return Boolean(subscription || id);
}

/** Re-registers the subscription this browser already holds. It never
 *  prompts, so it is safe on load — and it is what repairs a
 *  `pushsubscriptionchange` that happened with no page open. */
async function sync() {
  if (!supported().supported || Notification.permission !== "granted") return null;
  listen();
  const registration = await navigator.serviceWorker.getRegistration();
  const subscription = registration && (await registration.pushManager.getSubscription());
  return subscription ? put(subscription) : null;
}

/** One tag for the whole enable block: the button and the three states
 *  around it. Every string is an attribute, so the copy is the page's. */
class CfPush extends HTMLElement {
  connectedCallback() {
    listen();
    this.render();
  }

  copy(name, fallback) {
    return this.getAttribute(name) || fallback;
  }

  render(note) {
    const check = supported();
    const help = document.createElement("p");
    help.className = "cf-help";
    if (!check.supported) {
      help.textContent =
        check.reason === "ios-needs-homescreen"
          ? this.copy("install", "Add this site to your Home Screen to turn notifications on.")
          : this.copy("unsupported", "This browser cannot show notifications.");
      this.replaceChildren(help);
      return;
    }
    if (Notification.permission === "denied") {
      help.textContent = this.copy("denied", "Notifications are blocked in your browser settings.");
      this.replaceChildren(help);
      return;
    }
    const on = Notification.permission === "granted";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "cf-submit";
    button.textContent = on ? this.copy("off-label", "Turn notifications off") : this.copy("label", "Turn notifications on");
    button.addEventListener("click", () => this.toggle(on, button));
    help.textContent = note || (on ? this.copy("on", "Notifications are on for this device.") : this.copy("intro", ""));
    this.replaceChildren(button, help);
  }

  async toggle(on, button) {
    button.disabled = true;
    try {
      // `subscribe` runs up to its permission prompt synchronously, so
      // the click's user activation is still there when it asks.
      await (on
        ? unsubscribe()
        : subscribe({ swUrl: this.getAttribute("sw") || undefined, appId: this.getAttribute("app-id") || undefined }));
      this.render();
      this.dispatchEvent(new CustomEvent("cf:push", { detail: { state: state() } }));
    } catch (err) {
      this.render(this.copy("error", "That did not work. Try again."));
      this.dispatchEvent(new CustomEvent("cf:error", { detail: { error: err } }));
    }
  }
}

const push = { supported, state, subscribe, unsubscribe, sync };
cf.push = push;

if (!customElements.get("cf-form")) customElements.define("cf-form", CfForm);
if (!customElements.get("cf-status")) customElements.define("cf-status", CfStatus);
if (!customElements.get("cf-push")) customElements.define("cf-push", CfPush);

export { CfForm, CfStatus, CfPush, push };
