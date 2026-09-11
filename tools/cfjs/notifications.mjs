// The notification centre half of cf.js (issue #188), against a stubbed
// `/v1/notifications*`.
//
// It runs the file that ships, byte for byte apart from the two edits the
// other suites make (the module origin, and the export line jsdom's
// classic-script eval cannot take). No server, so it runs beside the size
// gate rather than in the wrangler job.
//
// A fresh JSDOM per case: the element starts a poll on connect, and a
// shared world would let one case's timer answer another's assertion.
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

const API = "https://api.example.test";
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

/** A page with `/v1/notifications*` stubbed. Everything the code asked
 *  for is recorded on the returned world. */
function world(options = {}) {
  const dom = new JSDOM("<!doctype html><body></body>", {
    url: "https://site.example.test/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const { window } = dom;
  const requests = [];
  let unread = options.unread ?? 0;
  let rows = options.rows ?? [];

  // jsdom implements <dialog> without showModal in some versions; the
  // element only needs open/close semantics and the `close` event.
  window.HTMLDialogElement.prototype.showModal = function showModal() {
    this.open = true;
  };
  window.HTMLDialogElement.prototype.close = function close() {
    this.open = false;
    this.dispatchEvent(new window.Event("close"));
  };

  let hidden = options.hidden ?? false;
  Object.defineProperty(window.document, "visibilityState", {
    get: () => (hidden ? "hidden" : "visible"),
    configurable: true,
  });

  // The poll is a minute apart, so the tests watch it being scheduled and
  // cleared rather than waiting for it. Real timers underneath: the file
  // ends in `process.exit`, so a pending 60 s interval cannot hang the run.
  const started = [];
  const cleared = [];
  const realInterval = window.setInterval;
  const realClear = window.clearInterval;
  window.setInterval = (...args) => {
    const id = realInterval(...args);
    started.push(id);
    return id;
  };
  window.clearInterval = (id) => {
    cleared.push(id);
    return realClear(id);
  };

  window.fetch = async (url, init = {}) => {
    const text = String(url);
    requests.push({ url: text, method: init.method ?? "GET", headers: init.headers ?? {} });
    if (text.includes("/unread-count")) {
      return { ok: true, status: 200, json: async () => ({ unread }) };
    }
    if (text.includes("/read-all")) {
      unread = 0;
      return { ok: true, status: 200, json: async () => ({ marked: 2 }) };
    }
    if (/\/read$/.test(text)) {
      unread = Math.max(0, unread - 1);
      return { ok: true, status: 204, json: async () => null };
    }
    return { ok: true, status: 200, json: async () => ({ notifications: rows, cursor: null }) };
  };

  window.eval(script);
  window.cf.auth = TOKEN;
  return {
    window,
    requests,
    started,
    cleared,
    setUnread: (n) => {
      unread = n;
    },
    setRows: (r) => {
      rows = r;
    },
    /** Flip the tab between `visible` and `hidden`, as a browser would. */
    visibility: async (state) => {
      hidden = state === "hidden";
      window.document.dispatchEvent(new window.Event("visibilitychange"));
      await settle();
    },
    polls: () => requests.filter((r) => r.url.includes("/unread-count")).length,
  };
}

const ROWS = [
  { id: "01A", title: "Booked", body: "Tuesday", url: "/bookings/1", created_at: "2026-09-11T10:00:00Z" },
  { id: "01B", title: "Notes", body: "From your coach", created_at: "2026-09-11T09:00:00Z", read_at: "2026-09-11T09:30:00Z" },
];

/** Lets the element's connect-time poll settle. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

async function mount(w, attrs = "") {
  w.window.document.body.innerHTML = `<cf-notifications ${attrs}></cf-notifications>`;
  await settle();
  return w.window.document.querySelector("cf-notifications");
}

// --- the count -------------------------------------------------------

{
  const w = world({ unread: 3 });
  const el = await mount(w);
  const count = el.querySelector(".cf-count");
  assert(count.textContent === "3", "the bell shows the unread count");
  assert(!count.hidden, "and the count is visible when there is one");
  assert(
    el.querySelector("button").getAttribute("aria-label") === "Notifications, 3 unread",
    "the bell's accessible name carries the count",
  );
}

{
  const w = world({ unread: 0 });
  const el = await mount(w);
  assert(el.querySelector(".cf-count").hidden, "a zero count is hidden, not a `0` badge");
}

{
  const w = world({ unread: 1234 });
  const el = await mount(w);
  assert(el.querySelector(".cf-count").textContent === "99+", "a bell is not a place for a four-digit number");
}

// --- opening and reading ---------------------------------------------

{
  const w = world({ unread: 1, rows: ROWS });
  const el = await mount(w);
  await el.open();
  const items = el.querySelectorAll("li");
  assert(items.length === 2, "opening lists the page");
  assert(items[0].className === "cf-unread", "an unread row is marked");
  assert(items[1].className === "", "a read row is not");

  const before = w.requests.length;
  items[0].querySelector("button").click();
  await settle();
  assert(
    w.requests.slice(before).some((r) => r.method === "POST" && /\/01A\/read$/.test(r.url)),
    "clicking an item marks exactly that item read",
  );
}

{
  const w = world({ unread: 2, rows: ROWS });
  const el = await mount(w);
  await el.open();
  el.querySelector(".cf-all").click();
  await settle();
  assert(
    w.requests.some((r) => r.method === "POST" && r.url.endsWith("/read-all")),
    "mark all read posts once",
  );
  assert(el.querySelector(".cf-count").hidden, "and the count goes to nothing");
}

{
  const w = world({ unread: 0, rows: [] });
  const el = await mount(w, 'empty="All quiet."');
  await el.open();
  assert(el.querySelector(".cf-empty")?.textContent === "All quiet.", "an empty inbox says so, in the venture's words");
}

// --- the panel and the keyboard --------------------------------------

{
  const w = world({ unread: 1, rows: ROWS });
  const el = await mount(w);
  const bell = el.querySelector("button");
  assert(bell.getAttribute("aria-haspopup") === "dialog", "the bell says what it opens");
  // Through the bell itself, not `el.open()`: a native <button> turns
  // Enter and Space into this click, so this is the keyboard path too.
  bell.click();
  await settle();
  assert(el.querySelector("dialog").open, "the panel is open");

  el.querySelector("dialog").close();
  await settle();
  assert(!el.querySelector("dialog").open, "and closes");
  assert(
    w.window.document.activeElement === bell,
    "focus returns to the bell however the dialog closed",
  );
}

{
  // `display` is deliberately never set on the panel: an author rule beats
  // the UA's own hiding, so a closed dialog would stay painted.
  assert(
    !/\.cf-panel[^{]*\{[^}]*display/.test(source),
    "nothing sets `display` on the dialog",
  );
}

// --- auth ------------------------------------------------------------

{
  const w = world({ unread: 1 });
  await mount(w);
  assert(
    w.requests.every((r) => r.headers.authorization === `Bearer ${TOKEN}`),
    "every request carries the token from cf.auth",
  );
}

{
  const w = world({ unread: 1 });
  w.window.cf.auth = null;
  let refused = false;
  try {
    await w.window.cf.notifications.unreadCount();
  } catch {
    refused = true;
  }
  assert(refused, "with no token it refuses rather than fetching a 401");
}

// --- polling ---------------------------------------------------------

{
  const w = world({ unread: 1, hidden: true });
  await mount(w);
  assert(
    w.requests.length === 0,
    "a hidden tab polls nothing: a background request nobody can see is one nobody asked for",
  );
}

{
  const w = world({ unread: 1 });
  await mount(w);
  const polled = w.requests.filter((r) => r.url.includes("/unread-count")).length;
  assert(polled === 1, "a visible tab reads the count once on connect");
}

{
  // A page with no `cf.auth` — a static example, or a signed-out visitor —
  // must leave no timer running. This is not only about wasted wakeups:
  // `site.mjs` ends without `process.exit`, so node exits when the event
  // loop drains, and one `setInterval` in the page keeps the whole CI step
  // alive until the job times out. That is how this was found.
  const w = world({ unread: 1 });
  // Exactly what `examples/venture/site/index.html` sets: a function,
  // which is truthy, returning null. Checking `cf.auth` alone does not
  // catch this — the first read has to actually succeed.
  w.window.cf.auth = () => null;
  await mount(w);
  assert(w.started.length === 0, "with no way to authenticate, it starts no timer");
  assert(w.requests.length === 0, "and makes no request it could not have signed");
}

{
  // Pausing and resuming, which is the half the mount-time case above
  // cannot reach: a tab that goes hidden *after* the poll is running.
  const w = world({ unread: 1 });
  await mount(w);
  assert(w.started.length === 1, "a visible tab schedules the poll");
  const atMount = w.requests.length;

  await w.visibility("hidden");
  assert(w.cleared.includes(w.started[0]), "going hidden clears the poll");
  assert(w.requests.length === atMount, "and a hidden tab asks for nothing");

  await w.visibility("visible");
  assert(w.polls() === 2, "coming back re-reads the count at once, so nothing read is stale");
  assert(w.started.length === 2, "and schedules the poll again");
}

{
  // The watcher listens on the *document*, which outlives the element.
  // Stopping has to take the listener with it: otherwise a bell that has
  // been removed from the page starts polling again on the next visibility
  // change — forever, writing counts into a node nobody can see.
  const w = world({ unread: 1 });
  const el = await mount(w);
  el.remove();
  await settle();
  const timers = w.started.length;
  const calls = w.requests.length;
  await w.visibility("hidden");
  await w.visibility("visible");
  assert(w.started.length === timers, "a removed bell schedules no new poll");
  assert(w.requests.length === calls, "and makes no request once it is gone");
}

// --- realtime --------------------------------------------------------

{
  // Where the page exposes a Realtime client, an event moves the count
  // without waiting for the poll — which is a minute away and, here,
  // never fires.
  const w = world({ unread: 1 });
  const rooms = [];
  let deliver = null;
  w.window.cf.realtime = {
    subscribe: (room, handler) => {
      rooms.push(room);
      deliver = handler;
    },
  };
  const el = await mount(w, 'account="acct-7"');
  assert(rooms[0] === "notifications:acct-7", "it joins this account's room");

  w.setUnread(4);
  // Optional call: with the subscription gone this stays null, and the
  // assertions below report that rather than dying on a TypeError.
  deliver?.();
  await settle();
  assert(el.querySelector(".cf-count").textContent === "4", "an incoming event moves the count");
  assert(
    el.querySelector("button").getAttribute("aria-label") === "Notifications, 4 unread",
    "and the bell's accessible name with it",
  );
  assert(w.started.length === 1, "the event did that, not a poll: no second timer ran");
}

process.exit(failures === 0 ? 0 : 1);
