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

  Object.defineProperty(window.document, "visibilityState", {
    get: () => options.hidden ? "hidden" : "visible",
    configurable: true,
  });

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
    setUnread: (n) => {
      unread = n;
    },
    setRows: (r) => {
      rows = r;
    },
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
  await el.open();
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

process.exit(failures === 0 ? 0 : 1);
