// The example static site against the running harness (issue #77): the
// page at examples/venture/site is served on SITE (default
// http://127.0.0.1:8788) by a plain static server, the API on BASE
// (default http://127.0.0.1:8787). Both embeds load, the site's stylesheet
// restyles with properties and unlayered rules only, and a submit
// through the restyled form reaches the module.
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

const BASE = process.env.BASE || "http://127.0.0.1:8787";
const SITE = process.env.SITE || "http://127.0.0.1:8788";

function assert(cond, message) {
  if (!cond) {
    console.error(`FAIL: ${message}`);
    process.exit(1);
  }
  console.log(`ok: ${message}`);
}

// The stylesheet contract: no !important, and nothing inside a @layer of
// its own (plain rules beat cf.css's layer by being unlayered).
const css = readFileSync(new URL("../../examples/venture/site/site.css", import.meta.url), "utf8");
assert(!css.includes("!important"), "site.css has no !important");
assert(!/^\s*@layer/m.test(css), "site.css writes unlayered rules only");
assert(/--cf-accent:/.test(css) && /\.cf-submit\s*\{/.test(css), "site.css restyles with both properties and rules");

const html = readFileSync(new URL("../../examples/venture/site/index.html", import.meta.url), "utf8")
  .replaceAll("http://127.0.0.1:8787", BASE);
const dom = new JSDOM(html, { url: `${SITE}/`, runScripts: "outside-only", pretendToBeVisual: true });
const { window } = dom;
window.fetch = (url, init) => {
  if (init?.body && !(init.body instanceof URLSearchParams)) {
    init = { ...init, body: new URLSearchParams(String(init.body)) };
  }
  return fetch(String(url), { ...init, headers: { ...(init?.headers || {}), Origin: SITE } });
};
// jsdom does not run module scripts: evaluate the served cf.js itself.
const served = await (await fetch(`${BASE}/ui/cf.js`)).text();
window.eval(served.replace("new URL(import.meta.url).origin", JSON.stringify(BASE)).replace(/^export .*$/m, ""));

function once(el, type) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timed out waiting for ${type}`)), 10_000);
    el.addEventListener(type, (e) => { clearTimeout(t); resolve(e); }, { once: true });
  });
}

const { document } = window;
const status = document.querySelector("cf-status");
status.load();
assert(status.querySelector(".cf-status-empty"), "status embed without a token explains itself instead of fetching");
const forms = [...document.querySelectorAll("cf-form")];
assert(forms.length === 2, "two embeds on the page");
// Re-trigger the load: the elements were parsed before the script ran.
await Promise.all(forms.map((el) => { const p = once(el, "cf:loaded"); el.load(); return p; }));
assert(forms[0].querySelector("form[data-cf-module='waitlist']"), "default card holds the waitlist form");
assert(forms[1].querySelector("form[data-cf-module='email-signup']"), "themed card holds the signup form");
assert(forms[1].closest(".card--themed"), "the restyled form sits in the themed card");

// The push block (issue #183). jsdom has no service worker, so what this
// proves is that the element is defined, upgrades, and reports the
// browser it is actually running in rather than throwing — the browser
// half itself is `push.mjs` and, live, issue #186.
const block = document.querySelector("cf-push");
assert(block && block.textContent.trim().length > 0, "the push block renders something in a browser without push");
assert(!block.querySelector("button"), "and offers no button it could not honour");
assert(typeof window.cf.push.subscribe === "function", "cf.push is on the page's own cf object");
// jsdom's `outside-only` never runs the page's own inline script, so the
// ordering is checked in the source instead — and it is the ordering that
// matters: `cf.js` is a module and therefore deferred, so a `window.cf`
// set after the tag still arrives first, and one set in another module
// would not.
const config = html.indexOf("window.cf =");
const embed = html.indexOf("/ui/cf.js");
assert(config > -1 && config < embed, "the page sets window.cf (base and auth) before the embed loads");
assert(/auth:/.test(html.slice(config, embed)), "and the auth seam is what it sets");

// CORS: the fragment came with the site's origin allowed.
const probe = await fetch(`${BASE}/ui/waitlist/join?fragment=1`, { headers: { Origin: SITE } });
assert(probe.headers.get("access-control-allow-origin") === SITE, "API allows the site origin");

// Submit an invalid address through the default form: the error lands on
// the field, the restyled card next to it is untouched.
forms[0].querySelector("input[name='email']").value = "nope";
const done = once(forms[0], "cf:submitted");
forms[0].querySelector("form").dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
const ev = await done;
assert(ev.detail.status === 422, `invalid submit answered 422 (got ${ev.detail.status})`);
assert(forms[0].querySelector(".cf-field--invalid[data-cf-field='email']"), "error on the email field");
assert(forms[1].querySelector("form"), "other embed untouched");

console.log("example site: all assertions passed");
