// The embed against a running harness (issue #73). Run with the example
// venture up on BASE (default http://127.0.0.1:8787, what `wrangler dev`
// binds in CI): embeds two forms, checks attributes pre-fill and hide,
// submits the sample module's form and expects the swapped notice, submits
// an invalid waitlist form and expects the error on its field.
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

const BASE = process.env.BASE || "http://127.0.0.1:8787";
const source = readFileSync(new URL("../../crates/ui/assets/cf.js", import.meta.url), "utf8");

// jsdom runs classic scripts only: inline the module's origin and drop the
// export. Everything else is the served file, byte for byte.
const script = source
  .replace("new URL(import.meta.url).origin", JSON.stringify(BASE))
  .replace(/^export .*$/m, "");

const dom = new JSDOM("<!doctype html><body></body>", {
  url: "https://example.factory0.dev/waitlist?token=not-a-real-token",
  runScripts: "outside-only",
  pretendToBeVisual: true,
});
const { window } = dom;
// jsdom's URLSearchParams is not Node's, and undici only recognises its
// own, so re-wrap the body or it goes out as text without a content-type.
window.fetch = (url, init) => {
  if (init?.body && !(init.body instanceof URLSearchParams)) {
    init = { ...init, body: new URLSearchParams(String(init.body)) };
  }
  return fetch(String(url), init);
};
window.eval(script);

function once(el, type, timeout = 10_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${type}`)), timeout);
    el.addEventListener(type, (e) => {
      clearTimeout(timer);
      resolve(e);
    }, { once: true });
  });
}

function assert(cond, message) {
  if (!cond) {
    console.error(`FAIL: ${message}`);
    process.exit(1);
  }
  console.log(`ok: ${message}`);
}

const { document } = window;
window.addEventListener("cf:error", (e) => console.error("cf:error", e.detail.error), true);
document.body.innerHTML = `
  <cf-form id="sample" module="sample" action="insert"></cf-form>
  <cf-form id="join" module="waitlist" action="join" product="kontinuum" ref="R1"></cf-form>
  <cf-status id="status" module="waitlist"></cf-status>
`;
const sample = document.getElementById("sample");
const join = document.getElementById("join");
const status = document.getElementById("status");

// The link fallback is there before anything loads.
assert(join.querySelector("a.cf-embed-link"), "fallback link rendered while loading");
assert(
  join.querySelector("a.cf-embed-link").href.startsWith(`${BASE}/ui/waitlist/join?`),
  "fallback link points at the full page on the API origin",
);

await Promise.all([once(sample, "cf:loaded"), once(join, "cf:loaded"), once(status, "cf:loaded")]);

assert(sample.querySelector("form.cf-form[data-cf-module='sample'][data-cf-action='insert']"), "sample form embedded");
assert(join.querySelector("form.cf-form[data-cf-module='waitlist']"), "waitlist form embedded");
assert(!join.querySelector("select[name='product']"), "attribute-supplied product is not a select");
assert(join.querySelector("input[type='hidden'][name='product'][value='kontinuum']"), "product pre-filled as hidden input");
assert(join.querySelector("input[type='hidden'][name='ref'][value='R1']"), "ref pre-filled as hidden input");
assert(!join.querySelector("form").getAttribute("action").includes("/v1/"), "form posts to /ui, never /v1");
assert(status.querySelector(".cf-notice--error, .cf-status"), "status embed rendered the module's answer for the page token");

// Submit the sample form: D1-backed, no mailer needed, answers 202.
sample.querySelector("input[name='email']").value = "embed@example.com";
const submitted = once(sample, "cf:submitted");
sample.querySelector("form").dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
const ok = await submitted;
assert(ok.detail.status === 200, `sample submit swapped a 200 (got ${ok.detail.status})`);
assert(sample.querySelector(".cf-notice--success"), "success notice swapped in");
assert(sample.textContent.includes("Row stored."), "notice carries the action's message");

// Submit an invalid waitlist form: the error lands on the email field.
join.querySelector("input[name='email']").value = "not-an-email";
const failed = once(join, "cf:submitted");
join.querySelector("form").dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
const err = await failed;
assert(err.detail.status === 422, `invalid submit answered 422 (got ${err.detail.status})`);
assert(join.querySelector(".cf-field--invalid[data-cf-field='email']"), "error on the email field");
assert(join.querySelector("input[name='email']").value === "not-an-email", "typed value preserved");
assert(join.querySelector("input[type='hidden'][name='product'][value='kontinuum']"), "hidden product survives the re-render");
assert(!join.querySelector(".cf-submit").disabled, "submit button re-enabled on the re-rendered form");

console.log("cf.js embed: all assertions passed");
