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

if (!customElements.get("cf-form")) customElements.define("cf-form", CfForm);
if (!customElements.get("cf-status")) customElements.define("cf-status", CfStatus);

export { CfForm, CfStatus };
