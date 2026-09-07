# ADR 0010: Modules declare a UI surface; the harness renders it

Status: proposed, 2026-09-07

## Context
A venture composes modules and gets an API (ADR 0003). It gets no UI. Every
Factory Zero site today hand-writes the signup and waitlist forms against
`/v1/<module>` and re-implements the same states: pending, captcha, `202`,
`problem+json` field errors, the confirm redirect. The Cratefield control plane
will provision a backend for a customer in seconds and then leave them with
nothing to look at, and later we want a customer to describe the UI they want
in a prompt and get one.

Three constraints shape the answer.

1. **Automatic.** The UI has to follow from the modules that are mounted, with
   no per-venture UI code. An axum `Router` is opaque, so nothing can be
   discovered from the routes; a module has to say what it offers.
2. **Fast and light.** The sites are static HTML on Cloudflare Pages and the
   API is a Worker at the edge. A framework runtime in the browser (React, or a
   Rust-to-wasm UI crate at hundreds of KB plus a build step) is the wrong
   weight class for a signup form. Server-rendered HTML from the Worker costs
   microseconds and ships no JavaScript of ours; the only script on a public
   form is Turnstile's, and only when the captcha port is configured.
3. **Styleable.** A venture must be able to make it look like theirs with a
   stylesheet and nothing else, without fighting specificity or reaching into a
   shadow root.

The chi platform already solved the adjacent problem for ticket storefronts:
`@chi-ecosystem/storefront-react` ships a generated `manifest.json` and JSON
Schemas that an agent reads before writing a storefront. That is the shape the
"describe it in a prompt" step needs, so the surface here is designed to be
that manifest from day one rather than an afterthought.

## Decision
**A module declares a `Surface`. The harness serves it as data and renders it
as HTML from one renderer in the Worker. Static sites embed that HTML with a
tiny script, and styling is plain CSS against a fixed markup contract.**

### 1. The surface is declared, typed, and served
`Module` gains `fn surface(&self) -> Surface { Surface::none() }`. A `Surface`
is a list of **actions** and **views**:

- An `Action` names a route the module already serves (method and path
  relative to `/v1/<name>`), its **audience** (`Public`, `Admin`, or `Link`
  for signed-token GETs such as `confirm`), its **input schema**, and its
  **outcome** (`Accepted { message }`, `Redirect`, or `Json`).
- The input schema is derived with `schemars` from the **same serde type the
  handler deserializes**, so the surface cannot drift from the handler. UI
  hints (label, placeholder, widget, hidden) are `x-cf-*` extension keywords
  set through `schemars` attributes on the field. `captchaToken` is hidden and
  supplied by the renderer, never by the user.
- A `View` composes actions: `Form(action)`, `Status(action)`, or
  `Table { source, columns }` over an admin export.

`Harness::build()` validates the surface the way it validates ports and
tables: duplicate action names, views that reference unknown actions, and a
non-object input schema are build errors. The composed surface is computed
once at build and served at **`GET /__surface`**, public subset only; the
admin subset is included when the request carries the admin bearer. The
response carries an `ETag` that is the hash of the surface, so tooling caches
it until the deploy changes. The surface has its own contract
version, `surface_api`, alongside `harness_api`.

### 2. One renderer, HTML over the wire
The renderer is a new `cratefield-ui` crate built on `maud`, which is string
building and runs on wasm. Mounting `.ui(Ui::default())` in the builder adds
`/ui/<module>/<action>` (a full page), the same path with `?fragment=1` (the
form markup alone, no `<html>` wrapper), `/ui/cf.css` and `/ui/cf.js`.

**Modules stay JSON-only.** A page's form posts to its own `/ui` route, not to
`/v1`. The UI handler turns the form body into the JSON request the module
already accepts, dispatches it **in-process** to the module router (the API
router is a `tower::Service`; the UI holds a clone and calls it, so nothing
leaves the isolate and every module middleware still runs), and renders the
result: a `202` becomes the success notice, a `problem+json` becomes the form
re-rendered with the errors on their fields and the values preserved, a `303`
is passed to the browser. The client's `cf-connecting-ip`, `x-forwarded-for`
and `Authorization` headers are forwarded on the internal request so rate
limiting, captcha verification and admin checks see the real caller. No
module handler changes, no content negotiation, no second body encoding.

**`cf.js` is an embed, not a renderer.** It is one dependency-free ES2020
file of at most 4 KB minified and gzipped, checked in and size-gated in CI. A
custom element such as `<cf-form module="waitlist" action="join"
product="kontinuum">` fetches the fragment from the API origin, inserts it
into the **light DOM**, and turns the submit into a `fetch` of the same `/ui`
route that swaps the returned fragment back in. Attributes that name a field
pre-fill and hide it. Every byte of markup comes from the one Rust renderer,
so there is nothing to keep in parity and nothing to restyle twice; a
`<noscript>` link to the full `/ui` page is the fallback.

The wasm build renders a page and submits it under `wrangler dev` in CI,
because a green build proves nothing about a Workers request.

### 3. Styling is a CSS contract, not a theme API
The markup uses a fixed class vocabulary (`cf-form`, `cf-field`,
`cf-field--invalid`, `cf-label`, `cf-input`, `cf-submit`, `cf-notice`,
`cf-error`, and so on) plus `data-cf-module`, `data-cf-action` and
`data-cf-field` attributes, and never a shadow root. `cf.css` is small, sits in
`@layer cf`, and is written entirely against `--cf-*` custom properties.
Because it is layered, any unlayered author stylesheet wins without
`!important`; a venture that wants to restyle sets the custom properties, adds
its own rules, or drops `cf.css` and writes against the vocabulary. The
vocabulary and the properties are a documented, versioned contract; changing
a class name is a breaking change of the UI surface.

### 4. `UiSpec` is the thing a prompt will produce
Everything that is not code or CSS is a **`UiSpec`**: per-action labels and
copy, field order, hidden fields, the success message, the page title. It is
JSON validated against a published `ui-spec-v1.schema.json`, given to the
builder as `.ui(Ui::from_spec(...))` or by runtime configuration, and applied
by the renderer. Where per-venture runtime configuration lives is the same
open question as ADR 0009's sidecar mount table and is decided once, there. `/__surface`, the schema, and a `docs/ui-llms.txt` that states the
class vocabulary, the custom properties and worked examples are the complete
input an LLM needs to turn "make it look like a record label site" into a
`UiSpec` plus a stylesheet. That generation step lives in the Cratefield
control plane, not in this repository, and the same shape is what a
prompt-driven storefront builder in chi-web would produce from the
storefront-react manifest.

## Consequences
- A module author adds a `JsonSchema` derive, a handful of `x-cf-*` hints and
  a `surface()` that lists the actions. Nothing else changes for the module,
  and a module that declares nothing renders nothing.
- A venture gets working, styleable pages for every module the moment it
  builds, and the same forms embed in a static site with one script tag. No
  venture writes form-state code again.
- Admin pages need a session. The first version takes the admin token in a
  login form and sets a cookie signed by the `Signer`; the accounts module,
  when it exists, replaces that.
- `/ui` and `/__surface` join `/.well-known` as the only root-mounted paths;
  ARCHITECTURE §6 and the comment on `Harness::router` change accordingly.
- Rejected: a Rust-to-wasm browser UI (size and a build step), React or any
  framework (a dependency on a stack the sites do not have), shadow DOM (the
  styling promise), a second client-side renderer with a parity test (the
  first draft of this ADR had one; HTML over the wire makes it unnecessary),
  form-encoded bodies on module routes (a `JsonOrForm` extractor would have
  put a second encoding and its edge cases into every handler), runtime
  template files (ADR 0003's compile-time composition applies), and a page
  builder in the harness (that is a control plane product; the harness only
  renders what a `UiSpec` says).
- The sidecar mount (ADR 0009) must forward `/__surface` from the sidecar and
  merge it, or a sidecar module renders nothing. Tracked with the epic.
