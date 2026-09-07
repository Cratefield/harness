<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-ui"><img src="https://img.shields.io/crates/v/cratefield-ui.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-ui on crates.io"></a>
  <a href="https://docs.rs/cratefield-ui"><img src="https://img.shields.io/docsrs/cratefield-ui?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-ui documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-ui

Renders the harness's UI surface (ADR 0010) as HTML from inside the Worker.
Mount it with `Harness::builder().ui(cratefield_ui::Ui::default())` and every
module that declares a surface gets pages at `/ui/<module>/<action>`, the
same markup as a fragment with `?fragment=1`, landing pages at
`/ui/<module>/<action>/{done,expired}`, and the base stylesheet at
`/ui/cf.css`.

A form posts to its own `/ui` route. The handler turns the form into the JSON
the module accepts and dispatches it in-process to the `/v1` router, then
renders the `202` as a notice, a `problem+json` as the form with the error on
its field, and passes a `303` to the browser. Modules stay JSON-only.

Styling is a CSS contract, not an API: `cf-*` classes and `data-cf-*`
attributes, no shadow DOM, and `cf.css` inside `@layer cf` written against
`--cf-*` custom properties, so any venture stylesheet wins without
`!important`. The contract is documented in `docs/UI.md`.

On a static site, `cf.js` (under 4 KB) embeds those fragments:

```html
<script type="module" src="https://api.example.com/ui/cf.js"></script>
<cf-form module="waitlist" action="join" product="kontinuum"></cf-form>
```
