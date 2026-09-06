# factory0-ui

Renders the harness's UI surface (ADR 0010) as HTML from inside the Worker.
Mount it with `Harness::builder().ui(factory0_ui::Ui::default())` and every
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
