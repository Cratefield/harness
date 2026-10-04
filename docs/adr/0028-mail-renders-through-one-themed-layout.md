# ADR 0028: Mail renders through one themed layout, and the theme travels by composition and config, not through core

Status: proposed, 2026-10-04. Issue #715. Extends issue #12 (default
templates with venture overrides) and the template registry in
`cratefield-core` (`template.rs`). Changes no locked contract: the `Module`
trait, `ModuleContext`, `Brand` and `HARNESS_API` are untouched.

## Context

Every venture's mail comes from harness modules: the waitlist confirmation,
the magic-link sign-in, email-signup, org invitations, notifications and the
password flows. Each module rendered its own markup — askama pages with one
accent colour in three modules, a `format!` fragment in two — so no mail
looked like the venture that sent it, the layouts differed from module to
module, and email-client safety (tables, inline styles, a dark variant, a
preheader, `lang`) was nobody's job. Owlpost's own mail
(`owlpost-mail-templates`) had already solved the layout once.

Two questions had to be answered: where the layout lives, and how a module
learns the venture's theme.

The obvious home for the theme is core: a richer `Brand` on `Venture`, which
every module already sees through `ctx.venture`. But `Brand` and `Venture`
are public structs with public fields and no `#[non_exhaustive]`, so a new
field breaks every venture that builds one with a literal, and a core minor
bump cascades a release through every crate (docs/RELEASING.md). A theme is
presentation; it should not cost a breaking core release.

The template registry is the other venture-level mail hook every module
sees (`ctx.templates`), but its ids must name a registered module
(`HarnessBuilder::build` refuses `mail/theme`), so it cannot carry one
venture-wide value either.

## Decision

1. **One layout crate.** `cratefield-mail-templates` owns the layout: a
   `Message` builder rendered with a `MailTheme` into an HTML part and a
   plain-text twin. Modules describe what a mail says; the crate decides
   how it looks and escapes everything. It depends only on core, serde and
   tracing, and builds for wasm32.

2. **The theme travels with the templates.** Each mail-sending module
   exports `themed_templates(&MailTheme)` beside `default_templates()`,
   returning the same template ids carrying the venture's theme. A venture
   composes its theme exactly where it already registers templates, one
   line per module. Modules that rendered outside the registry
   (`module-orgs`, `module-notifications`) now render through it
   (`orgs/invitation`, `notifications/email`), which also makes them
   overridable like the rest.

3. **The module attaches what it can resolve.** At send time the module
   puts `MailTheme::from_config(venture, config)` into the template data
   under `theme`, and the raw `MAIL_THEME` config object under
   `theme_override`. A composed theme wins over the attached one; the
   override is merged over either. So the precedence is: composition, then
   the deployment's `MAIL_THEME` adjustments on top, else a neutral theme
   derived from the venture's name, public URL and core `Brand`. A venture
   that does nothing keeps working, and a venture's own override template
   can read `theme` and render in the same style.

4. **Themes are data, checked at render.** `MailTheme` is serde with
   defaults on every field, so the same JSON drives config and previews.
   Because a theme can come from config, colours must be hex, font stacks
   are filtered, and the logo must be an `http(s)` URL before anything
   reaches a `style` or `src` attribute.

## Consequences

- Every mail a module sends has the same structure, dark variant, preheader
  and text part, and changes to that structure happen in one crate with one
  set of snapshots.
- A venture adopts its brand with one dependency and a `themed_templates`
  call per module; the per-venture issues filed alongside #715 carry the
  theme values.
- The rendered output of every default template changed (subjects and
  security wording did not), so ventures with snapshot tests of mail see a
  diff.
- A future core minor can still move the theme onto `Venture` if one place
  per venture proves better than one call per module; the data shape would
  not change.
