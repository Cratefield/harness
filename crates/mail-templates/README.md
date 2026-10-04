<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-mail-templates.png" alt="cratefield-mail-templates — Mail that looks like the venture." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-mail-templates"><img src="https://img.shields.io/crates/v/cratefield-mail-templates.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-mail-templates on crates.io"></a>
  <a href="https://docs.rs/cratefield-mail-templates"><img src="https://img.shields.io/docsrs/cratefield-mail-templates?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-mail-templates documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-mail-templates

Branded transactional mail for Cratefield ventures: one email-client-safe
layout, themed with the venture's own website colours, logo and fonts, and a
plain-text twin for every message. Every harness module that sends mail
(`module-waitlist`, `module-email-signup`, `module-orgs`,
`module-notifications`, `auth-magic-link`, `auth-password`, the control-plane
console) renders through it. Generalised from Owlpost's own mail templates.

## What a mail gets

- A 600px table layout with every style inline, which reads the same in
  Gmail, Outlook, Apple Mail and clients that ignore `<style>`. The one
  `<style>` block only adds narrow-screen and `prefers-color-scheme: dark`
  overrides.
- A preheader, `lang` and `dir` on the document, alt text on the logo.
- One image: the venture's hosted PNG logo. No web fonts, no tracking
  pixel, no click tracking.
- A primary button, its URL repeated as a copyable link, muted notes for
  link expiry and "ignore this if you didn't ask", and a footer saying who it
  was sent to and why.
- A `text/plain` part with the same content, which the mailer sends as
  `multipart/alternative` (Resend and Owlpost adapters both send both parts).

Every value reaches the HTML escaped and the text part with control
characters removed, so a name typed by a person can neither add markup nor
forge a line. Theme colours must be hex and fonts lose anything that could
leave a CSS declaration, so a theme read from config cannot inject CSS. Only
`https:`, `http:` and `mailto:` URLs become links.

## A venture's theme

```rust
use cratefield_mail_templates::{MailTheme, Palette};

fn theme() -> MailTheme {
    MailTheme::new("FindsYou", "https://findsyou.work")
        .wordmark("FindsYou")
        .logo("https://findsyou.work/assets/email/logo-64.png", "FindsYou")
        .light(Palette::neutral_light().bg("#F6F4EF").accent("#2F6B4F").button("#1B1B1B"))
        .dark(Palette::neutral_dark().button("#F6F4EF").button_text("#1B1B1B"))
        .font("Inter,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif")
        .footer_line("FindsYou, Bali, Indonesia")
        .contact("hello@findsyou.work")
}
```

Compose it into each module that sends mail, in place of its
`default_templates()`:

```rust
Harness::builder()
    .templates(cratefield_module_waitlist::themed_templates(&theme()))
    .templates(factory0_auth_magic_link::themed_templates(&theme()))
```

Where a module's theme comes from, strongest first:

1. **Composition** — `themed_templates(&theme)` on the module.
2. **Config** — `MAIL_THEME`, a JSON object with any subset of the fields,
   merged over (1) field by field (`{"light":{"button":"#123456"}}`). A
   value that does not parse is logged and ignored: a typo never stops mail.
3. **Default** — `MailTheme::for_venture`: the venture's name and public URL
   and what its core `Brand` says (accent, logo, footer line), on neutral
   greys. A venture that does nothing keeps working.

The logo is a PNG (most clients drop SVG), hosted on the venture's site at
twice its display size: `logo-64.png` for the default 32×32. Themes are
plain data (`serde`), so the same JSON drives `MAIL_THEME` and the preview
tool.

## Writing a mail

```rust
use cratefield_mail_templates::{MailTheme, Message};

let email = Message::new("Sign in to Acme", "Sign in to Acme")
    .preheader("This link works once, for 15 minutes.")
    .paragraph("Use the button below to sign in.")
    .button("Sign in", "https://api.acme.test/v1/auth-magic-link/consume?token=abc")
    .fallback_link()
    .note("If you didn't ask for this, ignore this email.")
    .recipient("ada@example.com")
    .why("someone asked to sign in to Acme with this address")
    .render(&MailTheme::new("Acme", "https://acme.test"));
// email.subject, email.preheader, email.html, email.text
```

## Previews

```sh
tools/render-emails --theme theme.json --product findsyou out/ --screenshots --logo logo-64.png
```

renders every module's mail with sample values in that theme, and with
`--screenshots` takes PNGs at 600px and 360px, light and dark, in headless
Chrome. `--logo` serves a local file for the logo URL so previews show it
before the website hosts it.
