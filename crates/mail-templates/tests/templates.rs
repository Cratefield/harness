//! Snapshots of the sample messages (HTML and text) in the neutral theme and
//! a branded one, the layout essentials every mail must have, and the
//! escaping of every value a person can influence.

use cratefield_mail_templates::{Dir, MailTheme, Message, Palette, escape, samples};

fn branded() -> MailTheme {
    MailTheme::new("Acme", "https://acme.test")
        .wordmark("acme")
        .logo("https://acme.test/assets/email/logo-64.png", "Acme")
        .logo_tile("#0E1526")
        .light(
            Palette::neutral_light()
                .bg("#F5F6F8")
                .ink("#0E1526")
                .accent("#B7791F")
                .button("#0E1526"),
        )
        .dark(
            Palette::neutral_dark()
                .button("#F4B63F")
                .button_text("#0E1526"),
        )
        .font("Satoshi,-apple-system,'Segoe UI',sans-serif")
        .footer_line("Acme Ltd, 1 Example Road, Testville")
        .contact("hello@acme.test")
}

#[test]
fn every_sample_matches_its_snapshot() {
    for (theme_name, theme) in [
        ("neutral", MailTheme::new("Acme", "https://acme.test")),
        ("branded", branded()),
    ] {
        for (name, message) in samples() {
            let email = message.render(&theme);
            insta::assert_snapshot!(format!("{theme_name}-{name}.html"), email.html);
            insta::assert_snapshot!(
                format!("{theme_name}-{name}.txt"),
                format!(
                    "Subject: {}\nPreheader: {}\n\n{}",
                    email.subject, email.preheader, email.text
                )
            );
        }
    }
}

#[test]
fn every_sample_has_the_layout_essentials() {
    let theme = branded();
    for (name, message) in samples() {
        let e = message.render(&theme);
        let h = &e.html;
        assert!(h.starts_with("<!doctype html>"), "{name}");
        assert!(
            h.contains("<html lang=\"en\" dir=\"ltr\""),
            "{name}: lang and dir"
        );
        assert!(
            h.contains("prefers-color-scheme:dark"),
            "{name}: dark variant"
        );
        assert!(
            h.contains(".cf-btn{background:#F4B63F!important}"),
            "{name}: dark button"
        );
        assert!(h.contains("max-width:600px"), "{name}: 600px");
        assert!(
            h.contains("@media (max-width:620px)"),
            "{name}: narrow screens"
        );
        assert!(h.contains(&escape(&e.preheader)), "{name}: preheader");
        assert!(h.contains("alt=\"Acme\""), "{name}: logo alt");
        assert_eq!(h.matches("<img").count(), 1, "{name}: only the logo");
        assert!(
            !h.contains("<link") && !h.contains("@import") && !h.contains("@font-face"),
            "{name}: no external CSS or web fonts"
        );
        assert!(!h.contains("<script"), "{name}");
        assert_eq!(
            h.matches("class=\"cf-btn\"").count(),
            1,
            "{name}: one primary button"
        );
        assert!(
            h.contains("Acme Ltd, 1 Example Road"),
            "{name}: footer line"
        );
        assert!(
            e.text.contains("Acme Ltd, 1 Example Road"),
            "{name}: text footer"
        );
        assert!(!e.text.contains('<'), "{name}: text has no markup");
    }
}

#[test]
fn the_fallback_link_is_a_button_and_a_plain_url() {
    let link = "https://api.acme.test/v1/x?token=abc_DEF-123";
    let e = Message::new("s", "h")
        .button("Sign in", link)
        .fallback_link()
        .render(&MailTheme::default());
    assert_eq!(e.html.matches(&format!("href=\"{link}\"")).count(), 2);
    assert!(e.html.contains(&format!(">{link}</a>")));
    assert!(e.text.contains(link));
}

#[test]
fn a_url_that_is_not_web_or_mailto_is_never_a_link() {
    let e = Message::new("s", "h")
        .button("Open", "javascript:alert(1)")
        .footer_link("Unsubscribe", "javascript:alert(2)")
        .render(&MailTheme::default());
    assert!(!e.html.contains("href=\"javascript"), "{}", e.html);
    assert!(!e.html.contains("class=\"cf-btn\""), "no button for it");
}

#[test]
fn right_to_left_and_another_language_reach_the_document() {
    let e = Message::new("s", "h")
        .lang("ar")
        .dir(Dir::Rtl)
        .render(&MailTheme::default());
    assert!(e.html.contains("<html lang=\"ar\" dir=\"rtl\""));
}

#[test]
fn the_neutral_theme_without_a_logo_names_the_brand_in_text() {
    let e = Message::new("s", "h").render(&MailTheme::new("acme", "https://acme.test"));
    assert!(!e.html.contains("<img"));
    assert!(e.html.contains(">acme</td>"));
}

const HOSTILE: &str =
    "<img src=x onerror=alert(1)>\"'&<script>alert(2)</script>\r\nBcc: x@evil.test";

#[test]
fn every_value_is_escaped_in_html_and_cannot_forge_a_text_line() {
    let theme = MailTheme::new(HOSTILE, "https://acme.test")
        .wordmark(HOSTILE)
        .logo("https://acme.test/l.png", HOSTILE)
        .footer_line(HOSTILE)
        .contact(HOSTILE);
    let e = Message::new(HOSTILE, HOSTILE)
        .preheader(HOSTILE)
        .lang(HOSTILE)
        .paragraph(HOSTILE)
        .fact(HOSTILE, HOSTILE)
        .code_fact("Key", HOSTILE)
        .button(HOSTILE, format!("https://acme.test/?q={HOSTILE}"))
        .fallback_link()
        .link_intro(HOSTILE)
        .code(HOSTILE, HOSTILE)
        .note(HOSTILE)
        .recipient(HOSTILE)
        .why(HOSTILE)
        .footer_link(HOSTILE, format!("https://acme.test/u?{HOSTILE}"))
        .render(&theme);
    assert!(!e.html.contains("<script"), "raw script tag");
    assert!(!e.html.contains("<img src=x"), "raw img tag");
    assert!(!e.html.contains("onerror=alert(1)>"), "raw attribute");
    assert!(
        e.html
            .contains("&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;&lt;script&gt;")
    );
    for part in [&e.text, &e.subject, &e.preheader] {
        assert!(
            !part.contains("\nBcc:") && !part.contains("\rBcc:"),
            "line forged: {part}"
        );
    }
}
