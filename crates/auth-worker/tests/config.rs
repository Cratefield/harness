//! The configuration surface (issues #646, #777): an instance names
//! itself — origin, id, browser origins, display name — and anything
//! missing or invalid is refused rather than silently replaced by another
//! app's value.

use cratefield_auth_worker::{AuthWorkerConfig, MailerKind, validate_config};
use cratefield_core::{MapConfig, VentureEnv};

/// The four values every instance must name, for a hypothetical app.
const REQUIRED: &[(&str, &str)] = &[
    ("AUTH_PUBLIC_URL", "https://auth.example.test"),
    ("AUTH_VENTURE_NAME", "example-auth"),
    ("AUTH_CORS_ORIGINS", "https://example.test"),
    ("AUTH_BRAND_NAME", "Example"),
];

/// `REQUIRED` with `pairs` laid over it (a later pair wins).
fn with_required(pairs: &[(&str, &str)]) -> MapConfig {
    let mut all: Vec<(&str, &str)> = REQUIRED
        .iter()
        .copied()
        .filter(|(key, _)| !pairs.iter().any(|(k, _)| k == key))
        .collect();
    all.extend(pairs.iter().copied());
    MapConfig::from_pairs(all)
}

fn config(pairs: &[(&str, &str)]) -> AuthWorkerConfig {
    AuthWorkerConfig::from_config(&with_required(pairs)).expect("valid configuration")
}

fn refusal(pairs: &[(&str, &str)]) -> String {
    AuthWorkerConfig::from_config(&with_required(pairs))
        .expect_err("must be refused")
        .to_string()
}

#[test]
fn an_empty_config_is_refused_naming_every_required_value() {
    let message = AuthWorkerConfig::from_config(&MapConfig::default())
        .expect_err("an instance must name itself")
        .to_string();
    for key in [
        "AUTH_PUBLIC_URL is required",
        "AUTH_VENTURE_NAME is required",
        "AUTH_CORS_ORIGINS is required",
        "AUTH_BRAND_NAME is required",
    ] {
        assert!(message.contains(key), "{key} missing from: {message}");
    }
    // Nothing falls back to another app's value.
    let lower = message.to_ascii_lowercase();
    // Spelt in halves so this file does not match a search for them.
    assert!(
        !lower.contains(concat!("factory", "0")) && !lower.contains(concat!("factory", " zero"))
    );
}

#[test]
fn a_minimal_instance_derives_everything_else_from_its_own_values() {
    let cfg = config(&[]);
    let venture = cfg.venture();

    assert_eq!(venture.name, "example-auth");
    assert_eq!(venture.domain, "auth.example.test");
    assert_eq!(venture.public_url, "https://auth.example.test");
    assert_eq!(venture.cors_origins, ["https://example.test"]);
    assert_eq!(venture.env, VentureEnv::default());
    assert_eq!(venture.problem_base, None);
    // Problem URIs follow the instance's public URL (issue #557).
    assert_eq!(
        venture.problem_type_base(),
        "https://auth.example.test/problems/"
    );

    assert_eq!(cfg.brand.name, "Example");
    assert_eq!(cfg.brand.footer, "auth.example.test · Example");
    assert_eq!(cfg.brand.accent, auth_core::brand::DEFAULT_ACCENT);
    assert_eq!(cfg.turnstile_hostname, "auth.example.test");
    assert_eq!(cfg.mail_from, "no-reply@auth.example.test");
    assert_eq!(cfg.mail_reply_to, None);
    // No provider key outside production: no mail is sent.
    assert_eq!(cfg.mailer_kind, MailerKind::None);
}

#[test]
fn branding_and_the_problem_base_are_configurable() {
    let cfg = config(&[
        ("AUTH_BRAND_LOGO_URL", "https://example.test/logo.svg"),
        ("AUTH_BRAND_ACCENT", "#0A84FF"),
        ("AUTH_BRAND_SUPPORT_EMAIL", "help@example.test"),
        ("AUTH_BRAND_FOOTER", "Example Ltd"),
        ("AUTH_BRAND_PRIVACY_URL", "https://example.test/privacy"),
        ("AUTH_BRAND_TERMS_URL", "https://example.test/terms"),
        ("AUTH_PROBLEM_BASE", "https://example.test/problems/"),
    ]);
    assert_eq!(cfg.brand.accent, "#0a84ff");
    assert_eq!(cfg.brand.footer, "Example Ltd");
    let venture = cfg.venture();
    assert_eq!(
        venture.problem_type_base(),
        "https://example.test/problems/"
    );
    assert_eq!(venture.brand.accent, "#0a84ff");
    assert_eq!(
        venture.brand.logo_url.as_deref(),
        Some("https://example.test/logo.svg")
    );

    assert!(refusal(&[("AUTH_BRAND_ACCENT", "orange")]).contains("AUTH_BRAND_ACCENT"));
    assert!(
        refusal(&[("AUTH_BRAND_LOGO_URL", "ftp://x.test/l.png")]).contains("AUTH_BRAND_LOGO_URL")
    );
    assert!(refusal(&[("AUTH_PROBLEM_BASE", "not a url")]).contains("AUTH_PROBLEM_BASE"));
}

#[test]
fn the_mailer_is_chosen_by_config_with_owlpost_first() {
    let owlpost = config(&[("OWLPOST_API_KEY", "k")]);
    assert_eq!(owlpost.mailer_kind, MailerKind::Owlpost);
    let resend = config(&[("RESEND_API_KEY", "k")]);
    assert_eq!(resend.mailer_kind, MailerKind::Resend);
    let chosen = config(&[
        ("AUTH_MAILER", "resend"),
        ("RESEND_API_KEY", "k"),
        ("OWLPOST_API_KEY", "k"),
    ]);
    assert_eq!(chosen.mailer_kind, MailerKind::Resend);

    assert!(
        refusal(&[("RESEND_API_KEY", "k"), ("OWLPOST_API_KEY", "k")]).contains("AUTH_MAILER"),
        "two keys and no choice is ambiguous"
    );
    assert!(
        refusal(&[("ENV", "production")]).contains("ENV=production needs a mailer"),
        "production refuses to run without a mailer"
    );
}

#[test]
fn a_public_url_drives_the_domain_and_the_derived_defaults() {
    let cfg = config(&[("AUTH_PUBLIC_URL", "https://auth.example.test")]);
    assert_eq!(cfg.venture().domain, "auth.example.test");
    assert_eq!(cfg.public_url, "https://auth.example.test");
    assert_eq!(cfg.turnstile_hostname, "auth.example.test");
    assert_eq!(cfg.mail_from, "no-reply@auth.example.test");
    // A bare trailing slash is allowed and normalized away.
    let slashy = config(&[("AUTH_PUBLIC_URL", "https://auth.example.test/")]);
    assert_eq!(slashy.public_url, "https://auth.example.test");
}

#[test]
fn localhost_may_use_http() {
    for local in [
        "http://localhost:8788",
        "http://127.0.0.1:8788",
        "http://[::1]:8788",
    ] {
        assert_eq!(config(&[("AUTH_PUBLIC_URL", local)]).public_url, local);
    }
}

#[test]
fn cors_origins_are_trimmed() {
    let cfg = config(&[(
        "AUTH_CORS_ORIGINS",
        "https://one.example.test, https://two.example.test",
    )]);
    assert_eq!(
        cfg.cors_origins,
        ["https://one.example.test", "https://two.example.test"]
    );
}

#[test]
fn the_issuer_must_name_the_instance_s_own_origin() {
    // The same origin, in any case and with or without a trailing slash.
    let same = config(&[("AUTH_CORE_ISSUER", "HTTPS://AUTH.Example.Test/")]);
    assert_eq!(same.public_url, "https://auth.example.test");

    assert!(
        refusal(&[("AUTH_CORE_ISSUER", "https://other.example.test")])
            .contains("AUTH_CORE_ISSUER must equal AUTH_PUBLIC_URL")
    );
}

#[test]
fn mail_addresses_may_carry_a_display_name() {
    let cfg = config(&[
        ("MAIL_FROM", "Auth <no-reply@auth.example.test>"),
        ("MAIL_REPLY_TO", "help@auth.example.test"),
    ]);
    assert_eq!(cfg.mail_from, "Auth <no-reply@auth.example.test>");
    assert_eq!(cfg.mail_reply_to.as_deref(), Some("help@auth.example.test"));

    assert!(refusal(&[("MAIL_FROM", "Auth no-reply@auth.example.test")]).contains("MAIL_FROM"));
    assert!(refusal(&[("MAIL_FROM", "Auth <@auth.example.test>")]).contains("MAIL_FROM"));
    assert!(
        refusal(&[("MAIL_FROM", "no-reply@auth.example.test\r\nBcc: x")]).contains("MAIL_FROM")
    );
}

#[test]
fn invalid_values_are_refused() {
    assert!(refusal(&[("AUTH_PUBLIC_URL", "not a url")]).contains("AUTH_PUBLIC_URL"));
    assert!(
        refusal(&[("AUTH_PUBLIC_URL", "https://auth.example.test/path")])
            .contains("AUTH_PUBLIC_URL")
    );
    assert!(
        refusal(&[("AUTH_PUBLIC_URL", "http://auth.example.test")]).contains("AUTH_PUBLIC_URL"),
        "http is refused off loopback"
    );
    assert!(refusal(&[("ENV", "prod")]).contains("ENV"), "unknown ENV");
    assert!(refusal(&[("AUTH_CORS_ORIGINS", "*")]).contains("AUTH_CORS_ORIGINS"));
    assert!(
        refusal(&[("AUTH_CORS_ORIGINS", "https://a.example.test/x")]).contains("AUTH_CORS_ORIGINS")
    );
    assert!(
        refusal(&[("AUTH_CORS_ORIGINS", "https://a.example.test/")]).contains("AUTH_CORS_ORIGINS")
    );
    // Loopback is compared exactly, not by prefix.
    for origin in ["http://localhost.evil.com", "http://127.0.0.10"] {
        assert!(
            refusal(&[("AUTH_CORS_ORIGINS", origin)]).contains("AUTH_CORS_ORIGINS"),
            "{origin} must be refused"
        );
    }
    // Browsers send the canonical origin, so a non-canonical entry is refused
    // rather than stored and echoed back unmatchable.
    for origin in ["https://App.example.test", "https://a.example.test:443"] {
        assert!(
            refusal(&[("AUTH_CORS_ORIGINS", origin)])
                .contains("must be written as its canonical origin"),
            "{origin} must be refused"
        );
    }
    assert!(
        refusal(&[("AUTH_CORS_ORIGINS", "http://a.example.test")]).contains("AUTH_CORS_ORIGINS"),
        "http is refused off loopback"
    );
    // Set-but-empty cannot be represented: an empty allowlist is refused.
    assert!(refusal(&[("AUTH_CORS_ORIGINS", "")]).contains("AUTH_CORS_ORIGINS"));
    assert!(refusal(&[("AUTH_MAILER", "mailgun")]).contains("AUTH_MAILER"));
    assert!(refusal(&[("AUTH_MAILER", "owlpost")]).contains("OWLPOST_API_KEY"));
    assert!(refusal(&[("AUTH_MAILER", "resend")]).contains("RESEND_API_KEY"));
    assert!(
        refusal(&[("ENV", "production"), ("AUTH_MAILER", "none")]).contains("AUTH_MAILER"),
        "an explicit none is refused in production"
    );
    assert!(
        refusal(&[("OWLPOST_BASE_URL", "http://owlpost.example.test")])
            .contains("OWLPOST_BASE_URL")
    );
    assert!(refusal(&[("MAIL_FROM", "not an address")]).contains("MAIL_FROM"));
}

#[test]
fn validate_config_matches_the_from_config_contract() {
    assert!(validate_config(&with_required(&[("AUTH_MAILER", "resend")])).is_err());
    assert!(validate_config(&MapConfig::default()).is_err());
    assert!(validate_config(&with_required(&[])).is_ok());
}
