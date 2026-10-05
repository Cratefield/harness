//! The configuration surface (issue #646): the defaults match today's
//! deployment, and every invalid value is refused rather than silently
//! replaced.

use cratefield_auth_worker::{AuthWorkerConfig, MailerKind, validate_config};
use cratefield_core::{MapConfig, VentureEnv};

fn config(pairs: &[(&str, &str)]) -> AuthWorkerConfig {
    AuthWorkerConfig::from_config(&MapConfig::from_pairs(pairs.iter().copied()))
        .expect("valid configuration")
}

fn refusal(pairs: &[(&str, &str)]) -> String {
    let cfg: MapConfig = MapConfig::from_pairs(pairs.iter().copied());
    AuthWorkerConfig::from_config(&cfg)
        .expect_err("must be refused")
        .to_string()
}

#[test]
fn empty_config_is_todays_deployment() {
    let cfg = config(&[]);
    let venture = cfg.venture();

    assert_eq!(venture.name, "factory0-auth");
    assert_eq!(venture.domain, "auth.factory0.ventures");
    assert_eq!(venture.public_url, "https://auth.factory0.ventures");
    assert_eq!(
        venture.cors_origins,
        [
            "https://app.cratefield.com",
            "https://cratefield.com",
            "https://yoginini.us"
        ]
    );
    assert_eq!(venture.env, VentureEnv::default());
    assert_eq!(venture.problem_base, None);
    // Problem URIs follow the public URL (issue #557).
    assert_eq!(
        venture.problem_type_base(),
        "https://auth.factory0.ventures/problems/"
    );

    assert_eq!(cfg.turnstile_hostname, "auth.factory0.ventures");
    assert_eq!(cfg.mail_from, "no-reply@auth.factory0.ventures");
    assert_eq!(cfg.mail_reply_to, None);
    // Unset `AUTH_MAILER` with no key: no mail is sent.
    assert_eq!(cfg.mailer_kind, MailerKind::None);
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
fn the_issuer_only_has_to_agree_when_the_public_url_is_set() {
    // Nothing is cross-checked by default: a staging deployment may rely on
    // the default public URL and point the issuer at its own host.
    let staging = config(&[("AUTH_CORE_ISSUER", "https://staging.example.test")]);
    assert_eq!(staging.public_url, "https://auth.factory0.ventures");

    // With `AUTH_PUBLIC_URL` set, the same origin must be named, in any case
    // and with or without a trailing slash.
    let same = config(&[
        ("AUTH_PUBLIC_URL", "https://auth.example.test"),
        ("AUTH_CORE_ISSUER", "HTTPS://AUTH.Example.Test/"),
    ]);
    assert_eq!(same.public_url, "https://auth.example.test");

    assert!(
        refusal(&[
            ("AUTH_PUBLIC_URL", "https://auth.example.test"),
            ("AUTH_CORE_ISSUER", "https://other.example.test"),
        ])
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
    let bad = MapConfig::from_pairs([("AUTH_MAILER", "resend")]);
    assert!(validate_config(&bad).is_err());
    assert!(validate_config(&MapConfig::default()).is_ok());
}
