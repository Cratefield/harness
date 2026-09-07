//! The email-signup UI surface (ADR 0010, issue #71).

use cratefield_core::{Audience, Module, Outcome, View};
use cratefield_module_email_signup::EmailSignup;

#[test]
fn subscribe_form_message_follows_double_opt_in() {
    let single = EmailSignup::new().double_opt_in(false).surface();
    let double = EmailSignup::new().double_opt_in(true).surface();
    let message = |s: &cratefield_core::Surface| match &s.actions[0].outcome {
        Outcome::Accepted { message } => message.clone(),
        other => panic!("unexpected outcome {other:?}"),
    };
    assert_eq!(single.actions[0].name, "subscribe");
    assert_eq!(message(&single), "You're subscribed.");
    assert!(message(&double).contains("inbox"));
}

#[test]
fn only_email_is_visible_and_admin_actions_are_hidden_publicly() {
    let surface = EmailSignup::new().surface();
    let subscribe = &surface.actions[0];
    assert!(subscribe.captcha);
    let input = subscribe.input.as_ref().unwrap().as_value();
    assert_eq!(input["properties"]["email"]["x-cf-widget"], "email");
    for hidden in ["source", "locale", "captchaToken"] {
        assert_eq!(input["properties"][hidden]["x-cf-hidden"], true, "{hidden}");
    }
    let names: Vec<&str> = surface.actions.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(
        names,
        ["subscribe", "confirm", "unsubscribe", "export", "delete"]
    );
    let public = surface.public();
    assert!(public.actions.iter().all(|a| a.audience != Audience::Admin));
    assert_eq!(public.views.len(), 1);
    assert!(matches!(public.views[0], View::Form { .. }));
}
