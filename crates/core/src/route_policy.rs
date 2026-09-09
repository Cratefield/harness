//! Route protection policies and the production abuse gate (issue #133).
//!
//! Every declared write route carries an explicit [`RoutePolicy`]: it is
//! open, protected by a human-form CAPTCHA, or protected by a machine
//! signature (a payments webhook). The old shape — a bare `captcha: bool`
//! plus the module-level `public_writes()` flag consulted only by
//! `fz doctor` — let a webhook satisfy "has captcha" while simultaneously
//! getting a captcha widget rendered on it, and left production booting
//! with no verification at all as long as nobody ran the doctor.
//!
//! [`WriteGuards::collect`] reads the composed modules and says what the
//! venture demands; [`production_readiness`] turns that plus what the
//! runtime can actually do into build errors. `HarnessBuilder::build`
//! calls it — enforcement moved from a CLI report to runtime
//! initialization — and `fz doctor` keeps calling the same function as an
//! advisory re-check, the way it re-checks `harness_api` (issue #17).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::harness::Runtime;
use crate::module::Module;
use crate::ports::{Captcha, Port};
use crate::problem::Problem;
use crate::problems::SLUGS;
use crate::surface::Surface;
use crate::venture::VentureEnv;

/// How a request to a declared route proves it is legitimate.
///
/// The variants are mutually exclusive by construction: a route is
/// protected by a human proof, a machine signature, or nothing — never
/// both, and never by whichever check the module happened to wire up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RoutePolicy {
    /// No gateway-level protection. The default, and correct for reads
    /// and for anything the handler authenticates itself.
    #[default]
    Open,
    /// A public form submission from a browser. The handler verifies the
    /// `captchaToken` the renderer supplies through the `Captcha` port,
    /// and `Harness::build` refuses to boot a production venture whose
    /// runtime cannot actually do that ([`captcha_effective`]).
    HumanForm,
    /// An authenticated machine caller — a payments webhook. The handler
    /// proves the delivery with [`Payments::verify_webhook`]
    /// (`cratefield_core::Payments`) plus the [`Inbox`] dedup ledger. A
    /// CAPTCHA is meaningless here (the caller has no browser) and must
    /// never be rendered or required on such a route.
    ///
    /// [`Payments::verify_webhook`]: crate::ports::Payments::verify_webhook
    /// [`Inbox`]: crate::idempotency::Inbox
    Signature,
}

impl RoutePolicy {
    /// Whether this policy is a protection (as opposed to [`RoutePolicy::Open`]).
    #[must_use]
    pub fn is_guarded(self) -> bool {
        self != Self::Open
    }
}

/// What the composed modules demand of the runtime, module by module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteGuards {
    /// Modules with a [`RoutePolicy::HumanForm`]-guarded write (or the
    /// conservative fallback: [`public_writes`] and no declared policy at all).
    ///
    /// [`public_writes`]: Module::public_writes
    pub captcha_modules: Vec<String>,
    /// Modules with a [`RoutePolicy::Signature`]-guarded write (webhooks).
    pub signature_modules: Vec<String>,
}

impl WriteGuards {
    /// Reads each module's declared surface. A module whose surface has
    /// no policy-guarded write but still sets [`public_writes`] counts as
    /// needing a CAPTCHA — the undeclared-public-writer fallback keeps
    /// out-of-tree and surface-less modules (the auth crates predate
    /// ADR 0010 surfaces) under the same gate instead of silently
    /// exempting them.
    ///
    /// [`public_writes`]: Module::public_writes
    #[must_use]
    pub fn collect(modules: &[Arc<dyn Module>]) -> Self {
        let mut guards = Self::default();
        for module in modules {
            let surface: Surface = module.surface();
            let (mut form, signature) = Self::surface_flags(&surface);
            // The undeclared-public-writer fallback only applies when
            // nothing in the surface is guarded.
            if !form && !signature && module.public_writes() {
                form = true;
            }
            if form {
                guards.captcha_modules.push(module.name().to_owned());
            }
            if signature {
                guards.signature_modules.push(module.name().to_owned());
            }
        }
        guards
    }

    /// The guards a **declared surface** demands (issue #131). A sidecar's
    /// merged surface is not a [`Module`] this process can ask
    /// [`public_writes`](Module::public_writes) of, so the fallback has no
    /// meaning here: whatever the document declares is exactly what it
    /// needs. Same per-action reading as [`Self::collect`] through the one
    /// [`Action::demands_captcha`] predicate.
    ///
    /// [`Action::demands_captcha`]: crate::surface::Action::demands_captcha
    #[must_use]
    pub fn from_surface(module: &str, surface: &Surface) -> Self {
        let (form, signature) = Self::surface_flags(surface);
        Self {
            captcha_modules: form.then(|| module.to_owned()).into_iter().collect(),
            signature_modules: signature.then(|| module.to_owned()).into_iter().collect(),
        }
    }

    /// Whether any action needs a captcha and whether any is a signature
    /// route. The `Open`-with-`captcha` legacy mirror resolves inside
    /// [`Action::demands_captcha`].
    fn surface_flags(surface: &Surface) -> (bool, bool) {
        let mut form = false;
        let mut signature = false;
        for action in &surface.actions {
            if action.demands_captcha() {
                form = true;
            }
            if action.policy == RoutePolicy::Signature {
                signature = true;
            }
        }
        (form, signature)
    }

    /// Whether any module needs the `Captcha` port.
    #[must_use]
    pub fn needs_captcha(&self) -> bool {
        !self.captcha_modules.is_empty()
    }

    /// Whether any module needs the `Payments` port.
    #[must_use]
    pub fn needs_payments(&self) -> bool {
        !self.signature_modules.is_empty()
    }
}

/// Whether the runtime's `Captcha` port can really verify a token in
/// production: the port is provided **and**, when the adapter reports,
/// hostname-bound and not fail-open. An adapter that does not report
/// ([`Captcha::binding`] = `None`) counts as effective — presence is all
/// the harness can know about a third-party implementation; the adapter
/// contract carries the duty to fail closed per request.
///
/// [`Captcha::binding`]: crate::ports::Captcha::binding
#[must_use]
pub fn captcha_effective(runtime: Option<&Arc<dyn Runtime>>) -> bool {
    runtime.is_some_and(|runtime| runtime.effectively_configured(Port::Captcha))
}

/// Whether the runtime can verify webhook signatures for
/// [`RoutePolicy::Signature`]-guarded routes. Presence of the `Payments`
/// bar: signature verification is the adapter's per-request duty
/// (`verify_webhook` + `Inbox`), and which secret it checks against is
/// deploy configuration that `fz doctor` reads from the environment.
#[must_use]
pub fn payments_effective(runtime: Option<&Arc<dyn Runtime>>) -> bool {
    runtime.is_some_and(|runtime| runtime.effectively_configured(Port::Payments))
}

/// The production abuse-control gate (issue #133), as collected error
/// strings (the [`ConfigError`] convention: report every problem at
/// once). Empty for anything but `Production`; pass
/// `allow_no_captcha = Some(reason)` (the `fz doctor` override) to
/// downgrade the CAPTCHA refusal to nothing — the runtime path has no
/// override and always fails closed.
///
/// [`ConfigError`]: crate::config::ConfigError
#[must_use]
pub fn production_readiness(
    env: VentureEnv,
    guards: &WriteGuards,
    runtime: Option<&Arc<dyn Runtime>>,
    allow_no_captcha: Option<&str>,
) -> Vec<String> {
    if env != VentureEnv::Production {
        return Vec::new();
    }
    let mut errors = Vec::new();
    if guards.needs_captcha() && !captcha_effective(runtime) && allow_no_captcha.is_none() {
        errors.push(format!(
            "production venture has captcha-guarded public writes from [{}] but the Captcha \
             port is not effectively configured: provide it on the runtime with a bound \
             adapter (Turnstile needs its secret and expected hostname) — `fz doctor \
             --allow-no-captcha <reason>` overrides this check for previews only",
            guards.captcha_modules.join(", ")
        ));
    }
    if guards.needs_payments() && !payments_effective(runtime) {
        errors.push(format!(
            "production venture has signature-guarded routes from [{}] but the Payments port \
             is not provided — webhook deliveries cannot be verified (see the Inbox dedup \
             ledger and the STRIPE_WEBHOOK_SECRET doctor rule)",
            guards.signature_modules.join(", ")
        ));
    }
    errors
}

/// The shared CAPTCHA gate for `HumanForm` handlers (issue #133): the
/// single place a module asks "is this form submission a human?".
///
/// Fail-closed rules, in order:
///
/// - the port is present: the token must exist and verify — any
///   non-`ok` verdict or transport error is a `captcha-failed` problem;
/// - the port is absent in **production**: `captcha-failed` as well.
///   `Harness::build` refuses that composition, so reaching this branch
///   means a runtime lied about its binding — refuse rather than wave
///   the request through;
/// - the port is absent in development/staging: allow, so a staging
///   deploy can drive the form without a live Turnstile.
///
/// # Errors
///
/// A `captcha-failed` problem when the submission is not proven human.
pub async fn verify_human_form(
    captcha: Option<&Arc<dyn Captcha>>,
    env: VentureEnv,
    token: Option<&str>,
    remote_ip: Option<&str>,
    instance: &str,
) -> Result<(), Problem> {
    let refused = || Problem::new(&SLUGS.captcha_failed).instance(instance);
    match captcha {
        Some(captcha) => {
            let Some(token) = token else {
                return Err(refused());
            };
            match captcha.verify(token, remote_ip).await {
                Ok(verdict) if verdict.ok => Ok(()),
                _ => Err(refused()),
            }
        }
        None if env == VentureEnv::Production => Err(refused()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Migrations;
    use crate::ports::{CaptchaError, Verdict};
    use crate::surface::Action;
    use async_trait::async_trait;

    struct StubCaptcha {
        ok: bool,
        transport_error: bool,
    }

    #[async_trait]
    impl Captcha for StubCaptcha {
        async fn verify(
            &self,
            _token: &str,
            _remote_ip: Option<&str>,
        ) -> Result<Verdict, CaptchaError> {
            if self.transport_error {
                return Err(CaptchaError::Transport("down".to_owned()));
            }
            Ok(Verdict {
                ok: self.ok,
                reason: None,
            })
        }
    }

    fn port(ok: bool, transport_error: bool) -> Arc<dyn Captcha> {
        Arc::new(StubCaptcha {
            ok,
            transport_error,
        })
    }

    #[pollster::test]
    async fn verified_tokens_pass_in_every_environment() {
        for env in [
            VentureEnv::Development,
            VentureEnv::Staging,
            VentureEnv::Production,
        ] {
            verify_human_form(
                Some(&port(true, false)),
                env,
                Some("token"),
                Some("203.0.113.7"),
                "request-1",
            )
            .await
            .expect("a verified token passes");
        }
    }

    #[pollster::test]
    async fn refused_missing_or_unreachable_verifications_fail_closed() {
        let good = port(true, false);
        let refused = port(false, false);
        let unreachable = port(true, true);
        for env in [VentureEnv::Development, VentureEnv::Production] {
            assert!(
                verify_human_form(Some(&refused), env, Some("t"), None, "r")
                    .await
                    .is_err()
            );
            assert!(
                verify_human_form(Some(&unreachable), env, Some("t"), None, "r")
                    .await
                    .is_err()
            );
            assert!(
                verify_human_form(Some(&good), env, None, None, "r")
                    .await
                    .is_err()
            );
        }
    }

    #[pollster::test]
    async fn absent_port_refuses_production_and_allows_lower_envs() {
        assert!(
            verify_human_form(None, VentureEnv::Production, Some("t"), None, "r")
                .await
                .is_err()
        );
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            assert!(
                verify_human_form(None, env, Some("t"), None, "r")
                    .await
                    .is_ok()
            );
        }
    }

    struct Guarded {
        name: &'static str,
        surface: Surface,
        public_writes: bool,
    }

    impl Module for Guarded {
        fn name(&self) -> &'static str {
            self.name
        }
        fn version(&self) -> &'static str {
            "0.0.0-test"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn public_writes(&self) -> bool {
            self.public_writes
        }
        fn migrations(&self) -> Migrations {
            Migrations::default()
        }
        fn validate_config(
            &self,
            _: &dyn crate::config::Config,
        ) -> Result<(), crate::config::ConfigError> {
            Ok(())
        }
        fn surface(&self) -> Surface {
            self.surface.clone()
        }
        fn router(&self, _: crate::ModuleContext) -> axum::Router {
            axum::Router::new()
        }
    }

    fn module(name: &'static str, actions: Vec<Action>, public_writes: bool) -> Arc<dyn Module> {
        Arc::new(Guarded {
            name,
            surface: Surface {
                actions,
                views: vec![],
            },
            public_writes,
        })
    }

    #[test]
    fn human_form_action_requires_captcha() {
        let guards = WriteGuards::collect(&[module(
            "forms",
            vec![Action::post("join", "/").policy(RoutePolicy::HumanForm)],
            false,
        )]);
        assert_eq!(guards.captcha_modules, vec!["forms".to_owned()]);
        assert!(!guards.needs_payments());
    }

    #[test]
    fn signature_action_never_requires_captcha() {
        // The old bug: a webhook counted as "protected", so a captcha
        // config problem passed unnoticed AND the widget rendered on the
        // webhook. A Signature-only module must ask for Payments only.
        let guards = WriteGuards::collect(&[module(
            "billing",
            vec![Action::post("webhook", "/webhook").policy(RoutePolicy::Signature)],
            true, // even with the legacy flag set, the declared policy wins
        )]);
        assert!(guards.captcha_modules.is_empty());
        assert_eq!(guards.signature_modules, vec!["billing".to_owned()]);
    }

    #[test]
    fn undeclared_public_writer_falls_back_to_captcha() {
        let guards = WriteGuards::collect(&[module("auth", Vec::new(), true)]);
        assert_eq!(guards.captcha_modules, vec!["auth".to_owned()]);
    }

    #[test]
    fn legacy_captcha_flag_alias_still_guards() {
        // Pre-#133 declaration shapes — a bare `captcha: true` without a
        // policy — must still pull the module into the captcha gate.
        let mut action = Action::post("join", "/");
        action.captcha = true;
        let guards = WriteGuards::collect(&[module("forms", vec![action], false)]);
        assert_eq!(guards.captcha_modules, vec!["forms".to_owned()]);
    }

    #[test]
    fn guarded_surface_does_not_need_the_fallback() {
        // A module with declared policies is read as declared: `public_writes`
        // adds nothing on top (a form writer declares HumanForm; the
        // fallback exists for modules that predate surfaces).
        let guards = WriteGuards::collect(&[module(
            "waitlist",
            vec![
                Action::post("join", "/").captcha(),
                Action::post("webhook", "/webhook").policy(RoutePolicy::Signature),
            ],
            true,
        )]);
        assert_eq!(guards.captcha_modules, vec!["waitlist".to_owned()]);
        assert_eq!(guards.signature_modules, vec!["waitlist".to_owned()]);
    }

    #[test]
    fn development_venture_needs_nothing() {
        let guards = WriteGuards::collect(&[module("forms", Vec::new(), true)]);
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            assert!(
                production_readiness(env, &guards, None, None).is_empty(),
                "{env:?} must not gate"
            );
        }
    }

    #[test]
    fn production_without_runtime_refuses_captcha_writes() {
        let guards = WriteGuards::collect(&[module(
            "forms",
            vec![Action::post("join", "/").captcha()],
            false,
        )]);
        let errors = production_readiness(VentureEnv::Production, &guards, None, None);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("forms"));
        assert!(errors[0].contains("Captcha"));
        // The override exists for `fz doctor` previews only.
        assert!(
            production_readiness(VentureEnv::Production, &guards, None, Some("preview")).is_empty()
        );
    }

    #[test]
    fn production_signature_without_payments_refuses() {
        let guards = WriteGuards::collect(&[module(
            "billing",
            vec![Action::post("webhook", "/webhook").policy(RoutePolicy::Signature)],
            false,
        )]);
        let errors = production_readiness(VentureEnv::Production, &guards, None, None);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("billing"));
        assert!(errors[0].contains("Payments"));
        // No override for the payments leg — webhooks cannot be "previewed"
        // unverified without shipping unsigned money events.
        assert_eq!(
            production_readiness(VentureEnv::Production, &guards, None, Some("preview")).len(),
            1
        );
    }
}
