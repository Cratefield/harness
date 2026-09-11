//! The smallest complete Factory Zero venture: the `cratefield` facade
//! with the `cloudflare` feature, and one sample module that writes and
//! reads a row through sea-query and D1 (issue #5 acceptance).
//!
//! It depends on one crate rather than six, which is the point of the
//! facade — and building this canary through it is how CI knows the
//! facade works on Workers.
//!
//! CI boots this under `wrangler dev --local` and curls `/__health`,
//! `/__ready` and the sample module's round-trip.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

// `pub` + the `rlib` crate type in `Cargo.toml` so the native example
// (`examples/venture-native`) reuses this exact module — one source of
// truth for the wasm and native canaries.
pub mod rooms;
pub mod sample;

use cratefield::Harness;
use cratefield::cloudflare::{Cloudflare, serve, serve_scheduled};
use cratefield::email_signup::EmailSignup;
use cratefield::notifications::{Category, Notifications};
use cratefield::waitlist::Waitlist;
use std::sync::OnceLock;
use worker::{Context, Env, Request, Response, event};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

fn instance() -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        // **One** runtime, built once. `Harness::build` validates every
        // module's `requires()` against the ports of the instance it is
        // given, so a second, separately-built instance is a build that
        // checked something other than what serves — and these two had
        // already diverged: the one that served had no `.mailer(..)`, while
        // both modules require the Mailer port.
        let runtime = Cloudflare::new()
            .db("DB")
            // The `Push` port assembled from the environment (issue #191).
            // Nothing is configured here, so the router answers
            // NotConfigured for every recipient and `serve` logs that once
            // at cold start — which is what the wrangler smoke exercises.
            .push_from_env()
            // Both modules require the Mailer port. With no API key the
            // adapter is NotConfigured: the port is provided and no mail is
            // ever sent, which is what an example wants.
            .mailer(cratefield::resend::Resend::new(
                std::sync::Arc::new(cratefield::cloudflare::FetchClient),
                None,
                "example@factory0.dev",
                None,
            ));
        let mut templates = cratefield::email_signup::default_templates();
        templates.extend(cratefield::waitlist::default_templates());
        let harness = Harness::builder()
            .venture(
                cratefield::Venture::new("venture-example", "example.factory0.dev")
                    .public_url("https://example.factory0.dev")
                    // The second origin is the example static site served
                    // next to the API in the CI smoke (`site/`); a real
                    // venture lists only its own sites.
                    .cors_origins(["https://example.factory0.dev", "http://127.0.0.1:8788"]),
            )
            .module(sample::SampleRowModule)
            .module(EmailSignup::new())
            .module(
                Waitlist::new()
                    .products(["kontinuum", "undercover-rockstars"])
                    .confirm_ttl_days(7),
            )
            // Notifications (issue #182). It requires the `Push` port,
            // which `push_from_env()` above provides whatever the
            // environment holds: with no keys the router answers
            // `NotConfigured` for every recipient and a send dead-letters
            // with that reason, rather than looking delivered. The routes
            // need `NOTIFICATIONS_AUTH_ISSUER` / `_CLIENT_ID` and answer
            // 401 until a venture sets them.
            .module(
                Notifications::new()
                    .category(Category::new("booking"))
                    .category(Category::new("room_starting").badge(true))
                    // The push environment has one reader (issue #191), so
                    // the module takes the verdict rather than reading the
                    // variables: in production a venture that wired no
                    // transport is a misconfiguration, because every send
                    // would dead-letter as `not_configured`.
                    .transport_probe(|cfg| cratefield::push_wiring::inspect_push(cfg).any_routed())
                    // The browser half (issue #183): the key `cf.js`
                    // subscribes with, from the same one reader. With no
                    // VAPID key set it answers `None` and the route is a
                    // 404, which is what `<cf-push>` on the example site
                    // renders as "this site does not do this".
                    .vapid_public_key(cratefield::push_wiring::vapid_public_key),
            )
            .templates(templates)
            // The UI renderer (ADR 0010): pages at /ui/<module>/<action>,
            // copy and theme from ui.json (validated by build()).
            .ui(cratefield::ui::Ui::from_spec(include_str!("../ui.json")).expect("ui.json parses"))
            .runtime(runtime.clone())
            .build()
            .expect("example venture harness is valid");
        (harness, runtime)
    })
}

#[cfg(test)]
mod tests {
    use cratefield::Runtime as _;
    use cratefield::cloudflare::Cloudflare;

    fn sorted(mut ports: Vec<cratefield::Port>) -> Vec<&'static str> {
        ports.sort_by_key(cratefield::Port::name);
        ports.iter().map(cratefield::Port::name).collect()
    }

    #[test]
    fn the_runtime_that_serves_is_the_one_the_harness_was_built_against() {
        // `Harness::build` rejects a module that requires a port the
        // runtime does not provide — against the instance it was handed. A
        // venture that builds one instance and serves with another has that
        // check pointing at something other than what runs, and the failure
        // is silent: the port is simply absent at runtime. These two had
        // already diverged on the Mailer both modules require.
        let (harness, serving) = super::instance();
        let validated = harness.runtime().expect("the example declares a runtime");
        assert_eq!(sorted(validated.provides()), sorted(serving.provides()));
        assert!(
            serving.provides().contains(&cratefield::Port::Mailer),
            "the serving runtime lost the Mailer port both modules require"
        );
    }

    /// `Cloudflare` has to be `Clone` for there to be one instance at all.
    #[test]
    fn the_runtime_is_clonable() {
        let runtime = Cloudflare::new().db("DB");
        assert_eq!(
            sorted(runtime.clone().provides()),
            sorted(runtime.provides())
        );
    }
}

#[event(fetch)]
/// Worker fetch entry point.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    // **The upgrade goes to the object, not to the router** (issue #103). A
    // Durable Object is the only thing on Workers that can hold a socket, and
    // the room id is the name that picks which object — so two people asking
    // for `/rooms/sunrise` land in the same one, on the same edge location,
    // which is the whole reason the room exists.
    //
    // The original request is forwarded whole: the `Upgrade` header has to
    // survive, and so does the query the venture reads the member from.
    if let Some(room) = req.path().strip_prefix("/rooms/").map(str::to_owned) {
        if !room.is_empty() {
            let stub = env.durable_object("ROOMS")?.id_from_name(&room)?.get_stub()?;
            return stub.fetch_with_request(req).await;
        }
    }
    let (harness, runtime) = instance();
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = instance();
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
