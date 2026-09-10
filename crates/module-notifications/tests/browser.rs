//! The browser half of the module (issue #183): the application server
//! key a page fetches before it subscribes, and the registration body
//! `cf.js` actually builds.
//!
//! The body test is the one that would otherwise be written twice and
//! agree with itself twice: `cf.js` composes the JSON by hand from
//! `PushSubscription.toJSON()`, whose shape is *not* the shape this route
//! reads, and the route is `deny_unknown_fields`. Pinning the exact
//! object here means a rename on either side fails in Rust rather than in
//! a browser nobody is watching.

mod support;

use axum::http::{Method, StatusCode, header};
use serde_json::json;
use support::{ALICE, kit, kit_serving_vapid, send, token_for};

const KEY: &str = "/v1/notifications/vapid-public-key";
const SUBS: &str = "/v1/notifications/subscriptions";

/// A P-256 public point, uncompressed, base64url — the shape
/// `WebPush::public_key()` produces and the browser accepts.
const APPLICATION_SERVER_KEY: &str =
    "BMnoZrNHaWFZwLcli9rMtHS5Y7IMqsKZ4_gc9aCFGZ-hrjPdTHuYbdiXP5q5FoG6QoaJxJ1K9Ub6MZ5DCvd81qA";

#[pollster::test]
async fn the_application_server_key_is_served_from_the_ventures_own_config() {
    let kit = kit_serving_vapid(APPLICATION_SERVER_KEY);
    let answer = send(&kit.harness.router, Method::GET, KEY, None, None).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(answer.json()["public_key"], APPLICATION_SERVER_KEY);
}

#[pollster::test]
async fn the_key_route_takes_no_token() {
    // Every other route here is 401 without one. This one must not be:
    // a site puts "turn notifications on" in front of a visitor, and the
    // value is the public half of a pair, handed to every browser that
    // subscribes. Asked with a token it answers the same.
    let kit = kit_serving_vapid(APPLICATION_SERVER_KEY);
    let anonymous = send(&kit.harness.router, Method::GET, KEY, None, None).await;
    let signed_in = send(
        &kit.harness.router,
        Method::GET,
        KEY,
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(anonymous.status, StatusCode::OK);
    assert_eq!(signed_in.status, StatusCode::OK);
    assert_eq!(anonymous.json(), signed_in.json());

    // The subscription routes are still shut.
    let subscriptions = send(&kit.harness.router, Method::GET, SUBS, None, None).await;
    assert_eq!(subscriptions.status, StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn a_venture_that_wired_no_key_answers_404_rather_than_an_empty_one() {
    // `kit()` wires no probe, which is what a venture with no VAPID key
    // has. An empty string or a `null` here would be a subscribe that
    // fails inside `pushManager.subscribe` with an `InvalidAccessError`,
    // which says nothing about the deployment being unconfigured.
    let kit = kit();
    let answer = send(&kit.harness.router, Method::GET, KEY, None, None).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.text());
    assert!(
        answer.json()["type"]
            .as_str()
            .is_some_and(|slug| slug.ends_with("/webpush-not-configured")),
        "{}",
        answer.text()
    );
    let body = answer.text();
    assert!(
        !body.contains("VAPID"),
        "the refusal names no environment variable: {body}"
    );
}

#[pollster::test]
async fn the_key_is_no_store_like_every_other_v1_response() {
    // The handler sets no cache policy on purpose. `/v1/*` is `no-store`
    // at the root, so anything it set would be silently replaced — and a
    // route documenting a `max-age` it does not have is how a rotation
    // comes to be believed propagated when it is not. `cf.js` fetches the
    // key once per page and holds it in memory instead.
    let kit = kit_serving_vapid(APPLICATION_SERVER_KEY);
    let response = raw(&kit.harness.router, KEY).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

#[pollster::test]
async fn the_body_cf_js_builds_registers_a_browser_subscription() {
    let kit = kit_serving_vapid(APPLICATION_SERVER_KEY);
    // Exactly what `cf.js`'s `put()` sends: `PushSubscription.toJSON()`
    // hands the client `{ endpoint, expirationTime, keys: { p256dh, auth } }`,
    // and this route reads a flat `web_push` recipient with
    // `deny_unknown_fields`. Passing `toJSON()` through unchanged — which
    // is the obvious thing to write — never parses at all.
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(json!({
            "transport": "webpush",
            "recipient": {
                "web_push": {
                    "endpoint": "https://push.example.test/subscription/abc",
                    "p256dh": "BMnoZrNHaWFZwLcli9rMtHS5Y7IMqsKZ4_gc9aCFGZ-hrjPdTHuYbdiXP5q5FoG6QoaJxJ1K9Ub6MZ5DCvd81qA",
                    "auth": "Zm9vYmFyYmF6cXV4MTIzNDU2",
                },
            },
            "app_id": "example.factory0.dev",
            "app_version": "1.0.0",
        })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let id = answer.json()["id"].as_str().expect("an id").to_owned();

    let listed = send(
        &kit.harness.router,
        Method::GET,
        SUBS,
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(listed.json()["subscriptions"][0]["transport"], "webpush");

    // And the second half of `cf.push.unsubscribe()`: the row goes.
    let deleted = send(
        &kit.harness.router,
        Method::DELETE,
        &format!("{SUBS}/{id}"),
        Some(&token_for(ALICE)),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(kit.count("notifications_subscriptions").await, 0);
}

#[pollster::test]
async fn the_transport_spelling_cf_js_sends_is_the_one_the_route_reads() {
    // Two vocabularies, one letter apart: the column says `webpush` and
    // the port's recipient tag is `web_push`. `cf.js` writes both, in one
    // object, and getting either wrong is a refusal no browser reports.
    let kit = kit_serving_vapid(APPLICATION_SERVER_KEY);
    let answer = send(
        &kit.harness.router,
        Method::PUT,
        SUBS,
        Some(&token_for(ALICE)),
        Some(json!({
            "transport": "web_push",
            "recipient": {
                "webpush": {
                    "endpoint": "https://push.example.test/subscription/abc",
                    "p256dh": "BMnoZrNHaWFZwLcli9rMtHS5Y7IMqsKZ4_gc9aCFGZ-hrjPdTHuYbdiXP5q5FoG6QoaJxJ1K9Ub6MZ5DCvd81qA",
                    "auth": "Zm9vYmFyYmF6cXV4MTIzNDU2",
                },
            },
        })),
    )
    .await;
    // A 400 from the body reader, not a 422 from a validator: neither
    // spelling parses, so nothing reaches the handler at all.
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.text());
    assert_eq!(kit.count("notifications_subscriptions").await, 0);
}

/// The whole response, for the headers `send` drops.
async fn raw(router: &axum::Router, path: &str) -> axum::response::Response {
    use tower::ServiceExt as _;

    router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router answers")
}
