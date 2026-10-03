//! RFC 8628 over the wire (issue #587): the code pair, the polling state
//! machine with its interval gate, the approval page, and the two decision
//! forms with their same-origin and wrong-entry controls. Runs against
//! every available dialect.

mod support;

use axum::http::StatusCode;
use cratefield_core::{Decision, Statement};
use cratefield_testing::{FakeRateLimiter, TestHarness};
use serde_json::json;

use support::{
    ApproverKind, CLIENT_A, CLIENT_B, Res, Spec, approve, create_code, deny, fixture, get,
    get_with, issue, page, poll, post_form, post_json,
};

// ---------------------------------------------------------------------------
// Round-tripping a request

/// The happy path: a code pair is minted with the RFC 8628 response shape,
/// both verification URIs point at this module, and the first poll reports
/// that nobody has approved yet.
#[pollster::test]
async fn a_code_pair_is_minted_and_the_first_poll_is_pending() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        let response =
            create_code(&kit.harness, CLIENT_A, "read write", Some("Alice's laptop")).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        let body = response.json();
        let device_code = body["device_code"].as_str().expect("device_code");
        let user_code = body["user_code"].as_str().expect("user_code");
        assert_eq!(
            device_code.len(),
            43,
            "32 bytes of base64url: {device_code}"
        );
        assert_eq!(user_code.len(), 9, "XXXX-XXXX: {user_code}");
        assert_eq!(&user_code[4..5], "-", "{user_code}");
        assert!(
            !user_code.chars().any(|ch| "IOU018".contains(ch)),
            "the alphabet has no look-alikes: {user_code}"
        );
        assert_eq!(body["expires_in"], json!(600));
        assert_eq!(body["interval"], json!(5));
        let verification = body["verification_uri"].as_str().expect("verification_uri");
        assert!(verification.ends_with("/v1/device-auth"), "{verification}");
        assert_eq!(
            body["verification_uri_complete"],
            json!(format!("{verification}?user_code={user_code}"))
        );

        let pending = poll(&kit.harness, device_code, CLIENT_A).await;
        assert_eq!(
            pending.status,
            StatusCode::BAD_REQUEST,
            "{}",
            pending.text()
        );
        assert_eq!(pending.oauth_error(), "authorization_pending");
    }
}

/// The `/code` route reads its parameters as a form as well as JSON: an
/// RFC 8628 client posts `application/x-www-form-urlencoded`.
#[pollster::test]
async fn the_code_route_accepts_a_form_body() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        let response = post_form(
            &kit.harness,
            "/v1/device-auth/code",
            &format!("client_id={CLIENT_A}&scope=read"),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert_eq!(response.json()["interval"], json!(5));
    }
}

/// A poll that has waited out the interval is `authorization_pending`; one
/// that has not is `slow_down`, and the interval has widened by five
/// seconds — the RFC 8628 §3.5 penalty, held on the row.
#[pollster::test]
async fn an_early_poll_slows_down_and_widens_the_interval() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        kit.clock.reset();
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;

        let first = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(first.oauth_error(), "authorization_pending");

        let early = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(early.status, StatusCode::BAD_REQUEST);
        assert_eq!(early.oauth_error(), "slow_down");
        assert_eq!(interval_secs(&kit.harness).await, 10, "5 + 5");

        // Waiting out the widened interval is answered normally again.
        kit.clock.advance_secs(11);
        let waited = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(waited.oauth_error(), "authorization_pending");
    }
}

/// An approval issues exactly one credential: the poll that wins the
/// consume gets it, and the next poll of the same code is `expired_token`.
#[pollster::test]
async fn approval_issues_exactly_one_credential() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        kit.issuer.reset();
        let codes = issue(&kit.harness, CLIENT_A, "read write", Some("Alice's laptop")).await;

        let approved = approve(&kit.harness, &codes.user_code).await;
        assert_eq!(approved.status, StatusCode::OK, "{}", approved.text());
        assert!(approved.text().contains("Device approved"));

        let issued = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(issued.status, StatusCode::OK, "{}", issued.text());
        let credential = issued.json();
        assert_eq!(credential["subject"], json!("alice"));
        assert_eq!(credential["client_id"], json!(CLIENT_A));
        assert_eq!(credential["name"], json!("Alice's laptop"));
        assert_eq!(credential["scopes"], json!(["read", "write"]));
        assert_eq!(
            issued
                .headers
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "a credential is never cached"
        );
        assert_eq!(kit.issuer.calls(), 1);

        let reused = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(reused.status, StatusCode::BAD_REQUEST);
        assert_eq!(reused.oauth_error(), "expired_token");
        assert_eq!(kit.issuer.calls(), 1, "a reused code mints nothing");
    }
}

/// A denial is `access_denied` on every poll, and mints nothing.
#[pollster::test]
async fn a_denial_is_access_denied() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        kit.issuer.reset();
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;
        let denied = deny(&kit.harness, &codes.user_code).await;
        assert_eq!(denied.status, StatusCode::OK, "{}", denied.text());
        assert!(denied.text().contains("Request denied"));

        let polled = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(polled.oauth_error(), "access_denied");
        assert_eq!(kit.issuer.calls(), 0);
    }
}

/// A code past its expiry is `expired_token`, and the code that never
/// existed is `invalid_grant`.
#[pollster::test]
async fn an_expired_code_is_expired_token() {
    let spec = Spec {
        expires_in_secs: 60,
        ..Spec::default()
    };
    for kit in fixture(&spec, |_| {}).kits {
        kit.clock.reset();
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;
        kit.clock.advance_secs(61);

        let expired = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(expired.oauth_error(), "expired_token");

        let unknown = poll(&kit.harness, "not-a-real-device-code", CLIENT_A).await;
        assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
        assert_eq!(unknown.oauth_error(), "invalid_grant");
    }
}

/// The client id is part of the code's identity: another client's id (or a
/// missing one) is no code at all.
#[pollster::test]
async fn a_code_belongs_to_the_client_that_asked_for_it() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;
        let foreign = poll(&kit.harness, &codes.device_code, CLIENT_B).await;
        assert_eq!(foreign.oauth_error(), "invalid_grant");

        let missing = post_json(
            &kit.harness,
            "/v1/device-auth/token",
            r#"{"grant_type":"urn:ietf:params:oauth:grant-type:device_code"}"#,
        )
        .await;
        assert_eq!(missing.oauth_error(), "invalid_request");
    }
}

/// The two client mistakes RFC 6749 §5.2 names, and the grant type.
#[pollster::test]
async fn a_mistyped_request_is_named_not_guessed() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        let unknown_client = create_code(&kit.harness, "no-such-client", "read", None).await;
        assert_eq!(unknown_client.status, StatusCode::BAD_REQUEST);
        assert_eq!(unknown_client.oauth_error(), "invalid_client");

        let unknown_scope = create_code(&kit.harness, CLIENT_A, "admin", None).await;
        assert_eq!(unknown_scope.oauth_error(), "invalid_scope");

        let wrong_grant = post_json(
            &kit.harness,
            "/v1/device-auth/token",
            r#"{"grant_type":"password","device_code":"x","client_id":"sealb-cli"}"#,
        )
        .await;
        assert_eq!(wrong_grant.oauth_error(), "unsupported_grant_type");
    }
}

/// A `name` longer than the page will carry is refused as a plain
/// `invalid_request` — the label is the client's, but it is not unbounded.
#[pollster::test]
async fn an_overlong_device_name_is_refused() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        kit.issuer.reset();
        let long = "a".repeat(101);
        let refused = create_code(&kit.harness, CLIENT_A, "read", Some(&long)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(refused.oauth_error(), "invalid_request");
        assert_eq!(kit.issuer.calls(), 0);
    }
}

// ---------------------------------------------------------------------------
// The browser page

/// An anonymous visitor is sent to sign in, and the URL they come back to
/// still carries the code they were asked about.
#[pollster::test]
async fn the_page_sends_an_anonymous_visitor_to_sign_in() {
    let spec = Spec {
        approver: Some(ApproverKind::Anonymous),
        ..Spec::default()
    };
    for kit in fixture(&spec, |_| {}).kits {
        let response = get(&kit.harness, "/v1/device-auth?user_code=BCDF-GHJK").await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        let location = response.location().expect("location");
        assert!(location.starts_with("/login?return_to="), "{location}");
        assert!(
            location.contains("user_code%3DBCDF-GHJK"),
            "the code comes back with them: {location}"
        );
    }
}

/// The page with no code is the form, and with a code it is the request's
/// details — every caller-supplied value escaped.
#[pollster::test]
async fn the_page_shows_the_request_with_every_value_escaped() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        let bare = get(&kit.harness, "/v1/device-auth").await;
        assert_eq!(bare.status, StatusCode::OK);
        assert!(bare.text().contains("Enter the code shown on your device"));

        let name = "<script>alert('x')</script>";
        let codes = issue(&kit.harness, CLIENT_A, "read write", Some(name)).await;
        let shown = page(&kit.harness, &codes.user_code).await;
        assert_eq!(shown.status, StatusCode::OK);
        assert_eq!(
            shown
                .headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = shown.text();
        assert!(body.contains(CLIENT_A), "{body}");
        assert!(body.contains("read write"), "{body}");
        assert!(body.contains(&codes.user_code), "{body}");
        assert!(
            body.contains("&lt;script&gt;"),
            "the label is escaped: {body}"
        );
        assert!(
            !body.contains("<script>"),
            "the label survives unescaped: {body}"
        );
    }
}

/// A code that names nothing pending shows the "try again" page rather
/// than an error, and a wrong-format code is the same page.
#[pollster::test]
async fn an_unknown_code_shows_the_try_again_page() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        let unknown = page(&kit.harness, "BCDF-GHJK").await;
        assert_eq!(unknown.status, StatusCode::OK);
        assert!(unknown.text().contains("not valid"));
    }
}

/// The stock `CallerApprover` over the `Auth` port: a bearer token is a
/// subject, and no token at all is a redirect to sign in.
#[pollster::test]
async fn the_auth_port_backs_the_stock_approver() {
    let spec = Spec {
        approver: None,
        ..Spec::default()
    };
    let patch = |ports: &mut cratefield_core::Ports| {
        ports.auth = Some(std::sync::Arc::new(cratefield_testing::FakeAuth::subjects()));
    };
    for kit in fixture(&spec, patch).kits {
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;
        let signed_in = get_with(
            &kit.harness,
            &format!("/v1/device-auth?user_code={}", codes.user_code),
            &[("authorization", "Bearer alice")],
        )
        .await;
        assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.text());
        assert!(signed_in.text().contains("Approve this device?"));

        let anonymous = get(&kit.harness, "/v1/device-auth").await;
        assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    }
}

// ---------------------------------------------------------------------------
// The decision forms

/// The same-origin guard runs before the body is trusted: a request the
/// browser reports as cross-site is refused whether it says so in
/// `sec-fetch-site` or in `Origin`.
#[pollster::test]
async fn a_cross_site_approval_is_refused() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;
        let form = format!("user_code={}", codes.user_code);

        let cross_site = support::post_form_with(
            &kit.harness,
            "/v1/device-auth/approve",
            &form,
            &[("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(
            cross_site.status,
            StatusCode::FORBIDDEN,
            "{}",
            cross_site.text()
        );
        assert!(problem_type(&cross_site).ends_with("/problems/device-auth/cross-site-request"));

        let foreign_origin = support::post_form_with(
            &kit.harness,
            "/v1/device-auth/approve",
            &form,
            &[("origin", "https://evil.example"), ("host", "test.example")],
        )
        .await;
        assert_eq!(foreign_origin.status, StatusCode::FORBIDDEN);
        assert!(
            problem_type(&foreign_origin).ends_with("/problems/device-auth/cross-site-request")
        );

        // Nothing was decided: the code is still pending.
        let pending = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(pending.oauth_error(), "authorization_pending");
    }
}

/// An approval with no subject behind it is refused, not guessed at.
#[pollster::test]
async fn an_approval_without_a_subject_is_refused() {
    let spec = Spec {
        approver: Some(ApproverKind::Failing),
        ..Spec::default()
    };
    for kit in fixture(&spec, |_| {}).kits {
        let refused = approve(&kit.harness, "BCDF-GHJK").await;
        assert_eq!(
            refused.status,
            StatusCode::UNAUTHORIZED,
            "{}",
            refused.text()
        );
        assert!(problem_type(&refused).ends_with("/problems/device-auth/approver-required"));
    }
}

/// After the configured allowance of wrong codes, the approver's limiter
/// refuses under this module's own slug — the brute-force control over the
/// eight-character code space.
#[pollster::test]
async fn wrong_codes_trip_the_per_approver_lockout() {
    let spec = Spec {
        max_wrong_entries: 3,
        ..Spec::default()
    };
    let allow = Decision {
        ok: true,
        retry_after: None,
        quota: None,
    };
    let deny = Decision {
        ok: false,
        retry_after: Some(std::time::Duration::from_secs(30)),
        quota: None,
    };
    let patch = move |ports: &mut cratefield_core::Ports| {
        ports.rate_limiter = Some(std::sync::Arc::new(FakeRateLimiter::scripted(
            vec![allow.clone(), allow.clone(), allow.clone()],
            deny.clone(),
        )));
    };
    for kit in fixture(&spec, patch).kits {
        for attempt in 1..=3 {
            let wrong = approve(&kit.harness, "BCDF-GHJK").await;
            assert_eq!(
                wrong.status,
                StatusCode::NOT_FOUND,
                "attempt {attempt}: {}",
                wrong.text()
            );
            assert!(problem_type(&wrong).ends_with("/problems/device-auth/unknown-user-code"));
        }
        let locked = approve(&kit.harness, "BCDF-GHJK").await;
        assert_eq!(
            locked.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            locked.text()
        );
        assert!(problem_type(&locked).ends_with("/problems/device-auth/too-many-attempts"));
        assert_eq!(
            locked
                .headers
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("30")
        );
    }
}

/// `/code` is the public write path, and its limiter is the abuse control
/// it actually has: a denial is a 429 before anything is written.
#[pollster::test]
async fn a_denied_code_request_writes_nothing() {
    let deny = Decision {
        ok: false,
        retry_after: Some(std::time::Duration::from_secs(45)),
        quota: None,
    };
    let patch = move |ports: &mut cratefield_core::Ports| {
        ports.rate_limiter = Some(std::sync::Arc::new(FakeRateLimiter::scripted(
            Vec::new(),
            deny.clone(),
        )));
    };
    for kit in fixture(&Spec::default(), patch).kits {
        let refused = create_code(&kit.harness, CLIENT_A, "read", None).await;
        assert_eq!(
            refused.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            refused.text()
        );
        assert_eq!(support::code_rows(&kit.harness).await, 0);
    }
}

// ---------------------------------------------------------------------------
// Helpers

/// The `interval_secs` of the one row a fresh kit holds.
async fn interval_secs(kit: &TestHarness) -> i64 {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT interval_secs FROM device_auth_codes".to_owned(),
            Vec::new(),
        ))
        .await
        .expect("interval query");
    rows.first()
        .and_then(|row| row.get("interval_secs"))
        .unwrap_or(0)
}

/// The RFC 9457 `type` of a problem response.
fn problem_type(response: &Res) -> String {
    response.json()["type"]
        .as_str()
        .unwrap_or_else(|| panic!("no problem type: {}", response.text()))
        .to_owned()
}
