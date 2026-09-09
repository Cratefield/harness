//! A sidecar-mounted module renders and submits through `/ui` (issue
//! #76): the host reads the sidecar's surface through the dispatcher, and
//! the form's in-process dispatch goes out over the same mount.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use bytes::Bytes;
use cratefield_core::{
    Action, DispatchError, Dispatcher, HARNESS_API, HARNESS_SIDECARS, MapConfig, ModuleSurface,
    SURFACE_API, Surface, SurfaceDocument, VentureSurface,
};
use cratefield_module_hello::Hello;
use cratefield_module_waitlist::Waitlist;
use cratefield_testing::TestHarness;
use cratefield_ui::Ui;
use tower::ServiceExt;

struct HarnessDispatcher(axum::Router);

#[async_trait]
impl Dispatcher for HarnessDispatcher {
    fn has(&self, binding: &str) -> bool {
        binding == "HELLO"
    }
    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        if binding != "HELLO" {
            return Err(DispatchError::NotBound(binding.to_owned()));
        }
        let (parts, body) = request.into_parts();
        let response = self
            .0
            .clone()
            .oneshot(http::Request::from_parts(parts, Body::from(body)))
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        Ok(http::Response::from_parts(parts, bytes))
    }
}

async fn send(
    kit: &TestHarness,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    form: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = match form {
        Some(form) => {
            builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(form.to_owned())
        }
        None => Body::empty(),
    };
    let response = kit
        .router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    (parts.status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[pollster::test]
async fn sidecar_module_renders_and_submits_through_the_host_ui() {
    // The sidecar: its own harness with the hello module and a database.
    let sidecar = TestHarness::new(vec![Box::new(Hello::new())]);
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(HarnessDispatcher(sidecar.router.clone()));

    // The host: the waitlist in-process, hello mounted as a sidecar.
    let host = TestHarness::with_builder(
        vec![Box::new(Waitlist::new().products(["kontinuum"]))],
        |builder| builder.ui(Ui::new()),
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("HARNESS_SECRET", cratefield_testing::TEST_HARNESS_SECRET),
                (HARNESS_SIDECARS, r#"{"hello":"HELLO"}"#),
            ]));
            ports.dispatcher = Some(dispatcher);
        },
    );

    let (status, surface) = send(&host, Method::GET, "/__surface", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(surface.contains(r#""name":"hello""#), "{surface}");

    let (status, html) = send(&host, Method::GET, "/ui/hello/record?fragment=1", &[], None).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains(r#"data-cf-module="hello" data-cf-action="record""#));
    assert!(html.contains(r#"name="name""#));

    let (status, html) = send(
        &host,
        Method::POST,
        "/ui/hello/record?fragment=1",
        &[],
        Some("name=Ada"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("cf-notice--success"), "{html}");
    assert!(html.contains("Recorded. Hello!"), "{html}");

    // The row landed in the sidecar's database, not the host's.
    let (status, body) = send(&sidecar, Method::GET, "/v1/hello/count", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"visits":1}"#);
}

/// A sidecar whose `/__surface` declares an `/admin/` path with a
/// `public` audience — a drift the host's build-time validation can never
/// catch, because the document arrives at runtime and is merged per
/// request. Every non-surface fetch is counted, then answered `202`.
struct DriftedDispatcher {
    surface: Bytes,
    forwarded: Arc<AtomicUsize>,
}

#[async_trait]
impl Dispatcher for DriftedDispatcher {
    fn has(&self, binding: &str) -> bool {
        binding == "DRIFT"
    }
    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        if binding != "DRIFT" {
            return Err(DispatchError::NotBound(binding.to_owned()));
        }
        let (status, body) = if request.uri().path() == "/__surface" {
            (StatusCode::OK, self.surface.clone())
        } else {
            self.forwarded.fetch_add(1, Ordering::SeqCst);
            (StatusCode::ACCEPTED, Bytes::from_static(br#"{"ok":true}"#))
        };
        Ok(http::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .expect("static response builds"))
    }
}

fn drifted_surface() -> Bytes {
    let document = SurfaceDocument {
        surface_api: SURFACE_API,
        harness_api: HARNESS_API,
        venture: VentureSurface {
            name: "drift".to_owned(),
            public_url: "https://drift.test".to_owned(),
        },
        modules: vec![ModuleSurface {
            name: "drift".to_owned(),
            version: "9.9.9".to_owned(),
            surface: Surface::new().action(Action::post("wipe", "/admin/wipe").accepted("Wiped.")),
        }],
        ui: None,
    };
    Bytes::from(serde_json::to_vec(&document).expect("document serializes"))
}

/// Issues #130 and #131. #130 established that hiding is not
/// authorizing: a sidecar surface reaching the renderer at runtime was
/// not re-validated, so an entry could claim the public audience over an
/// admin path, and the dispatch gate had to authorize the execution with
/// the same `require_admin` the target route runs.
///
/// #131 closes that at an earlier layer — a sidecar's document is now
/// validated against the mount before anything merges, and a public
/// audience over an admin path fails `Surface::validate`, so the whole
/// document is refused rather than partly rendered. The action is
/// therefore not renderable *at all*, which is strictly stronger than
/// rendering it and gating the dispatch.
///
/// The dispatch gate itself is unchanged and remains defence in depth;
/// it simply can no longer be reached through a merged sidecar surface,
/// so this test asserts the refusal and that nothing is ever dispatched.
#[pollster::test]
async fn a_misdeclared_admin_action_never_merges_and_never_dispatches() {
    const TOKEN: &str = "test-admin-token-with-enough-entropy";
    let forwarded = Arc::new(AtomicUsize::new(0));
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(DriftedDispatcher {
        surface: drifted_surface(),
        forwarded: Arc::clone(&forwarded),
    });
    let host = TestHarness::with_builder(
        vec![Box::new(Hello::new())],
        |builder| builder.ui(Ui::new()),
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("HARNESS_SECRET", cratefield_testing::TEST_HARNESS_SECRET),
                (HARNESS_SIDECARS, r#"{"drift":"DRIFT"}"#),
                ("ADMIN_TOKEN", TOKEN),
            ]));
            ports.dispatcher = Some(dispatcher);
        },
    );

    // The document claims the public audience over `/admin/wipe`. It is
    // refused at merge, so the action is on no rendered surface.
    let (status, html) = send(&host, Method::GET, "/ui/drift/wipe?fragment=1", &[], None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{html}");

    // And it is not executable by any caller — no credential, a wrong
    // one, or the real admin token. The sidecar is never reached.
    for headers in [
        Vec::new(),
        vec![("authorization", "Bearer not-the-token".to_owned())],
        vec![("authorization", format!("Bearer {TOKEN}"))],
    ] {
        let borrowed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let (status, html) = send(
            &host,
            Method::POST,
            "/ui/drift/wipe",
            &borrowed,
            Some("x=1"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{html}");
    }
    assert_eq!(
        forwarded.load(Ordering::SeqCst),
        0,
        "a refused surface must never dispatch, whatever the caller presents"
    );
}
