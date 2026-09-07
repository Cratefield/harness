//! A sidecar-mounted module renders and submits through `/ui` (issue
//! #76): the host reads the sidecar's surface through the dispatcher, and
//! the form's in-process dispatch goes out over the same mount.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use bytes::Bytes;
use cratefield_core::{DispatchError, Dispatcher, HARNESS_SIDECARS, MapConfig};
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
    form: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
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

    let (status, surface) = send(&host, Method::GET, "/__surface", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(surface.contains(r#""name":"hello""#), "{surface}");

    let (status, html) = send(&host, Method::GET, "/ui/hello/record?fragment=1", None).await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains(r#"data-cf-module="hello" data-cf-action="record""#));
    assert!(html.contains(r#"name="name""#));

    let (status, html) = send(
        &host,
        Method::POST,
        "/ui/hello/record?fragment=1",
        Some("name=Ada"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("cf-notice--success"), "{html}");
    assert!(html.contains("Recorded. Hello!"), "{html}");

    // The row landed in the sidecar's database, not the host's.
    let (status, body) = send(&sidecar, Method::GET, "/v1/hello/count", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"visits":1}"#);
}
