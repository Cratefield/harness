//! `GET /__surface` with a sidecar mounted (issue #76): the sidecar's own
//! surface is fetched through the dispatcher and merged in, public part
//! only, and an unreachable sidecar contributes nothing without failing
//! the document.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{Method, StatusCode, header};
use bytes::Bytes;
use common::*;
use factory0_core::{
    Action, Audience, Config, ConfigError, DispatchError, Dispatcher, HARNESS_SIDECARS, Harness,
    MapConfig, Migrations, Module, ModuleContext, Outcome, Port, Ports, Surface, View,
};
use tower::ServiceExt;

/// The module that lives in the sidecar Worker: one public form, one
/// admin export that must not cross the boundary.
struct Remote;

impl Module for Remote {
    fn name(&self) -> &'static str {
        "remote"
    }
    fn version(&self) -> &'static str {
        "3.2.1"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn surface(&self) -> Surface {
        Surface::new()
            .action(Action::post("ask", "/").accepted("Asked."))
            .action(
                Action::get("export", "/admin/export.csv")
                    .audience(Audience::Admin)
                    .outcome(Outcome::Json),
            )
            .view(View::form("ask"))
            .view(View::table("export", vec![]))
    }
}

/// A dispatcher whose binding is a whole second harness: what the service
/// binding does on Workers, in-process.
struct HarnessDispatcher {
    binding: &'static str,
    router: axum::Router,
}

#[async_trait]
impl Dispatcher for HarnessDispatcher {
    fn has(&self, binding: &str) -> bool {
        binding == self.binding
    }
    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        if binding != self.binding {
            return Err(DispatchError::NotBound(binding.to_owned()));
        }
        let (parts, body) = request.into_parts();
        let request = http::Request::from_parts(parts, axum::body::Body::from(body));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
        Ok(http::Response::from_parts(parts, bytes))
    }
}

fn sidecar_router() -> axum::Router {
    Harness::builder()
        .venture(
            factory0_core::Venture::new("sidecar", "sidecar.test")
                .cors_origins(["https://sidecar.test"]),
        )
        .module(Remote)
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("sidecar builds")
        .router(Ports::empty())
}

fn host(dispatcher: Option<Arc<dyn Dispatcher>>) -> axum::Router {
    let harness = harness_with_sample();
    let mut ports = Ports::with_config(Arc::new(MapConfig::from_pairs([(
        HARNESS_SIDECARS,
        r#"{"remote":"REMOTE"}"#,
    )])));
    ports.dispatcher = dispatcher;
    harness.router(ports)
}

#[pollster::test]
async fn sidecar_surface_is_merged_public_part_only() {
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(HarnessDispatcher {
        binding: "REMOTE",
        router: sidecar_router(),
    });
    let router = host(Some(dispatcher));
    let response = request(&router, Method::GET, "/__surface", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers().get(header::ETAG).unwrap().clone();
    let body = body_json(response).await;
    let remote = body["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "remote")
        .expect("sidecar module merged in");
    assert_eq!(remote["version"], "3.2.1");
    let names: Vec<&str> = remote["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["ask"],
        "the sidecar's admin export stays behind its own token"
    );
    assert_eq!(remote["views"].as_array().unwrap().len(), 1);

    // The merged document has its own validator, different from the
    // build-time one, and it still answers 304 to itself.
    let plain = host(None);
    let alone = request(&plain, Method::GET, "/__surface", &[], None).await;
    assert_ne!(alone.headers().get(header::ETAG).unwrap(), &etag);
    let again = request(
        &router,
        Method::GET,
        "/__surface",
        &[("if-none-match", etag.to_str().unwrap())],
        None,
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
}

#[pollster::test]
async fn unreachable_sidecar_contributes_nothing() {
    struct Down;
    #[async_trait]
    impl Dispatcher for Down {
        fn has(&self, _: &str) -> bool {
            true
        }
        async fn dispatch(
            &self,
            binding: &str,
            _: http::Request<Bytes>,
        ) -> Result<http::Response<Bytes>, DispatchError> {
            Err(DispatchError::Unavailable {
                binding: binding.to_owned(),
                reason: "cold start timed out".into(),
            })
        }
    }
    let router = host(Some(Arc::new(Down)));
    let response = request(&router, Method::GET, "/__surface", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(
        body["modules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["name"] != "remote"),
        "{body}"
    );
    // No binding at all: same answer, no dispatch attempted.
    let router = host(None);
    let response = request(&router, Method::GET, "/__surface", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
}
