//! `GET /__surface` and the build-time surface checks (ADR 0010, issue
//! #70): public subset by default, admin actions with the bearer, strong
//! `ETag` with `304`, and a readable build error for a bad declaration.

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode, header};
use common::*;
use cratefield_core::{
    Action, Audience, Column, Config, ConfigError, Harness, MapConfig, Migrations, Module,
    ModuleContext, Outcome, Port, Ports, SURFACE_API, Surface, View,
};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct JoinBody {
    #[schemars(extend("x-cf-label" = "Email", "x-cf-widget" = "email"))]
    email: String,
    #[schemars(extend("x-cf-hidden" = true))]
    #[serde(rename = "captchaToken")]
    captcha_token: Option<String>,
}

/// A module with one public form, one signed link and one admin export.
struct Described {
    bad: bool,
}

impl Module for Described {
    fn name(&self) -> &'static str {
        "described"
    }
    fn version(&self) -> &'static str {
        "9.9.9"
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
        let surface = Surface::new()
            .action(
                Action::post("join", "/")
                    .input::<JoinBody>()
                    .captcha()
                    .accepted("Check your inbox."),
            )
            .action(Action::get("confirm", "/confirm"))
            .action(
                Action::get("export", "/admin/export.csv")
                    .audience(Audience::Admin)
                    .outcome(Outcome::Json),
            )
            .view(View::form("join"))
            .view(View::table("export", vec![Column::new("email", "Email")]));
        if self.bad {
            surface.view(View::form("nope"))
        } else {
            surface
        }
    }
}

fn harness() -> Harness {
    builder_with_sample()
        .module(Described { bad: false })
        .build()
        .expect("builds")
}

fn ports_with_admin_token() -> Ports {
    let mut ports = Ports::empty();
    ports.config = Arc::new(MapConfig::from_pairs([("ADMIN_TOKEN", "test-admin-token")]));
    ports
}

#[pollster::test]
async fn public_surface_lists_public_actions_only() {
    let router = harness().router(ports_with_admin_token());
    let response = request(&router, Method::GET, "/__surface", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert!(response.headers().contains_key(header::ETAG));
    assert_eq!(
        response.headers().get(header::VARY).unwrap(),
        "Authorization"
    );
    let body = body_json(response).await;
    assert_eq!(body["surface_api"], SURFACE_API);
    assert_eq!(body["venture"]["name"], "test-venture");
    // The sample module declares nothing and is omitted.
    assert_eq!(body["modules"].as_array().unwrap().len(), 1);
    let module = &body["modules"][0];
    assert_eq!(module["name"], "described");
    assert_eq!(module["version"], "9.9.9");
    let names: Vec<&str> = module["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["join", "confirm"]);
    assert_eq!(
        module["views"].as_array().unwrap().len(),
        1,
        "table over admin export hidden"
    );
    let join = &module["actions"][0];
    assert_eq!(join["method"], "POST");
    assert_eq!(join["path"], "/");
    assert_eq!(join["captcha"], true);
    assert_eq!(join["outcome"]["kind"], "accepted");
    assert_eq!(join["outcome"]["message"], "Check your inbox.");
    assert_eq!(join["input"]["type"], "object");
    assert_eq!(join["input"]["properties"]["email"]["x-cf-label"], "Email");
    assert_eq!(
        join["input"]["properties"]["captchaToken"]["x-cf-hidden"],
        true
    );
}

#[pollster::test]
async fn admin_bearer_reveals_admin_actions_with_a_different_etag() {
    let router = harness().router(ports_with_admin_token());
    let public = request(&router, Method::GET, "/__surface", &[], None).await;
    let public_etag = public.headers().get(header::ETAG).unwrap().clone();

    let admin = request(
        &router,
        Method::GET,
        "/__surface",
        &[("authorization", "Bearer test-admin-token")],
        None,
    )
    .await;
    assert_eq!(admin.status(), StatusCode::OK);
    let admin_etag = admin.headers().get(header::ETAG).unwrap().clone();
    assert_ne!(public_etag, admin_etag);
    let body = body_json(admin).await;
    let module = &body["modules"][0];
    assert_eq!(module["actions"].as_array().unwrap().len(), 3);
    assert_eq!(module["actions"][2]["audience"], "admin");
    assert_eq!(module["views"].as_array().unwrap().len(), 2);
    assert_eq!(module["views"][1]["kind"], "table");

    // A wrong bearer is not an error: it gets the public document.
    let wrong = request(
        &router,
        Method::GET,
        "/__surface",
        &[("authorization", "Bearer nope")],
        None,
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::OK);
    assert_eq!(wrong.headers().get(header::ETAG).unwrap(), &public_etag);
}

#[pollster::test]
async fn if_none_match_answers_304_for_the_same_variant_only() {
    let router = harness().router(ports_with_admin_token());
    let first = request(&router, Method::GET, "/__surface", &[], None).await;
    let etag = first
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let again = request(
        &router,
        Method::GET,
        "/__surface",
        &[("if-none-match", &etag)],
        None,
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(again.headers().get(header::ETAG).unwrap(), etag.as_str());

    // The public tag does not validate the admin document.
    let admin = request(
        &router,
        Method::GET,
        "/__surface",
        &[
            ("if-none-match", &etag),
            ("authorization", "Bearer test-admin-token"),
        ],
        None,
    )
    .await;
    assert_eq!(admin.status(), StatusCode::OK);
}

#[pollster::test]
async fn harness_exposes_the_full_document_for_tooling() {
    let harness = harness();
    let document = harness.surface();
    assert_eq!(document.modules.len(), 1);
    assert_eq!(document.modules[0].surface.actions.len(), 3);
}

#[test]
fn bad_surface_fails_the_build_naming_the_module() {
    let err = builder_with_sample()
        .module(Described { bad: true })
        .build()
        .expect_err("must fail");
    let text = err.to_string();
    assert!(
        text.contains("module `described` surface view references action `nope`"),
        "{text}"
    );
}

/// Doc comments on a body type are developer notes; schemars would emit
/// them as `description`, which a renderer shows to visitors. Modules use
/// plain `//` comments on surfaced fields, and this guards the rule for
/// the core fixture.
#[test]
fn fixture_schema_has_no_leaked_descriptions() {
    let schema = cratefield_core::schema_for::<JoinBody>();
    let value = schema.as_value();
    for (name, property) in value["properties"].as_object().unwrap() {
        assert!(
            property.get("description").is_none(),
            "field `{name}` leaks a doc comment into the surface"
        );
    }
}
