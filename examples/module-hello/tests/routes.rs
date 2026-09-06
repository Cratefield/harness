//! Route tests for `/v1/hello` over the kit's fake ports: a recorded
//! visit is counted, an over-long name is a `400 validation-failed`
//! problem, and the config key `HELLO_MAX_NAME_LEN` overrides the builder.

use factory0_module_hello::Hello;
use factory0_testing::{TestHarness, request};
use http::{Method, StatusCode};

fn kit() -> TestHarness {
    TestHarness::new(vec![Box::new(Hello::new())])
}

#[pollster::test]
async fn a_recorded_visit_is_counted() {
    let kit = kit();
    let res = request(
        &kit.router,
        Method::POST,
        "/v1/hello",
        Some(r#"{ "name": "factory zero" }"#),
    )
    .await;
    assert_eq!(res.status, StatusCode::ACCEPTED);
    assert_eq!(res.json()["name"], "factory zero");

    let res = request(&kit.router, Method::GET, "/v1/hello/count", None).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["visits"], 1);
}

#[pollster::test]
async fn an_over_long_name_is_a_validation_problem() {
    let kit = kit();
    let body = format!(r#"{{ "name": "{}" }}"#, "x".repeat(65));
    let res = request(&kit.router, Method::POST, "/v1/hello", Some(&body)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(
        res.json()["type"]
            .as_str()
            .is_some_and(|uri| uri.ends_with("/problems/validation-failed")),
        "got {}",
        res.json()
    );
}

#[pollster::test]
async fn config_overrides_the_builder_limit() {
    let kit = TestHarness::new(vec![Box::new(Hello::new().max_name_len(4))]);
    let ok = request(
        &kit.router,
        Method::POST,
        "/v1/hello",
        Some(r#"{ "name": "ventures" }"#),
    )
    .await;
    assert_eq!(ok.status, StatusCode::BAD_REQUEST);
}
