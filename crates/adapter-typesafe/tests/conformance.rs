//! The shared `Classifier` conformance suite (issue #456) run against the
//! `TypeSafe` adapter: the same common contract every adapter answers,
//! over a local `HttpClient` scripted with one well-formed Jev body for
//! `classifier_conformance_questions`.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_typesafe::TypeSafe;
use cratefield_core::{Clock, HttpClient, HttpError};
use cratefield_testing::{
    classifier_conformance, classifier_not_configured, classifier_rejects_malformed_questions,
    classifier_truncates_long_state,
};
use http::{Request, Response, StatusCode};
use std::sync::Arc;
use time::OffsetDateTime;

/// A well-formed success body for the canonical question set, in the
/// documented Jev shape: every id asked, every chosen label offered, the
/// masses summing to one. The score answer is weighted over the level
/// *indices* Jev was sent (`"0"` = the port's `"1"`, `"1"` = its `"5"`)
/// and lands between them, so the adapter interpolates it onto the
/// caller's scale; the confidences are the vendor's own, agreeing with
/// the probability under the chosen label where the port can see one.
const CONFORMANCE_BODY: &str = r#"{"model":"jev-1.13.0","answers":{
  "topic":{"type":"choice","choice":"bugs","probabilities":{"billing":0.1,"bugs":0.9},"confidence":0.9},
  "severity":{"type":"score","score":0.7,"probabilities":{"0":0.3,"1":0.7},"confidence":0.7},
  "urgent":{"type":"noul","noul":0.75}},
  "usage":{"input_tokens":296,"output_tokens":20}}"#;

/// An `HttpClient` that answers every call with the same scripted status
/// and body — the suite asks at most twice, and a vendor answers each
/// classify request the same way.
struct StaticHttp {
    status: u16,
    body: &'static str,
}

#[async_trait]
impl HttpClient for StaticHttp {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        Response::builder()
            .status(StatusCode::from_u16(self.status).expect("valid status"))
            .body(Bytes::from(self.body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

struct FixedClock(OffsetDateTime);

#[async_trait]
impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn clock() -> Arc<dyn Clock> {
    Arc::new(FixedClock(
        OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
    ))
}

/// The adapter over the scripted transport, with a (dummy) key.
fn scripted() -> TypeSafe {
    TypeSafe::new(
        Arc::new(StaticHttp {
            status: 200,
            body: CONFORMANCE_BODY,
        }),
        clock(),
        Some("ts_live_dummy_key_000000".to_owned()),
    )
}

#[test]
fn the_shared_conformance_suite_passes_over_the_typesafe_adapter() {
    pollster::block_on(classifier_conformance(&scripted()));
}

#[test]
fn the_shared_malformed_question_suite_passes() {
    pollster::block_on(classifier_rejects_malformed_questions(&scripted()));
}

#[test]
fn a_missing_key_answers_not_configured() {
    let adapter = TypeSafe::new(
        Arc::new(StaticHttp {
            status: 200,
            body: CONFORMANCE_BODY,
        }),
        clock(),
        None,
    );
    pollster::block_on(classifier_not_configured(&adapter));
}

#[test]
fn an_over_limit_state_still_answers() {
    pollster::block_on(classifier_truncates_long_state(&scripted()));
}
