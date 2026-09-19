//! The shared `Classifier` conformance suite (issue #456) run against the
//! `TypeSafe` adapter: the same common contract every adapter answers,
//! over a local `HttpClient` scripted with one well-formed classify body
//! for `classifier_conformance_questions`.

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

/// A well-formed success body for the canonical question set: every id
/// asked, every chosen label offered, a probability for every offered
/// label, the masses summing to one. The adapter validates and does not
/// renormalise, so this is exactly the shape a conforming vendor sends.
/// The score answer is a JSON number on the `"1"`/`"5"` scale.
const CONFORMANCE_BODY: &str = r#"{"answers":[
  {"id":"topic","value":"bugs","probabilities":{"billing":0.1,"bugs":0.9}},
  {"id":"severity","value":5,"probabilities":{"1":0.2,"5":0.8}},
  {"id":"urgent","value":"true","probabilities":{"true":0.75,"false":0.25}}]}"#;

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
