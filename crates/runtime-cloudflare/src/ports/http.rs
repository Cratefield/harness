//! `HttpClient` over `worker::Fetch`.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError, HttpPolicy};
use worker::send::IntoSendFuture;
use worker::{Fetch, Headers, Method, Request as WorkerRequest, RequestInit};

pub struct FetchClient;

#[async_trait]
impl HttpClient for FetchClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let policy = HttpPolicy::of_request(&request);
        let (parts, body) = request.into_parts();
        let mut init = RequestInit::new();
        init.method = Method::from(parts.method.as_str().to_string());
        let headers = Headers::new();
        for (name, value) in &parts.headers {
            let _ = headers.set(name.as_str(), value.to_str().unwrap_or_default());
        }
        init.headers = headers;

        // A body is attached only when there is one. The Fetch spec refuses
        // to construct a Request whose method is GET or HEAD and whose body
        // is non-null, and an empty JS string is not null: setting it
        // unconditionally makes every GET through this port throw a
        // TypeError before it leaves the isolate.
        //
        // Nothing caught it because every adapter shipped so far POSTs
        // (Resend, Turnstile). The first GET consumer is OpenID Connect
        // discovery in the `auth-oidc` crate, which fetches a configuration
        // document and a JWKS.
        if !body.is_empty() {
            // The port's adapters send JSON bodies; non-UTF-8 is a hard
            // error rather than a lossy corruption.
            let body_text = String::from_utf8(body.to_vec())
                .map_err(|err| HttpError::Transport(err.to_string()))?;
            init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body_text)));
        }
        let worker_request = WorkerRequest::new_with_init(&parts.uri.to_string(), &init)
            .map_err(|err| HttpError::Transport(err.to_string()))?;

        let mut response = Fetch::Request(worker_request)
            .send()
            .into_send()
            .await
            .map_err(|err| HttpError::Transport(err.to_string()))?;

        // `bytes()` buffers the whole body, so refuse a declared body the
        // cap has already out before allocating it (issue #136).
        let declared = response
            .headers()
            .get("content-length")
            .ok()
            .flatten()
            .and_then(|length| length.trim().parse::<usize>().ok());
        if declared.is_some_and(|declared| declared > policy.max_response_bytes) {
            return Err(HttpError::ResponseTooLarge {
                limit: policy.max_response_bytes,
            });
        }

        let mut builder = http::Response::builder().status(response.status_code());
        let response_headers = response.headers();
        if let Some(headers) = builder.headers_mut() {
            for (name, value) in response_headers {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::try_from(name.as_str()),
                    http::HeaderValue::try_from(value.as_str()),
                ) {
                    headers.insert(name, value);
                }
            }
        }
        let bytes = response
            .bytes()
            .into_send()
            .await
            .map_err(|err| HttpError::Transport(err.to_string()))?;
        builder
            .body(Bytes::from(bytes))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}
