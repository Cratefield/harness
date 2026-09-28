//! The one 401 policy worth sharing: a rejected call gets one refresh and a
//! replay, and only then gives up. Never a loop — a provider that answers
//! 401 twice in a row is not answered by a third try.

use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError};
use http::Request;
use thiserror::Error;

/// What a [`send_with_refresh`] call can end as. The replay's own outcome —
/// whatever status the provider answered it with — is a success here: a 401
/// on the replay is data for the caller's token layer, not this helper's
/// error to name.
#[derive(Debug, Error)]
pub enum SendWithRefreshError<E> {
    /// The transport refused a send (either one).
    #[error("transport: {0}")]
    Transport(#[from] HttpError),
    /// The refresh did not produce a token, so there was no replay. The
    /// caller's own refresh error is carried untouched.
    #[error("the access token was rejected and the refresh failed")]
    Refresh(E),
}

/// Sends a bearer-authenticated request; if the provider answers 401,
/// refreshes the token once and replays the request with it.
///
/// - `build` makes the request from an access token. It is called at most
///   twice: once with the token it is handed, once with the refreshed one.
/// - `refresh` is called at most once, and only after a 401. Its error is
///   returned as [`SendWithRefreshError::Refresh`] and the request is never
///   retried — what a failed refresh means (reconnect, back off) is the
///   caller's decision, not this helper's.
///
/// # Errors
///
/// A refused send, either one, as [`SendWithRefreshError::Transport`]; a
/// refresh that did not produce a token as
/// [`SendWithRefreshError::Refresh`]. The replay's status is returned as
/// data even when it is another 401.
pub async fn send_with_refresh<E, R>(
    http: &dyn HttpClient,
    access_token: &str,
    build: impl Fn(&str) -> Request<Bytes>,
    refresh: impl FnOnce() -> R,
) -> Result<http::Response<Bytes>, SendWithRefreshError<E>>
where
    R: Future<Output = Result<String, E>>,
{
    let response = http.send(build(access_token)).await?;
    if response.status() != http::StatusCode::UNAUTHORIZED {
        return Ok(response);
    }
    let fresh = refresh().await.map_err(SendWithRefreshError::Refresh)?;
    Ok(http.send(build(&fresh)).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A refresh that counts it ran and always produces a token.
    fn refreshing(
        count: Arc<AtomicUsize>,
    ) -> impl FnOnce() -> std::future::Ready<Result<String, ()>> {
        move || {
            count.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Ok("fresh-token".to_owned()))
        }
    }

    /// A refresh that never produces a token.
    async fn refusing() -> Result<String, ()> {
        Err(())
    }

    /// Answers statuses from a script, in order, and counts the sends.
    struct Scripted {
        statuses: Vec<u16>,
        next: AtomicUsize,
        sends: AtomicUsize,
    }

    impl Scripted {
        fn with(statuses: &[u16]) -> Self {
            Self {
                statuses: statuses.to_vec(),
                next: AtomicUsize::new(0),
                sends: AtomicUsize::new(0),
            }
        }

        fn sends(&self) -> usize {
            self.sends.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl HttpClient for Scripted {
        async fn send(&self, _request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            let index = self.next.fetch_add(1, Ordering::Relaxed);
            let status = self.statuses.get(index).copied().unwrap_or(500);
            Ok(http::Response::builder()
                .status(status)
                .body(Bytes::new())
                .expect("status"))
        }
    }

    fn request_for(token: &str) -> Request<Bytes> {
        Request::builder()
            .uri("https://provider.example/things")
            .header("authorization", format!("Bearer {token}"))
            .body(Bytes::new())
            .expect("builds")
    }

    #[pollster::test]
    async fn a_401_gets_one_refresh_and_one_replay() {
        let http = Scripted::with(&[401, 201]);
        let refreshed = Arc::new(AtomicUsize::new(0));
        let response = send_with_refresh(
            &http,
            "stale-token",
            request_for,
            refreshing(Arc::clone(&refreshed)),
        )
        .await
        .expect("the replay succeeds");
        assert_eq!(response.status(), 201);
        assert_eq!(refreshed.load(Ordering::Relaxed), 1, "exactly one refresh");
        assert_eq!(http.sends(), 2, "one send, one replay");
    }

    #[pollster::test]
    async fn a_failed_refresh_ends_the_sequence_without_a_replay() {
        let http = Scripted::with(&[401]);
        let error = send_with_refresh(&http, "stale-token", request_for, refusing)
            .await
            .expect_err("the refresh failed");
        assert!(
            matches!(error, SendWithRefreshError::Refresh(())),
            "{error:?}"
        );
        assert_eq!(http.sends(), 1, "no replay after a failed refresh");
    }

    #[pollster::test]
    async fn a_401_on_the_replay_is_data_not_a_loop() {
        let http = Scripted::with(&[401, 401]);
        let refreshed = Arc::new(AtomicUsize::new(0));
        let response = send_with_refresh(
            &http,
            "stale-token",
            request_for,
            refreshing(Arc::clone(&refreshed)),
        )
        .await
        .expect("the replay's status is returned, however unhelpful");
        assert_eq!(response.status(), 401);
        assert_eq!(
            refreshed.load(Ordering::Relaxed),
            1,
            "never a second refresh"
        );
        assert_eq!(http.sends(), 2, "never a third send");
    }

    #[pollster::test]
    async fn a_non_401_never_touches_the_refresh() {
        let http = Scripted::with(&[403]);
        let response = send_with_refresh(&http, "token", request_for, refusing)
            .await
            .expect("the status is passed through");
        assert_eq!(response.status(), 403);
        assert_eq!(http.sends(), 1);
    }
}
