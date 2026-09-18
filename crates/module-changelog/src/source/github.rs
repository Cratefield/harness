//! The GitHub Releases source: page through
//! `GET /repos/{owner}/{name}/releases` until a short page or the cap.
//!
//! The walk is deliberately bounded — five pages of one hundred — so a
//! repository cannot make one refresh unbounded. Whether the walk saw the
//! end of the list is part of the result: a walk cut off at the cap still
//! applies what it fetched, but only a complete walk may prune, and only a
//! walk that finished inside a single page stores an etag — a page's etag
//! is that page's etag, and a repository of more than one page would
//! `304` away an edit made on a later page.

use bytes::Bytes;
use cratefield_core::HttpClient;
use http::{Method, Request, StatusCode, header};
use serde_json::Value;

use crate::Settings;
use crate::source::{
    FetchError, Fetched, decode_error, etag_of, release_from_json, send, transport_error,
    upstream_error,
};

/// GitHub's own page size maximum, and the hard cap: five pages of it, five
/// hundred releases, is far more than a changelog serves.
const PAGE_SIZE: u64 = 100;
const MAX_PAGES: u64 = 5;

const API_VERSION: &str = "2022-11-28";
const ACCEPT: &str = "application/vnd.github+json";
const USER_AGENT: &str = "cratefield-module-changelog";

/// Walks the repository's releases, newest page first. Page 1 carries
/// `If-None-Match` when we hold an etag, and a `304` there means upstream
/// has nothing we have not stored. The returned [`Fetched::Fresh`] says
/// whether the walk saw the end of the list: only then may the caller
/// prune, and only a walk that fit one page carries an etag to store.
pub(crate) async fn fetch(
    http: &dyn HttpClient,
    settings: &Settings,
    owner: &str,
    name: &str,
    etag: Option<&str>,
) -> Result<Fetched, FetchError> {
    let mut releases = Vec::new();
    let mut skipped = 0u64;
    let mut pages = 0u64;
    let mut complete = false;
    let mut page_one_etag = String::new();

    for page in 1..=MAX_PAGES {
        let request = build_request(
            settings,
            owner,
            name,
            page,
            if page == 1 { etag } else { None },
        )?;
        let response = send(http, request).await?;
        let status = response.status();

        if page == 1 && status == StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if status != StatusCode::OK {
            let body: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
            return Err(upstream_error(status.as_u16(), &body));
        }
        if page == 1 {
            // Page 1's etag is the only one with a use — and only for the
            // single-page walk that body belongs to.
            page_one_etag = etag_of(&response);
        }
        pages += 1;

        let body: Value = serde_json::from_slice(response.body()).map_err(decode_error)?;
        let Some(entries) = body.as_array() else {
            return Err(decode_error("the releases response is not a JSON array"));
        };
        for entry in entries {
            match release_from_json(entry) {
                Some(release) => releases.push(release),
                None => skipped += 1,
            }
        }
        // A short page is the last page: the walk saw the end of the list.
        if (entries.len() as u64) < PAGE_SIZE {
            complete = true;
            break;
        }
    }

    if !complete {
        // The cap is not an end of the list — it is where we stopped
        // looking. Upstream may hold releases we never saw, so nothing may
        // be pruned on this refresh and no etag may be stored: the next
        // refresh must walk again in full.
        tracing::warn!(
            owner = %owner,
            name = %name,
            pages = MAX_PAGES,
            "changelog: the releases walk hit the page cap; everything fetched still applies, \
             but pruning is skipped for this refresh and no etag is stored"
        );
    }

    // The etag belongs to one response body. A repository of more than one
    // page can take an edit on page 2 or later and leave page 1
    // byte-identical — a stored etag would then `304` that edit away on
    // every refresh after, so only a complete single-page walk stores one,
    // and any previously stored etag is cleared instead.
    let etag = if complete && pages == 1 {
        page_one_etag
    } else {
        String::new()
    };

    Ok(Fetched::Fresh {
        etag,
        releases,
        skipped,
        complete,
    })
}

fn build_request(
    settings: &Settings,
    owner: &str,
    name: &str,
    page: u64,
    etag: Option<&str>,
) -> Result<Request<Bytes>, FetchError> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}/repos/{owner}/{name}/releases?per_page={PAGE_SIZE}&page={page}",
            settings.api_base,
        ))
        .header(header::ACCEPT, ACCEPT)
        .header("X-GitHub-Api-Version", API_VERSION)
        .header(header::USER_AGENT, USER_AGENT);
    if let Some(token) = &settings.token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(etag) = etag {
        builder = builder.header(header::IF_NONE_MATCH, etag);
    }
    builder.body(Bytes::new()).map_err(transport_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_release_is_picked_from_its_loose_fields() {
        let release = release_from_json(&json!({
            "tag_name": "v1.2.0",
            "name": "1.2.0 — the long-awaited",
            "body": "### Added\n- something",
            "html_url": "https://github.com/owner/name/releases/tag/v1.2.0",
            "published_at": "2026-05-06T10:00:00Z",
            "draft": false,
            "prerelease": false,
        }))
        .expect("parses");
        assert_eq!(release.version, "v1.2.0");
        assert_eq!(release.title, "1.2.0 — the long-awaited");
        assert_eq!(
            release.url,
            "https://github.com/owner/name/releases/tag/v1.2.0"
        );
        assert_eq!(release.published_at, "2026-05-06T10:00:00Z");
        assert!(!release.draft && !release.prerelease);
    }

    #[test]
    fn a_draft_falls_back_to_created_at_and_a_nameless_release_to_its_tag() {
        let release = release_from_json(&json!({
            "tag_name": "v0.1.0-rc1",
            "body": null,
            "created_at": "2026-01-02T03:04:05Z",
            "published_at": null,
            "draft": true,
            "prerelease": true,
        }))
        .expect("parses");
        assert_eq!(release.title, "v0.1.0-rc1", "no name: the tag titles it");
        assert_eq!(release.body, "");
        assert_eq!(release.published_at, "2026-01-02T03:04:05Z");
        assert!(release.draft && release.prerelease);
    }

    #[test]
    fn an_empty_name_titles_the_release_with_its_tag() {
        for name in ["", "   "] {
            let release = release_from_json(&json!({
                "tag_name": "v1.2.0",
                "name": name,
                "body": "### Added\n- something",
                "html_url": "https://github.com/owner/name/releases/tag/v1.2.0",
                "published_at": "2026-05-06T10:00:00Z",
                "draft": false,
                "prerelease": false,
            }))
            .expect("parses");
            assert_eq!(
                release.title, "v1.2.0",
                "an empty name is not a title; the tag is"
            );
        }
    }

    #[test]
    fn a_release_without_a_usable_tag_is_none() {
        assert!(release_from_json(&json!({ "name": "no tag here" })).is_none());
        assert!(release_from_json(&json!({ "tag_name": "   " })).is_none());
        assert!(release_from_json(&json!("a string")).is_none());
    }

    #[test]
    fn upstream_statuses_map_onto_their_problems() {
        let not_found = upstream_error(404, &json!({"message": "Not Found"}));
        assert_eq!(not_found.last_status, "404");
        assert_eq!(not_found.problem.status, StatusCode::NOT_FOUND);

        let rate_limited = upstream_error(429, &json!({}));
        assert_eq!(rate_limited.last_status, "429");
        assert_eq!(rate_limited.problem.status, StatusCode::TOO_MANY_REQUESTS);

        let forbidden = upstream_error(403, &json!({"message": "API rate limit exceeded"}));
        assert_eq!(forbidden.last_status, "403");
        let detail = forbidden.problem.detail.unwrap_or_default();
        assert!(detail.contains("CHANGELOG_TOKEN"), "{detail}");

        let server = upstream_error(503, &json!({}));
        assert_eq!(server.last_status, "503");
        assert_eq!(server.problem.status, StatusCode::BAD_GATEWAY);
    }
}
