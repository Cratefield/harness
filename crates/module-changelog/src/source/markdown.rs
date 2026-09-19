//! The `CHANGELOG.md` source: read the file raw out of the repository and
//! split it into Keep-a-Changelog sections.
//!
//! A `## ` heading starts a release; its body is everything up to the next
//! `## ` heading. Three heading shapes are read — `## [1.2.3] - 2024-05-06`,
//! `## 1.2.3 - 2024-05-06` and `## v1.2.3` — a date is stored as midnight
//! UTC when present and left empty when not, and `## [Unreleased]` is
//! skipped: it is a draft, and drafts do not ship until they are sections.

use bytes::Bytes;
use cratefield_core::HttpClient;
use http::{Method, Request, StatusCode, header};

use crate::Settings;
use crate::source::{FetchError, Fetched, etag_of, send, transport_error, upstream_error};
use crate::store::UpstreamRelease;

const ACCEPT_RAW: &str = "application/vnd.github.raw";
const USER_AGENT: &str = "cratefield-module-changelog";

/// Fetches the configured file and sections it. The same 304 contract as
/// the releases source: the stored etag goes out, and a `304` means the
/// file has not moved.
pub(crate) async fn fetch(
    http: &dyn HttpClient,
    settings: &Settings,
    owner: &str,
    name: &str,
    etag: Option<&str>,
) -> Result<Fetched, FetchError> {
    let mut url = format!(
        "{}/repos/{owner}/{name}/contents/{}",
        settings.api_base,
        encode_path(&settings.path),
    );
    if let Some(git_ref) = &settings.git_ref {
        url.push_str("?ref=");
        url.push_str(&encode_path(git_ref));
    }

    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(url)
        .header(header::ACCEPT, ACCEPT_RAW)
        .header(header::USER_AGENT, USER_AGENT);
    if let Some(token) = &settings.token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(etag) = etag {
        builder = builder.header(header::IF_NONE_MATCH, etag);
    }
    let request = builder.body(Bytes::new()).map_err(transport_error)?;
    let response = send(http, request).await?;
    let status = response.status();

    if status == StatusCode::NOT_MODIFIED {
        return Ok(Fetched::NotModified);
    }
    if status != StatusCode::OK {
        return Err(upstream_error(status.as_u16(), &serde_json::Value::Null));
    }

    let text = String::from_utf8_lossy(response.body());
    let (releases, skipped) = parse(&text);
    Ok(Fetched::Fresh {
        etag: etag_of(&response),
        releases,
        skipped,
        // One file arrives in one response: the fetch is the whole source,
        // every time, so it may always prune.
        complete: true,
    })
}

/// One section of a Keep-a-Changelog file.
struct Section {
    version: String,
    title: String,
    published_at: String,
    body: String,
}

/// Splits `text` at `## ` headings into releases. `skipped` counts headings
/// that name no release: the preamble above the first heading belongs to no
/// section at all, `Unreleased` is a draft, a heading with no version is
/// nothing, and a repeated version would collide with the row the first one
/// wrote.
pub(crate) fn parse(text: &str) -> (Vec<UpstreamRelease>, u64) {
    let mut releases: Vec<UpstreamRelease> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut skipped = 0u64;
    let mut current: Option<Section> = None;

    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            if let Some(section) = current.take() {
                finish(section, &mut releases, &mut seen, &mut skipped);
            }
            let (version, title, date) = split_heading(heading);
            current = Some(Section {
                version,
                title,
                published_at: date
                    .map(|date| format!("{date}T00:00:00Z"))
                    .unwrap_or_default(),
                body: String::new(),
            });
        } else if let Some(section) = current.as_mut() {
            section.body.push_str(line);
            section.body.push('\n');
        }
    }
    if let Some(section) = current.take() {
        finish(section, &mut releases, &mut seen, &mut skipped);
    }
    (releases, skipped)
}

/// Decides whether a finished section is a release, and records it.
fn finish(
    section: Section,
    releases: &mut Vec<UpstreamRelease>,
    seen: &mut std::collections::HashSet<String>,
    skipped: &mut u64,
) {
    // `## [Unreleased]` is a draft, never a release, whatever it holds.
    if section.version.is_empty() || section.version.eq_ignore_ascii_case("unreleased") {
        *skipped += 1;
        return;
    }
    // A repeated version would fight the row the first copy wrote.
    if !seen.insert(section.version.clone()) {
        *skipped += 1;
        return;
    }
    let title = if section.title.is_empty() {
        section.version.clone()
    } else {
        section.title
    };
    releases.push(UpstreamRelease {
        version: section.version,
        title,
        body: section.body.trim().to_owned(),
        // A section of a file has no canonical page of its own.
        url: String::new(),
        published_at: section.published_at,
        prerelease: false,
        draft: false,
    });
}

/// Splits one `## ` heading into `(version, title, date)`. The bracketed
/// Keep-a-Changelog form and the bare form both read; the date is the tail
/// when it parses as one, and the title is whatever else the tail says.
fn split_heading(heading: &str) -> (String, String, Option<String>) {
    let heading = heading.trim();
    let (version, tail) = match bracketed(heading) {
        Some((version, tail)) => (version.trim().to_owned(), tail.trim()),
        None => match heading.split_once(char::is_whitespace) {
            Some((version, tail)) => (version.trim().to_owned(), tail.trim()),
            None => (heading.to_owned(), ""),
        },
    };
    // ` - 2024-05-06`, `— some title`, or nothing.
    let tail = tail
        .trim_start_matches(['-', '\u{2013}', '\u{2014}', ' '])
        .trim();
    if is_date(tail) {
        (version, String::new(), Some(tail.to_owned()))
    } else {
        (version, tail.to_owned(), None)
    }
}

/// `## [1.2.3] - …` — the version inside the brackets, the rest after them.
fn bracketed(heading: &str) -> Option<(String, &str)> {
    let rest = heading.strip_prefix('[')?;
    let (version, tail) = rest.split_once(']')?;
    Some((version.to_owned(), tail))
}

/// `YYYY-MM-DD`, and a real calendar date at that — `2024-02-30` is not a
/// date just because it fits the shape.
fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        value[..4].parse::<i32>(),
        value[5..7].parse::<u8>(),
        value[8..10].parse::<u8>(),
    ) else {
        return false;
    };
    let Ok(month) = time::Month::try_from(month) else {
        return false;
    };
    time::Date::from_calendar_date(year, month, day).is_ok()
}

/// Percent-encodes a path for the contents URL, keeping `/` so a file like
/// `docs/CHANGELOG.md` survives and encoding the rest of GitHub's reserved
/// set. Deliberately hand-rolled: it is the only URL the module builds.
fn encode_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char);
            }
            other => {
                const HEX: [u8; 16] = *b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[usize::from(other >> 4)] as char);
                out.push(HEX[usize::from(other & 0x0F)] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANGELOG: &str = "# Changelog\n\nAll notable changes.\n\n\
## [Unreleased]\n\n- nothing yet\n\n\
## [1.2.0] - 2024-05-06\n\n### Added\n\n- the thing\n\n\
## 1.1.0 - 2024-01-15\n\n- the earlier thing\n\n\
## v1.0.0\n\n- where it started\n";

    #[test]
    fn sections_split_at_double_hash_headings() {
        let (releases, skipped) = parse(CHANGELOG);
        assert_eq!(skipped, 1, "Unreleased is a draft: {releases:?}");
        assert_eq!(
            releases
                .iter()
                .map(|release| release.version.as_str())
                .collect::<Vec<_>>(),
            ["1.2.0", "1.1.0", "v1.0.0"]
        );
    }

    #[test]
    fn bodies_run_to_the_next_heading_and_keep_their_markdown() {
        let (releases, _) = parse(CHANGELOG);
        assert_eq!(releases[0].body, "### Added\n\n- the thing");
        assert_eq!(releases[2].body, "- where it started");
    }

    #[test]
    fn dates_become_midnight_and_absent_dates_stay_empty() {
        let (releases, _) = parse(CHANGELOG);
        assert_eq!(releases[0].published_at, "2024-05-06T00:00:00Z");
        assert_eq!(releases[1].published_at, "2024-01-15T00:00:00Z");
        assert_eq!(releases[2].published_at, "");
    }

    #[test]
    fn titles_fall_back_to_the_version_and_keep_a_written_one() {
        let (releases, _) = parse(CHANGELOG);
        assert_eq!(
            releases[0].title, "1.2.0",
            "no title: the version titles it"
        );
        assert_eq!(releases[2].title, "v1.0.0");

        let (titled, _) = parse("## 2.0.0 - Rewritten\n\n- all of it\n");
        assert_eq!(titled[0].title, "Rewritten");
        assert_eq!(titled[0].published_at, "", "a title is not a date");
    }

    #[test]
    fn a_non_date_that_looks_like_one_is_not_one() {
        assert!(!is_date("2024-02-30"));
        assert!(!is_date("2024-13-01"));
        assert!(!is_date("20240506"));
        assert!(is_date("2024-05-06"));
    }

    #[test]
    fn duplicate_versions_are_skipped_not_duplicated() {
        let (releases, skipped) = parse("## 1.0.0\n\n- first\n\n## 1.0.0\n\n- again\n");
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].body, "- first");
        assert_eq!(skipped, 1);
    }

    #[test]
    fn paths_encode_but_keep_their_slashes() {
        assert_eq!(encode_path("CHANGELOG.md"), "CHANGELOG.md");
        assert_eq!(encode_path("docs/CHANGELOG.md"), "docs/CHANGELOG.md");
        assert_eq!(encode_path("a b.md"), "a%20b.md");
        assert_eq!(encode_path("feature?md"), "feature%3Fmd");
    }
}
