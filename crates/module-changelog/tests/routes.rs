//! Behaviour of the changelog module through its router, across dialects:
//! the refresh that mirrors upstream, the reads that never leave the
//! database, the etag contract, pruning, paging, the admin guard, the
//! `CHANGELOG.md` source, and the rendering forward-compatibility surface.
//!
//! Every test loops over [`support::kits`] — one kit per database dialect
//! the environment provides — with a scripted fake GitHub whose counter
//! proves the read path makes zero upstream calls.

mod support;

use cratefield_module_changelog::Changelog;
use http::StatusCode;
use serde_json::{Value, json};
use support::{
    ADMIN, API_BASE, CHANGELOG_MD, CHANGELOG_MD_120_BODY, KitSpec, MARKDOWN_BODY, REPO, body_of,
    filler_page, get, kits_from, kits_with, refresh, refresh_as, release, updated_at_by_version,
};

/// The versions of a list response, in the order the body served them.
fn versions(json: &Value) -> Vec<&str> {
    json["releases"]
        .as_array()
        .expect("releases is an array")
        .iter()
        .map(|release| {
            release["version"]
                .as_str()
                .expect("every release names a version")
        })
        .collect()
}

/// The stock fixture: three stable releases, scripted in ascending order so
/// the served order is provably the store's, not the payload's.
fn three_stable() -> Vec<Value> {
    vec![
        release("v1.0.0", "2025-12-31T23:59:59Z", "- where it started"),
        release("v1.2.0", "2026-06-01T10:00:00Z", MARKDOWN_BODY),
        release("v1.1.0", "2026-03-15T09:30:00Z", "- the earlier thing"),
    ]
}

/// 1. A venture that only sets configuration and composes `Changelog::new()`
/// is complete: one refresh mirrors the repository, and the list serves it
/// newest first, body byte-for-byte as upstream sent it.
#[pollster::test]
async fn config_alone_composes_the_mirror_and_serves_upstream_verbatim() {
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());

        let refreshed_at = kit.clock.now_iso();
        let report = refresh(&kit).await;
        assert_eq!(report["inserted"], 3, "{report}");

        let list = get(&kit, "/v1/changelog").await;
        assert_eq!(list.status, StatusCode::OK, "{}", body_of(&list));
        let json = list.json();
        assert_eq!(
            versions(&json),
            ["v1.2.0", "v1.1.0", "v1.0.0"],
            "newest first, whatever order upstream sent"
        );
        assert_eq!(json["releases"][0]["body"], MARKDOWN_BODY, "verbatim");
        assert_eq!(json["releases"][0]["title"], "v1.2.0 — release notes");
        assert_eq!(
            json["releases"][0]["url"],
            format!("https://github.com/{REPO}/releases/tag/v1.2.0")
        );
        assert_eq!(json["releases"][0]["published_at"], "2026-06-01T10:00:00Z");
        assert_eq!(json["releases"][0]["prerelease"], false);
        assert_eq!(json["total"], 3);
        assert_eq!(json["page"], 1);
        assert_eq!(json["per_page"], 20);
        assert_eq!(json["refreshed_at"], refreshed_at.as_str());
        assert_eq!(json["source"]["kind"], "github-releases");
        assert_eq!(json["source"]["repo"], REPO);

        // The refresh went where CHANGELOG_API_BASE pointed: configuration
        // alone picked the repository and the endpoint.
        let calls = kit.fake.calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(
            calls[0]
                .url
                .starts_with(&format!("{API_BASE}/repos/{REPO}/releases?")),
            "the refresh ignored CHANGELOG_API_BASE: {}",
            calls[0].url,
        );
    }
}

/// 2. The reads are database-only: after a refresh, page loads make zero
/// upstream requests — including reads whose fingerprint the cache has
/// never seen.
#[pollster::test]
async fn a_page_load_hits_the_database_never_github() {
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());
        refresh(&kit).await;

        kit.fake.forget_calls();
        let list = get(&kit, "/v1/changelog").await;
        assert_eq!(list.status, StatusCode::OK);
        assert_eq!(list.json()["total"], 3);

        let one = get(&kit, "/v1/changelog/v1.2.0").await;
        assert_eq!(one.status, StatusCode::OK);

        // A fingerprint the read cache has not seen either — still the
        // database and nothing else.
        let paged = get(&kit, "/v1/changelog?page=2&per_page=1").await;
        assert_eq!(paged.status, StatusCode::OK);

        assert_eq!(
            kit.fake.requests(),
            0,
            "the read path reached upstream: {:?}",
            kit.fake.calls(),
        );
    }
}

/// 3. GitHub being down (a 500) or refusing (a 403 rate limit) costs a
/// refresh, never the changelog: the reads still serve the stored rows and
/// a failed refresh leaves them intact, unchanged and unpruned.
#[pollster::test]
async fn github_being_down_does_not_take_the_changelog_down() {
    for status in [500u16, 403] {
        for kit in support::kits() {
            kit.fake.script_releases(&three_stable());
            refresh(&kit).await;
            // Two fingerprints that are cache misses, so both reads are
            // genuine database reads, not cached bytes.
            let before = get(&kit, "/v1/changelog?locale=probe-before").await;
            assert_eq!(before.status, StatusCode::OK);
            let stored = updated_at_by_version(&kit);

            kit.fake
                .fail_every_call(status, json!({ "message": "upstream is having a bad day" }));
            kit.clock.advance_secs(300);

            let after = get(&kit, "/v1/changelog?locale=probe-after").await;
            assert_eq!(after.status, StatusCode::OK, "{status} took the read down");
            assert_eq!(after.json()["releases"], before.json()["releases"]);
            assert_eq!(after.json()["total"], 3);

            let failed = refresh_as(&kit, Some(ADMIN)).await;
            assert_eq!(
                failed.status,
                StatusCode::BAD_GATEWAY,
                "an upstream {status} is a bad gateway, not a hang: {}",
                body_of(&failed),
            );
            let problem = failed.json();
            assert!(
                problem["type"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("changelog-upstream"),
                "{problem}",
            );

            // The stored rows are intact and unchanged, and the failure is
            // recorded as an attempt and nothing else.
            assert_eq!(support::release_count(&kit), 3);
            assert_eq!(
                updated_at_by_version(&kit),
                stored,
                "a failed refresh moved a row",
            );
            assert_eq!(
                support::source_field(&kit, "last_status"),
                Some(status.to_string()),
            );
            let still_there = get(&kit, "/v1/changelog?locale=probe-final").await;
            assert_eq!(still_there.json()["releases"], before.json()["releases"]);
        }
    }
}

/// 4. Before the first refresh the list is empty — a 200 with
/// `"releases": []`, not an error and not an empty error page — and the
/// detail view of a version that does not exist is a 404, not a 500.
#[pollster::test]
async fn before_the_first_refresh_the_list_is_empty_not_broken() {
    for kit in support::kits() {
        let list = get(&kit, "/v1/changelog").await;
        assert_eq!(list.status, StatusCode::OK);
        let json = list.json();
        assert_eq!(json["releases"], json!([]));
        assert_eq!(json["total"], 0);
        assert_eq!(json["refreshed_at"], Value::Null);
        assert_eq!(json["source"]["repo"], REPO);

        let one = get(&kit, "/v1/changelog/v1.0.0").await;
        assert_eq!(one.status, StatusCode::NOT_FOUND);

        // None of this reached for the network.
        assert_eq!(kit.fake.requests(), 0);
    }
}

/// 5. A refresh over identical upstream data rewrites nothing: the report
/// says everything was unchanged, and `updated_at` on every row is
/// byte-identical to after the first refresh — with the clock advanced in
/// between, so a spurious write would be visible.
#[pollster::test]
async fn an_unchanged_refresh_writes_nothing() {
    for kit in support::kits() {
        let releases = three_stable();
        kit.fake.script_releases(&releases);
        let first = refresh(&kit).await;
        assert_eq!(first["inserted"], 3, "{first}");

        let first_stamp = kit.clock.now_iso();
        let stored = updated_at_by_version(&kit);
        assert!(
            stored.values().all(|stamp| *stamp == first_stamp),
            "the first refresh did not stamp its rows: {stored:?}",
        );

        // Same content upstream. Re-scripting moves the fake's etag, so
        // this refresh is a full fetch of identical data, not a 304.
        kit.clock.advance_secs(120);
        kit.fake.script_releases(&releases);
        let second = refresh(&kit).await;
        assert_eq!(second["fetched"], 3, "{second}");
        assert_eq!(second["inserted"], 0, "{second}");
        assert_eq!(second["updated"], 0, "{second}");
        assert_eq!(second["unchanged"], 3, "everything is unchanged: {second}");
        assert_eq!(second["removed"], 0, "{second}");
        assert_eq!(second["not_modified"], false, "{second}");

        assert_eq!(
            updated_at_by_version(&kit),
            stored,
            "a no-op refresh touched a row",
        );
        assert_eq!(support::release_count(&kit), 3);
    }
}

/// 6. A changed release updates in place: one updated and the rest
/// unchanged, `first_seen_at` preserved, `updated_at` moved only on the
/// changed row, and no duplicate row.
#[pollster::test]
async fn a_changed_release_updates_in_place_without_duplication() {
    for kit in support::kits() {
        let releases = three_stable();
        kit.fake.script_releases(&releases);
        refresh(&kit).await;

        let first_seen = support::release_field(&kit, "v1.1.0", "first_seen_at");
        let stored = updated_at_by_version(&kit);

        // Upstream rewrites v1.1.0's body and nothing else.
        let edited_body = "### Changed\n\n- the notes were rewritten upstream";
        let edited = vec![
            release("v1.0.0", "2025-12-31T23:59:59Z", "- where it started"),
            release("v1.2.0", "2026-06-01T10:00:00Z", MARKDOWN_BODY),
            release("v1.1.0", "2026-03-15T09:30:00Z", edited_body),
        ];
        kit.clock.advance_secs(120);
        kit.fake.script_releases(&edited);

        let report = refresh(&kit).await;
        assert_eq!(report["updated"], 1, "{report}");
        assert_eq!(report["unchanged"], 2, "{report}");
        assert_eq!(report["inserted"], 0, "{report}");
        assert_eq!(report["removed"], 0, "{report}");

        assert_eq!(support::release_count(&kit), 3, "a duplicate row appeared");
        assert_eq!(
            support::release_field(&kit, "v1.1.0", "first_seen_at"),
            first_seen,
            "first_seen_at did not survive the update",
        );
        let after = updated_at_by_version(&kit);
        assert_eq!(
            after.get("v1.1.0").map(String::as_str),
            Some(kit.clock.now_iso().as_str()),
            "updated_at did not move on the changed row",
        );
        assert_eq!(
            after.get("v1.2.0"),
            stored.get("v1.2.0"),
            "an untouched row's updated_at moved",
        );
        assert_eq!(after.get("v1.0.0"), stored.get("v1.0.0"));

        let one = get(&kit, "/v1/changelog/v1.1.0").await;
        assert_eq!(one.status, StatusCode::OK);
        assert_eq!(
            one.json()["body"],
            edited_body,
            "the new body is what is served"
        );
    }
}

/// 7. Drafts and prereleases are excluded by default and mirrored only when
/// `CHANGELOG_INCLUDE_DRAFTS` / `CHANGELOG_INCLUDE_PRERELEASES` say so —
/// a draft's `published_at` falling back to `created_at`, since GitHub
/// sends no published date for one.
#[pollster::test]
async fn drafts_and_prereleases_stay_hidden_until_configured_in() {
    let script = || {
        vec![
            release("v1.2.0", "2026-06-01T10:00:00Z", "the stable one"),
            support::draft("v0.9.0-draft", "2026-07-01T08:00:00Z"),
            support::prerelease("v2.0.0-rc.1", "2026-08-01T12:00:00Z"),
        ]
    };

    // By default: both hidden, counted as skipped, never stored.
    for kit in support::kits() {
        kit.fake.script_releases(&script());
        let report = refresh(&kit).await;
        assert_eq!(report["fetched"], 3, "{report}");
        assert_eq!(
            report["skipped"], 2,
            "the draft and the prerelease: {report}"
        );
        assert_eq!(
            report["inserted"], 1,
            "only the stable release is stored: {report}"
        );

        let json = get(&kit, "/v1/changelog").await.json();
        assert_eq!(versions(&json), ["v1.2.0"]);
        assert_eq!(json["total"], 1);
    }

    // Flagged in: both mirrored, the draft dated from `created_at`.
    for kit in kits_with(&[
        ("CHANGELOG_INCLUDE_DRAFTS", "true"),
        ("CHANGELOG_INCLUDE_PRERELEASES", "true"),
    ]) {
        kit.fake.script_releases(&script());
        let report = refresh(&kit).await;
        assert_eq!(report["skipped"], 0, "{report}");
        assert_eq!(report["inserted"], 3, "{report}");

        let json = get(&kit, "/v1/changelog").await.json();
        assert_eq!(
            versions(&json),
            ["v2.0.0-rc.1", "v0.9.0-draft", "v1.2.0"],
            "newest first, the draft dated from created_at",
        );
        let draft = get(&kit, "/v1/changelog/v0.9.0-draft").await;
        assert_eq!(draft.status, StatusCode::OK);
        assert_eq!(
            draft.json()["published_at"],
            "2026-07-01T08:00:00Z",
            "created_at is the draft's published date",
        );
        let rc = get(&kit, "/v1/changelog/v2.0.0-rc.1").await;
        assert_eq!(rc.json()["prerelease"], true);
        assert_eq!(rc.json()["body"], "the v2.0.0-rc.1 release candidate");
    }
}

/// 8. The etag contract: the second refresh presents the stored etag,
/// upstream answers `304 Not Modified`, the report says `not_modified` —
/// and nothing at all is written, not even the refresh timestamp.
#[pollster::test]
async fn an_unmoved_upstream_answers_304_and_writes_nothing() {
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());
        refresh(&kit).await;
        let first_stamp = kit.clock.now_iso();
        let stored = updated_at_by_version(&kit);

        kit.clock.advance_secs(120);
        let report = refresh(&kit).await;
        assert_eq!(report["not_modified"], true, "{report}");
        assert_eq!(report["fetched"], 0, "{report}");
        assert_eq!(report["inserted"], 0, "{report}");
        assert_eq!(report["updated"], 0, "{report}");
        assert_eq!(report["removed"], 0, "{report}");

        // The conditional request went out carrying the stored etag.
        let calls = kit.fake.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(
            calls[0].if_none_match, None,
            "the first fetch is unconditional"
        );
        assert_eq!(
            calls[1].if_none_match.as_deref(),
            Some(kit.fake.releases_etag().as_str()),
            "the stored etag was not presented",
        );

        // And nothing was written: the rows and the bookkeeping both still
        // read as the first refresh left them.
        assert_eq!(updated_at_by_version(&kit), stored);
        assert_eq!(support::release_count(&kit), 3);
        assert_eq!(
            support::source_field(&kit, "last_refreshed_at"),
            Some(first_stamp),
            "a 304 rewrote the refresh timestamp",
        );
        assert_eq!(get(&kit, "/v1/changelog").await.json()["total"], 3);
    }
}

/// 9. Pruning: a release that disappears upstream is removed by a fully
/// successful fetch — and by nothing else. A fetch that dies partway
/// (page 2 of the walk fails) removes nothing and touches nothing.
#[pollster::test]
async fn rows_are_pruned_only_after_a_fully_successful_fetch() {
    // A complete fetch prunes what upstream dropped.
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());
        refresh(&kit).await;
        assert_eq!(support::release_count(&kit), 3);

        let mut pruned = three_stable();
        pruned.remove(0); // v1.0.0 is gone upstream
        kit.clock.advance_secs(120);
        kit.fake.script_releases(&pruned);

        let report = refresh(&kit).await;
        assert_eq!(report["removed"], 1, "{report}");
        assert_eq!(report["unchanged"], 2, "{report}");
        assert_eq!(
            report["complete"], true,
            "a short page is a complete walk: {report}",
        );
        assert_eq!(support::release_count(&kit), 2);

        let json = get(&kit, "/v1/changelog").await.json();
        assert_eq!(versions(&json), ["v1.2.0", "v1.1.0"]);
        assert_eq!(json["total"], 2);
    }

    // A fetch that fails on page 2 prunes nothing.
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());
        refresh(&kit).await;
        let stored = updated_at_by_version(&kit);
        assert_eq!(support::release_count(&kit), 3);

        // A full first page of 100 sends the walk on to page 2, which dies.
        let mut page_one = three_stable();
        page_one.extend(support::filler_releases(97));
        assert_eq!(
            page_one.len(),
            100,
            "the page must be full or the walk stops"
        );
        kit.fake.script_release_pages(&[
            page_one.as_slice(),
            &[support::filler_releases(1).remove(0)],
        ]);
        kit.fake
            .fail_page(2, 500, json!({ "message": "the walk died here" }));
        kit.clock.advance_secs(120);

        let failed = refresh_as(&kit, Some(ADMIN)).await;
        assert_eq!(
            failed.status,
            StatusCode::BAD_GATEWAY,
            "{}",
            body_of(&failed)
        );
        assert_eq!(
            support::release_count(&kit),
            3,
            "a partial fetch pruned rows",
        );
        assert_eq!(
            updated_at_by_version(&kit),
            stored,
            "a partial fetch touched rows",
        );
        assert_eq!(get(&kit, "/v1/changelog").await.json()["total"], 3);
    }
}

/// 10. `GET /{version}` serves exactly the one stored release; an unknown
/// version is a 404, not a 500.
#[pollster::test]
async fn one_version_one_release_and_an_unknown_version_is_404() {
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());
        refresh(&kit).await;

        let one = get(&kit, "/v1/changelog/v1.2.0").await;
        assert_eq!(one.status, StatusCode::OK);
        let json = one.json();
        assert_eq!(json["version"], "v1.2.0");
        assert_eq!(json["title"], "v1.2.0 — release notes");
        assert_eq!(json["body"], MARKDOWN_BODY);
        assert_eq!(
            json["url"],
            format!("https://github.com/{REPO}/releases/tag/v1.2.0"),
        );
        assert_eq!(json["published_at"], "2026-06-01T10:00:00Z");
        assert_eq!(json["prerelease"], false);
        assert_eq!(json["rendering"]["style"], "original");

        let missing = get(&kit, "/v1/changelog/v9.9.9").await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        assert!(
            missing.json()["type"]
                .as_str()
                .unwrap_or_default()
                .contains("not-found"),
            "{}",
            body_of(&missing),
        );
    }
}

/// 11. Paging: `page`/`per_page` page over seven releases, `total` stays
/// the whole count, `per_page` clamps to the maximum of 100, and a nonsense
/// value is a 400 problem — never a 500.
#[pollster::test]
async fn paging_is_bounded_and_nonsense_does_not_500() {
    for kit in support::kits() {
        // v1.1.0 (January) through v1.7.0 (July); scripted oldest first.
        let seven: Vec<Value> = (1..=7)
            .map(|month| {
                release(
                    &format!("v1.{month}.0"),
                    &format!("2026-0{month}-01T00:00:00Z"),
                    "paged",
                )
            })
            .collect();
        kit.fake.script_releases(&seven);
        let report = refresh(&kit).await;
        assert_eq!(report["inserted"], 7, "{report}");

        let page = get(&kit, "/v1/changelog?per_page=3&page=2").await;
        assert_eq!(page.status, StatusCode::OK);
        let json = page.json();
        assert_eq!(json["page"], 2);
        assert_eq!(json["per_page"], 3);
        assert_eq!(json["total"], 7, "total is the whole set, not the page");
        assert_eq!(versions(&json), ["v1.4.0", "v1.3.0", "v1.2.0"]);

        let last = get(&kit, "/v1/changelog?per_page=3&page=3").await;
        let json = last.json();
        assert_eq!(json["page"], 3);
        assert_eq!(versions(&json), ["v1.1.0"], "the short last page");

        let clamped = get(&kit, "/v1/changelog?per_page=500").await;
        let json = clamped.json();
        assert_eq!(json["per_page"], 100, "per_page clamps to the maximum");
        assert_eq!(json["total"], 7);
        assert_eq!(json["releases"].as_array().map(Vec::len), Some(7));

        let zero = get(&kit, "/v1/changelog?per_page=0").await;
        let json = zero.json();
        assert_eq!(json["per_page"], 1, "per_page clamps up to 1");
        assert_eq!(versions(&json), ["v1.7.0"], "the newest, one to a page");

        let zero_page = get(&kit, "/v1/changelog?page=0").await;
        assert_eq!(zero_page.json()["page"], 1, "page clamps up to 1");

        for nonsense in ["?page=soon", "?per_page=-3"] {
            let refused = get(&kit, &format!("/v1/changelog{nonsense}")).await;
            assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{nonsense}");
            assert!(
                refused.json()["type"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("validation-failed"),
                "{}",
                body_of(&refused),
            );
        }

        // And the route still serves after all of that.
        assert_eq!(get(&kit, "/v1/changelog").await.status, StatusCode::OK);
    }
}

/// 12. `?locale=` and `?style=` are accepted and select nothing: whatever
/// they say, the original text is served and `rendering` reports
/// `style: "original"`, `machine_generated: false` and the configured
/// locale. This is the forward-compatibility contract the later `TextModel`
/// work has to keep — these assertions are the thing it must not break.
#[pollster::test]
async fn locale_and_style_are_accepted_and_select_nothing() {
    for kit in support::kits() {
        kit.fake
            .script_releases(&[release("v1.0.0", "2026-01-01T00:00:00Z", MARKDOWN_BODY)]);
        refresh(&kit).await;

        for query in [
            "",
            "?locale=fr",
            "?style=rewritten",
            "?locale=fr&style=rewritten",
            "?style=",
            "?locale=%22onerror%3D",
        ] {
            let response = get(&kit, &format!("/v1/changelog{query}")).await;
            assert_eq!(response.status, StatusCode::OK, "{query} errored");
            let json = response.json();
            let served = &json["releases"][0];
            assert_eq!(served["body"], MARKDOWN_BODY, "{query} rewrote the text");
            assert_eq!(served["rendering"]["style"], "original", "{query}");
            assert_eq!(served["rendering"]["machine_generated"], false, "{query}");
            assert_eq!(served["rendering"]["locale"], "en", "{query}");
        }
    }

    // The configured locale is what rendering reports; a query's locale
    // changes nothing (nothing does, until the TextModel port exists).
    for kit in kits_with(&[("CHANGELOG_LOCALE", "de-CH")]) {
        kit.fake
            .script_releases(&[release("v1.0.0", "2026-01-01T00:00:00Z", MARKDOWN_BODY)]);
        refresh(&kit).await;
        let json = get(&kit, "/v1/changelog?locale=fr").await.json();
        assert_eq!(json["releases"][0]["rendering"]["locale"], "de-CH");
    }
}

/// 13. The admin guard, with the exact semantics of `require_admin`: no
/// bearer is 401, a wrong token is 403, the right one gets through — and
/// with `ADMIN_TOKEN` unset the route is disabled even for a presented
/// token. A refused request never reaches upstream.
#[pollster::test]
async fn the_admin_refresh_is_guarded() {
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());

        let anonymous = refresh_as(&kit, None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        assert!(
            anonymous.json()["type"]
                .as_str()
                .unwrap_or_default()
                .contains("admin-unauthorized"),
            "{}",
            body_of(&anonymous),
        );
        assert_eq!(kit.fake.requests(), 0, "the guard let a request through");

        let wrong = refresh_as(&kit, Some("deliberately-not-the-token")).await;
        assert_eq!(wrong.status, StatusCode::FORBIDDEN);
        assert!(
            wrong.json()["type"]
                .as_str()
                .unwrap_or_default()
                .contains("admin-forbidden"),
            "{}",
            body_of(&wrong),
        );
        assert_eq!(kit.fake.requests(), 0);

        let report = refresh(&kit).await;
        assert_eq!(report["ok"], true, "{report}");
        assert_eq!(report["inserted"], 3, "{report}");
    }

    // `ADMIN_TOKEN` unset: the route is disabled, not merely wrong — even a
    // correctly spelled token is 401, and nothing refreshes.
    for kit in kits_from(&KitSpec::default().without("ADMIN_TOKEN")) {
        kit.fake.script_releases(&three_stable());
        let refused = refresh_as(&kit, Some(ADMIN)).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        assert_eq!(kit.fake.requests(), 0);
        assert_eq!(
            support::release_count(&kit),
            0,
            "a disabled route must not have refreshed",
        );
    }
}

/// 14. The `CHANGELOG.md` source: the Keep-a-Changelog file sections into
/// releases — headings, dates, bodies, all three heading shapes — and
/// `Unreleased` is skipped as the draft it is.
#[pollster::test]
async fn a_keep_a_changelog_file_sections_into_releases() {
    for kit in kits_with(&[("CHANGELOG_SOURCE", "changelog-md")]) {
        kit.fake.script_changelog_md(CHANGELOG_MD);
        let report = refresh(&kit).await;
        assert_eq!(report["fetched"], 3, "{report}");
        assert_eq!(
            report["skipped"], 1,
            "Unreleased is not a release: {report}"
        );
        assert_eq!(report["inserted"], 3, "{report}");

        let json = get(&kit, "/v1/changelog").await.json();
        assert_eq!(json["source"]["kind"], "changelog-md");
        assert_eq!(versions(&json), ["1.2.0", "1.1.0", "v1.0.0"]);
        let served = json["releases"].as_array().expect("releases");
        let titles: Vec<&str> = served
            .iter()
            .map(|release| release["title"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            titles,
            ["1.2.0", "1.1.0", "v1.0.0"],
            "a version titles itself"
        );
        let dates: Vec<&str> = served
            .iter()
            .map(|release| release["published_at"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            dates,
            ["2024-05-06T00:00:00Z", "2024-01-15T00:00:00Z", ""],
            "a section's date is midnight UTC; a heading without one sorts last",
        );
        assert!(
            served[2]["published_at"].is_null(),
            "no date stays null in the response"
        );
        assert_eq!(
            served[0]["body"], CHANGELOG_MD_120_BODY,
            "the markdown, intact"
        );
        assert_eq!(served[1]["body"], "- the earlier thing");
        assert_eq!(served[2]["body"], "- where it started");
        for release in served {
            assert!(
                !release["body"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("workbench"),
                "Unreleased content leaked into a release: {release}",
            );
        }

        let one = get(&kit, "/v1/changelog/1.2.0").await;
        assert_eq!(one.status, StatusCode::OK);
        assert_eq!(one.json()["body"], CHANGELOG_MD_120_BODY);
    }
}

/// 15. The `KeyValue` read cache is opportunistic and never wrong: two
/// identical GETs answer with identical bytes, and a refresh that adds a
/// release is visible on the very next GET — the generation bump, not a
/// TTL (the memory KV expires nothing, so if the bump were broken these
/// bytes would be the old ones forever). With no `KeyValue` port composed
/// at all, everything still works.
#[pollster::test]
async fn the_kv_cache_is_opportunistic_and_never_stale_after_a_refresh() {
    let first_upstream = || vec![release("v1.0.0", "2026-01-01T00:00:00Z", "the first")];
    let both_upstream = || {
        vec![
            release("v1.0.0", "2026-01-01T00:00:00Z", "the first"),
            release("v1.1.0", "2026-02-01T00:00:00Z", "the second"),
        ]
    };

    for kit in support::kits() {
        assert!(kit.kv.is_some(), "the stock kit composes the read cache");
        kit.fake.script_releases(&first_upstream());
        refresh(&kit).await;

        let first = get(&kit, "/v1/changelog").await;
        let second = get(&kit, "/v1/changelog").await;
        assert_eq!(first.status, StatusCode::OK);
        assert_eq!(
            first.body(),
            second.body(),
            "the two reads answered different bytes"
        );

        kit.fake.script_releases(&both_upstream());
        let report = refresh(&kit).await;
        assert_eq!(report["inserted"], 1, "{report}");

        let third = get(&kit, "/v1/changelog").await;
        assert_eq!(
            third.json()["total"],
            2,
            "the added release is not visible immediately after the refresh",
        );
        assert_ne!(
            third.body(),
            first.body(),
            "the cached bytes were served past the refresh"
        );
    }

    // No KeyValue port composed at all: the reads are the database, and
    // nothing else in this suite's behaviour changes.
    for kit in kits_from(&KitSpec::default().without_kv()) {
        assert!(kit.kv.is_none());
        kit.fake.script_releases(&first_upstream());
        refresh(&kit).await;
        let list = get(&kit, "/v1/changelog").await;
        assert_eq!(list.status, StatusCode::OK);
        assert_eq!(list.json()["total"], 1);
        let one = get(&kit, "/v1/changelog/v1.0.0").await;
        assert_eq!(one.status, StatusCode::OK);

        kit.fake.script_releases(&both_upstream());
        refresh(&kit).await;
        assert_eq!(get(&kit, "/v1/changelog").await.json()["total"], 2);
    }
}

/// 16. Configuration wins over the composed builder: a module composed with
/// `.locale("fr")` and `.include_drafts(false)` still obeys
/// `CHANGELOG_LOCALE` and `CHANGELOG_INCLUDE_DRAFTS` when the keys are set.
#[pollster::test]
async fn configuration_wins_over_the_composed_builder() {
    for kit in kits_from(
        &KitSpec::default()
            .module(|| Changelog::new().locale("fr").include_drafts(false))
            .config("CHANGELOG_LOCALE", "de")
            .config("CHANGELOG_INCLUDE_DRAFTS", "true"),
    ) {
        kit.fake.script_releases(&[
            release("v1.0.0", "2026-01-01T00:00:00Z", "the first"),
            support::draft("v0.9.0-draft", "2026-07-01T08:00:00Z"),
        ]);
        refresh(&kit).await;

        let json = get(&kit, "/v1/changelog").await.json();
        assert_eq!(
            json["releases"][0]["rendering"]["locale"], "de",
            "the builder's locale beat the configuration",
        );
        assert_eq!(
            json["total"], 2,
            "the builder's include_drafts beat the configuration",
        );
        assert!(
            versions(&json).contains(&"v0.9.0-draft"),
            "the draft the builder excluded is mirrored: {json}",
        );
    }
}

/// 17. The page cap: a walk that exhausts its five pages has seen a
/// **prefix** of upstream's list, and a prefix cannot say what upstream
/// deleted. So nothing is pruned, the report says `complete: false`, and the
/// pages that did arrive still insert and update. The next complete walk
/// repairs the mirror, which is where pruning still happens — pinned against
/// `complete` here as in test 9.
#[pollster::test]
async fn a_walk_that_hits_the_page_cap_prunes_nothing_and_says_so() {
    for kit in support::kits() {
        kit.fake.script_releases(&three_stable());
        refresh(&kit).await;
        assert_eq!(support::release_count(&kit), 3);
        let stored = updated_at_by_version(&kit);

        // Upstream now holds five full pages — 500 releases, exactly the
        // cap. Two of the stored three are in it (v1.2.0 with a rewritten
        // body, v1.1.0 untouched); v1.0.0 is nowhere, which is precisely
        // why the cap must not prune.
        let mut pages: Vec<Vec<Value>> = (1..=5).map(|page| filler_page(page, 100)).collect();
        pages[0][0] = release("v1.2.0", "2026-06-01T10:00:00Z", "rewritten past the cap");
        pages[0][1] = release("v1.1.0", "2026-03-15T09:30:00Z", "- the earlier thing");
        let page_slices: Vec<&[Value]> = pages.iter().map(Vec::as_slice).collect();
        // The single-page etag the first refresh stored is now stale.
        let stale_etag = kit.fake.releases_etag();
        kit.fake.script_release_pages(&page_slices);
        kit.fake.forget_calls();
        kit.clock.advance_secs(120);

        let report = refresh(&kit).await;
        assert_eq!(report["fetched"], 500, "{report}");
        assert_eq!(report["inserted"], 498, "{report}");
        assert_eq!(report["updated"], 1, "{report}");
        assert_eq!(report["unchanged"], 1, "{report}");
        assert_eq!(
            report["removed"], 0,
            "a capped walk took a stored row with it: {report}",
        );
        assert_eq!(report["complete"], false, "{report}");

        // The walk ran to the cap and stopped there: five pages, no sixth
        // (the fake has none scripted and would panic), the stale etag
        // presented once on page 1 and nothing conditional after it.
        let calls = kit.fake.calls();
        assert_eq!(calls.len(), 5, "{calls:?}");
        assert_eq!(calls[0].if_none_match.as_deref(), Some(stale_etag.as_str()));
        assert!(
            calls[1..].iter().all(|call| call.if_none_match.is_none()),
            "{calls:?}",
        );
        assert_eq!(
            support::source_field(&kit, "etag").as_deref(),
            Some(""),
            "a capped walk left an etag stored",
        );

        // The prefix's writes landed, and the stored row upstream dropped
        // is still there.
        let kept = get(&kit, "/v1/changelog/v1.0.0").await;
        assert_eq!(kept.status, StatusCode::OK, "the cap took a stored row");
        assert_eq!(kept.json()["body"], "- where it started");
        let edited = get(&kit, "/v1/changelog/v1.2.0").await;
        assert_eq!(edited.json()["body"], "rewritten past the cap");
        let from_page_five = get(&kit, "/v1/changelog/v5.0.99").await;
        assert_eq!(
            from_page_five.status,
            StatusCode::OK,
            "a page-5 insert did not land",
        );
        assert_eq!(support::release_count(&kit), 501);
        // The untouched release kept its stamp; only the rewritten one moved.
        let stamps = updated_at_by_version(&kit);
        assert_eq!(
            stamps.get("v1.1.0"),
            stored.get("v1.1.0"),
            "a capped refresh rewrote a row it did not have to",
        );
        assert_ne!(stamps.get("v1.2.0"), stored.get("v1.2.0"));

        // The next walk that sees the end of the list repairs the mirror:
        // everything but the two releases it names is pruned.
        kit.fake
            .script_releases(&[pages[0][0].clone(), pages[0][1].clone()]);
        kit.clock.advance_secs(120);
        let repaired = refresh(&kit).await;
        assert_eq!(repaired["complete"], true, "{repaired}");
        assert_eq!(repaired["removed"], 499, "{repaired}");
        assert_eq!(support::release_count(&kit), 2);
        assert_eq!(
            versions(&get(&kit, "/v1/changelog").await.json()),
            ["v1.2.0", "v1.1.0"],
        );
    }
}

/// 18. The etag is one page's etag, so it is stored — and sent — only when
/// the whole list fit that one page. A repository of two pages takes an edit
/// on page 2 while page 1 stays byte-identical, and that edit must be
/// mirrored, not `304`'d away forever. Once the list fits one page again the
/// shortcut is re-armed and a `304` ends the refresh before it starts.
#[pollster::test]
async fn an_edit_on_page_2_is_not_304d_away_by_page_1s_etag() {
    const PAGE_ONE_ETAG: &str = "\"multi-page-1\"";
    const PAGE_TWO_ETAG: &str = "\"multi-page-2\"";

    for kit in support::kits() {
        // Two pages: 100 on page 1 and one on page 2 — a complete walk that
        // does not fit one page, so nothing may be stored as the etag.
        let mut page_one = filler_page(1, 100);
        page_one[0] = release("v1.2.0", "2026-06-01T10:00:00Z", MARKDOWN_BODY);
        let page_two = [release(
            "v1.1.0",
            "2026-03-15T09:30:00Z",
            "- the earlier thing",
        )];
        kit.fake.script_release_pages_with_etags(&[
            (PAGE_ONE_ETAG, page_one.as_slice()),
            (PAGE_TWO_ETAG, page_two.as_slice()),
        ]);

        let first = refresh(&kit).await;
        assert_eq!(first["complete"], true, "{first}");
        assert_eq!(
            support::source_field(&kit, "etag").as_deref(),
            Some(""),
            "a two-page walk stored page 1's etag for the whole list",
        );

        // An edit lands on page 2; page 1 — and its etag — do not move.
        let edited = [release(
            "v1.1.0",
            "2026-03-15T09:30:00Z",
            "### Changed\n\n- rewritten on page 2",
        )];
        kit.fake.script_release_pages_with_etags(&[
            (PAGE_ONE_ETAG, page_one.as_slice()),
            (PAGE_TWO_ETAG, edited.as_slice()),
        ]);
        kit.clock.advance_secs(120);

        let report = refresh(&kit).await;
        assert_eq!(
            report["not_modified"], false,
            "page 1's etag short-circuited a page-2 edit: {report}",
        );
        assert_eq!(report["updated"], 1, "{report}");
        let one = get(&kit, "/v1/changelog/v1.1.0").await;
        assert_eq!(
            one.json()["body"],
            "### Changed\n\n- rewritten on page 2",
            "the page-2 edit never reached the mirror",
        );
        // And no conditional request went out: a multi-page walk holds no
        // etag to present.
        assert!(
            kit.fake
                .calls()
                .iter()
                .all(|call| call.if_none_match.is_none()),
            "{:?}",
            kit.fake.calls(),
        );

        // The list fits one page again: the next full fetch stores that
        // page's etag ...
        kit.fake
            .script_release_pages_with_etags(&[(PAGE_ONE_ETAG, edited.as_slice())]);
        kit.clock.advance_secs(120);
        let full = refresh(&kit).await;
        assert_eq!(full["not_modified"], false, "{full}");
        assert_eq!(full["unchanged"], 1, "{full}");
        assert_eq!(
            support::source_field(&kit, "etag").as_deref(),
            Some(PAGE_ONE_ETAG),
        );

        // ... and the refresh after it is a 304 again, as the small-repo
        // shortcut is meant to work.
        kit.clock.advance_secs(120);
        let shortcut = refresh(&kit).await;
        assert_eq!(shortcut["not_modified"], true, "{shortcut}");
        assert_eq!(shortcut["complete"], true, "{shortcut}");
        let calls = kit.fake.calls();
        let last = calls.last().expect("the 304 was requested");
        assert_eq!(last.if_none_match.as_deref(), Some(PAGE_ONE_ETAG));
    }
}

/// 19. The read cache keys a hash of the **whole** fingerprint, never a
/// prefix of it. The single-release fingerprint is `release:{version}`
/// (handlers.rs) and the historical key was its first 200 bytes: these
/// versions are 231 bytes each, so their fingerprints — 239 bytes — agree
/// through byte 235 and differ only past the old cut, which would have
/// filed both under one key and served the first release for the second
/// with a confident 200.
#[pollster::test]
async fn two_versions_that_share_a_long_prefix_do_not_share_a_cache_entry() {
    // 231 bytes each; the first 227 are identical, so the fingerprints
    // agree through byte 235 — past the 200-byte prefix the old key cut
    // at, which is the only reason this test can catch a revert.
    let shared = "a".repeat(220);
    let version_a = format!("v2.0.0-{shared}aaaa");
    let version_b = format!("v2.0.0-{shared}bbbb");
    let body_a = "the body of the a-tailed tag";
    let body_b = "the body of the b-tailed tag";

    for kit in support::kits() {
        assert!(kit.kv.is_some(), "the stock kit wires the read cache");
        kit.fake.script_releases(&[
            release(&version_a, "2026-01-01T00:00:00Z", body_a),
            release(&version_b, "2026-01-02T00:00:00Z", body_b),
        ]);
        refresh(&kit).await;

        let a = get(&kit, &format!("/v1/changelog/{version_a}")).await;
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(a.json()["body"], body_a);
        let b = get(&kit, &format!("/v1/changelog/{version_b}")).await;
        assert_eq!(b.status, StatusCode::OK);
        assert_eq!(
            b.json()["body"],
            body_b,
            "the second release was served the first release's body",
        );
        assert_ne!(a.body(), b.body());

        // Both fingerprints are now cached hits — and each hit is still its
        // own release.
        let a_again = get(&kit, &format!("/v1/changelog/{version_a}")).await;
        assert_eq!(a_again.body(), a.body(), "the cache mixed the two entries");
        let b_again = get(&kit, &format!("/v1/changelog/{version_b}")).await;
        assert_eq!(b_again.body(), b.body(), "the cache mixed the two entries");
    }
}

/// 20. An empty or blank release title is not a title: the release is served
/// under its tag, the way a missing `name` already is.
#[pollster::test]
async fn an_empty_release_title_falls_back_to_the_tag() {
    for kit in support::kits() {
        let mut unnamed = release("v1.0.0", "2026-01-01T00:00:00Z", "the first");
        unnamed["name"] = json!("");
        let mut blank = release("v1.1.0", "2026-02-01T00:00:00Z", "the second");
        blank["name"] = json!("   ");
        kit.fake.script_releases(&[unnamed, blank]);

        let report = refresh(&kit).await;
        assert_eq!(report["inserted"], 2, "{report}");

        let json = get(&kit, "/v1/changelog").await.json();
        let titles: Vec<&str> = json["releases"]
            .as_array()
            .expect("releases is an array")
            .iter()
            .map(|one| one["title"].as_str().expect("a title"))
            .collect();
        assert_eq!(
            titles,
            ["v1.1.0", "v1.0.0"],
            "an empty or blank name left the release untitled",
        );
    }
}
