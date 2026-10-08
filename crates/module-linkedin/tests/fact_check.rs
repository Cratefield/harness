//! The optional fact check: commentary checked against its `source` before
//! a post is created, scheduled or edited. Without `source` nothing about
//! a create or an edit changes.

mod support;

use axum::http::StatusCode;
use serde_json::{Value, json};
use support::{ORG, connect, get, patch_json, post_json};

const SOURCE: &str = "Release 2.4 ships today. Dana Okafor's team cut cold starts by 38%. \
Notes: https://example.com/releases/v2_4 #launch";

async fn ready_kit() -> support::Kit {
    let kit = support::kit();
    connect(&kit).await;
    let synced = post_json(&kit, "/v1/linkedin/admin/pages/sync", "{}").await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text());
    kit
}

fn posts_path() -> String {
    format!("/v1/linkedin/admin/pages/{ORG}/posts")
}

async fn create(kit: &support::Kit, body: Value) -> support::Res {
    post_json(kit, &posts_path(), &body.to_string()).await
}

fn keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<_> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

fn kinds_and_texts(list: &Value) -> Vec<(String, String)> {
    list.as_array()
        .expect("a list")
        .iter()
        .map(|item| {
            (
                item["kind"].as_str().expect("kind").to_owned(),
                item["text"].as_str().expect("text").to_owned(),
            )
        })
        .collect()
}

#[test]
fn without_source_a_create_and_an_edit_answer_as_before() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let created = create(
            &kit,
            json!({"commentary": "Up 18% (or 19%?)", "idempotency_key": "k1"}),
        )
        .await;
        assert_eq!(created.status, StatusCode::ACCEPTED, "{}", created.text());
        // No fact check ran, so there is no trace of one.
        assert_eq!(keys(&created.json()), ["duplicate", "post"]);

        let id = created.json()["post"]["id"]
            .as_str()
            .expect("id")
            .to_owned();
        let edited = patch_json(
            &kit,
            &format!("/v1/linkedin/admin/posts/{id}"),
            r#"{"commentary":"Up 20%"}"#,
        )
        .await;
        assert_eq!(edited.status, StatusCode::OK, "{}", edited.text());
        assert_eq!(keys(&edited.json()), ["post", "sent_to_linkedin"]);

        // The stored row is what it always was: no source column, no check.
        let listed = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(listed["posts"][0]["commentary"], "Up 20%");
        assert!(listed["posts"][0].get("source").is_none());
    });
}

#[test]
fn a_commentary_that_changes_a_fact_is_refused_and_nothing_is_stored() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let refused = create(
            &kit,
            json!({
                "commentary": "Release 2.4 is here: Dana Okafor's team cut cold starts by 40%. \
                               Notes: https://example.com/releases/v2_4 #launch",
                "source": SOURCE,
                "idempotency_key": "k1",
            }),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            refused.text()
        );
        let problem = refused.json();
        assert!(
            problem["type"]
                .as_str()
                .unwrap_or_default()
                .ends_with("linkedin-fact-check-failed"),
            "{problem}"
        );
        assert_eq!(
            kinds_and_texts(&problem["missing"]),
            [("number".to_owned(), "38%".to_owned())]
        );
        assert_eq!(
            kinds_and_texts(&problem["introduced"]),
            [("number".to_owned(), "40%".to_owned())]
        );

        kit.drain().await;
        assert_eq!(support::count(&kit, "linkedin_posts", "1=1"), 0);
        assert_eq!(kit.fake.created_posts(), 0);
    });
}

#[test]
fn a_faithful_commentary_is_created_with_its_locks_and_diff() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        // Little format with a hashtag template: the plain `#launch` of the
        // source and the template read the same, and the escaped `_` in the
        // link reads as the link.
        let commentary = "Dana Okafor's team cut cold starts by 38% in release 2.4. \
                          https://example.com/releases/v2\\_4 {hashtag|\\#|launch}";
        let created = create(
            &kit,
            json!({
                "commentary": commentary,
                "commentary_format": "little",
                "source": SOURCE,
                "idempotency_key": "k1",
            }),
        )
        .await;
        assert_eq!(created.status, StatusCode::ACCEPTED, "{}", created.text());
        let body = created.json();
        assert_eq!(keys(&body), ["duplicate", "fact_check", "post"]);

        let check = &body["fact_check"];
        assert_eq!(check["ok"], true);
        assert_eq!(
            kinds_and_texts(&check["locks"]),
            [
                ("number".to_owned(), "2.4".to_owned()),
                ("name".to_owned(), "Dana Okafor".to_owned()),
                ("number".to_owned(), "38%".to_owned()),
                (
                    "url".to_owned(),
                    "https://example.com/releases/v2_4".to_owned()
                ),
                ("hashtag".to_owned(), "#launch".to_owned()),
            ]
        );
        let diff = check["diff"].as_array().expect("diff");
        let ops: Vec<_> = diff
            .iter()
            .map(|segment| segment["op"].as_str().expect("op"))
            .collect();
        for op in ["locked", "removed", "added"] {
            assert!(ops.contains(&op), "{op} missing from {diff:?}");
        }
        // The segments that are not removed rebuild the commentary as a
        // person reads it.
        let rebuilt: String = diff
            .iter()
            .filter(|segment| segment["op"] != "removed")
            .map(|segment| segment["text"].as_str().expect("text"))
            .collect();
        assert_eq!(
            rebuilt,
            "Dana Okafor's team cut cold starts by 38% in release 2.4. \
             https://example.com/releases/v2_4 #launch"
        );

        // The post itself is the commentary as sent, and the source is not
        // stored anywhere.
        kit.drain().await;
        assert_eq!(kit.fake.created_posts(), 1);
        assert_eq!(kit.fake.post_commentaries(), [commentary]);
        assert_eq!(
            support::count(
                &kit,
                "linkedin_posts",
                "commentary LIKE '%Release 2.4 ships today%' \
                 OR previous_commentary LIKE '%Release 2.4 ships today%'"
            ),
            0
        );

        // A retry with the same key is still checked and answers the first row.
        let again = create(
            &kit,
            json!({
                "commentary": commentary,
                "commentary_format": "little",
                "source": SOURCE,
                "idempotency_key": "k1",
            }),
        )
        .await;
        assert_eq!(again.json()["duplicate"], true);
        assert_eq!(again.json()["fact_check"]["ok"], true);
    });
}

#[test]
fn mentions_and_hashtag_templates_survive_a_rewrite() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let source = "Big thanks to @[DevTestCo](urn:li:organization:2414183) for the \
                      {hashtag|\\#|launch}.";
        let created = create(
            &kit,
            json!({
                "commentary": "{hashtag|\\#|launch} done, with thanks to \
                               @[DevTestCo](urn:li:organization:2414183)\\!",
                "commentary_format": "little",
                "source": source,
                "idempotency_key": "k1",
            }),
        )
        .await;
        assert_eq!(created.status, StatusCode::ACCEPTED, "{}", created.text());
        assert_eq!(
            kinds_and_texts(&created.json()["fact_check"]["locks"]),
            [
                (
                    "mention".to_owned(),
                    "@[DevTestCo](urn:li:organization:2414183)".to_owned()
                ),
                ("hashtag".to_owned(), "#launch".to_owned()),
            ]
        );
        // The mention is one locked segment of the diff, never split.
        let diff = created.json()["fact_check"]["diff"].clone();
        assert!(
            diff.as_array().expect("diff").iter().any(|segment| {
                segment["op"] == "locked"
                    && segment["text"].as_str().is_some_and(|text| {
                        text.starts_with("@[DevTestCo](urn:li:organization:2414183)")
                    })
            }),
            "{diff}"
        );
    });
}

#[test]
fn a_mangled_mention_is_refused() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let source = "Thanks @[DevTestCo](urn:li:organization:2414183)";
        for (commentary, why) in [
            (
                "Thanks @[DevTestCo](urn:li:organization:2414184)",
                "another urn",
            ),
            (
                "Thanks @[DevTest Co](urn:li:organization:2414183)",
                "renamed",
            ),
            ("Thanks DevTestCo", "flattened to text"),
            (
                "Thanks \\@\\[DevTestCo\\]\\(urn:li:organization:2414183\\)",
                "escaped, so no longer a mention",
            ),
        ] {
            let refused = create(
                &kit,
                json!({
                    "commentary": commentary,
                    "commentary_format": "little",
                    "source": source,
                    "idempotency_key": "k1",
                }),
            )
            .await;
            assert_eq!(
                refused.status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{why}: {}",
                refused.text()
            );
            let problem = refused.json();
            assert_eq!(
                kinds_and_texts(&problem["missing"]),
                [(
                    "mention".to_owned(),
                    "@[DevTestCo](urn:li:organization:2414183)".to_owned()
                )],
                "{why}"
            );
            // The digits of a URN are never an introduced number.
            assert_eq!(problem["introduced"], json!([]), "{why}");
        }
        assert_eq!(support::count(&kit, "linkedin_posts", "1=1"), 0);
    });
}

#[test]
fn an_edit_with_a_source_is_checked_before_linkedin_is_called() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let created = create(
            &kit,
            json!({"commentary": "Cold starts down 38%", "idempotency_key": "k1"}),
        )
        .await;
        kit.drain().await;
        let id = created.json()["post"]["id"]
            .as_str()
            .expect("id")
            .to_owned();
        let path = format!("/v1/linkedin/admin/posts/{id}");
        let partial_updates = |kit: &support::Kit| {
            kit.fake
                .calls()
                .into_iter()
                .filter(|call| call.header("x-restli-method") == Some("PARTIAL_UPDATE"))
                .count()
        };

        let refused = patch_json(
            &kit,
            &path,
            &json!({"commentary": "Cold starts down 83%", "source": SOURCE}).to_string(),
        )
        .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(partial_updates(&kit), 0);
        let listed = get(&kit, "/v1/linkedin/admin/posts").await.json();
        assert_eq!(listed["posts"][0]["commentary"], "Cold starts down 38%");

        let edited = patch_json(
            &kit,
            &path,
            &json!({
                "commentary": "Release 2.4: Dana Okafor's team cut cold starts by 38%. \
                               https://example.com/releases/v2_4 #launch",
                "source": SOURCE,
            })
            .to_string(),
        )
        .await;
        assert_eq!(edited.status, StatusCode::OK, "{}", edited.text());
        assert_eq!(
            keys(&edited.json()),
            ["fact_check", "post", "sent_to_linkedin"]
        );
        assert_eq!(edited.json()["fact_check"]["ok"], true);
        assert_eq!(partial_updates(&kit), 1);
        // `source` is the check's input, never part of LinkedIn's patch.
        let update = kit
            .fake
            .calls()
            .into_iter()
            .find(|call| call.header("x-restli-method") == Some("PARTIAL_UPDATE"))
            .expect("a partial update");
        assert_eq!(keys(&update.json()["patch"]["$set"]), ["commentary"]);
    });
}

#[test]
fn a_source_needs_commentary_and_must_be_text() {
    pollster::block_on(async {
        let kit = ready_kit().await;
        let created = create(&kit, json!({"commentary": "x", "idempotency_key": "k1"})).await;
        let id = created.json()["post"]["id"]
            .as_str()
            .expect("id")
            .to_owned();
        let path = format!("/v1/linkedin/admin/posts/{id}");
        for (body, why) in [
            (json!({"source": SOURCE}), "no commentary"),
            (
                json!({"source": SOURCE, "content_call_to_action_label": "LEARN_MORE"}),
                "no commentary beside another field",
            ),
            (json!({"commentary": "x", "source": 7}), "not a string"),
            (json!({"commentary": "x", "source": "  "}), "empty"),
        ] {
            let refused = patch_json(&kit, &path, &body.to_string()).await;
            assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{why}");
        }
        let empty = create(
            &kit,
            json!({"commentary": "x", "source": "", "idempotency_key": "k2"}),
        )
        .await;
        assert_eq!(empty.status, StatusCode::BAD_REQUEST);
    });
}
