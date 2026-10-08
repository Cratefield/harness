//! Checks a post's commentary against the text it was written from.
//!
//! An agent drafts a post from release notes or an announcement; before the
//! post is created, scheduled or edited, the caller can send that `source`
//! along and the module checks the commentary kept every protected fact of
//! it — names, numbers, quotes, code, links, hashtags, and LinkedIn's own
//! mention and hashtag templates — with `cratefield-text-guard`, and made up
//! no number. A failed check is a `422` that names every missing span and
//! every introduced number; a passing one comes back with the locks and a
//! word diff (`cratefield-text-diff`) for a reviewer.
//!
//! The source is checked and dropped: it is never stored.

use cratefield_core::{Problem, ProblemDef};
use cratefield_text_diff::diff_words_locked;
use cratefield_text_guard::{Guard, Span, ViolationKind};
use http::StatusCode;
use serde_json::{Value, json};

pub(crate) const FACT_CHECK_FAILED: ProblemDef = ProblemDef {
    slug: "linkedin-fact-check-failed",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    title: "The commentary does not keep the facts of its source",
    description: "A protected span of the source (name, number, quote, code, link, hashtag or mention) is missing or altered in the commentary, or the commentary introduced a number. `missing` and `introduced` list each one.",
};

fn span_json(span: &Span) -> Value {
    json!({ "kind": span.kind_name(), "text": span.text })
}

/// Checks `commentary` (as it will be sent: `little`, escaped or not)
/// against `source`. Both are read as a person sees the post
/// ([`crate::little::for_check`]).
///
/// # Errors
///
/// A [`FACT_CHECK_FAILED`] problem whose `missing` and `introduced`
/// extension members list every violation as `{kind, text}`.
pub(crate) fn check(source: &str, commentary: &str) -> Result<Value, Problem> {
    let (source_text, source_locks) = crate::little::for_check(source);
    let (post_text, post_locks) = crate::little::for_check(commentary);
    let guard = Guard::new();

    if let Err(violations) = guard.verify_with(&source_text, &source_locks, &post_text, &post_locks)
    {
        let list = |kind: ViolationKind| -> Vec<Value> {
            violations
                .iter()
                .filter(|violation| violation.kind == kind)
                .map(|violation| span_json(&violation.span))
                .collect()
        };
        let missing = list(ViolationKind::Missing);
        let introduced = list(ViolationKind::Introduced);
        return Err(Problem::new(&FACT_CHECK_FAILED)
            .with_detail(format!(
                "the commentary dropped or altered {} protected span(s) of the source and \
                 introduced {} number(s); nothing was created, scheduled or edited",
                missing.len(),
                introduced.len()
            ))
            .with_extension("missing", missing)
            .with_extension("introduced", introduced));
    }

    let source_spans = guard.extract_with(&source_text, &source_locks);
    let diff = diff_words_locked(
        &source_text,
        &post_text,
        &source_spans.iter().map(Span::range).collect::<Vec<_>>(),
        &guard.ranges_with(&post_text, &post_locks),
    );
    Ok(json!({
        "ok": true,
        "locks": source_spans.iter().map(span_json).collect::<Vec<_>>(),
        "diff": diff,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_mention_and_an_escaped_link_pass() {
        let source = "Version 2.4 is out: https://example.com/notes/v2_4 thanks to \
                      @[Acme](urn:li:organization:123) #launch";
        let commentary = crate::little::escape("Out now, version 2.4 ")
            + "@[Acme](urn:li:organization:123)"
            + &crate::little::escape(" helped. https://example.com/notes/v2_4 ")
            + &crate::little::hashtag("launch");
        let checked = check(source, &commentary).expect("passes");
        assert_eq!(checked["ok"], true);
        let kinds: Vec<_> = checked["locks"]
            .as_array()
            .expect("locks")
            .iter()
            .map(|lock| lock["kind"].as_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(kinds, ["number", "url", "mention", "hashtag"]);
    }

    #[test]
    fn a_changed_urn_is_a_missing_mention_not_a_new_number() {
        let error = check(
            "Thanks @[Acme](urn:li:organization:123)",
            "Thanks @[Acme](urn:li:organization:124)",
        )
        .expect_err("fails");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn the_readme_example_passes() {
        let checked = check(
            "Release 2.4 ships today: cold starts down 38%, with \
             @[DevTestCo](urn:li:organization:2414183). Notes: \
             https://example.com/releases/v2_4 #launch",
            "Cold starts are down 38% in release 2.4, thanks to \
             @[DevTestCo](urn:li:organization:2414183). \
             https://example.com/releases/v2\\_4 {hashtag|\\#|launch}",
        );
        assert!(checked.is_ok(), "{checked:?}");
    }
}
