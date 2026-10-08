use super::*;

fn found(text: &str) -> Vec<(SpanKind, String)> {
    extract(text)
        .into_iter()
        .map(|s| (s.kind, s.text))
        .collect()
}

fn of_kind(text: &str, kind: SpanKind) -> Vec<String> {
    extract(text)
        .into_iter()
        .filter(|s| s.kind == kind)
        .map(|s| s.text)
        .collect()
}

/// The example paragraph on ghostwrit.in: five locked facts.
const SITE: &str = "In today's fast-paced digital landscape, it is important to note that our Q3 \
revenue grew by 18% to $4.2M. Furthermore, Dana Okafor stated that put it simply: \
“we doubled down on retention,” which ultimately serves as a testament to the team’s dedication.";

#[test]
fn the_site_example_locks_five_facts() {
    assert_eq!(
        found(SITE),
        [
            (SpanKind::Number, "Q3".to_owned()),
            (SpanKind::Number, "18%".to_owned()),
            (SpanKind::Number, "$4.2M".to_owned()),
            (SpanKind::Name, "Dana Okafor".to_owned()),
            (
                SpanKind::Quote,
                "“we doubled down on retention,”".to_owned()
            ),
        ]
    );
}

#[test]
fn the_site_rewrite_keeps_all_five() {
    let rewrite = "Q3 revenue grew 18% to $4.2M. Dana Okafor put it simply: \
        \"we doubled down on retention.\" The team earned it.";
    assert_eq!(verify(SITE, rewrite), Ok(()));
}

#[test]
fn spans_index_their_text() {
    for span in extract(SITE) {
        assert_eq!(&SITE[span.range()], span.text);
    }
}

#[test]
fn a_changed_figure_is_missing_and_introduced() {
    let rewrite = "Q3 revenue grew 19% to $4.2M. Dana Okafor: “we doubled down on retention”.";
    let violations = verify(SITE, rewrite).unwrap_err();
    let summary: Vec<_> = violations
        .iter()
        .map(|v| (v.kind, v.span.text.as_str()))
        .collect();
    assert_eq!(
        summary,
        [
            (ViolationKind::Missing, "18%"),
            (ViolationKind::Introduced, "19%")
        ]
    );
    // Missing spans are located in the original, introduced ones in the rewrite.
    assert_eq!(&SITE[violations[0].span.range()], "18%");
    assert_eq!(&rewrite[violations[1].span.range()], "19%");
}

#[test]
fn a_dropped_name_and_quote_are_missing() {
    let rewrite = "Q3 revenue grew 18% to $4.2M. The CEO said retention mattered.";
    let violations = verify(SITE, rewrite).unwrap_err();
    let kinds: Vec<_> = violations.iter().map(|v| v.span.kind).collect();
    assert_eq!(kinds, [SpanKind::Name, SpanKind::Quote]);
    assert!(violations.iter().all(|v| v.kind == ViolationKind::Missing));
}

#[test]
fn an_edited_quote_is_missing() {
    let rewrite =
        "Q3 revenue grew 18% to $4.2M. Dana Okafor said “we really doubled down on retention”.";
    let violations = verify(SITE, rewrite).unwrap_err();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].span.kind, SpanKind::Quote);
    assert_eq!(
        violations[0].span.protected(),
        "we doubled down on retention"
    );
}

#[test]
fn numbers() {
    assert_eq!(
        of_kind(
            "Up 18% to $4.2M in Q3 and FY2024, 1,250 users on 2026-10-08 at 10:30, 3rd time, 10x, \
             €5 and £12.50, GPT-4 and 2.5‰.",
            SpanKind::Number
        ),
        [
            "18%",
            "$4.2M",
            "Q3",
            "FY2024",
            "1,250",
            "2026-10-08",
            "10:30",
            "3rd",
            "10x",
            "€5",
            "£12.50",
            "GPT-4",
            "2.5‰"
        ]
    );
}

#[test]
fn a_full_stop_or_comma_after_a_number_is_not_part_of_it() {
    assert_eq!(
        of_kind("It cost 40. Then 12, then 7.", SpanKind::Number),
        ["40", "12", "7"]
    );
}

#[test]
fn numbers_inside_words_are_not_numbers() {
    assert!(of_kind("abc123 and COVIDXX19 and x2", SpanKind::Number).is_empty());
}

#[test]
fn a_number_is_not_found_inside_a_longer_one() {
    assert!(verify("Growth was 18%.", "Growth was 118%.").is_err());
    assert!(verify("It was 4.2 metres.", "It was 14.2 metres.").is_err());
    assert!(verify("It was 4.2 metres.", "It was 4.25 metres.").is_err());
    assert!(verify("It was 4.2 metres.", "Exactly 4.2, in metres.").is_ok());
}

#[test]
fn names() {
    assert_eq!(
        of_kind(
            "Dana Okafor met Jean-Luc Picard at the Bank of America. Ludwig van Beethoven \
             wrote it; Mary O'Brien's team agreed.",
            SpanKind::Name
        ),
        [
            "Dana Okafor",
            "Jean-Luc Picard",
            "Bank of America",
            "Ludwig van Beethoven",
            "Mary O'Brien"
        ]
    );
}

#[test]
fn a_sentence_start_is_not_a_name() {
    assert!(
        of_kind(
            "The team shipped. However the board waited.",
            SpanKind::Name
        )
        .is_empty()
    );
    assert_eq!(
        of_kind(
            "The Hague is a city. In New York it rained.",
            SpanKind::Name
        ),
        ["New York"]
    );
}

#[test]
fn a_single_capitalised_word_is_not_a_name() {
    assert!(of_kind("Ask her about Dana.", SpanKind::Name).is_empty());
    // The documented flip side: a capitalised verb before a name joins it.
    assert_eq!(of_kind("Ask Dana about it.", SpanKind::Name), ["Ask Dana"]);
}

#[test]
fn punctuation_breaks_a_name() {
    assert!(of_kind("Furthermore, Okafor. Later, Smith", SpanKind::Name).is_empty());
}

#[test]
fn a_possessive_name_survives_as_the_name() {
    assert_eq!(
        verify("Dana Okafor said so.", "It was Dana Okafor's call."),
        Ok(())
    );
}

#[test]
fn quotes_straight_and_curly() {
    assert_eq!(
        of_kind(
            r#"She said "ship it" and he said “not yet”."#,
            SpanKind::Quote
        ),
        ["\"ship it\"", "“not yet”"]
    );
}

#[test]
fn quote_marks_may_change_style() {
    assert_eq!(
        verify(r#"He said "ship it now"."#, "He said “ship it now”."),
        Ok(())
    );
}

#[test]
fn single_quotes_and_apostrophes_are_not_quotes() {
    assert!(of_kind("It's the team’s 'best' week.", SpanKind::Quote).is_empty());
}

#[test]
fn an_unclosed_quote_locks_nothing() {
    assert!(of_kind("He said \"ship it\n\nand left.", SpanKind::Quote).is_empty());
}

#[test]
fn a_quote_does_not_cross_a_paragraph() {
    let text = "Open \" here.\n\nAnd \"there\" too.";
    assert_eq!(of_kind(text, SpanKind::Quote), ["\"there\""]);
}

#[test]
fn inline_code() {
    assert_eq!(
        of_kind("Run `cargo test` or ``a ` b`` now.", SpanKind::Code),
        ["`cargo test`", "``a ` b``"]
    );
}

#[test]
fn fenced_code() {
    let text = "Before.\n\n```rust\nlet x = \"18%\";\n```\n\nAfter 18%.";
    let spans = extract(text);
    assert_eq!(spans[0].kind, SpanKind::Code);
    assert_eq!(spans[0].text, "```rust\nlet x = \"18%\";\n```");
    // The quote and the number inside the block are part of the code span,
    // not spans of their own; the 18% after it is.
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[1].kind, SpanKind::Number);
}

#[test]
fn an_unclosed_fence_runs_to_the_end() {
    let text = "Intro\n~~~\ncode here\n";
    assert_eq!(of_kind(text, SpanKind::Code), ["~~~\ncode here"]);
}

#[test]
fn code_must_survive_verbatim() {
    let original = "Call `fetch(url)` first.";
    assert_eq!(verify(original, "First, call `fetch(url)`."), Ok(()));
    assert!(verify(original, "First, call `fetch(uri)`.").is_err());
}

#[test]
fn a_repeated_span_is_reported_once() {
    let violations = verify("18% then 18% again", "nothing").unwrap_err();
    assert_eq!(violations.len(), 1);
}

#[test]
fn guard_kinds_can_be_switched_off() {
    let guard = Guard::new().names(false).quotes(false);
    let kinds: BTreeSet<_> = guard.extract(SITE).into_iter().map(|s| s.kind).collect();
    assert_eq!(kinds, BTreeSet::from([SpanKind::Number]));
    // Off code still shadows what is inside it.
    let text = "`a 18% b`";
    assert!(Guard::new().code(false).extract(text).is_empty());
}

#[test]
fn spans_never_overlap() {
    let text = "“Dana Okafor said 18%” and `Q3 \"x\"` and Mary Smith.";
    let spans = extract(text);
    for pair in spans.windows(2) {
        assert!(pair[0].end <= pair[1].start, "{pair:?}");
    }
}

#[test]
fn unicode_text_is_indexed_on_char_boundaries() {
    let text = "Ünïcödé Ärger kostete 5 € und „nichts“ — Zoë Ångström sagte “ja”.";
    for span in extract(text) {
        assert_eq!(&text[span.range()], span.text);
    }
    assert!(of_kind(text, SpanKind::Name).contains(&"Zoë Ångström".to_owned()));
    assert!(of_kind(text, SpanKind::Quote).contains(&"„nichts“".to_owned()));
    assert_eq!(
        of_kind("Il a dit « oui » hier.", SpanKind::Quote),
        ["« oui »"]
    );
}

#[test]
fn empty_text_has_no_spans() {
    assert!(extract("").is_empty());
    assert_eq!(verify("", ""), Ok(()));
}

#[test]
fn spans_and_violations_serialise_snake_case() {
    let v = verify("18%", "").unwrap_err();
    let json = serde_json::to_value(&v[0]).unwrap();
    assert_eq!(json["kind"], "missing");
    assert_eq!(json["span"]["kind"], "number");
    assert_eq!(json["span"]["text"], "18%");
}

// ---------------------------------------------------------------- links ----

#[test]
fn links() {
    assert_eq!(
        of_kind(
            "See https://example.com/a?b=1#c, http://x.io and www.example.org/path. \
             Also HTTPS://Example.com/Q3.",
            SpanKind::Url
        ),
        [
            "https://example.com/a?b=1#c",
            "http://x.io",
            "www.example.org/path",
            "HTTPS://Example.com/Q3"
        ]
    );
}

#[test]
fn sentence_punctuation_after_a_link_is_not_part_of_it() {
    for text in [
        "Go to https://example.com/x.",
        "Go to https://example.com/x, now",
        "Go to https://example.com/x; now",
        "Go to https://example.com/x: now",
        "Go to https://example.com/x!",
        "Go to https://example.com/x?",
        "(Go to https://example.com/x)",
        "(Go to https://example.com/x).",
        "Go to 'https://example.com/x'.",
        "[docs](https://example.com/x)",
        "Go to <https://example.com/x>",
        "Go to \"https://example.com/x\"",
    ] {
        let urls: Vec<_> = extract(text)
            .into_iter()
            .filter(|s| matches!(s.kind, SpanKind::Url | SpanKind::Quote))
            .map(|s| s.protected().to_owned())
            .collect();
        assert_eq!(urls, ["https://example.com/x"], "{text}");
    }
}

#[test]
fn balanced_parentheses_stay_in_a_link() {
    assert_eq!(
        of_kind(
            "(see https://en.wikipedia.org/wiki/Rust_(language)).",
            SpanKind::Url
        ),
        ["https://en.wikipedia.org/wiki/Rust_(language)"]
    );
}

#[test]
fn not_links() {
    assert!(
        of_kind(
            "https:// alone, www.nothing, xhttps://a.b, the www. prefix and https://.",
            SpanKind::Url
        )
        .is_empty()
    );
}

#[test]
fn digits_and_hashes_in_a_link_are_not_numbers_or_hashtags() {
    let text = "Read https://example.com/2026/10/q3-report#growth for #launch, up 18%.";
    assert_eq!(
        found(text),
        [
            (
                SpanKind::Url,
                "https://example.com/2026/10/q3-report#growth".to_owned()
            ),
            (SpanKind::Hashtag, "#launch".to_owned()),
            (SpanKind::Number, "18%".to_owned()),
        ]
    );
    // And in a rewrite: the link's digits are not introduced numbers.
    assert_eq!(
        verify("Up 18%.", "Up 18%, see https://example.com/2027/v19."),
        Ok(())
    );
}

#[test]
fn links_switched_off_still_shadow_their_digits() {
    let guard = Guard::new().urls(false);
    assert!(guard.extract("https://example.com/2026#tag").is_empty());
}

#[test]
fn a_link_must_survive_whole() {
    let original = "Notes: https://example.com/releases/v2.";
    assert_eq!(
        verify(original, "Read https://example.com/releases/v2 today."),
        Ok(())
    );
    assert_eq!(
        verify(original, "(https://example.com/releases/v2)"),
        Ok(())
    );
    for broken in [
        "Read https://example.com/releases/v20.",
        "Read https://example.com/releases/v2/extra.",
        "Read https://example.com/releases/.",
        "Read example.com/releases/v2.",
    ] {
        let violations = verify(original, broken).unwrap_err();
        assert_eq!(violations[0].kind, ViolationKind::Missing, "{broken}");
        assert_eq!(violations[0].span.kind, SpanKind::Url, "{broken}");
    }
}

// ------------------------------------------------------------- hashtags ----

#[test]
fn hashtags() {
    assert_eq!(
        of_kind(
            "Shipping #launch and #Q3_results with #café, (#OpenSource) and #日本語.",
            SpanKind::Hashtag
        ),
        ["#launch", "#Q3_results", "#café", "#OpenSource", "#日本語"]
    );
}

#[test]
fn not_hashtags() {
    let text = "# Heading\n## Sub\nWe are #1 on issue #123 in C# and F#, &#39; and ##double.";
    assert!(of_kind(text, SpanKind::Hashtag).is_empty());
    // The digits of #1 and #123 are protected as numbers instead.
    assert_eq!(of_kind(text, SpanKind::Number), ["1", "123", "39"]);
}

#[test]
fn a_glued_hashtag_number_is_one_hashtag() {
    assert_eq!(
        found("#2026Goals"),
        [(SpanKind::Hashtag, "#2026Goals".to_owned())]
    );
}

#[test]
fn a_hashtag_must_survive_whole() {
    let original = "Out now #launch";
    assert_eq!(verify(original, "#launch: out now"), Ok(()));
    assert!(verify(original, "Out now #launch_day").is_err());
    assert!(verify(original, "Out now #launched").is_err());
    assert!(verify(original, "Out now launch").is_err());
    assert!(verify(original, "Out now x#launch").is_err());
}

// --------------------------------------------------------- caller spans ----

/// `@[Name](id)` mentions, a stand-in for a platform's own syntax.
fn mentions(text: &str) -> Vec<ExtraSpan> {
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(open) = text[from..].find("@[").map(|at| from + at) {
        let Some(close) = text[open..].find(')').map(|at| open + at + 1) else {
            break;
        };
        spans.push(ExtraSpan::new(open..close, "mention"));
        from = close;
    }
    spans
}

#[test]
fn an_extractor_locks_caller_syntax_ahead_of_built_ins() {
    let guard = Guard::new().with_extra(mentions);
    let text = "Thanks @[Dana Okafor](urn:li:person:42) for #launch, 18%.";
    let spans = guard.extract(text);
    let summary: Vec<_> = spans
        .iter()
        .map(|s| (s.kind_name(), s.text.as_str()))
        .collect();
    // The name and the 42 inside the mention are not spans of their own.
    assert_eq!(
        summary,
        [
            ("mention", "@[Dana Okafor](urn:li:person:42)"),
            ("hashtag", "#launch"),
            ("number", "18%"),
        ]
    );
    assert_eq!(spans[0].kind, SpanKind::Custom);
    assert_eq!(spans[0].label.as_deref(), Some("mention"));
}

#[test]
fn caller_spans_beat_code_and_links() {
    let guard = Guard::new().with_extra(mentions);
    let spans = guard.extract("`@[a](b)` and @[x](https://example.com)");
    let kinds: Vec<_> = spans.iter().map(|s| s.kind).collect();
    assert_eq!(kinds, [SpanKind::Custom, SpanKind::Custom]);
}

#[test]
fn a_mangled_caller_span_is_missing_and_its_digits_are_not_introduced() {
    let guard = Guard::new().with_extra(mentions);
    let original = "Thanks @[Acme](urn:li:organization:123).";
    assert_eq!(
        guard.verify(original, "Big thanks to @[Acme](urn:li:organization:123)!"),
        Ok(())
    );
    let violations = guard
        .verify(original, "Thanks @[Acme](urn:li:organization:124).")
        .unwrap_err();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].kind, ViolationKind::Missing);
    assert_eq!(violations[0].span.kind_name(), "mention");
    // Without the extractor the same rewrite looks like a changed figure.
    let plain = verify(original, "Thanks @[Acme](urn:li:organization:124).").unwrap_err();
    assert_eq!(plain[0].span.text, "123");
    assert_eq!(plain[1].kind, ViolationKind::Introduced);
}

#[test]
fn per_call_spans_take_ranges_and_win_over_the_extractor() {
    let text = "Code X-42 ships @[A](b) today";
    let at = text.find("X-42").unwrap();
    let extra = [ExtraSpan::new(at..at + 4, "sku")];
    let spans = Guard::new().with_extra(mentions).extract_with(text, &extra);
    let summary: Vec<_> = spans
        .iter()
        .map(|s| (s.kind_name(), s.text.as_str()))
        .collect();
    assert_eq!(summary, [("sku", "X-42"), ("mention", "@[A](b)")]);
    // A per-call span overlapping the extractor's wins; the extractor's is dropped.
    let wide = [ExtraSpan::new(0..text.len(), "all")];
    let spans = Guard::new().with_extra(mentions).extract_with(text, &wide);
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].kind_name(), "all");

    let rewrite = "Today X-42 ships";
    let rewrite_at = rewrite.find("X-42").unwrap();
    assert_eq!(
        Guard::new().verify_with(
            "Code X-42 ships",
            &extra,
            rewrite,
            &[ExtraSpan::new(rewrite_at..rewrite_at + 4, "sku")]
        ),
        Ok(())
    );
    assert!(
        Guard::new()
            .verify_with("Code X-42 ships", &extra, "Code X-43 ships", &[])
            .is_err()
    );
    // The same characters, not locked as a caller span in the rewrite, do
    // not count: an escaped copy of a mention is text, not a mention.
    let violations = Guard::new()
        .verify_with("Code X-42 ships", &extra, "Code X-42 ships", &[])
        .unwrap_err();
    assert_eq!(violations[0].span.kind_name(), "sku");
}

#[test]
fn bad_caller_ranges_are_ignored() {
    let text = "Zoë 18%";
    let bad = [
        ExtraSpan::new(0..100, "x"),
        ExtraSpan::new(2..3, "x"), // inside ë
        ExtraSpan::new(4..4, "x"),
        ExtraSpan::new(5..7, "y"),
        ExtraSpan::new(6..8, "overlaps y"),
    ];
    let spans = Guard::new().extract_with(text, &bad);
    let summary: Vec<_> = spans
        .iter()
        .map(|s| (s.kind_name(), s.text.as_str()))
        .collect();
    assert_eq!(summary, [("y", "18")]);
}

#[test]
fn custom_spans_serialise_their_label_and_built_ins_do_not() {
    let spans = Guard::new().with_extra(mentions).extract("@[A](b) 18%");
    let json = serde_json::to_value(&spans).unwrap();
    assert_eq!(json[0]["kind"], "custom");
    assert_eq!(json[0]["label"], "mention");
    assert!(json[1].get("label").is_none());
    assert_eq!(serde_json::to_value(SpanKind::Url).unwrap(), "url");
    assert_eq!(serde_json::to_value(SpanKind::Hashtag).unwrap(), "hashtag");
}

#[test]
fn new_kinds_never_overlap_and_index_their_text() {
    let text = "“see https://x.io/1”, #tag_1 at www.a.io/#b (https://c.io/(d)) and @[E F](g:1) 2%";
    let spans = Guard::new().with_extra(mentions).extract(text);
    for pair in spans.windows(2) {
        assert!(pair[0].end <= pair[1].start, "{pair:?}");
    }
    for span in &spans {
        assert_eq!(&text[span.range()], span.text);
    }
}
