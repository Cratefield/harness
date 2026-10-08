use super::*;

fn ops(segments: &[Segment]) -> Vec<(Op, &str)> {
    segments.iter().map(|s| (s.op, s.text.as_str())).collect()
}

fn rebuilt_after(segments: &[Segment]) -> String {
    segments
        .iter()
        .filter(|s| s.op != Op::Removed)
        .map(|s| s.text.as_str())
        .collect()
}

/// The words of a side, from the segments that belong to it.
fn words_of(segments: &[Segment], skip: Op) -> Vec<String> {
    segments
        .iter()
        .filter(|s| s.op != skip)
        .flat_map(|s| {
            s.text
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn identical_texts_are_one_same_segment() {
    let segments = diff_words("the same text", "the same text");
    assert_eq!(ops(&segments), [(Op::Same, "the same text")]);
}

#[test]
fn empty_sides() {
    assert!(diff_words("", "").is_empty());
    assert_eq!(
        ops(&diff_words("", "new words")),
        [(Op::Added, "new words")]
    );
    assert_eq!(
        ops(&diff_words("old words", "")),
        [(Op::Removed, "old words")]
    );
}

#[test]
fn a_replaced_word() {
    let segments = diff_words("revenue grew fast", "revenue rose fast");
    assert_eq!(
        ops(&segments),
        [
            (Op::Same, "revenue "),
            (Op::Removed, "grew "),
            (Op::Added, "rose "),
            (Op::Same, "fast")
        ]
    );
}

#[test]
fn whitespace_changes_are_not_changes() {
    let segments = diff_words("one two\nthree", "one  two three");
    assert_eq!(ops(&segments), [(Op::Same, "one  two three")]);
}

#[test]
fn numbers_and_contractions_stay_whole() {
    let segments = diff_words("we don't grow 18% to $4.2M", "we don't grow 19% to $4.2M");
    assert_eq!(
        ops(&segments),
        [
            (Op::Same, "we don't grow "),
            (Op::Removed, "18% "),
            (Op::Added, "19% "),
            (Op::Same, "to $4.2M")
        ]
    );
}

#[test]
fn punctuation_is_its_own_token() {
    let segments = diff_words("Hello, world.", "Hello world!");
    assert_eq!(
        ops(&segments),
        [
            (Op::Same, "Hello "),
            (Op::Removed, ", "),
            (Op::Same, "world"),
            (Op::Removed, "."),
            (Op::Added, "!")
        ]
    );
}

#[test]
fn locked_ranges_are_atomic_and_reported_locked() {
    let before = "Furthermore, Dana Okafor stated that revenue was $4.2M overall.";
    let after = "Dana Okafor says revenue was $4.2M.";
    let lock = |text: &str, needle: &str| {
        let at = text.find(needle).unwrap();
        at..at + needle.len()
    };
    let segments = diff_words_locked(
        before,
        after,
        &[lock(before, "Dana Okafor"), lock(before, "$4.2M")],
        &[lock(after, "Dana Okafor"), lock(after, "$4.2M")],
    );
    assert_eq!(
        ops(&segments),
        [
            (Op::Removed, "Furthermore, "),
            (Op::Locked, "Dana Okafor "),
            (Op::Removed, "stated that "),
            (Op::Added, "says "),
            (Op::Same, "revenue was "),
            (Op::Locked, "$4.2M"),
            // Whitespace rides on the token before it: the space before
            // "overall" belongs to the kept "$4.2M", which carries the
            // rewrite's (none).
            (Op::Removed, "overall"),
            (Op::Same, "."),
        ]
    );
}

#[test]
fn a_locked_range_that_changed_is_removed_and_added_whole() {
    let before = "said “we doubled down” then";
    let after = "said “we doubled up” then";
    let quote = |t: &str| {
        let s = t.find('“').unwrap();
        let e = t.find('”').unwrap() + '”'.len_utf8();
        s..e
    };
    let segments = diff_words_locked(before, after, &[quote(before)], &[quote(after)]);
    assert_eq!(
        ops(&segments),
        [
            (Op::Same, "said "),
            (Op::Removed, "“we doubled down” "),
            (Op::Added, "“we doubled up” "),
            (Op::Same, "then")
        ]
    );
}

#[test]
fn bad_ranges_are_ignored() {
    let text = "Zoë said hi";
    // Out of bounds, inside a multi-byte char, empty, and overlapping.
    let bad = [0..100, 2..3, 4..4, 0..3, 1..5];
    let segments = diff_words_locked(text, text, &bad, &bad);
    assert_eq!(rebuilt_after(&segments), text);
}

#[test]
fn leading_whitespace_is_kept() {
    let segments = diff_words("  indented", "  indented now");
    assert_eq!(rebuilt_after(&segments), "  indented now");
}

#[test]
fn segments_serialise_snake_case() {
    let json = serde_json::to_value(diff_words("a", "b")).unwrap();
    assert_eq!(json[0]["op"], "removed");
    assert_eq!(json[1]["op"], "added");
}

/// A deterministic generator, so the property tests need no dependency.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn text(&mut self, words: usize, alphabet: &[&str]) -> String {
        let n = usize::try_from(self.next()).unwrap_or(0) % (words + 1);
        (0..n)
            .map(|_| alphabet[usize::try_from(self.next()).unwrap_or(0) % alphabet.len()])
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn lcs_len(a: &[&str], b: &[&str]) -> usize {
    let mut row = vec![0usize; b.len() + 1];
    for x in a {
        let mut diag = 0;
        for (j, y) in b.iter().enumerate() {
            let up = row[j + 1];
            row[j + 1] = if x == y { diag + 1 } else { up.max(row[j]) };
            diag = up;
        }
    }
    row[b.len()]
}

#[test]
fn random_diffs_rebuild_both_sides_and_are_minimal() {
    let alphabet = ["a", "b", "c", "d", "e", "the", "18%", "x"];
    let mut rng = Lcg(42);
    for _ in 0..2_000 {
        let before = rng.text(30, &alphabet);
        let after = rng.text(30, &alphabet);
        let segments = diff_words(&before, &after);

        let a: Vec<&str> = before.split_whitespace().collect();
        let b: Vec<&str> = after.split_whitespace().collect();
        assert_eq!(rebuilt_after(&segments), after, "{before:?} -> {after:?}");
        assert_eq!(words_of(&segments, Op::Added), a, "{before:?} -> {after:?}");
        assert_eq!(
            words_of(&segments, Op::Removed),
            b,
            "{before:?} -> {after:?}"
        );

        let same: usize = segments
            .iter()
            .filter(|s| s.op == Op::Same)
            .map(|s| s.text.split_whitespace().count())
            .sum();
        assert_eq!(
            same,
            lcs_len(&a, &b),
            "not minimal: {before:?} -> {after:?}"
        );
    }
}

#[test]
fn a_long_full_rewrite_is_fast_and_linear_in_memory() {
    let mut rng = Lcg(7);
    let alphabet = [
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    ];
    let before = rng.text(10_000, &alphabet);
    let after = rng.text(10_000, &alphabet);
    let segments = diff_words(&before, &after);
    assert_eq!(rebuilt_after(&segments), after);
}

#[test]
fn links_hashtags_and_caller_spans_from_the_guard_stay_whole() {
    use cratefield_text_guard::{ExtraSpan, Guard};

    fn mentions(text: &str) -> Vec<ExtraSpan> {
        text.find("@[")
            .and_then(|open| {
                let close = open + text[open..].find(')')? + 1;
                Some(vec![ExtraSpan::new(open..close, "mention")])
            })
            .unwrap_or_default()
    }

    let guard = Guard::new().with_extra(mentions);
    let before =
        "Read https://example.com/notes/v2-3 from @[Acme Co](urn:li:organization:12) #launch";
    let after =
        "From @[Acme Co](urn:li:organization:12): read https://example.com/notes/v2-3 #launch";
    let segments = diff_words_locked(before, after, &guard.ranges(before), &guard.ranges(after));
    let locked: Vec<_> = segments
        .iter()
        .filter(|s| s.op == Op::Locked)
        .map(|s| s.text.trim_end())
        .collect();
    assert!(
        locked.contains(&"https://example.com/notes/v2-3"),
        "{segments:?}"
    );
    assert!(locked.contains(&"#launch"), "{segments:?}");
    // Moved, so removed and added — each whole, inside one segment, never
    // split across two.
    let mention = "@[Acme Co](urn:li:organization:12)";
    for op in [Op::Removed, Op::Added] {
        assert!(
            segments
                .iter()
                .any(|s| s.op == op && s.text.contains(mention)),
            "{segments:?}"
        );
    }
    assert_eq!(rebuilt_after(&segments), after);

    // A changed link is removed and added whole.
    let changed =
        "Read https://example.com/notes/v2-4 from @[Acme Co](urn:li:organization:12) #launch";
    let segments = diff_words_locked(
        before,
        changed,
        &guard.ranges(before),
        &guard.ranges(changed),
    );
    assert_eq!(
        ops(&segments)[..3],
        [
            (Op::Same, "Read "),
            (Op::Removed, "https://example.com/notes/v2-3 "),
            (Op::Added, "https://example.com/notes/v2-4 "),
        ]
    );
}
