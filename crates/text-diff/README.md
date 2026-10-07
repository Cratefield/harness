# cratefield-text-diff

A word-level diff for showing what a rewrite changed: segments that are
`removed`, `added` or `same`, and `locked` for protected ranges that came
through unchanged.

```rust
use cratefield_text_diff::{Op, diff_words};

let segments = diff_words("revenue grew by 18%", "revenue rose 18%");
assert_eq!(segments[1].op, Op::Removed); // "grew by "
assert_eq!(segments[2].op, Op::Added);   // "rose "
```

`diff_words_locked(before, after, before_ranges, after_ranges)` treats each
protected byte range as one atomic token, never split into words, so a
quotation or a figure is shown as kept or changed as a whole. The ranges can
come from [`cratefield-text-guard`](../text-guard) or anywhere else.

Whitespace rides on the token before it and is not compared, so re-wrapping
is not a change; the segments that are not `removed`, in order, rebuild the
rewrite exactly. The algorithm is Myers' O(ND) diff in linear space, so a
full rewrite of a 10,000-word text costs memory proportional to its length.
Pure Rust, no dependencies beyond serde; builds for `wasm32-unknown-unknown`.
