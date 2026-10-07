# cratefield-text-guard

Keeps the facts when a model rewrites text. Finds the spans a rewrite must
not change, then checks a rewrite against its original and lists every span
it dropped or altered, and every number it made up.

```rust
use cratefield_text_guard::{SpanKind, extract, verify};

let original = "Our Q3 revenue grew by 18% to $4.2M, Dana Okafor said.";
assert_eq!(extract(original).len(), 4); // Q3, 18%, $4.2M, Dana Okafor

assert!(verify(original, "Dana Okafor says Q3 revenue rose 18% to $4.2M.").is_ok());
assert!(verify(original, "Dana Okafor says Q3 revenue rose 19% to $4.2M.").is_err());
```

| Kind | Found as | Must survive as |
|---|---|---|
| `code` | fenced blocks, then inline backtick runs | verbatim, fences included |
| `quote` | `"…"`, `“…”`, `„…“`, `«…»` within a paragraph, at most 600 chars | the quoted words (marks may change style; a closing `,.;:` may move) |
| `number` | currency sign + digits joined by `.,:/-`, `%`/`‰` and glued letters (`$4.2M`, `18%`, `3rd`); capitals glued to digits (`Q3`, `FY2024`, `GPT-4`) | verbatim, at a word boundary |
| `name` | two or more capitalised words, lowercase particles (`of`, `van`, …) between them, leading function words dropped | verbatim, at a word boundary |

A number in the rewrite that is not in the original is reported as
`introduced`, so a changed figure shows up as one missing and one
introduced. The heuristics are character scans with no regex, dictionary or
model, on purpose: their limits are listed in the crate docs. Pure text, no
I/O, no `cratefield-core`; builds for `wasm32-unknown-unknown`.

Pair it with [`cratefield-text-diff`](../text-diff), which takes the ranges
from `Guard::ranges` and keeps them whole in a word diff.
