//! Storage policies: which bucket a `storage.objects` / `storage.buckets`
//! policy governs, and the check a route needs in its place (ADR 0026,
//! Decision 5: every policy needs its own disposition).
//!
//! The bucket id(s) come from the `USING` / `WITH CHECK` text as
//! `pg_policies` renders it — `bucket_id = 'x'`, `'x'::text = bucket_id`, or
//! `bucket_id = ANY (ARRAY['a', 'b'])`; on `storage.buckets` the column is
//! `id` (or `name`). A policy naming no bucket that exists gets the
//! `all_buckets` flag and is attached to every bucket; with no buckets at
//! all it goes to [`Storage::unattached_policies`].

use crate::collect::RawPolicy;
use crate::report::{BucketPolicy, Disposition, Storage};

/// `storage.objects` and `storage.buckets`: the two tables whose policies
/// govern a bucket. Policies on any other `storage` table are managed and
/// belong in `report.managed_policies`.
#[must_use]
pub(crate) fn is_bucket_table(schema: &str, table: &str) -> bool {
    schema == "storage" && matches!(table, "objects" | "buckets")
}

/// Attaches every storage policy to the bucket(s) it names, filling each
/// bucket's `policies`. With no buckets at all they go to
/// `storage.unattached_policies` so they stay discoverable.
pub(crate) fn attach(storage: &mut Storage, policies: &[RawPolicy]) {
    // No buckets, or a bucket list the role cannot see (issue #723): the
    // policies cannot be attached, so they stay discoverable here.
    let Some(buckets) = storage.buckets.as_mut().filter(|buckets| !buckets.is_empty()) else {
        storage.unattached_policies = policies
            .iter()
            .map(|raw| policy_for(raw, true, false))
            .collect();
        return;
    };
    let ids: Vec<String> = buckets
        .iter()
        .map(|bucket| bucket.id.clone())
        .collect();
    for raw in policies {
        let columns: &[&str] = if raw.table == "buckets" {
            &["id", "name"]
        } else {
            &["bucket_id"]
        };
        let mut named = Vec::new();
        for expression in [raw.using.as_deref(), raw.with_check.as_deref()]
            .into_iter()
            .flatten()
        {
            named.extend(named_buckets(expression, columns));
        }
        named.sort();
        named.dedup();
        // A name that matches no bucket drops out; the rest still attach, so
        // `'gone' OR 'receipts'` lands on `receipts` alone. Only when nothing
        // matches does the policy apply to every bucket.
        let matched: Vec<String> = named
            .into_iter()
            .filter(|name| ids.contains(name))
            .collect();
        let all_buckets = matched.is_empty();
        for bucket in buckets.iter_mut() {
            if all_buckets || matched.contains(&bucket.id) {
                bucket
                    .policies
                    .push(policy_for(raw, all_buckets, bucket.public));
            }
        }
    }
}

fn policy_for(raw: &RawPolicy, all_buckets: bool, public: bool) -> BucketPolicy {
    let uses_owner = [raw.using.as_deref(), raw.with_check.as_deref()]
        .into_iter()
        .flatten()
        .any(mentions_owner);
    BucketPolicy {
        table: format!("{}.{}", raw.schema, raw.table),
        name: raw.name.clone(),
        command: raw.command.clone(),
        roles: raw.roles.clone(),
        using: raw.using.clone(),
        with_check: raw.with_check.clone(),
        all_buckets,
        suggested_equivalent: suggested(public, &raw.command, uses_owner),
        disposition: Disposition::Undecided,
    }
}

/// Whether an expression references the object's owner: the identifiers
/// `owner` or `owner_id`, or `auth.uid()`. A substring test would also match
/// `co_owner` or `ownership`.
fn mentions_owner(expression: &str) -> bool {
    expression.contains("auth.uid()")
        || tokenize(expression).iter().any(
            |token| matches!(token, Token::Ident(name) if name == "owner" || name == "owner_id"),
        )
}

/// The check to write: a public read is a public URL; anything else is a
/// route that checks the expression and hands out a signed URL.
fn suggested(public: bool, command: &str, uses_owner: bool) -> String {
    if public && command.eq_ignore_ascii_case("SELECT") {
        return "a public URL: serve the object under the same key from a public route".to_owned();
    }
    let condition = if uses_owner {
        "that the request's subject equals `owner`"
    } else {
        "the policy's own condition"
    };
    format!(
        "serve objects through a route that checks {condition} and hands out a signed URL; keep \
         the `owner` column"
    )
}

/// A token of the small SQL subset the bucket-id parser reads: identifiers,
/// single-quoted string literals and single-character symbols.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    Sym(char),
}

fn tokenize(text: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c.is_whitespace() {
            rest = &rest[c.len_utf8()..];
            continue;
        }
        if c == '\'' {
            let mut value = String::new();
            let mut chars = rest.chars();
            chars.next();
            loop {
                match chars.next() {
                    Some('\'') if chars.clone().next() == Some('\'') => {
                        value.push('\'');
                        chars.next();
                    }
                    None | Some('\'') => break,
                    Some(other) => value.push(other),
                }
            }
            let consumed = rest.len() - chars.as_str().len();
            rest = &rest[consumed..];
            tokens.push(Token::Str(value));
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == '"' {
            let end = rest
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '"'))
                .unwrap_or(rest.len());
            let ident = rest[..end].trim_matches('"').to_ascii_lowercase();
            rest = &rest[end..];
            tokens.push(Token::Ident(ident));
            continue;
        }
        tokens.push(Token::Sym(c));
        rest = &rest[c.len_utf8()..];
    }
    tokens
}

/// The bucket id(s) an expression names, via `column = 'x'`,
/// `'x'::text = column` or `column = ANY (ARRAY['a', 'b'])`.
fn named_buckets(expression: &str, columns: &[&str]) -> Vec<String> {
    let tokens = tokenize(expression);
    let is_column = |token: Option<&Token>| matches!(token, Some(Token::Ident(name)) if columns.contains(&name.as_str()));
    let mut names = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        // `column = value`, the value a literal or an `ANY (ARRAY[...])`.
        if is_column(tokens.get(i)) && tokens.get(i + 1) == Some(&Token::Sym('=')) {
            match tokens.get(i + 2) {
                Some(Token::Str(value)) => {
                    names.push(value.clone());
                    i += 3;
                    continue;
                }
                Some(Token::Ident(any)) if any == "any" => {
                    if let Some((values, next)) = array_literals(&tokens, i + 3) {
                        names.extend(values);
                        i = next;
                        continue;
                    }
                }
                _ => {}
            }
        }
        // `'x'::text = column`, the literal on the left.
        if let Token::Str(value) = &tokens[i] {
            let j = skip_cast(&tokens, i + 1);
            if tokens.get(j) == Some(&Token::Sym('=')) && is_column(tokens.get(j + 1)) {
                names.push(value.clone());
                i = j + 2;
                continue;
            }
        }
        i += 1;
    }
    names
}

/// The string literals directly inside `ANY (ARRAY[ ... ])`, from the token
/// after `any`. `None` when the shape is anything else — e.g.
/// `ARRAY[lower('a')]`, whose element is not a literal — so the caller leaves
/// it unparsed.
fn array_literals(tokens: &[Token], mut j: usize) -> Option<(Vec<String>, usize)> {
    if tokens.get(j) != Some(&Token::Sym('('))
        || !matches!(tokens.get(j + 1), Some(Token::Ident(name)) if name == "array")
        || tokens.get(j + 2) != Some(&Token::Sym('['))
    {
        return None;
    }
    j += 3;
    let mut values = Vec::new();
    loop {
        let Some(Token::Str(value)) = tokens.get(j) else {
            return None;
        };
        values.push(value.clone());
        j = skip_cast(tokens, j + 1);
        match tokens.get(j) {
            Some(Token::Sym(',')) => j += 1,
            Some(Token::Sym(']')) => return Some((values, j + 1)),
            _ => return None,
        }
    }
}

/// Skips a `::type` cast (with an optional ` varying` and `[]`), returning
/// the index of the first token after it.
fn skip_cast(tokens: &[Token], mut j: usize) -> usize {
    while tokens.get(j) == Some(&Token::Sym(':')) {
        j += 2;
        if matches!(tokens.get(j), Some(Token::Ident(_))) {
            j += 1;
        }
        if matches!(tokens.get(j), Some(Token::Ident(name)) if name == "varying") {
            j += 1;
        }
        while tokens.get(j) == Some(&Token::Sym('[')) && tokens.get(j + 1) == Some(&Token::Sym(']'))
        {
            j += 2;
        }
    }
    j
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Bucket;

    fn raw(table: &str, name: &str, using: Option<&str>, check: Option<&str>) -> RawPolicy {
        RawPolicy {
            schema: "storage".to_owned(),
            table: table.to_owned(),
            name: name.to_owned(),
            command: "SELECT".to_owned(),
            permissive: true,
            roles: vec!["public".to_owned()],
            using: using.map(str::to_owned),
            with_check: check.map(str::to_owned),
            columns: Vec::new(),
        }
    }

    fn bucket(id: &str, public: bool) -> Bucket {
        Bucket {
            id: id.to_owned(),
            name: id.to_owned(),
            public,
            file_size_limit: None,
            allowed_mime_types: Vec::new(),
            objects: Some(0),
            bytes: Some(0),
            objects_over_blob_cap: Some(0),
            policies: Vec::new(),
        }
    }

    fn storage_of(buckets: &[(&str, bool)]) -> Storage {
        Storage {
            present: true,
            buckets: Some(
                buckets
                    .iter()
                    .map(|(id, public)| bucket(id, *public))
                    .collect(),
            ),
            unattached_policies: Vec::new(),
        }
    }

    #[test]
    fn the_expression_selects_its_buckets() {
        let cases: &[(&str, &[&str], &[&str])] = &[
            (
                "(bucket_id = 'receipts'::text)",
                &["bucket_id"],
                &["receipts"],
            ),
            (
                "(('receipts'::text = bucket_id))",
                &["bucket_id"],
                &["receipts"],
            ),
            (
                "(bucket_id = ANY (ARRAY['a'::text, 'b'::text]))",
                &["bucket_id"],
                &["a", "b"],
            ),
            ("(id = 'photos'::text)", &["id", "name"], &["photos"]),
            ("(name = 'photos'::text)", &["id", "name"], &["photos"]),
            // A non-literal `ANY` element, e.g. `lower('a')`, is not parsed.
            ("(bucket_id = ANY (ARRAY[lower('a')]))", &["bucket_id"], &[]),
            ("(storage.foldername(name))[1] = 'x'", &["bucket_id"], &[]),
            ("true", &["bucket_id"], &[]),
        ];
        for (expression, columns, expected) in cases {
            assert_eq!(
                named_buckets(expression, columns),
                *expected,
                "{expression}"
            );
        }
    }

    #[test]
    fn a_policy_lands_on_its_buckets_and_is_suggested_a_check() {
        // Named: on the one bucket, no flag.
        let mut named = storage_of(&[("receipts", false), ("avatars", true)]);
        attach(
            &mut named,
            &[raw(
                "objects",
                "p",
                Some("(bucket_id = 'receipts'::text)"),
                None,
            )],
        );
        assert_eq!(named.buckets.as_ref().expect("buckets")[0].policies.len(), 1);
        assert!(!named.buckets.as_ref().expect("buckets")[0].policies[0].all_buckets);
        assert!(named.buckets.as_ref().expect("buckets")[1].policies.is_empty());

        // Mixed: an unknown name drops out, the rest still attach.
        let mut mixed = storage_of(&[("receipts", false)]);
        attach(
            &mut mixed,
            &[raw(
                "objects",
                "p",
                Some("((bucket_id = 'gone') OR (bucket_id = 'receipts'))"),
                None,
            )],
        );
        assert_eq!(mixed.buckets.as_ref().expect("buckets")[0].policies.len(), 1);
        assert!(!mixed.buckets.as_ref().expect("buckets")[0].policies[0].all_buckets);

        // Unparsed, or no existing bucket named: every bucket, flagged.
        for expression in ["true", "(bucket_id = 'gone')"] {
            let mut all = storage_of(&[("receipts", false), ("avatars", true)]);
            attach(&mut all, &[raw("objects", "p", Some(expression), None)]);
            assert!(
                all.buckets
                    .iter()
                    .flatten()
                    .all(|b| b.policies.len() == 1 && b.policies[0].all_buckets),
                "{expression}"
            );
        }

        // No buckets at all: keep them discoverable.
        let mut none = Storage::default();
        attach(&mut none, &[raw("objects", "p", Some("true"), None)]);
        assert_eq!(none.unattached_policies.len(), 1);
        assert!(none.unattached_policies[0].all_buckets);

        // The suggestion follows visibility and owner; `owner` is a whole
        // identifier, so `co_owner`/`ownership` alone does not count.
        assert!(suggested(true, "SELECT", false).contains("public URL"));
        let private = suggested(false, "SELECT", true);
        assert!(private.contains("signed URL") && private.contains("`owner`"));
        assert!(mentions_owner("(owner = 'x')"));
        assert!(mentions_owner("(owner_id = 'x')"));
        assert!(!mentions_owner("(co_owner = 'x')"));
        assert!(!mentions_owner("(ownership = 'x')"));
    }
}
