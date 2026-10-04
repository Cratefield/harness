//! What an RLS policy amounts to, and the Cratefield check to write for it.
//!
//! The harness has no row-level security (ADR 0008): every policy becomes a
//! check in a module route. This module places each policy on a pattern so
//! the report can say which check.
//!
//! **Rules first.** [`match_rules`] reads the policy's roles and its `USING`
//! / `WITH CHECK` expressions (as `pg_get_expr` renders them) and recognises
//! the common Supabase shapes: owner-only (`auth.uid() = user_id`),
//! tenant-scoped through a membership lookup, public read (`true`),
//! role- or claim-based (`auth.role()`, `auth.jwt()`), and service-role
//! only. Then the shapes those miss: ownership or membership reached
//! through a parent row, a public read bounded by a column filter, a
//! policy that refuses everything (`false`), and a disjunction of any of
//! these. A match has confidence 1.0.
//!
//! **A classifier for the rest, optionally.** When a [`Classifier`] is
//! configured (Jev, `TypeSafe`'s calibrated judge, through
//! `cratefield-adapter-typesafe`; or `cratefield-adapter-classifier-llm`),
//! each policy no rule placed is asked one typed question — which access
//! pattern is this? — and the top label is taken when its confidence is at
//! or above the threshold. Below it, the policy stays
//! [`PolicyPattern::NeedsReview`]. The confidence is the adapter's own
//! number, so the threshold is per adapter: changing the adapter re-tunes
//! it ([`Classifier`]'s docs).
//!
//! The classifier is sent the policy's SQL and the names of its table and
//! the table's columns. Never a row.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use cratefield_core::{AnswerValue, Classifier, Question};

use crate::report::{PolicyPattern, PolicySource};

/// The threshold used when none is given.
pub const DEFAULT_THRESHOLD: f32 = 0.8;

/// The id of the one question asked per policy.
pub const QUESTION_ID: &str = "access_pattern";

/// A policy as the classifier input sees it: SQL and names only.
#[derive(Debug, Clone)]
pub struct PolicyInput<'a> {
    /// `schema.table`.
    pub table: &'a str,
    /// The table's column names.
    pub columns: &'a [String],
    /// The policy's command.
    pub command: &'a str,
    /// Its roles.
    pub roles: &'a [String],
    /// Permissive or restrictive.
    pub permissive: bool,
    /// The `USING` expression.
    pub using: Option<&'a str>,
    /// The `WITH CHECK` expression.
    pub with_check: Option<&'a str>,
}

/// Where a policy landed.
#[derive(Debug, Clone, PartialEq)]
pub struct Placement {
    /// The pattern.
    pub pattern: PolicyPattern,
    /// 1.0 for a rule, the classifier's confidence, or 0.0.
    pub confidence: f32,
    /// Who placed it.
    pub source: PolicySource,
    /// The classifier's below-threshold label, if that is why it is
    /// `needs_review`.
    pub classifier_label: Option<String>,
    /// The check to write.
    pub suggested_equivalent: String,
}

/// One thing a rule found, with what makes its suggestion specific.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleMatch {
    Owner(String),
    Tenant(String),
    Public,
    PublicWrite,
    Role,
    ServiceRole,
    OwnerViaParent {
        parent: String,
        fk: String,
        owner: String,
    },
    TenantViaParent {
        parent: String,
        fk: String,
        membership: String,
        tenant_column: String,
        roles: Vec<String>,
    },
    PublicReadFiltered {
        columns: Vec<String>,
        parent: Option<(String, String)>,
        signed_in: bool,
    },
    DenyAll,
    Composite(Vec<Self>),
}

impl RuleMatch {
    fn pattern(&self) -> PolicyPattern {
        match self {
            Self::Owner(_) => PolicyPattern::OwnerOnly,
            Self::Tenant(_) => PolicyPattern::TenantScoped,
            Self::Public => PolicyPattern::PublicRead,
            Self::PublicWrite => PolicyPattern::PublicWrite,
            Self::Role => PolicyPattern::RoleBased,
            Self::ServiceRole => PolicyPattern::ServiceRoleOnly,
            Self::OwnerViaParent { .. } => PolicyPattern::OwnerViaParent,
            Self::TenantViaParent { .. } => PolicyPattern::TenantViaParent,
            Self::PublicReadFiltered { .. } => PolicyPattern::PublicReadFiltered,
            Self::DenyAll => PolicyPattern::DenyAll,
            Self::Composite(_) => PolicyPattern::Composite,
        }
    }

    fn suggestion(&self) -> String {
        match self {
            Self::Owner(column) => format!(
                "owner check in the route: the request's subject must equal `{column}` (filter \
                 reads and refuse writes by it)"
            ),
            Self::Tenant(table) => format!(
                "membership check in the route: the request's subject must be a member, looked \
                 up in `{table}`, of the row's tenant"
            ),
            Self::OwnerViaParent { parent, fk, owner } => format!(
                "owner check through the parent row in the route: load the `{parent}` row `{fk}` \
                 points at; the request's subject must equal its `{owner}` (filter reads and \
                 refuse writes by it)"
            ),
            Self::TenantViaParent {
                parent,
                fk,
                membership,
                tenant_column,
                roles,
            } => {
                let mut text = format!(
                    "membership check through the parent row in the route: load the `{parent}` \
                     row `{fk}` points at; the request's subject must be a member, looked up in \
                     `{membership}`, of its `{tenant_column}`"
                );
                if !roles.is_empty() {
                    let listed = roles
                        .iter()
                        .map(|role| format!("'{role}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = write!(text, ", holding one of the roles {listed}");
                }
                text
            }
            Self::PublicReadFiltered {
                columns,
                parent,
                signed_in,
            } => public_read_filtered_suggestion(columns, parent.as_ref(), *signed_in),
            Self::DenyAll => "no route: the policy refuses every request it covers; keep the \
                              table server-side and test that clients are refused"
                .to_owned(),
            Self::Composite(parts) => {
                let mut text = String::from(
                    "any one of these checks grants access, so the route must accept a request \
                     that passes any of them:",
                );
                for (index, part) in parts.iter().enumerate() {
                    let _ = write!(
                        text,
                        " ({}) {}: {};",
                        index + 1,
                        pattern_name(part.pattern()),
                        part.suggestion()
                    );
                }
                text
            }
            other => suggestion(other.pattern()),
        }
    }
}

/// The suggestion for a filtered public read.
fn public_read_filtered_suggestion(
    columns: &[String],
    parent: Option<&(String, String)>,
    signed_in: bool,
) -> String {
    let listed = columns
        .iter()
        .map(|column| format!("`{column}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let subject = if signed_in {
        "for signed-in subjects only, with no per-row subject check"
    } else {
        "with no subject check"
    };
    match parent {
        Some((parent, fk)) => format!(
            "a public read route {subject}, returning only rows whose `{parent}` row (through \
             `{fk}`) passes the filter on {listed}; confirm every column of those rows is meant \
             to be public"
        ),
        None => format!(
            "a public read route {subject}, returning only rows where {listed} match the \
             policy's filter; confirm every column of those rows is meant to be public"
        ),
    }
}

/// The `serde` name of a pattern, taken from the type so it cannot drift.
fn pattern_name(pattern: PolicyPattern) -> String {
    serde_json::to_value(pattern)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The generic suggestion for a pattern.
#[must_use]
pub fn suggestion(pattern: PolicyPattern) -> String {
    match pattern {
        PolicyPattern::OwnerOnly => {
            "owner check in the route: the request's subject must own the row".to_owned()
        }
        PolicyPattern::TenantScoped => {
            "membership check in the route: the request's subject must belong to the row's \
             tenant"
                .to_owned()
        }
        PolicyPattern::PublicRead => "a public read route with no subject check; confirm every \
                                      column is meant to be public"
            .to_owned(),
        PolicyPattern::PublicWrite => "a public write route: rate-limit it and put the Captcha \
                                       port in front; confirm it is meant to be open"
            .to_owned(),
        PolicyPattern::RoleBased => "a role or claim check in the route on the request's \
                                     subject (signed in, or holding the role)"
            .to_owned(),
        PolicyPattern::ServiceRoleOnly => "server-side only: no route exposes it; module code \
                                           reads and writes it directly"
            .to_owned(),
        PolicyPattern::OwnerViaParent => "owner check through the parent row in the route: load \
                                          the parent row the foreign key points at; the \
                                          request's subject must equal its owner column (filter \
                                          reads and refuse writes by it)"
            .to_owned(),
        PolicyPattern::TenantViaParent => "membership check through the parent row in the route: \
                                           load the parent row the foreign key points at; the \
                                           request's subject must be a member, looked up in the \
                                           membership table, of its tenant"
            .to_owned(),
        PolicyPattern::PublicReadFiltered => "a public read route with no subject check, \
                                              returning only the rows the policy's filter allows; \
                                              confirm every column of those rows is meant to be \
                                              public"
            .to_owned(),
        PolicyPattern::DenyAll => "no route: the policy refuses every request it covers; keep the \
                                   table server-side and test that clients are refused"
            .to_owned(),
        PolicyPattern::Composite => "any one of the policy's checks grants access, so the route \
                                     must accept a request that passes any of them"
            .to_owned(),
        PolicyPattern::CustomLogic => "a hand-written check in the route reproducing the \
                                       expression; write its failing test first"
            .to_owned(),
        PolicyPattern::NeedsReview => "read the expression and write the equivalent route \
                                       check, with a failing test first"
            .to_owned(),
    }
}

/// Places a policy by rule alone. `None` when no rule matched.
///
#[must_use]
pub fn match_rules(input: &PolicyInput<'_>) -> Option<(PolicyPattern, String)> {
    let roles: Vec<&str> = input.roles.iter().map(String::as_str).collect();
    if roles == ["service_role"] {
        return Some((
            PolicyPattern::ServiceRoleOnly,
            RuleMatch::ServiceRole.suggestion(),
        ));
    }
    let using = input.using.map(|expr| match_expression(expr, input));
    let check = input.with_check.map(|expr| match_expression(expr, input));
    // A side the rules cannot read vetoes the other: an unplaced or
    // unrecognised expression is never labelled by the side that placed.
    let placed = match (using, check) {
        (Some(Some(a)), Some(Some(b))) if a.pattern() == b.pattern() => a,
        (Some(Some(a)), None) | (None, Some(Some(a))) => a,
        _ => return None,
    };
    Some((placed.pattern(), placed.suggestion()))
}

fn match_expression(expr: &str, input: &PolicyInput<'_>) -> Option<RuleMatch> {
    let expr = normalize(expr);
    if let Some(matched) = match_old_rules(&expr, input) {
        return Some(matched);
    }
    if !input.permissive {
        return None;
    }
    // The rules below cover shapes the rules above miss. They run only once
    // every rule above has failed, so a policy the rules already placed
    // never changes.
    if let Some(matched) = parent_match(&expr, input) {
        return Some(matched);
    }
    if let Some(matched) = public_read_filtered(&expr, input) {
        return Some(matched);
    }
    if expr == "false" {
        return Some(RuleMatch::DenyAll);
    }
    composite(&expr, input)
}

fn match_old_rules(expr: &str, input: &PolicyInput<'_>) -> Option<RuleMatch> {
    let anonymous = input.roles.is_empty()
        || input
            .roles
            .iter()
            .any(|role| role == "public" || role == "anon");
    if expr == "true" {
        if !anonymous && input.roles.iter().all(|role| role == "authenticated") {
            return Some(RuleMatch::Role);
        }
        let read = input.command.eq_ignore_ascii_case("select");
        return Some(if read {
            RuleMatch::Public
        } else {
            RuleMatch::PublicWrite
        });
    }
    if let Some(column) = owner_column(expr) {
        return Some(RuleMatch::Owner(column));
    }
    if expr.contains("auth.uid()")
        && let Some(table) = membership_table(expr)
    {
        return Some(RuleMatch::Tenant(table));
    }
    let claims = expr.contains("auth.role()") || expr.contains("auth.jwt()");
    if claims && !expr.contains("auth.uid()") && !expr.contains("select ") {
        if expr.contains("'service_role'") && !expr.contains(" or ") {
            return Some(RuleMatch::ServiceRole);
        }
        return Some(RuleMatch::Role);
    }
    None
}

/// The bare table name of `schema.table`, as `pg_get_expr` renders it.
fn bare_table(table: &str) -> &str {
    table.rsplit('.').next().unwrap_or(table)
}

/// Lower-cases, collapses whitespace, unwraps `(select auth.x() as x)`,
/// drops casts and strips redundant outer parentheses, so the shapes
/// `pg_get_expr` renders compare as text.
fn normalize(expr: &str) -> String {
    let mut text = expr
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    for function in ["uid", "role", "jwt", "email"] {
        for wrapped in [
            format!("( select auth.{function}() as {function})"),
            format!("(select auth.{function}() as {function})"),
            format!("( select auth.{function}())"),
            format!("(select auth.{function}())"),
        ] {
            text = text.replace(&wrapped, &format!("auth.{function}()"));
        }
    }
    text = strip_casts(&text);
    strip_outer_parens(text.trim())
}

fn strip_casts(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("::") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '"'))
            .unwrap_or(after.len());
        rest = after[end..]
            .strip_prefix(" varying")
            .unwrap_or(&after[end..]);
        rest = rest.strip_prefix("[]").unwrap_or(rest);
    }
    out.push_str(rest);
    out
}

fn strip_outer_parens(text: &str) -> String {
    let mut text = text.trim();
    while text.starts_with('(') && text.ends_with(')') && encloses(text) {
        text = text[1..text.len() - 1].trim();
    }
    text.to_owned()
}

/// The first `(` closes at the last character.
fn encloses(text: &str) -> bool {
    let mut depth = 0usize;
    for (index, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return index == text.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// `auth.uid() = column` either way round, nothing else.
fn owner_column(expr: &str) -> Option<String> {
    if expr.contains(" and ") || expr.contains(" or ") || expr.contains("select ") {
        return None;
    }
    let (left, right) = expr.split_once(" = ")?;
    let (left, right) = (strip_outer_parens(left), strip_outer_parens(right));
    let column = if left == "auth.uid()" {
        right
    } else if right == "auth.uid()" {
        left
    } else {
        return None;
    };
    let column = column.rsplit('.').next()?.trim_matches('"');
    let identifier = !column.is_empty()
        && column
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    identifier.then(|| column.to_owned())
}

/// The words in a table name that say it holds memberships.
const MEMBERSHIP_WORDS: &[&str] = &[
    "member",
    "team",
    "org",
    "tenant",
    "workspace",
    "group",
    "account",
    "collaborator",
];

/// Whether a table's name says it holds memberships.
fn is_membership_table(name: &str) -> bool {
    MEMBERSHIP_WORDS
        .iter()
        .any(|word| name.to_lowercase().contains(word))
}

/// The table a subquery reads from, when its name says it holds
/// memberships.
fn membership_table(expr: &str) -> Option<String> {
    if !expr.contains("select ") {
        return None;
    }
    let mut rest = expr;
    while let Some(at) = rest.find(" from ") {
        rest = &rest[at + 6..];
        let table: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '"'))
            .collect();
        let bare = table.rsplit('.').next().unwrap_or(&table).trim_matches('"');
        if is_membership_table(bare) {
            return Some(bare.to_owned());
        }
    }
    None
}

/// Splits `text` on ` sep ` at parenthesis depth 0, outside single-quoted
/// strings; each piece is trimmed and stripped of redundant outer parens.
fn split_top_level(text: &str, sep: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let separator: Vec<char> = format!(" {sep} ").chars().collect();
    let mut pieces = Vec::new();
    let (mut start, mut depth, mut in_string, mut index) = (0usize, 0i32, false, 0usize);
    while index < chars.len() {
        let c = chars[index];
        if in_string {
            if c == '\'' {
                if chars.get(index + 1) == Some(&'\'') {
                    index += 2;
                    continue;
                }
                in_string = false;
            }
            index += 1;
            continue;
        }
        match c {
            '\'' => in_string = true,
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && chars.get(index..index + separator.len()) == Some(separator.as_slice()) {
            pieces.push(strip_outer_parens(
                chars[start..index].iter().collect::<String>().trim(),
            ));
            index += separator.len();
            start = index;
            continue;
        }
        index += 1;
    }
    pieces.push(strip_outer_parens(
        chars[start..].iter().collect::<String>().trim(),
    ));
    pieces
}

/// A bare identifier (`[a-z0-9_]`, optionally double-quoted); literals are
/// refused.
fn identifier(text: &str) -> Option<String> {
    let text = text.trim();
    let inner = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(text);
    (!inner.is_empty()
        && !matches!(inner, "true" | "false" | "null")
        && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then(|| inner.to_owned())
}

/// `qualifier.column`, or a bare `column`; a `schema.table` reads as its table.
fn column_ref(text: &str) -> Option<(Option<String>, String)> {
    let text = strip_outer_parens(text.trim());
    let (qualifier, column) = match text.rsplit_once('.') {
        Some((qualifier, column)) => (Some(identifier(qualifier)?), column),
        None => (None, text.as_str()),
    };
    Some((qualifier, identifier(column)?))
}

/// The column of `text`, its qualifier being `name` (or, if `or_bare`, absent).
/// A bare SQL session keyword is not a column.
fn column_of(text: &str, name: &str, or_bare: bool) -> Option<String> {
    let (qualifier, column) = column_ref(text)?;
    match qualifier.as_deref() {
        Some(found) if found == name => Some(column),
        None if or_bare && !is_session_keyword(&column) => Some(column),
        _ => None,
    }
}

/// A SQL keyword that names the session, not a column of the row.
fn is_session_keyword(name: &str) -> bool {
    matches!(
        name,
        "current_user"
            | "session_user"
            | "current_role"
            | "user"
            | "current_schema"
            | "current_catalog"
    )
}

/// `<table> [<alias>]`; the qualifier is the alias, or the table's own name.
fn from_qualifier(from: &str) -> Option<(String, String)> {
    let tokens: Vec<&str> = from.split_whitespace().collect();
    let table = column_ref(tokens.first()?)?.1;
    match tokens.as_slice() {
        [_] => Some((table.clone(), table)),
        [_, alias] => Some((table, identifier(alias)?)),
        _ => None,
    }
}

/// `exists ( select 1 from <from> where <and-conjuncts> )`.
fn exists_parts(expr: &str) -> Option<(String, Vec<String>)> {
    let inner = expr.strip_prefix("exists (")?.strip_suffix(')')?;
    let select = inner.trim().strip_prefix("select 1 from ")?;
    let mut parts = split_top_level(select, "where").into_iter();
    let from = parts.next()?;
    let cond = parts.next()?;
    parts
        .next()
        .is_none()
        .then(|| (from, split_top_level(&cond, "and")))
}

/// The join `<alias>.id = <table>.<fk>` (either order); the fk column on the
/// policy's own table, which must not be that table's `id`.
fn parent_join(conjunct: &str, qualifier: &str, table: &str) -> Option<String> {
    let text = strip_outer_parens(conjunct.trim());
    let (left, right) = text.split_once(" = ")?;
    [(left, right), (right, left)]
        .into_iter()
        .find_map(|(fk, parent)| {
            let fk = column_of(fk, table, false)?;
            (fk != "id" && column_of(parent, qualifier, false).as_deref() == Some("id"))
                .then_some(fk)
        })
}

/// `<alias>.<column> = auth.uid()` (either order); the column.
fn uid_column(conjunct: &str, qualifier: &str) -> Option<String> {
    let text = strip_outer_parens(conjunct.trim());
    let (left, right) = text.split_once(" = ")?;
    if strip_outer_parens(right.trim()) == "auth.uid()" {
        return column_of(left, qualifier, false);
    }
    if strip_outer_parens(left.trim()) == "auth.uid()" {
        return column_of(right, qualifier, false);
    }
    None
}

/// `<column> = any (array['a', 'b'])` on the qualifier; the roles.
fn roles_in(conjunct: &str, qualifier: &str) -> Option<Vec<String>> {
    let text = strip_outer_parens(conjunct.trim());
    let (left, right) = text.split_once("= any")?;
    column_of(left, qualifier, false)?;
    let inner = strip_outer_parens(right.trim());
    let inner = strip_outer_parens(inner.trim());
    let inner = inner.strip_prefix("array[")?.strip_suffix(']')?;
    let roles: Option<Vec<String>> = inner
        .split(',')
        .map(|part| {
            part.trim()
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
                .map(str::to_owned)
        })
        .collect();
    roles.filter(|roles| !roles.is_empty())
}

/// The parent's table, the fk into it, its qualifier and the conjuncts other
/// than the `<parent>.id = <table>.<fk>` join.
fn parent_parts(
    from: &str,
    conjuncts: &[String],
    table: &str,
) -> Option<(String, String, String, Vec<String>)> {
    let (parent, qualifier) = from_qualifier(from)?;
    let index = conjuncts
        .iter()
        .position(|conjunct| parent_join(conjunct, &qualifier, table).is_some())?;
    let fk = parent_join(&conjuncts[index], &qualifier, table)?;
    let rest = conjuncts
        .iter()
        .enumerate()
        .filter(|(at, _)| *at != index)
        .map(|(_, conjunct)| conjunct.clone())
        .collect();
    Some((parent, fk, qualifier, rest))
}

/// Ownership (`<alias>.<owner> = auth.uid()`) or membership through a parent
/// row, sharing the `exists ( select 1 from … )` parse.
fn parent_match(expr: &str, input: &PolicyInput<'_>) -> Option<RuleMatch> {
    let table = bare_table(input.table);
    let (from, conjuncts) = exists_parts(expr)?;
    if let Some((parent, fk, qualifier, rest)) = parent_parts(&from, &conjuncts, table)
        && let [only] = rest.as_slice()
        && let Some(owner) = uid_column(only, &qualifier)
    {
        return Some(RuleMatch::OwnerViaParent { parent, fk, owner });
    }
    let mut joins = split_top_level(&from, "join").into_iter();
    let (parent_part, membership_on) = (joins.next()?, joins.next()?);
    if joins.next().is_some() {
        return None;
    }
    let mut on = split_top_level(&membership_on, "on").into_iter();
    let (membership_part, on_cond) = (on.next()?, on.next()?);
    if on.next().is_some() {
        return None;
    }
    let (parent, parent_qualifier) = from_qualifier(&parent_part)?;
    let (membership, membership_qualifier) = from_qualifier(&membership_part)?;
    if !is_membership_table(&membership) || !(2..=3).contains(&conjuncts.len()) {
        return None;
    }
    let on_cond = strip_outer_parens(&on_cond);
    let (left, right) = on_cond.split_once(" = ")?;
    let tenant_column = column_of(left, &membership_qualifier, false)
        .filter(|_| column_of(right, &parent_qualifier, false).is_some())
        .or_else(|| {
            column_of(right, &membership_qualifier, false)
                .filter(|_| column_of(left, &parent_qualifier, false).is_some())
        })?;
    let mut fk = None;
    let mut uid = false;
    let mut roles = Vec::new();
    for conjunct in &conjuncts {
        if fk.is_none()
            && let Some(found) = parent_join(conjunct, &parent_qualifier, table)
        {
            fk = Some(found);
            continue;
        }
        if !uid && uid_column(conjunct, &membership_qualifier).is_some() {
            uid = true;
            continue;
        }
        if roles.is_empty()
            && let Some(found) = roles_in(conjunct, &membership_qualifier)
        {
            roles = found;
            continue;
        }
        return None;
    }
    Some(RuleMatch::TenantViaParent {
        parent,
        fk: fk?,
        membership,
        tenant_column,
        roles,
    })
}

/// A literal: a well-formed quoted string, a number, `true`/`false`, an
/// `array[…]` of literals, or a comma-separated list of them.
fn literal(text: &str) -> bool {
    let text = strip_outer_parens(text.trim());
    if quoted(&text)
        || matches!(text.as_str(), "true" | "false")
        || (text.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '.')
            && text.parse::<f64>().is_ok())
    {
        return true;
    }
    if let Some(inner) = text
        .strip_prefix("array[")
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return !inner.trim().is_empty() && inner.split(',').all(literal);
    }
    text.contains(',') && text.split(',').all(literal)
}

/// A single quoted literal: `''` is an escape, any other interior quote ends
/// it early (so a surrounding quote pair does not make text a literal).
fn quoted(text: &str) -> bool {
    let Some(inner) = text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')) else {
        return false;
    };
    let chars: Vec<char> = inner.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\'' {
            if chars.get(index + 1) == Some(&'\'') {
                index += 2;
                continue;
            }
            return false;
        }
        index += 1;
    }
    true
}

/// One column predicate (`col` bool, `not col`, `col is [not] null`,
/// `col = <> / in / = any` a literal); the column name.
fn simple_predicate(conjunct: &str, qualifier: &str) -> Option<String> {
    let text = strip_outer_parens(conjunct.trim());
    if let Some(column) = text
        .strip_suffix(" is not null")
        .or_else(|| text.strip_suffix(" is null"))
    {
        return column_of(column, qualifier, true);
    }
    if let Some(column) = text.strip_prefix("not ") {
        return column_of(column, qualifier, true);
    }
    if let Some((left, right)) = text.split_once("= any") {
        let column = column_of(left, qualifier, true)?;
        return literal(right).then_some(column);
    }
    for operator in [" = ", " <> ", " in "] {
        if let Some((left, right)) = text.split_once(operator) {
            let column = column_of(left, qualifier, true)?;
            return literal(right).then_some(column);
        }
    }
    column_of(&text, qualifier, true)
}

/// A public read bounded by simple column predicates, optionally through a
/// parent row's filter.
fn public_read_filtered(expr: &str, input: &PolicyInput<'_>) -> Option<RuleMatch> {
    if !input.command.eq_ignore_ascii_case("select") || expr.contains("auth.") {
        return None;
    }
    let table = bare_table(input.table);
    let signed_in = input.roles.len() == 1 && input.roles[0] == "authenticated";
    if let Some((from, conjuncts)) = exists_parts(expr) {
        if conjuncts.len() < 2 {
            return None;
        }
        let (parent, fk, qualifier, rest) = parent_parts(&from, &conjuncts, table)?;
        let columns = rest
            .iter()
            .map(|conjunct| simple_predicate(conjunct, &qualifier))
            .collect::<Option<Vec<_>>>()?;
        return Some(RuleMatch::PublicReadFiltered {
            columns,
            parent: Some((parent, fk)),
            signed_in,
        });
    }
    let columns = split_top_level(expr, "and")
        .iter()
        .map(|conjunct| simple_predicate(conjunct, table))
        .collect::<Option<Vec<_>>>()?;
    Some(RuleMatch::PublicReadFiltered {
        columns,
        parent: None,
        signed_in,
    })
}

/// A top-level `or` whose every disjunct some rule places; one unplaced,
/// refusing or nested disjunct leaves the whole policy for review.
fn composite(expr: &str, input: &PolicyInput<'_>) -> Option<RuleMatch> {
    let disjuncts = split_top_level(expr, "or");
    if disjuncts.len() < 2 {
        return None;
    }
    let mut parts = Vec::with_capacity(disjuncts.len());
    for disjunct in &disjuncts {
        match match_expression(disjunct, input) {
            Some(matched) if !matches!(matched, RuleMatch::Composite(_) | RuleMatch::DenyAll) => {
                parts.push(matched);
            }
            _ => return None,
        }
    }
    Some(RuleMatch::Composite(parts))
}

/// The classifier's question: one choice over the patterns a person would
/// otherwise decide between.
#[must_use]
pub fn question() -> BTreeMap<String, Question> {
    let criteria = [
        (
            "owner_only",
            "Each row belongs to one user; only that user may access it (for example the \
             signed-in user's id equals an owner column).",
        ),
        (
            "tenant_scoped",
            "Rows belong to a team, organisation or tenant; a user may access them when they \
             are a member, usually through a membership table lookup.",
        ),
        (
            "public_read",
            "Anyone, signed in or not, may read the rows.",
        ),
        (
            "role_based",
            "Access depends on the user's role or a claim in their token, not on which row it \
             is.",
        ),
        (
            "custom_logic",
            "Bespoke logic that none of the other patterns describes: time windows, row state, \
             several conditions combined.",
        ),
    ]
    .into_iter()
    .map(|(label, text)| (label.to_owned(), text.to_owned()))
    .collect();
    BTreeMap::from([(
        QUESTION_ID.to_owned(),
        Question::Choice {
            instructions: "This is a PostgreSQL row-level-security policy from a Supabase \
                           project. Which access pattern does it express?"
                .to_owned(),
            criteria,
        },
    )])
}

/// The text the classifier is given: SQL and names only.
#[must_use]
pub fn state(input: &PolicyInput<'_>) -> String {
    let roles = if input.roles.is_empty() {
        "public".to_owned()
    } else {
        input.roles.join(", ")
    };
    format!(
        "Row-level-security policy on table {table}\ncolumns: {columns}\ncommand: {command}\n\
         roles: {roles}\npermissive: {permissive}\nusing: {using}\nwith check: {check}\n",
        table = input.table,
        columns = input.columns.join(", "),
        command = input.command,
        permissive = input.permissive,
        using = input.using.unwrap_or("(none)"),
        check = input.with_check.unwrap_or("(none)"),
    )
}

/// A failing test stub for one policy: a `todo!()` that names the policy,
/// quotes its expressions as comments and carries the suggested check as
/// advice. It compiles to a test that fails until someone writes it — it
/// is not, and never claims to be, the replacement check.
#[must_use]
pub fn test_stub(input: &PolicyInput<'_>, name: &str, suggested: &str) -> String {
    let mut ident = String::from("rls_");
    for c in format!("{}_{name}", input.table).chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            ident.push(c);
        } else if !ident.ends_with('_') {
            ident.push('_');
        }
    }
    let mut ident = ident.trim_end_matches('_').to_owned();
    ident.truncate(96);
    let roles = if input.roles.is_empty() {
        "public".to_owned()
    } else {
        input.roles.join(", ")
    };
    let mut out = format!(
        "#[tokio::test]\nasync fn {ident}() {{\n    // Supabase RLS policy {name:?} on {table} ({command}, roles: {roles}).\n",
        table = input.table,
        command = input.command,
    );
    for (label, expr) in [("USING", input.using), ("WITH CHECK", input.with_check)] {
        if let Some(expr) = expr {
            let _ = writeln!(out, "    // {label}:");
            for line in expr.lines() {
                let _ = writeln!(out, "    //   {line}");
            }
        }
    }
    let _ = write!(
        out,
        "    // Suggested check (advice, not a translation): {suggested}\n    todo!(\"prove the route refuses what this policy refused, then record the policy as covered\");\n}}\n"
    );
    out
}

fn label_pattern(label: &str) -> Option<PolicyPattern> {
    Some(match label {
        "owner_only" => PolicyPattern::OwnerOnly,
        "tenant_scoped" => PolicyPattern::TenantScoped,
        "public_read" => PolicyPattern::PublicRead,
        "role_based" => PolicyPattern::RoleBased,
        "custom_logic" => PolicyPattern::CustomLogic,
        _ => return None,
    })
}

/// Places one policy: rules first, then the classifier if there is one.
///
/// # Errors
///
/// The classifier's error, as text, when it was asked and failed; the
/// caller records it as a warning and keeps the policy `needs_review`.
pub async fn place(
    input: &PolicyInput<'_>,
    classifier: Option<&dyn Classifier>,
    threshold: f32,
) -> Result<Placement, String> {
    if let Some((pattern, suggested_equivalent)) = match_rules(input) {
        return Ok(Placement {
            pattern,
            confidence: 1.0,
            source: PolicySource::Rule,
            classifier_label: None,
            suggested_equivalent,
        });
    }
    let unplaced = Placement {
        pattern: PolicyPattern::NeedsReview,
        confidence: 0.0,
        source: PolicySource::Rule,
        classifier_label: None,
        suggested_equivalent: suggestion(PolicyPattern::NeedsReview),
    };
    let Some(classifier) = classifier else {
        return Ok(unplaced);
    };
    let answers = classifier
        .ask(&state(input), &question())
        .await
        .map_err(|error| error.to_string())?;
    let Some(answer) = answers.get(QUESTION_ID) else {
        return Err("the classifier returned no answer to the access-pattern question".to_owned());
    };
    let AnswerValue::Choice(label) = &answer.value else {
        return Err("the classifier answered the choice question with another kind".to_owned());
    };
    let confidence = answer.confidence;
    match label_pattern(label) {
        Some(pattern) if confidence >= threshold => Ok(Placement {
            pattern,
            confidence,
            source: PolicySource::Classifier,
            classifier_label: None,
            suggested_equivalent: suggestion(pattern),
        }),
        _ => Ok(Placement {
            confidence,
            source: PolicySource::Classifier,
            classifier_label: Some(label.clone()),
            ..unplaced
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(
        command: &'a str,
        roles: &'a [String],
        using: Option<&'a str>,
        check: Option<&'a str>,
    ) -> PolicyInput<'a> {
        PolicyInput {
            table: "public.t",
            columns: &[],
            command,
            roles,
            permissive: true,
            using,
            with_check: check,
        }
    }

    fn roles(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn pattern(
        command: &str,
        role_names: &[&str],
        using: Option<&str>,
        check: Option<&str>,
    ) -> Option<PolicyPattern> {
        let roles = roles(role_names);
        match_rules(&input(command, &roles, using, check)).map(|(pattern, _)| pattern)
    }

    fn authed(command: &str, expr: &str) -> Option<PolicyPattern> {
        pattern(command, &["authenticated"], Some(expr), None)
    }

    fn public_read(command: &str, expr: &str) -> Option<PolicyPattern> {
        pattern(command, &["public"], Some(expr), None)
    }

    #[test]
    fn owner_only_in_every_rendering() {
        for expr in [
            "(auth.uid() = user_id)",
            "(( SELECT auth.uid() AS uid) = id)",
            "(user_id = auth.uid())",
            "((auth.uid())::text = (owner)::text)",
        ] {
            assert_eq!(
                pattern("SELECT", &["public"], Some(expr), None),
                Some(PolicyPattern::OwnerOnly),
                "{expr}"
            );
        }
    }

    #[test]
    fn tenant_scoped_through_a_membership_table() {
        let expr = "(EXISTS ( SELECT 1 FROM team_members m WHERE ((m.team_id = projects.team_id) \
                    AND (m.user_id = auth.uid()))))";
        assert_eq!(
            pattern("SELECT", &["authenticated"], Some(expr), None),
            Some(PolicyPattern::TenantScoped)
        );
    }

    #[test]
    fn true_is_public_read_or_write_or_signed_in() {
        assert_eq!(
            pattern("SELECT", &["public"], Some("true"), None),
            Some(PolicyPattern::PublicRead)
        );
        assert_eq!(
            pattern("INSERT", &["anon"], None, Some("true")),
            Some(PolicyPattern::PublicWrite)
        );
        assert_eq!(
            pattern("SELECT", &["authenticated"], Some("true"), None),
            Some(PolicyPattern::RoleBased)
        );
    }

    #[test]
    fn claims_and_the_service_role() {
        assert_eq!(
            pattern(
                "DELETE",
                &["public"],
                Some("(((auth.jwt() -> 'app_metadata'::text) ->> 'role'::text) = 'admin'::text)"),
                None
            ),
            Some(PolicyPattern::RoleBased)
        );
        assert_eq!(
            pattern(
                "ALL",
                &["public"],
                Some("(auth.role() = 'service_role'::text)"),
                None
            ),
            Some(PolicyPattern::ServiceRoleOnly)
        );
        assert_eq!(
            pattern("ALL", &["service_role"], Some("(status = 'x')"), None),
            Some(PolicyPattern::ServiceRoleOnly)
        );
    }

    #[test]
    fn disagreement_and_bespoke_logic_are_left_for_review() {
        assert_eq!(
            pattern(
                "UPDATE",
                &["public"],
                Some("(auth.uid() = owner)"),
                Some("true")
            ),
            None
        );
        assert_eq!(
            pattern(
                "SELECT",
                &["public"],
                Some(
                    "((status <> 'archived'::text) OR (created_at > (now() - '30 days'::interval)))"
                ),
                None
            ),
            None
        );
        // An owner check AND-ed with more is not owner-only.
        assert_eq!(
            pattern(
                "SELECT",
                &["public"],
                Some("((auth.uid() = owner) AND (deleted_at IS NULL))"),
                None
            ),
            None
        );
    }

    #[test]
    fn the_question_is_valid_for_every_adapter() {
        cratefield_core::validate_questions(&question()).expect("valid question set");
    }

    #[test]
    fn the_new_shapes_and_their_edges() {
        // Renderings the fixture lacks: the parent's own name as the
        // qualifier, and a single-element role array.
        let bare = "(EXISTS ( SELECT 1 FROM parents WHERE ((parents.id = t.parent_id) AND (parents.owner_id = auth.uid()))))";
        assert_eq!(authed("SELECT", bare), Some(PolicyPattern::OwnerViaParent));
        let one = "(visibility = ANY (ARRAY['public'::text]))";
        assert_eq!(
            public_read("SELECT", one),
            Some(PolicyPattern::PublicReadFiltered)
        );
        // A filtered write, a function-call predicate, and storage's bucket
        // filter paired with an owner check are not filtered reads.
        assert_eq!(
            pattern("UPDATE", &["public"], Some("(is_active = true)"), None),
            None
        );
        assert_eq!(
            pattern("INSERT", &["public"], None, Some("(is_active = true)")),
            None
        );
        assert_eq!(public_read("SELECT", "(created_at > now())"), None);
        let storage = "((bucket_id = 'avatars'::text) AND (( SELECT auth.uid() AS uid) = owner))";
        assert_eq!(
            pattern("INSERT", &["authenticated"], None, Some(storage)),
            None
        );
        // `false` with `WITH CHECK (true)` disagrees: still for review.
        assert_eq!(
            pattern("UPDATE", &["public"], Some("false"), Some("true")),
            None
        );
        // An unplaced or refusing disjunct leaves the whole policy for review.
        let loose =
            "((status <> 'archived'::text) OR (created_at > (now() - '30 days'::interval)))";
        assert_eq!(public_read("SELECT", loose), None);
        assert_eq!(authed("SELECT", "(false OR (auth.uid() = user_id))"), None);
        // A quote pair does not straddle an `or` into one literal: the `or`
        // is nested, so no rule places the policy.
        let nested = "((a = 'x' or b = 'y') AND (c = 'z'))";
        assert_eq!(public_read("SELECT", nested), None);
        // SQL session keywords are not columns, bare or compared, in the
        // policy or in a parent's filter.
        for expr in [
            "(current_user = 'admin')",
            "(current_user)",
            "(session_user = 'x')",
            "(user = 'x')",
            "(current_role = 'x')",
            "(EXISTS ( SELECT 1 FROM parents p WHERE ((p.id = t.parent_id) AND (current_user = 'x'))))",
        ] {
            assert_eq!(public_read("SELECT", expr), None, "{expr}");
        }
        let roles = roles(&["authenticated"]);
        // The join must run `parent.id` -> this table's fk, not the reverse.
        let inverted = "(EXISTS ( SELECT 1 FROM acls a WHERE ((a.user_id = auth.uid()) AND (a.project_id = projects.id))))";
        let projects = PolicyInput {
            table: "public.projects",
            ..input("SELECT", &roles, Some(inverted), None)
        };
        assert_eq!(match_rules(&projects).map(|(pattern, _)| pattern), None);
        // The new rules do not place restrictive policies.
        let restrictive = PolicyInput {
            permissive: false,
            ..input("SELECT", &roles, Some("(is_active = true)"), None)
        };
        assert_eq!(match_rules(&restrictive).map(|(pattern, _)| pattern), None);
    }

    #[test]
    fn one_readable_side_does_not_carry_an_unreadable_one() {
        // USING is owner-only and WITH CHECK a shape only the new rules read:
        // the two sides disagree, so neither labels the policy.
        let owner = "(auth.uid() = user_id)";
        let parent = "(EXISTS ( SELECT 1 FROM parents p WHERE ((p.id = t.parent_id) AND (p.owner_id = auth.uid()))))";
        assert_eq!(
            pattern("INSERT", &["authenticated"], Some(owner), Some(parent)),
            None
        );
    }

    #[test]
    fn the_new_suggestions_name_their_specifics() {
        let role_names = roles(&["authenticated"]);
        let owner = "(EXISTS ( SELECT 1 FROM api_clients c WHERE ((c.id = api_keys.api_client_id) AND (c.owner_user_id = auth.uid()))))";
        let input = PolicyInput {
            table: "public.api_keys",
            columns: &[],
            command: "SELECT",
            roles: &role_names,
            permissive: true,
            using: Some(owner),
            with_check: None,
        };
        let (pattern, suggestion) = match_rules(&input).expect("placed");
        assert_eq!(pattern, PolicyPattern::OwnerViaParent);
        for needle in ["api_clients", "api_client_id", "owner_user_id"] {
            assert!(
                suggestion.contains(needle),
                "{needle} missing: {suggestion}"
            );
        }
        let input = PolicyInput {
            table: "public.courses",
            using: Some("(is_active = true)"),
            ..input
        };
        let (_, suggestion) = match_rules(&input).expect("placed");
        assert!(
            suggestion.contains("signed-in subjects only"),
            "{suggestion}"
        );
    }

    #[test]
    fn the_earthos_fixture_places_the_unplaced() {
        let fixture = include_str!("../tests/fixtures/earthos-policies.tsv");
        let mut unplaced_before = 0usize;
        let mut unplaced_after = 0usize;
        for line in fixture.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') || line.starts_with("table\t") {
                continue;
            }
            let cells: Vec<&str> = line.split('\t').collect();
            assert_eq!(
                cells.len(),
                8,
                "fixture row has {} cells: {line}",
                cells.len()
            );
            let roles: Vec<String> = if cells[3].is_empty() {
                Vec::new()
            } else {
                cells[3]
                    .split(',')
                    .map(|role| role.trim().to_owned())
                    .collect()
            };
            let table = format!("public.{}", cells[0]);
            let input = PolicyInput {
                table: &table,
                columns: &[],
                command: cells[2],
                roles: &roles,
                permissive: true,
                using: (!cells[4].is_empty()).then_some(cells[4]),
                with_check: (!cells[5].is_empty()).then_some(cells[5]),
            };
            let actual = match_rules(&input).map_or_else(
                || "needs_review".to_owned(),
                |(pattern, _)| pattern_name(pattern),
            );
            // The column under test: `before` while the change is developed,
            // `after` once the new rules are in.
            assert_eq!(actual, cells[7], "{} on {table}", cells[1]);
            if cells[6] == "needs_review" {
                unplaced_before += 1;
            } else {
                assert_eq!(
                    cells[6], cells[7],
                    "an already-placed row changed: {} on {table}",
                    cells[1]
                );
            }
            if cells[7] == "needs_review" {
                unplaced_after += 1;
            }
        }
        assert_eq!(unplaced_before, 66, "needs_review rows before the change");
        assert!(
            unplaced_after <= 6,
            "needs_review rows after the change: {unplaced_after}"
        );
    }
}
