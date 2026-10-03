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
//! only. A match has confidence 1.0.
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
            other => suggestion(other.pattern()),
        }
    }
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
        PolicyPattern::CustomLogic => "a hand-written check in the route reproducing the \
                                       expression; write its failing test first"
            .to_owned(),
        PolicyPattern::NeedsReview => "read the expression and write the equivalent route \
                                       check, with a failing test first"
            .to_owned(),
    }
}

/// Places a policy by rule alone. `None` when no rule matched.
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
    let placed = match (using, check) {
        (Some(Some(a)), Some(Some(b))) if a.pattern() == b.pattern() => a,
        (Some(Some(a)), None) | (None, Some(Some(a))) => a,
        _ => return None,
    };
    Some((placed.pattern(), placed.suggestion()))
}

fn match_expression(expr: &str, input: &PolicyInput<'_>) -> Option<RuleMatch> {
    let expr = normalize(expr);
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
    if let Some(column) = owner_column(&expr) {
        return Some(RuleMatch::Owner(column));
    }
    if expr.contains("auth.uid()")
        && let Some(table) = membership_table(&expr)
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

/// The table a subquery reads from, when its name says it holds
/// memberships.
fn membership_table(expr: &str) -> Option<String> {
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
        if MEMBERSHIP_WORDS.iter().any(|word| bare.contains(word)) {
            return Some(bare.to_owned());
        }
    }
    None
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
}
