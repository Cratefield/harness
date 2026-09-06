//! CSV cell escaping for admin exports (architecture section 11, issue
//! #13 — landed with issue #10 because the first export endpoint needs
//! it).
//!
//! Spreadsheet formula injection: a cell whose first character is one of
//! `= + - @ \t \r` is prefixed with `'` before quoting so Excel, Numbers
//! and Google Sheets render it as text instead of evaluating it.

/// Characters that make a cell a formula when it starts with one of them.
pub const FORMULA_PREFIXES: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Escapes one CSV field: formula-guard, then RFC 4180 quoting.
#[must_use]
pub fn escape(field: &str) -> String {
    let guarded = if field.starts_with(FORMULA_PREFIXES) {
        format!("'{field}")
    } else {
        field.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// Escapes and joins one CSV row, with a trailing newline.
#[must_use]
pub fn row(fields: &[&str]) -> String {
    let mut line = fields
        .iter()
        .map(|field| escape(field))
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_fields_pass_through() {
        assert_eq!(escape("nick@example.com"), "nick@example.com");
        assert_eq!(escape("pending"), "pending");
    }

    #[test]
    fn formula_leading_cells_are_prefixed() {
        for evil in ["=cmd|' /C", "+1", "-1", "@SUM(A1)", "\ttab", "\rCR"] {
            let escaped = escape(evil);
            // Strip RFC 4180 quoting, then the first char must be the guard.
            let unquoted = escaped.trim_matches('"');
            assert!(unquoted.starts_with('\''), "{evil:?} -> {escaped:?}");
            assert!(!unquoted.starts_with(evil.chars().next().unwrap()));
        }
    }

    #[test]
    fn quoting_doubles_embedded_quotes() {
        assert_eq!(escape("a\"b"), "\"a\"\"b\"");
        assert_eq!(escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn formula_guard_applies_before_quoting() {
        // `=a,b` -> `'` prefix -> `'=a,b` contains a comma -> quoted.
        assert_eq!(escape("=a,b"), "\"'=a,b\"");
    }

    #[test]
    fn row_joins_and_terminates() {
        assert_eq!(row(&["a", "=b", "c"]), "a,'=b,c\n");
    }
}
