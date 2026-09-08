//! LinkedIn URN handling (issues #7, #15).
//!
//! Two things bite here. Rest.li wants URNs percent-encoded inside a path or
//! a query value, but leaves the commas of a `List(...)` alone. And since
//! January 2024 the organizationBrand API is gone: `urn:li:organizationBrand:{id}`
//! addresses the same entity as `urn:li:organization:{id}`, so a showcase page
//! supplied in the old spelling has to keep working everywhere.

/// Percent-encodes a URN for use in a path segment or a query value.
/// Only the characters Rest.li actually objects to are touched, so
/// `List(a,b)` keeps its commas and parentheses.
pub(crate) fn encode(urn: &str) -> String {
    let mut out = String::with_capacity(urn.len() + 8);
    for ch in urn.chars() {
        match ch {
            ':' => out.push_str("%3A"),
            '(' => out.push_str("%28"),
            ')' => out.push_str("%29"),
            ' ' => out.push_str("%20"),
            _ => out.push(ch),
        }
    }
    out
}

/// The numeric organization id behind any accepted page spelling.
pub(crate) fn page_id(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let candidate = if let Some(rest) = trimmed.strip_prefix("urn:li:organizationBrand:") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("urn:li:organization:") {
        rest
    } else {
        trimmed
    };
    if !candidate.is_empty() && candidate.bytes().all(|b| b.is_ascii_digit()) {
        Some(candidate.to_owned())
    } else {
        None
    }
}

/// The id part of any `urn:li:<type>:<id>`; used for image and post URNs
/// where the type is not ours to choose.
pub(crate) fn urn_id(urn: &str) -> Option<&str> {
    urn.rsplit_once(':')
        .map(|(_, id)| id)
        .filter(|id| !id.is_empty())
}

/// Whether a URN names a post: LinkedIn returns either spelling from the
/// same endpoints and both are addressable.
pub(crate) fn is_post_urn(urn: &str) -> bool {
    (urn.starts_with("urn:li:share:") || urn.starts_with("urn:li:ugcPost:"))
        && urn_id(urn).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_only_what_restli_objects_to() {
        assert_eq!(encode("urn:li:ugcPost:123"), "urn%3Ali%3AugcPost%3A123");
        assert_eq!(encode("plain-value_1"), "plain-value_1");
    }

    #[test]
    fn brand_and_organization_urns_are_the_same_page() {
        // The organizationBrand API was deprecated in January 2024 and its
        // URNs now address the same entity, so every spelling has to resolve
        // to one id or old links and old notes stop working.
        assert_eq!(page_id("urn:li:organization:123").as_deref(), Some("123"));
        assert_eq!(
            page_id("urn:li:organizationBrand:123").as_deref(),
            Some("123")
        );
        assert_eq!(page_id("123").as_deref(), Some("123"));
        assert_eq!(
            page_id("  urn:li:organization:123  ").as_deref(),
            Some("123")
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_page() {
        assert!(page_id("urn:li:person:abc").is_none());
        assert!(page_id("urn:li:organization:abc").is_none());
        assert!(page_id("").is_none());
        assert!(page_id("../../etc").is_none());
        assert!(page_id("12 OR 1=1").is_none());
    }

    #[test]
    fn post_urns_are_recognized_in_both_spellings() {
        assert!(is_post_urn("urn:li:share:6844785523593134080"));
        assert!(is_post_urn("urn:li:ugcPost:68447855235931240"));
        assert!(!is_post_urn("urn:li:organization:123"));
        assert!(!is_post_urn("urn:li:share:"));
    }
}
