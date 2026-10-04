//! The clock, the id generator and the one RFC 3339 spelling this module
//! writes — in one place, on the pattern of `module-notifications`' own
//! `clock.rs`.
//!
//! Every stored timestamp is `Rfc3339` with the sub-second part dropped,
//! because lexicographic order on that spelling is chronological order,
//! and that is what every `next_attempt_at` compare in the drain relies
//! on.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The RFC 3339 spelling the module stores, to the second.
#[must_use]
pub(crate) fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn stored_timestamps_are_second_resolution_rfc3339() {
        assert_eq!(
            iso(datetime!(2026-09-27 12:00:00.5 UTC)),
            "2026-09-27T12:00:00Z"
        );
    }
}
