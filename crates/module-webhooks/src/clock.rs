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

/// `now` shifted by `secs` (negative for the past), in the stored spelling.
#[must_use]
pub(crate) fn plus_secs(now: &str, secs: i64) -> String {
    let parsed = OffsetDateTime::parse(now, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    iso(parsed.saturating_add(time::Duration::seconds(secs)))
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

    #[test]
    fn plus_secs_shifts_and_keeps_the_spelling() {
        assert_eq!(
            plus_secs("2026-09-27T12:00:00Z", 30),
            "2026-09-27T12:00:30Z"
        );
        assert_eq!(
            plus_secs("2026-09-27T12:00:00Z", -3_600),
            "2026-09-27T11:00:00Z"
        );
    }

    #[test]
    fn an_unparsable_timestamp_is_treated_as_the_epoch() {
        // Due immediately rather than stranded in the future.
        assert!(plus_secs("not a timestamp", 30).starts_with("1970-01-01"));
    }
}
