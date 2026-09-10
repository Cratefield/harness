//! The clock, the id generator and the one RFC 3339 spelling this module
//! writes — in one place.
//!
//! Every timestamp the module stores is `Rfc3339` with the sub-second part
//! dropped, because lexicographic order on that spelling is chronological
//! order and that is what every window compare in `store.rs` and every
//! lease compare in the drain relies on. Three call sites used to carry
//! their own copy of "the `Clock` port, or `SystemClock` when a deployment
//! provides none"; a fourth would have been written the next time someone
//! needed a timestamp, and a copy that drifts on the nanosecond truncation
//! is a comparison that silently stops matching.

use std::sync::Arc;

use cratefield_core::{Clock, IdGen, SystemClock, UlidIdGen};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The RFC 3339 spelling the module stores, to the second.
pub(crate) fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// One stored timestamp back into a time. An unparsable one becomes the
/// epoch, which is due and never in the future — a value that makes the
/// drain retry rather than strand a row.
pub(crate) fn parse(stored: &str) -> OffsetDateTime {
    OffsetDateTime::parse(stored, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Now, through the deployment's `Clock` port when it has one.
pub(crate) fn now_iso(clock: Option<&Arc<dyn Clock>>) -> String {
    match clock {
        Some(clock) => iso(clock.now()),
        None => iso(SystemClock.now()),
    }
}

/// Now as Unix seconds, through the deployment's `Clock` port when it has
/// one. The webhook's replay window is in seconds because that is the
/// unit the provider signs, so it does not go through the stored RFC 3339
/// spelling and back.
pub(crate) fn now_unix(clock: Option<&Arc<dyn Clock>>) -> i64 {
    match clock {
        Some(clock) => clock.now().unix_timestamp(),
        None => SystemClock.now().unix_timestamp(),
    }
}

/// A fresh id, through the deployment's `IdGen` port when it has one.
pub(crate) fn new_id(id_gen: Option<&Arc<dyn IdGen>>) -> String {
    match id_gen {
        Some(id_gen) => id_gen.ulid(),
        None => UlidIdGen.ulid(),
    }
}

/// `at` plus `seconds`, in the same spelling.
pub(crate) fn plus_secs(at: &str, seconds: i64) -> String {
    iso(parse(at).saturating_add(time::Duration::seconds(seconds)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_spelling_drops_the_sub_second_part() {
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000)
            .expect("in range")
            .replace_nanosecond(123_456_789)
            .expect("in range");
        assert_eq!(iso(at), "2027-01-15T08:00:00Z");
    }

    #[test]
    fn a_stored_timestamp_round_trips_and_a_broken_one_is_due() {
        let text = "2027-01-15T08:00:00Z";
        assert_eq!(iso(parse(text)), text);
        assert_eq!(parse("not a timestamp"), OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn a_window_is_the_same_arithmetic_everywhere() {
        assert_eq!(
            plus_secs("2027-01-15T08:00:00Z", 300),
            "2027-01-15T08:05:00Z"
        );
        assert_eq!(
            plus_secs("2027-01-15T08:00:00Z", -3_600),
            "2027-01-15T07:00:00Z"
        );
    }
}
