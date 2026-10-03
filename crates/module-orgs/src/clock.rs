//! The clock, the id generator and the one RFC 3339 spelling this module
//! writes, in one place.
//!
//! Every timestamp the module stores is `Rfc3339` with the sub-second part
//! dropped: lexicographic order on that spelling is chronological order, which
//! is what every compare in `store.rs` relies on — the invitation's expiry
//! against now, and the listing order the two `ORDER BY created_at` clauses
//! ask for.

use cratefield_core::{Clock as _, IdGen as _, ModuleContext, SystemClock, UlidIdGen};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The RFC 3339 spelling the module stores, to the second.
pub(crate) fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// A stored timestamp back into a time. An unparsable one becomes the epoch,
/// which is before now — so an invitation with a broken deadline reads as
/// lapsed rather than as valid forever.
pub(crate) fn parse(stored: &str) -> OffsetDateTime {
    OffsetDateTime::parse(stored, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Now, through the deployment's `Clock` port when it has one.
pub(crate) fn now(ctx: &ModuleContext) -> String {
    match ctx.ports.clock.as_ref() {
        Some(clock) => iso(clock.now()),
        None => iso(SystemClock.now()),
    }
}

/// A fresh id, through the deployment's `IdGen` port when it has one.
pub(crate) fn new_id(ctx: &ModuleContext) -> String {
    match ctx.ports.id_gen.as_ref() {
        Some(id_gen) => id_gen.ulid(),
        None => UlidIdGen.ulid(),
    }
}

/// `at` plus `seconds`, in the same spelling.
pub(crate) fn plus_secs(at: &str, seconds: i64) -> String {
    iso(parse(at).saturating_add(time::Duration::seconds(seconds)))
}

/// A fresh invitation token. Two ULIDs concatenated: 256 bits of the
/// generator's own randomness, spelled in a form safe to put in a URL, and
/// drawn from the `IdGen` port the module already requires rather than from a
/// CSPRNG core does not carry. The raw value is never stored — only its
/// SHA-256 — so this is the one moment it exists.
pub(crate) fn new_token(ctx: &ModuleContext) -> String {
    format!("{}{}", new_id(ctx), new_id(ctx))
}
