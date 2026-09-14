//! The non-goal in #44 is one rule, so it is one list.
//!
//! It was two. `cratefield_core::CARD_DATA` is what a declared table's
//! column names are checked against and what `fz doctor` reads;
//! `tools/migration-guard.sh` carried its own pattern for `.sql`
//! migrations. Comparing them, each caught fragments the other missed —
//! `expiry_month`, `cardholder` and `track2` were only in the shell, and
//! `exp_month`, `card_expiry`, `full_pan`, `track_data` and `magstripe`
//! only in Rust. A declared table's DDL never becomes a `.sql` file, so
//! it only ever meets the Rust list: a column named `expiry_month` was
//! accepted by everything.
//!
//! The shell pattern is now written from this list. This is the test that
//! notices when somebody adds a fragment to one of them.

#[test]
fn the_migration_guard_knows_the_same_card_data() {
    let script = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/migration-guard.sh"
    ))
    .expect("the guard is in the repository");
    let line = script
        .lines()
        .find(|line| line.trim_start().starts_with("card_pattern="))
        .expect("the guard still defines card_pattern");

    for fragment in cratefield_core::CARD_DATA {
        assert!(
            line.contains(fragment),
            "`{fragment}` is card data in Rust and not in the migration guard: {line}"
        );
    }

    // And nothing extra, so the shell cannot quietly refuse a column the
    // canonical list allows — a bare `pan` is the one that was there, and
    // an audio pan column is exactly why the list leaves it out.
    let inside = line
        .split_once('(')
        .and_then(|(_, rest)| rest.rsplit_once(')'))
        .map(|(inside, _)| inside)
        .expect("the pattern is an alternation");
    for fragment in inside.split('|') {
        assert!(
            cratefield_core::CARD_DATA.contains(&fragment),
            "the migration guard refuses `{fragment}`, which is not card data here"
        );
    }
}
