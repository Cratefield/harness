//! Consent for aggregate usage reporting (issue #413): the decision, the
//! notice and the status rendering, all pure. Nothing here reads
//! `std::env`, opens a connection or touches the network — the decision
//! runs over an [`Environment`] its caller built, so the same code decides
//! on a laptop, in continuous integration and on wasm, and a rule that
//! never makes a request cannot leak one on the way to deciding not to
//! report.

use time::OffsetDateTime;

use crate::handlers::Settings;
use crate::payload::{self, Batch};

/// How many days one install id lives (issue #413). Rotation bounds how
/// long any one id can accumulate; nothing anywhere stores the link
/// between one id and the next, which is the point of rotating it.
pub const ROTATION_DAYS: u32 = 30;

/// Whether this client reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// Reporting is on: the person has not said no anywhere.
    On,
    /// Reporting is off, for the stated reason.
    Off(OffBecause),
}

/// Why reporting is off, in the order the decision checks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffBecause {
    /// The person switched it off on this machine.
    OptedOut,
    /// `DO_NOT_TRACK` is set: a standing industry-wide opt-out, honoured
    /// verbatim.
    DoNotTrack,
    /// `CI` is set: an automated environment has not consented to anything.
    ContinuousIntegration,
}

impl OffBecause {
    /// The fixed sentence printed with the off state.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::OptedOut => "reporting was switched off on this machine",
            Self::DoNotTrack => "the DO_NOT_TRACK environment variable is set",
            Self::ContinuousIntegration => {
                "the CI environment variable is set: an automated environment has not \
                 consented to anything"
            }
        }
    }
}

/// The inputs [`decide`] reads: the two environment variables that matter
/// and the local opt-out. Built through [`Environment::from_vars`] so the
/// decision itself never touches `std::env`, and a test can hand it a map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// `DO_NOT_TRACK`, if the variable is present at all.
    pub do_not_track: Option<String>,
    /// `CI`, if the variable is present at all.
    pub ci: Option<String>,
    /// Whether the person opted out on this machine.
    pub opted_out: bool,
}

impl Environment {
    /// Builds the environment through a lookup the caller supplies —
    /// `std::env::var` in production, a map in a test.
    #[must_use]
    pub fn from_vars(get: impl Fn(&str) -> Option<String>, opted_out: bool) -> Self {
        Self {
            do_not_track: get("DO_NOT_TRACK"),
            ci: get("CI"),
            opted_out,
        }
    }
}

/// Whether a variable counts as set: present, non-empty after trimming,
/// and neither `0` nor `false` (ASCII case-insensitive). A vendor that
/// exports `CI=false` switches nothing, and neither does an empty
/// `DO_NOT_TRACK=` left in a dotfile — a value that names "no" must not
/// act as a yes.
fn is_set(raw: Option<&str>) -> bool {
    raw.map(str::trim).is_some_and(|value| {
        !value.is_empty()
            && !value.eq_ignore_ascii_case("0")
            && !value.eq_ignore_ascii_case("false")
    })
}

/// The consent decision, in a fixed precedence (issue #413): the person's
/// own opt-out first — it beats everything and needs no network, because a
/// switch that only worked offline some of the time would not be one —
/// then `DO_NOT_TRACK`, then `CI`.
#[must_use]
pub fn decide(env: &Environment) -> Consent {
    if env.opted_out {
        Consent::Off(OffBecause::OptedOut)
    } else if is_set(env.do_not_track.as_deref()) {
        Consent::Off(OffBecause::DoNotTrack)
    } else if is_set(env.ci.as_deref()) {
        Consent::Off(OffBecause::ContinuousIntegration)
    } else {
        Consent::On
    }
}

/// The install id the caller minted, as the 32 lowercase hex characters
/// the payload grammar accepts. The bytes are the caller's: this crate
/// generates no randomness — it must stay wasm-safe and dependency-free —
/// and the id is deliberately never derived from the hostname, a MAC
/// address, an account or anything else about the machine, because an id
/// derived from hardware is a tracking id wearing a random costume.
#[must_use]
pub fn install_id_from_bytes(bytes: [u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// Whether a string is a well-formed install id: exactly 32 lowercase hex
/// characters, the grammar [`crate::payload::Batch::parse`] enforces.
#[must_use]
pub fn install_id_is_valid(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether the id minted at `minted_at` is due for rotation at `now`.
/// Due on the boundary, not after it, so a client that checks daily never
/// carries an id past its thirtieth day.
#[must_use]
pub fn rotation_due(minted_at: OffsetDateTime, now: OffsetDateTime) -> bool {
    now - minted_at >= time::Duration::days(i64::from(ROTATION_DAYS))
}

/// The first-run notice: every field the payload can carry, with its
/// permitted vocabulary — generated from the schema so the text cannot
/// drift from the parser — what is never sent, the rotation interval, and
/// the one-line opt-out. Printable with no network: consent that needs a
/// round trip to be checked is not consent.
#[must_use]
pub fn notice(settings: &Settings) -> String {
    use std::fmt::Write as _;
    let mut text = String::from(
        "This client counts which of this venture's named commands ran — and nothing \
         else. Every batch it sends carries only:\n",
    );
    for field in payload::fields(&settings.vocabulary) {
        if field.values.is_empty() {
            let _ = write!(text, "\n  {} — {}", field.path, field.rule);
        } else {
            let _ = write!(
                text,
                "\n  {} — one of: {}",
                field.path,
                field.values.join(", ")
            );
            if !field.rule.is_empty() {
                let _ = write!(text, " ({})", field.rule);
            }
        }
    }
    let _ = write!(
        text,
        "\n\nNo identifier, path, repository or branch name, prompt, model output, \
         commit or issue text, or free text of any kind is sent: every field above is \
         one value from a closed list, and anything else is rejected, never trimmed or \
         stored. The install id is pseudonymous, with no stored link to a person, and \
         is replaced every {ROTATION_DAYS} days."
    );
    let _ = write!(
        text,
        "\n\nReporting is on by default. It honours the DO_NOT_TRACK and CI environment \
         variables without further configuration, and switching it off is local: no \
         network call is made, and nothing is sent afterwards.\n\nTurn it off: {}\nSee \
         exactly what would be sent: {}",
        settings.opt_out_command, settings.status_command
    );
    text
}

/// The `telemetry status` rendering: the state, the reason if off, then
/// the pending payload as pretty JSON — the same bytes the sender would
/// POST, from the same serializer. Nobody has to trust a description of
/// the data when the data itself is one command away.
#[must_use]
pub fn status(consent: &Consent, pending: &Batch) -> String {
    let state = match consent {
        Consent::On => "on".to_owned(),
        Consent::Off(because) => format!("off ({})", because.reason()),
    };
    format!("telemetry: {state}\n{}", payload::to_wire(pending))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{
        Arch, Client, ClientKind, ErrorKind, EventRecord, Outcome, Platform, Version,
    };

    fn vars<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    fn batch() -> Batch {
        Batch {
            schema: payload::SCHEMA,
            install: install_id_from_bytes([7; 16]),
            client: Client {
                kind: ClientKind::Cli,
                version: Version {
                    major: 0,
                    minor: 4,
                    patch: 1,
                },
                platform: Platform::Linux,
                arch: Arch::Aarch64,
            },
            modules: vec!["telemetry".to_owned()],
            events: vec![EventRecord {
                name: "run".to_owned(),
                outcome: Outcome::Ok,
                error: ErrorKind::None,
                duration: crate::payload::DurationBucket::Unknown,
                count: 1,
            }],
        }
    }

    #[test]
    fn the_local_opt_out_beats_everything() {
        // The person's own switch wins even when the environment says
        // nothing and when it says both of the other things.
        assert_eq!(
            decide(&Environment {
                opted_out: true,
                ..Environment::default()
            }),
            Consent::Off(OffBecause::OptedOut)
        );
        assert_eq!(
            decide(&Environment::from_vars(
                vars(&[("DO_NOT_TRACK", "1"), ("CI", "1")]),
                true,
            )),
            Consent::Off(OffBecause::OptedOut)
        );
    }

    #[test]
    fn do_not_track_beats_ci() {
        assert_eq!(
            decide(&Environment::from_vars(
                vars(&[("DO_NOT_TRACK", "1"), ("CI", "1")]),
                false
            )),
            Consent::Off(OffBecause::DoNotTrack)
        );
        assert_eq!(
            decide(&Environment::from_vars(vars(&[("CI", "1")]), false)),
            Consent::Off(OffBecause::ContinuousIntegration)
        );
        assert_eq!(
            decide(&Environment::from_vars(vars(&[]), false)),
            Consent::On
        );
    }

    #[test]
    fn a_value_that_names_no_is_unset() {
        // Empty, zero and false — in any case — must not act as a yes.
        for raw in ["", "   ", "0", "false", "FALSE", "False"] {
            assert_eq!(
                decide(&Environment::from_vars(
                    vars(&[("DO_NOT_TRACK", raw)]),
                    false
                )),
                Consent::On,
                "DO_NOT_TRACK={raw:?} must read as unset"
            );
        }
    }

    #[test]
    fn install_ids_are_random_bytes_never_names() {
        let id =
            install_id_from_bytes([0x7b, 0x0a, 0x1f, 0x2c, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        assert!(install_id_is_valid(&id), "{id}");
        assert_eq!(id.len(), 32);
        assert_eq!(
            id, "7b0a1f2c000102030405060708090a0b",
            "lowercase hex, padded"
        );
        for bad in [
            "",
            "7B0A",
            &"g".repeat(32),
            &"7b".repeat(15),
            &"7b".repeat(17),
        ] {
            assert!(!install_id_is_valid(bad), "{bad:?} is not an install id");
        }
    }

    #[test]
    fn rotation_is_due_on_the_thirtieth_day() {
        let minted = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
        assert!(!rotation_due(
            minted,
            minted + time::Duration::days(i64::from(ROTATION_DAYS) - 1)
        ));
        assert!(rotation_due(
            minted,
            minted + time::Duration::days(i64::from(ROTATION_DAYS))
        ));
        assert!(rotation_due(minted, minted + time::Duration::days(365)));
    }

    #[test]
    fn the_notice_names_what_is_never_sent_and_how_to_stop() {
        let settings = Settings {
            vocabulary: crate::payload::Vocabulary {
                events: vec!["run".to_owned()],
                modules: vec!["telemetry".to_owned()],
                max_events: crate::payload::MAX_EVENTS_PER_BATCH,
            },
            retention_days: 180,
            opt_out_command: "fz telemetry off".to_owned(),
            status_command: "fz telemetry status".to_owned(),
        };
        let text = notice(&settings);
        // The promise is about the categories a payload has no field for.
        for promised in [
            "prompt",
            "model output",
            "commit or issue text",
            "path",
            "free text",
        ] {
            assert!(
                text.contains(promised),
                "the notice must name {promised:?}:\n{text}"
            );
        }
        // The vocabularies are listed, so the notice cannot be vaguer than
        // the parser.
        assert!(text.contains("/events[]/name — one of: run"), "{text}");
        assert!(text.contains("/modules — one of: telemetry"), "{text}");
        // Rotation and the two commands, as printed lines.
        assert!(text.contains("every 30 days"), "{text}");
        assert!(text.contains("Turn it off: fz telemetry off"), "{text}");
        assert!(
            text.contains("See exactly what would be sent: fz telemetry status"),
            "{text}"
        );
    }

    #[test]
    fn status_reports_the_state_and_the_exact_bytes() {
        let pending = batch();
        let out = status(&Consent::On, &pending);
        let (state, json) = out
            .split_once('\n')
            .expect("a status line then the payload");
        assert_eq!(state, "telemetry: on");
        assert_eq!(
            json,
            payload::to_wire(&pending),
            "the status bytes are the wire bytes"
        );

        let out = status(&Consent::Off(OffBecause::DoNotTrack), &pending);
        let (state, json) = out
            .split_once('\n')
            .expect("a status line then the payload");
        assert!(state.contains("DO_NOT_TRACK"), "{state}");
        assert_eq!(
            json,
            payload::to_wire(&pending),
            "off does not change the payload"
        );
    }
}
