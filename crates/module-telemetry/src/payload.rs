//! The batch payload and its closed grammar (issue #413). Every field is
//! validated against a fixed vocabulary — an enum, a bounded count, a
//! duration bucket, a fixed-width hex id or a numeric version triple — and
//! a value outside any of them is a rejection, never a truncation or a
//! coercion. There is no string anywhere a sentence could fit, which is
//! what makes the consent notice short enough to be true: the collector
//! can list every value it will ever hold, because the client sent it.

use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use std::fmt::Display;

use crate::consent::{ROTATION_DAYS, install_id_is_valid};

/// The only payload schema this crate parses. Any other value is its own
/// rejection (and its own problem slug at the route): a schema bump is a
/// new contract, not a hint.
pub const SCHEMA: u32 = 1;

/// The most modules one batch may report (issue #413). A ceiling on the
/// payload, so a client cannot grow it into a list of whatever it wants.
pub const MAX_MODULES: usize = 32;

/// The most event records one batch may carry (issue #413). The ceiling is
/// part of the closed grammar: "at most this many" is what bounds what a
/// single request can do, on a route with no other way to bound it.
pub const MAX_EVENTS_PER_BATCH: usize = 64;

/// The most runs one event record may claim. Bounded so a bad client
/// cannot claim a billion runs in one small, valid-shaped body.
pub const MAX_EVENT_COUNT: u32 = 100_000;

/// Defines a closed enum with a stable wire name, an `ALL` slice and an
/// exhaustive `as_str`, in the shape of `DataKind` in core (issue #413).
/// The wire names are spelled out per variant rather than derived: values
/// like `100ms-1s` cannot come from a Rust identifier, and a renamed wire
/// value is a new contract.
macro_rules! closed_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $(
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The stable wire name.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }

            /// Never called; exists so that adding a variant without
            /// adding it to this match — and so to `ALL` — is a compile
            /// error here rather than a hole in the published vocabulary.
            #[expect(dead_code, reason = "its only job is to be exhaustive")]
            fn every_value_is_in_all(value: Self) {
                match value {
                    $(Self::$variant => {}),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

closed_enum! {
    /// What kind of thing is reporting.
    ClientKind {
        Cli => "cli",
        Desktop => "desktop",
        Agent => "agent",
        Server => "server",
        Browser => "browser",
        Other => "other",
    }
}

closed_enum! {
    /// The operating system family the client runs on.
    Platform {
        Linux => "linux",
        Macos => "macos",
        Windows => "windows",
        Other => "other",
    }
}

closed_enum! {
    /// The instruction set the client runs as. `x86-64` with a hyphen:
    /// the wire name follows the architecture's own spelling.
    Arch {
        X86_64 => "x86-64",
        Aarch64 => "aarch64",
        Other => "other",
    }
}

closed_enum! {
    /// How the run ended.
    Outcome {
        Ok => "ok",
        Error => "error",
        Cancelled => "cancelled",
    }
}

closed_enum! {
    /// Why a run failed — a class, never a message. `None` is the value
    /// that pairs with the `Ok` and `Cancelled` outcomes; see
    /// [`Rejection::ErrorMismatch`] for the rule that binds them.
    ErrorKind {
        None => "none",
        Network => "network",
        Timeout => "timeout",
        Auth => "auth",
        Config => "config",
        Permission => "permission",
        NotFound => "not-found",
        Conflict => "conflict",
        RateLimited => "rate-limited",
        Unsupported => "unsupported",
        Internal => "internal",
        Other => "other",
    }
}

closed_enum! {
    /// How long the run took — a bucket, not a stopwatch. A precise
    /// duration would be a number a client could be talked into padding
    /// with meaning; a bucket is only good for the question it answers.
    DurationBucket {
        Unknown => "unknown",
        Under100ms => "under-100ms",
        S100msTo1s => "100ms-1s",
        S1To10s => "1s-10s",
        S10To1m => "10s-1m",
        S1mTo10m => "1m-10m",
        Over10m => "over-10m",
    }
}

/// A numeric release triple: `MAJOR.MINOR.PATCH`, each part one to six
/// digits, nothing else (issue #413). Pre-release tags and build metadata
/// are free text wearing a semver costume — `1.0.0-beta+homebrew` can
/// carry an opinion about a distribution channel, a flag, an experiment —
/// so a client that has one rounds down to the release triple before
/// reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// The major version.
    pub major: u32,
    /// The minor version.
    pub minor: u32,
    /// The patch version.
    pub patch: u32,
}

impl Version {
    /// Parses a release triple, or nothing: anything but exactly three
    /// dot-separated digit parts — a fourth part, a pre-release tag, build
    /// metadata, an empty part — is no version at all.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (major, rest) = raw.split_once('.')?;
        let (minor, rest) = rest.split_once('.')?;
        // No third dot: a fourth part is metadata or worse, and the
        // grammar above says a client rounds down rather than report it.
        if rest.contains('.') {
            return None;
        }
        Some(Self {
            major: part(major)?,
            minor: part(minor)?,
            patch: part(rest)?,
        })
    }
}

/// One part of a [`Version`]: one to six ASCII digits, which fits a
/// `u32` with room to spare and cannot begin a pre-release tag.
fn part(raw: &str) -> Option<u32> {
    if raw.is_empty() || raw.len() > 6 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Serialize for Version {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        // This path is only exercised on an already-accepted batch's own
        // bytes (the status round trip); the ingest path rejects through
        // [`Rejection`], whose rendering never quotes a value.
        Self::parse(&raw)
            .ok_or_else(|| de::Error::custom("expected a MAJOR.MINOR.PATCH release triple"))
    }
}

/// The client section of a batch: what kind of thing reported, and on
/// what. Every field is a closed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    /// What kind of thing is reporting.
    pub kind: ClientKind,
    /// The release triple the client reports (rounded down, per
    /// [`Version`]).
    pub version: Version,
    /// The operating system family.
    pub platform: Platform,
    /// The instruction set.
    pub arch: Arch,
}

/// One counted event: a named run, how it ended, in which bucket of time,
/// and how many times. The batch is *counted* — one record aggregates many
/// runs — which is why there is no timestamp, no duration number and no
/// message per run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    /// A name from the venture's declared event vocabulary.
    pub name: String,
    /// How the run ended.
    pub outcome: Outcome,
    /// The error class; `None` exactly when the outcome is not `Error`.
    pub error: ErrorKind,
    /// Which bucket of time the run fell into.
    pub duration: DurationBucket,
    /// How many runs this record aggregates, `1..=[MAX_EVENT_COUNT]`.
    pub count: u32,
}

/// A whole reporting batch, version [`SCHEMA`]. Built only by
/// [`Batch::parse`], which enforces the grammar this type's shape can only
/// suggest: the derives exist for the wire format and the status round
/// trip, never as an ingest path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    /// The schema version; always [`SCHEMA`] after a parse.
    pub schema: u32,
    /// The install id: 32 lowercase hex characters.
    pub install: String,
    /// What reported.
    pub client: Client,
    /// Which of the venture's declared modules the client composes, no
    /// duplicates.
    pub modules: Vec<String>,
    /// One or more counted events.
    pub events: Vec<EventRecord>,
}

/// The venture-declared part of the grammar: the event names and composed
/// module names the collector will count, and the batch ceiling. Both
/// lists default to **empty**, which means [`Batch::parse`] rejects every
/// batch naming an event or a module — fail closed, on purpose (issue
/// #413): a vocabulary the venture forgot is a collector that counts
/// nothing, not one that counts anything it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vocabulary {
    /// The event names a batch may count.
    pub events: Vec<String>,
    /// The composed module names a client may report.
    pub modules: Vec<String>,
    /// The batch ceiling; never above [`MAX_EVENTS_PER_BATCH`].
    pub max_events: usize,
}

impl Default for Vocabulary {
    fn default() -> Self {
        // Empty lists, the schema ceiling: the most closed a grammar can
        // be while still being one.
        Self {
            events: Vec::new(),
            modules: Vec::new(),
            max_events: MAX_EVENTS_PER_BATCH,
        }
    }
}

/// Why [`Batch::parse`] refused a batch. The rendering is the contract: a
/// **fixed sentence** that names the field path and the rule, and never
/// echoes the offending value. An error body that quoted what the client
/// sent would be the free-text channel this module exists to close, one
/// `Debug` print away from a log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The body is not a JSON object.
    Body,
    /// A field the schema does not define, at any level.
    UnknownField,
    /// `/schema` is missing or not a number.
    Schema,
    /// `/schema` names a version this collector does not parse.
    SchemaUnsupported,
    /// `/install` is not 32 lowercase hex characters.
    Install,
    /// `/client` is missing or not an object.
    Client,
    /// `/client/kind` is not a declared kind.
    ClientKind,
    /// `/client/version` is not a release triple.
    ClientVersion,
    /// `/client/platform` is not a declared platform.
    ClientPlatform,
    /// `/client/arch` is not a declared architecture.
    ClientArch,
    /// `/modules` is not a list of declared names.
    Modules,
    /// `/modules` names the same module more than once.
    ModulesDuplicate,
    /// `/modules` carries more than the schema ceiling.
    ModulesTooMany,
    /// `/events` is not a list of records.
    Events,
    /// `/events` carries no record.
    EventsEmpty,
    /// `/events` carries more than the configured ceiling.
    EventsTooMany,
    /// `/events[]/name` is not a declared event name.
    EventName,
    /// `/events[]/outcome` is not a declared outcome.
    EventOutcome,
    /// `/events[]/error` is not a declared error class.
    EventError,
    /// `/events[]/error` contradicts `/events[]/outcome`.
    ErrorMismatch,
    /// `/events[]/duration` is not a declared bucket.
    EventDuration,
    /// `/events[]/count` is not a whole number in range.
    EventCount,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sentence = match self {
            // Rule text only, in every branch: the message is allowed to
            // name the grammar (which is published on the notice route)
            // and never the value that broke it. Sentences deliberately
            // carry no digits where the refused value was a number, and
            // never repeat a key or name the client chose.
            Self::Body => "the payload must be a JSON object",
            Self::UnknownField => {
                "the payload carries a field the schema does not define; \
                 a new field is a new schema version, never an accepted one"
            }
            Self::Schema => {
                "the value at /schema must be present and be the schema version this collector parses"
            }
            Self::SchemaUnsupported => {
                "the value at /schema names a schema version this collector does not parse; \
                 upgrade the client or stop reporting"
            }
            Self::Install => {
                "the value at /install must be exactly 32 lowercase hexadecimal characters"
            }
            Self::Client => "the value at /client must be the client object the schema defines",
            Self::ClientKind => {
                "the value at /client/kind must be one of the kinds the notice route publishes"
            }
            Self::ClientVersion => {
                "the value at /client/version must be a numeric release triple — \
                 MAJOR.MINOR.PATCH, each part one to six digits — with no pre-release \
                 and no build metadata; a client with one of those rounds down"
            }
            Self::ClientPlatform => {
                "the value at /client/platform must be one of the platforms the notice \
                 route publishes"
            }
            Self::ClientArch => {
                "the value at /client/arch must be one of the architectures the notice \
                 route publishes"
            }
            Self::Modules => {
                "the value at /modules must be a list of names from the venture's \
                 declared module vocabulary"
            }
            Self::ModulesDuplicate => {
                "the value at /modules must not name the same module more than once"
            }
            Self::ModulesTooMany => {
                "the value at /modules must not carry more names than the schema ceiling"
            }
            Self::Events => "the value at /events must be a list of event records",
            Self::EventsEmpty => "the value at /events must carry at least one event record",
            Self::EventsTooMany => {
                "the value at /events must not carry more records than the configured batch ceiling"
            }
            Self::EventName => {
                "the value at /events[]/name must be a name from the venture's declared \
                 event vocabulary"
            }
            Self::EventOutcome => {
                "the value at /events[]/outcome must be one of the outcomes the notice \
                 route publishes"
            }
            Self::EventError => {
                "the value at /events[]/error must be one of the error classes the \
                 notice route publishes"
            }
            Self::ErrorMismatch => {
                "the value at /events[]/error must be none when the outcome is ok or \
                 cancelled, and must never be none when the outcome is error"
            }
            Self::EventDuration => {
                "the value at /events[]/duration must be one of the duration buckets the \
                 notice route publishes"
            }
            Self::EventCount => {
                "the value at /events[]/count must be a whole number between one and one \
                 hundred thousand"
            }
        };
        f.write_str(sentence)
    }
}

/// Reads one closed value: the JSON field must be a string equal to one
/// member of `all`. A wrong type and an undeclared name are the same
/// rejection — the message names the rule, never the value.
fn enum_of<E>(
    value: &Value,
    all: &[E],
    wire: impl Fn(E) -> &'static str,
    rejection: Rejection,
) -> Result<E, Rejection>
where
    E: Copy + PartialEq,
{
    let raw = value.as_str().ok_or(rejection)?;
    all.iter()
        .copied()
        .find(|candidate| wire(*candidate) == raw)
        .ok_or(rejection)
}

impl Batch {
    /// Parses a batch against the venture's declared vocabulary. Every
    /// value outside the grammar — an unknown field, an undeclared name, a
    /// malformed id, a version with a pre-release tag, a count out of
    /// range, an error class that contradicts the outcome — is a
    /// [`Rejection`], never a truncation or a coercion (issue #413).
    ///
    /// The parse is written by hand over `serde_json::Value` rather than
    /// delegated to serde's deserializers on purpose: serde's error
    /// messages quote the offending value, and a quoted value is exactly
    /// what a rejection body must never carry.
    ///
    /// # Errors
    /// A [`Rejection`] naming the field path and the rule that was broken.
    pub fn parse(value: &Value, vocabulary: &Vocabulary) -> Result<Self, Rejection> {
        let object = value.as_object().ok_or(Rejection::Body)?;
        let mut schema = false;
        let mut install = None;
        let mut client = None;
        let mut modules = None;
        let mut events = None;
        for (key, field) in object {
            match key.as_str() {
                "schema" => match field.as_u64() {
                    Some(found) if found == u64::from(SCHEMA) => schema = true,
                    Some(_) => return Err(Rejection::SchemaUnsupported),
                    None => return Err(Rejection::Schema),
                },
                "install" => match field.as_str() {
                    Some(raw) if install_id_is_valid(raw) => install = Some(raw.to_owned()),
                    _ => return Err(Rejection::Install),
                },
                "client" => client = Some(parse_client(field)?),
                "modules" => modules = Some(parse_modules(field, vocabulary)?),
                "events" => events = Some(parse_events(field, vocabulary)?),
                _ => return Err(Rejection::UnknownField),
            }
        }
        Ok(Self {
            schema: if schema {
                SCHEMA
            } else {
                return Err(Rejection::Schema);
            },
            install: install.ok_or(Rejection::Install)?,
            client: client.ok_or(Rejection::Client)?,
            modules: modules.ok_or(Rejection::Modules)?,
            events: events.ok_or(Rejection::Events)?,
        })
    }
}

/// Parses `/client`, admitting exactly the four fields of [`Client`].
fn parse_client(value: &Value) -> Result<Client, Rejection> {
    let object = value.as_object().ok_or(Rejection::Client)?;
    let mut kind = None;
    let mut version = None;
    let mut platform = None;
    let mut arch = None;
    for (key, field) in object {
        match key.as_str() {
            "kind" => {
                kind = Some(enum_of(
                    field,
                    ClientKind::ALL,
                    ClientKind::as_str,
                    Rejection::ClientKind,
                )?);
            }
            "version" => match field.as_str().and_then(Version::parse) {
                Some(parsed) => version = Some(parsed),
                None => return Err(Rejection::ClientVersion),
            },
            "platform" => {
                platform = Some(enum_of(
                    field,
                    Platform::ALL,
                    Platform::as_str,
                    Rejection::ClientPlatform,
                )?);
            }
            "arch" => {
                arch = Some(enum_of(
                    field,
                    Arch::ALL,
                    Arch::as_str,
                    Rejection::ClientArch,
                )?);
            }
            _ => return Err(Rejection::UnknownField),
        }
    }
    Ok(Client {
        kind: kind.ok_or(Rejection::ClientKind)?,
        version: version.ok_or(Rejection::ClientVersion)?,
        platform: platform.ok_or(Rejection::ClientPlatform)?,
        arch: arch.ok_or(Rejection::ClientArch)?,
    })
}

/// Parses `/modules`: at most [`MAX_MODULES`] names, each from the
/// venture's declared vocabulary, no duplicates.
fn parse_modules(value: &Value, vocabulary: &Vocabulary) -> Result<Vec<String>, Rejection> {
    let items = value.as_array().ok_or(Rejection::Modules)?;
    if items.len() > MAX_MODULES {
        return Err(Rejection::ModulesTooMany);
    }
    let mut modules = Vec::with_capacity(items.len());
    for item in items {
        let name = item.as_str().ok_or(Rejection::Modules)?;
        if !vocabulary.modules.iter().any(|declared| declared == name) {
            return Err(Rejection::Modules);
        }
        if modules.iter().any(|seen| seen == name) {
            return Err(Rejection::ModulesDuplicate);
        }
        modules.push(name.to_owned());
    }
    Ok(modules)
}

/// Parses `/events`: at least one record and at most the configured
/// ceiling, each record admitting exactly the five fields of
/// [`EventRecord`], with the cross-field rule that `error` is `None`
/// exactly when the outcome is not `Error` — redundant on purpose, because
/// a pairing that is enforced is one a reader never has to second-guess.
fn parse_events(value: &Value, vocabulary: &Vocabulary) -> Result<Vec<EventRecord>, Rejection> {
    let items = value.as_array().ok_or(Rejection::Events)?;
    if items.is_empty() {
        return Err(Rejection::EventsEmpty);
    }
    if items.len() > vocabulary.max_events {
        return Err(Rejection::EventsTooMany);
    }
    let mut events = Vec::with_capacity(items.len());
    for item in items {
        let object = item.as_object().ok_or(Rejection::Events)?;
        let mut name = None;
        let mut outcome = None;
        let mut error = None;
        let mut duration = None;
        let mut count = None;
        for (key, field) in object {
            match key.as_str() {
                "name" => {
                    let raw = field.as_str().ok_or(Rejection::EventName)?;
                    if !vocabulary.events.iter().any(|declared| declared == raw) {
                        return Err(Rejection::EventName);
                    }
                    name = Some(raw.to_owned());
                }
                "outcome" => {
                    outcome = Some(enum_of(
                        field,
                        Outcome::ALL,
                        Outcome::as_str,
                        Rejection::EventOutcome,
                    )?);
                }
                "error" => {
                    error = Some(enum_of(
                        field,
                        ErrorKind::ALL,
                        ErrorKind::as_str,
                        Rejection::EventError,
                    )?);
                }
                "duration" => {
                    duration = Some(enum_of(
                        field,
                        DurationBucket::ALL,
                        DurationBucket::as_str,
                        Rejection::EventDuration,
                    )?);
                }
                "count" => match field.as_u64() {
                    // Both ends of the range are grammar: a claim of zero
                    // runs is as meaningless as a claim of a billion.
                    Some(found) if (1..=u64::from(MAX_EVENT_COUNT)).contains(&found) => {
                        count = Some(u32::try_from(found).unwrap_or_default());
                    }
                    _ => return Err(Rejection::EventCount),
                },
                _ => return Err(Rejection::UnknownField),
            }
        }
        let outcome = outcome.ok_or(Rejection::EventOutcome)?;
        let error = error.ok_or(Rejection::EventError)?;
        let consistent = match outcome {
            Outcome::Error => !matches!(error, ErrorKind::None),
            Outcome::Ok | Outcome::Cancelled => matches!(error, ErrorKind::None),
        };
        if !consistent {
            return Err(Rejection::ErrorMismatch);
        }
        events.push(EventRecord {
            name: name.ok_or(Rejection::EventName)?,
            outcome,
            error,
            duration: duration.ok_or(Rejection::EventDuration)?,
            count: count.ok_or(Rejection::EventCount)?,
        });
    }
    Ok(events)
}

/// Serializes a batch exactly the way the sender does — pretty JSON, one
/// serializer, no second formatting. `telemetry status` embeds these
/// bytes, so what a person reads is byte-identical to what the wire would
/// carry; there is no description of the data that can drift from it.
///
/// # Panics
/// Never for a parsed batch: every field is an enum's wire name, a hex
/// install id, a version triple, a declared name or a number, all of which
/// serialize, so the underlying `Result` cannot be `Err`.
#[must_use]
pub fn to_wire(batch: &Batch) -> String {
    serde_json::to_string_pretty(batch).expect("a closed payload always serializes")
}

/// One entry of the field inventory [`fields`] publishes: where the field
/// sits and what it may hold, generated from the grammar itself so the
/// notice cannot drift from the parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldDoc {
    /// The JSON pointer of the field, as the rejection messages name it.
    pub path: &'static str,
    /// The rule in words, for the fields that are not plain closed lists.
    pub rule: String,
    /// The permitted values, for the closed lists; generated from the
    /// enums' `ALL` slices so it cannot disagree with them.
    pub values: Vec<String>,
}

/// The wire names of one closed enum, in declaration order — the source
/// for every inventory entry whose values come from a grammar type, so a
/// value added to the enum appears in the notice without a second edit.
fn values<E: Display>(all: &[E]) -> Vec<String> {
    all.iter().map(ToString::to_string).collect()
}

/// Every payload field with its permitted vocabulary — the raw material of
/// the first-run notice and of the notice route, so both are generated
/// from one place and neither can promise less or more than
/// [`Batch::parse`] enforces (issue #413).
#[must_use]
pub fn fields(vocabulary: &Vocabulary) -> Vec<FieldDoc> {
    vec![
        FieldDoc {
            path: "/schema",
            rule: format!("exactly the value {SCHEMA}; any other schema is rejected, not coerced"),
            values: Vec::new(),
        },
        FieldDoc {
            path: "/install",
            rule: format!(
                "exactly 32 lowercase hex characters: 16 random bytes the client mints, \
                 never derived from anything about the machine, replaced every \
                 {ROTATION_DAYS} days"
            ),
            values: Vec::new(),
        },
        FieldDoc {
            path: "/client/kind",
            rule: String::new(),
            values: values(ClientKind::ALL),
        },
        FieldDoc {
            path: "/client/version",
            rule: "a numeric release triple, MAJOR.MINOR.PATCH, each part one to six \
                   digits; no pre-release, no build metadata"
                .to_owned(),
            values: Vec::new(),
        },
        FieldDoc {
            path: "/client/platform",
            rule: String::new(),
            values: values(Platform::ALL),
        },
        FieldDoc {
            path: "/client/arch",
            rule: String::new(),
            values: values(Arch::ALL),
        },
        FieldDoc {
            path: "/modules",
            rule: format!(
                "at most {MAX_MODULES} names, no duplicates, each from the venture's \
                 declared module vocabulary, listed below"
            ),
            values: vocabulary.modules.clone(),
        },
        FieldDoc {
            path: "/events",
            rule: "at least one record and at most the batch ceiling; each record counts \
                   many runs of one named command"
                .to_owned(),
            values: Vec::new(),
        },
        FieldDoc {
            path: "/events[]/name",
            rule: "a name from the venture's declared event vocabulary, listed below".to_owned(),
            values: vocabulary.events.clone(),
        },
        FieldDoc {
            path: "/events[]/outcome",
            rule: String::new(),
            values: values(Outcome::ALL),
        },
        FieldDoc {
            path: "/events[]/error",
            rule: "none when the outcome is ok or cancelled, one of the classes below \
                   when it is error — a class, never a message"
                .to_owned(),
            values: values(ErrorKind::ALL),
        },
        FieldDoc {
            path: "/events[]/duration",
            rule: String::new(),
            values: values(DurationBucket::ALL),
        },
        FieldDoc {
            path: "/events[]/count",
            rule: format!("a whole number from one to {MAX_EVENT_COUNT}"),
            values: Vec::new(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The no-echo rule, on the exact case that motivates it: a payload
    /// carrying an address is refused with a sentence about the rule, not
    /// a copy of the address. An error body that quoted the client would
    /// be the free-text channel this module exists to close (issue #413).
    #[test]
    fn a_rejection_never_echoes_what_the_client_sent() {
        let value = serde_json::json!({
            "schema": 1,
            "install": "alice@example.com",
            "client": {"kind": "cli", "version": "0.4.1", "platform": "linux", "arch": "other"},
            "modules": [],
            "events": [
                {"name": "run", "outcome": "ok", "error": "none", "duration": "unknown", "count": 1}
            ],
        });
        let vocabulary = Vocabulary {
            events: vec!["run".to_owned()],
            modules: Vec::new(),
            max_events: MAX_EVENTS_PER_BATCH,
        };
        let rejection =
            Batch::parse(&value, &vocabulary).expect_err("the address is not an install id");
        assert_eq!(rejection, Rejection::Install);
        let message = rejection.to_string();
        assert!(
            !message.contains("alice@example.com"),
            "the rejection echoed what the client sent: {message}"
        );
        assert!(
            message.contains("/install"),
            "the rejection names the field path: {message}"
        );
    }

    /// The count ceiling is part of the grammar: one more than it is a
    /// rejection, not a clamp.
    #[test]
    fn a_count_above_the_ceiling_is_rejected() {
        let value = serde_json::json!({
            "schema": 1,
            "install": "7b0a1f2c3d4e5f60718293a4b5c6d7e8",
            "client": {"kind": "cli", "version": "0.4.1", "platform": "linux", "arch": "other"},
            "modules": [],
            "events": [
                {"name": "run", "outcome": "ok", "error": "none", "duration": "unknown", "count": MAX_EVENT_COUNT + 1}
            ],
        });
        let vocabulary = Vocabulary {
            events: vec!["run".to_owned()],
            modules: Vec::new(),
            max_events: MAX_EVENTS_PER_BATCH,
        };
        assert_eq!(
            Batch::parse(&value, &vocabulary),
            Err(Rejection::EventCount),
            "a count above the ceiling is refused"
        );
    }

    /// The version grammar, at its edges: a plain triple parses, and every
    /// costume free text could wear is refused.
    #[test]
    fn a_version_is_a_release_triple_and_nothing_else() {
        assert_eq!(
            Version::parse("0.4.1"),
            Some(Version {
                major: 0,
                minor: 4,
                patch: 1
            })
        );
        assert!(
            Version::parse("123456.123456.123456").is_some(),
            "six digits per part"
        );
        assert_eq!(
            Version::parse("1234567.0.0"),
            None,
            "a part longer than six digits"
        );
        assert_eq!(Version::parse("1.0.0-beta"), None, "a pre-release tag");
        assert_eq!(Version::parse("1.0.0+homebrew"), None, "build metadata");
        assert_eq!(Version::parse("1.0"), None, "a missing part");
        assert_eq!(Version::parse("1.0.0.0"), None, "a fourth part");
        assert_eq!(Version::parse("latest"), None, "a name");
        assert_eq!(Version::parse("1..0"), None, "an empty part");
    }
}
