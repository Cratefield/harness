//! One value against one [`FieldKind`].
//!
//! Every rule here is written to be reimplementable exactly, because a
//! generated TypeScript client will check the same values in the browser
//! and the two must agree. The pairs that drift are pinned in
//! `corpus/rows.json` rather than left to prose.
//!
//! The rules, in full:
//!
//! - **No coercion.** A value has the JSON type its kind names, or it is
//!   rejected. `"42"` is not an integer, `1` is not `true`, `"true"` is
//!   not a boolean.
//! - **An integer is a number with no fractional part.** `42` and `42.0`
//!   are the same JSON number and both are accepted; `42.5` is not. The
//!   rule is `Number.isInteger(v)` in JavaScript, so a corpus file cannot
//!   mean one thing in Rust and another in a browser.
//! - **Length is counted in Unicode scalar values.** Not bytes, and not
//!   UTF-16 code units. A JavaScript implementation must count
//!   `[...s].length`, never `s.length`: `"\u{1F600}"` is one character,
//!   four bytes and two UTF-16 code units.
//! - **Nothing is trimmed.** Surrounding whitespace is part of the value
//!   and counts toward length. Trimming is a transformation, and a
//!   transformation belongs to whatever writes the row.
//! - **Bounds are inclusive** on both ends.
//! - **`null` never reaches here.** The row validator treats a JSON
//!   `null` as the absence of a value, so a null is answered before a
//!   kind is consulted.

use serde_json::Value;

use crate::schema::{FieldKind, TextFormat};

/// The stable vocabulary a conformance case is matched on. Messages are
/// prose and may be reworded; a code may not, because a second
/// implementation asserts against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The row was not a JSON object.
    NotAnObject,
    /// The row carried a key the table does not declare.
    UnknownField,
    /// A field that must be present was absent or `null`.
    Required,
    /// The value had the wrong JSON type for its kind.
    WrongType,
    /// A string was shorter than `min_len` characters.
    TooShort,
    /// A string was longer than `max_len` characters.
    TooLong,
    /// A number was below `min`.
    TooSmall,
    /// A number was above `max`.
    TooLarge,
    /// A string was not one of an enum's declared values.
    NotInEnum,
    /// A string did not match its declared format: `email`, `url`, a
    /// timestamp or a UUID.
    BadFormat,
}

impl ErrorCode {
    /// Every code, for the corpus coverage check.
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::NotAnObject,
        ErrorCode::UnknownField,
        ErrorCode::Required,
        ErrorCode::WrongType,
        ErrorCode::TooShort,
        ErrorCode::TooLong,
        ErrorCode::TooSmall,
        ErrorCode::TooLarge,
        ErrorCode::NotInEnum,
        ErrorCode::BadFormat,
    ];

    /// The wire name used in `corpus/rows.json`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotAnObject => "not_an_object",
            ErrorCode::UnknownField => "unknown_field",
            ErrorCode::Required => "required",
            ErrorCode::WrongType => "wrong_type",
            ErrorCode::TooShort => "too_short",
            ErrorCode::TooLong => "too_long",
            ErrorCode::TooSmall => "too_small",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::NotInEnum => "not_in_enum",
            ErrorCode::BadFormat => "bad_format",
        }
    }
}

/// Why one value was rejected: a code to match on and a line to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueError {
    pub code: ErrorCode,
    pub message: String,
}

impl ValueError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Checks `value` against `kind`.
///
/// # Errors
///
/// The first rule the value breaks, as a code and a message.
pub fn check_value(kind: &FieldKind, value: &Value) -> Result<(), ValueError> {
    match kind {
        FieldKind::Text {
            min_len,
            max_len,
            format,
        } => {
            let text = as_string(value, "a string")?;
            check_length(text, *min_len, *max_len)?;
            check_format(text, *format)
        }
        FieldKind::Integer { min, max } => {
            let integer = as_integer(as_number(value)?)?;
            if let Some(min) = *min
                && integer < min
            {
                return Err(too_small(min));
            }
            if let Some(max) = *max
                && integer > max
            {
                return Err(too_large(max));
            }
            Ok(())
        }
        FieldKind::Real { min, max } => {
            let number = as_number(value)?;
            if let Some(min) = *min
                && number < min
            {
                return Err(too_small(min));
            }
            if let Some(max) = *max
                && number > max
            {
                return Err(too_large(max));
            }
            Ok(())
        }
        FieldKind::Boolean => {
            if value.is_boolean() {
                Ok(())
            } else {
                Err(wrong_type(value, "true or false"))
            }
        }
        FieldKind::Timestamp => {
            let text = as_string(value, "an RFC 3339 timestamp string")?;
            if is_rfc3339(text) {
                Ok(())
            } else {
                Err(ValueError::new(
                    ErrorCode::BadFormat,
                    "is not an RFC 3339 timestamp such as 2026-09-08T09:30:00Z",
                ))
            }
        }
        FieldKind::Uuid => {
            let text = as_string(value, "a UUID string")?;
            if is_uuid(text) {
                Ok(())
            } else {
                Err(ValueError::new(
                    ErrorCode::BadFormat,
                    "is not a hyphenated 8-4-4-4-12 UUID",
                ))
            }
        }
        FieldKind::Json => {
            if value.is_null() {
                Err(wrong_type(value, "any JSON value other than null"))
            } else {
                Ok(())
            }
        }
        FieldKind::Enum { values } => {
            let text = as_string(value, "one of the declared values")?;
            if values.iter().any(|allowed| allowed == text) {
                Ok(())
            } else {
                Err(ValueError::new(
                    ErrorCode::NotInEnum,
                    format!("is not one of {}", values.join(", ")),
                ))
            }
        }
    }
}

fn too_small(min: impl std::fmt::Display) -> ValueError {
    ValueError::new(
        ErrorCode::TooSmall,
        format!("is below the minimum of {min}"),
    )
}

fn too_large(max: impl std::fmt::Display) -> ValueError {
    ValueError::new(
        ErrorCode::TooLarge,
        format!("is above the maximum of {max}"),
    )
}

fn wrong_type(value: &Value, expected: &str) -> ValueError {
    ValueError::new(
        ErrorCode::WrongType,
        format!("must be {expected}, not {}", json_type_name(value)),
    )
}

/// The JSON type name used in messages, so `"42"` against an integer says
/// `a string` rather than repeating the value back.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn as_string<'a>(value: &'a Value, expected: &str) -> Result<&'a str, ValueError> {
    value.as_str().ok_or_else(|| wrong_type(value, expected))
}

fn as_number(value: &Value) -> Result<f64, ValueError> {
    value
        .as_f64()
        .filter(|number| number.is_finite())
        .ok_or_else(|| wrong_type(value, "a number"))
}

/// A number with no fractional part, inside `i64`. `42.0` passes; `42.5`
/// does not. JSON has one number type, so this is the only rule that
/// means the same thing in Rust and in a browser.
fn as_integer(number: f64) -> Result<i64, ValueError> {
    #[allow(clippy::cast_precision_loss)]
    let in_range = number >= i64::MIN as f64 && number <= i64::MAX as f64;
    if number.fract() != 0.0 || !in_range {
        return Err(ValueError::new(
            ErrorCode::WrongType,
            "must be a whole number that fits in 64 bits",
        ));
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(number as i64)
}

fn check_length(text: &str, min_len: Option<u32>, max_len: Option<u32>) -> Result<(), ValueError> {
    let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
    if let Some(min) = min_len
        && length < u64::from(min)
    {
        return Err(ValueError::new(
            ErrorCode::TooShort,
            format!("is {length} characters, shorter than the minimum of {min}"),
        ));
    }
    if let Some(max) = max_len
        && length > u64::from(max)
    {
        return Err(ValueError::new(
            ErrorCode::TooLong,
            format!("is {length} characters, longer than the maximum of {max}"),
        ));
    }
    Ok(())
}

fn check_format(text: &str, format: Option<TextFormat>) -> Result<(), ValueError> {
    match format {
        None => Ok(()),
        Some(TextFormat::Email) => {
            if let Some(reason) = cratefield_core::validation_error(text) {
                Err(ValueError::new(ErrorCode::BadFormat, reason))
            } else {
                Ok(())
            }
        }
        Some(TextFormat::Url) => {
            if is_url(text) {
                Ok(())
            } else {
                Err(ValueError::new(
                    ErrorCode::BadFormat,
                    "is not an absolute http or https URL",
                ))
            }
        }
    }
}

/// An absolute `http` or `https` URL: a case-insensitive scheme, `://`, a
/// non-empty authority, and no ASCII whitespace or control character
/// anywhere. Deliberately narrow — a declared field is a form input, not
/// a URL parser test suite.
#[must_use]
pub fn is_url(text: &str) -> bool {
    if text
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
    {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    let rest = if let Some(rest) = lower.strip_prefix("https://") {
        rest
    } else if let Some(rest) = lower.strip_prefix("http://") {
        rest
    } else {
        return false;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_owned();
    !authority.is_empty()
}

/// A hyphenated 8-4-4-4-12 UUID in either case. No braces, no
/// `urn:uuid:` prefix, and no version or variant check: the value is an
/// identifier, and the harness does not mint it.
#[must_use]
pub fn is_uuid(text: &str) -> bool {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut parts = text.split('-');
    for width in GROUPS {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.len() != width || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    parts.next().is_none()
}

/// A strict RFC 3339 timestamp:
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`.
///
/// Uppercase `T` and `Z` only, which is what
/// `new Date().toISOString()` emits. The calendar day is checked against
/// the month and the leap year. A leap second (`:60`) is accepted,
/// because RFC 3339 allows it.
#[must_use]
pub fn is_rfc3339(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !text.is_ascii() {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        text.get(range)
            .filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|part| part.parse().ok())
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return false;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let (Some(hour), Some(minute), Some(second)) = (digits(11..13), digits(14..16), digits(17..19))
    else {
        return false;
    };
    if month == 0 || month > 12 || day == 0 || day > days_in_month(year, month) {
        return false;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return false;
    }

    let mut rest = &text[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let fraction: String = after_dot
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        if fraction.is_empty() {
            return false;
        }
        rest = &after_dot[fraction.len()..];
    }
    if rest == "Z" {
        return true;
    }
    let signed = rest
        .strip_prefix('+')
        .or_else(|| rest.strip_prefix('-'))
        .unwrap_or("");
    if signed.len() != 5 || signed.as_bytes()[2] != b':' {
        return false;
    }
    let (Some(offset_hour), Some(offset_minute)) = (
        signed[0..2]
            .parse::<u32>()
            .ok()
            .filter(|_| signed[0..2].bytes().all(|b| b.is_ascii_digit())),
        signed[3..5]
            .parse::<u32>()
            .ok()
            .filter(|_| signed[3..5].bytes().all(|b| b.is_ascii_digit())),
    ) else {
        return false;
    };
    offset_hour <= 23 && offset_minute <= 59
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}
