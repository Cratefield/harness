//! Sign-up intents: what brings a new account to an application (one
//! entry flow, Continue).
//!
//! An application registers an optional list of intents with
//! `POST /admin/clients` or `PATCH /admin/clients/{id}` (`signup_intents`).
//! When a person creates an account through that application's sign-in, the
//! hosted page asks "What brings you here?" once, before the account exists,
//! and the keys they choose are stored per (account, client) and echoed in the
//! ID token and at the userinfo endpoint as an `intents` claim.
//!
//! **An intent never grants anything.** It is a preference the person states,
//! and it is a different thing from `roles`: `roles` is written only by an
//! operator through `POST /admin/users/{sub}/role` (issue #912), no request
//! can set it, and nothing in this module writes `users.role`.
//!
//! An intent is `{key, label, description?, multi?}`:
//!
//! - `key` names the intent in the claim. `[a-z][a-z0-9_]{0,31}`, unique
//!   within the list.
//! - `label` maps a locale tag to its text. It must carry `en`, which is the
//!   fallback for a locale it does not name.
//! - `description` optionally maps locale tags to a sentence under the label.
//! - `multi` (default `true`): whether the intent may be chosen together with
//!   others. `false` makes it exclusive, so picking it with anything else is
//!   refused.

use std::collections::BTreeMap;

use cratefield_core::{Clock, Database, DbError};
use serde::{Deserialize, Serialize};

use crate::store;

/// The most intents one client may register.
pub const MAX_INTENTS: usize = 12;
/// The longest key, in bytes.
pub const MAX_KEY_BYTES: usize = 32;
/// The longest label or description, in bytes.
pub const MAX_TEXT_BYTES: usize = 300;
/// The most locale entries one label or description may carry.
pub const MAX_LOCALES: usize = 16;

/// One sign-up intent as a client registers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupIntent {
    /// The value carried in the `intents` claim.
    pub key: String,
    /// Locale tag to label. Must contain `en`.
    pub label: BTreeMap<String, String>,
    /// Optional locale tag to description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<BTreeMap<String, String>>,
    /// Whether the intent may be combined with others. Defaults to `true`.
    #[serde(default = "default_multi")]
    pub multi: bool,
}

fn default_multi() -> bool {
    true
}

/// Why a client's intent list was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentListError(pub String);

/// Checks a client's whole list before it is stored.
///
/// # Errors
///
/// [`IntentListError`] naming the first rule the list breaks.
pub fn validate_list(list: &[SignupIntent]) -> Result<(), IntentListError> {
    if list.is_empty() {
        return Err(IntentListError(
            "signup_intents must not be empty; send null to remove the list".to_owned(),
        ));
    }
    if list.len() > MAX_INTENTS {
        return Err(IntentListError(format!(
            "at most {MAX_INTENTS} signup_intents per client"
        )));
    }
    let mut seen: Vec<&str> = Vec::new();
    for intent in list {
        if !valid_key(&intent.key) {
            return Err(IntentListError(format!(
                "intent key `{}` must match [a-z][a-z0-9_]{{0,31}}",
                intent.key
            )));
        }
        if seen.contains(&intent.key.as_str()) {
            return Err(IntentListError(format!(
                "intent key `{}` appears twice",
                intent.key
            )));
        }
        seen.push(&intent.key);
        validate_text(&intent.key, "label", &intent.label, true)?;
        if let Some(description) = &intent.description {
            validate_text(&intent.key, "description", description, false)?;
        }
    }
    Ok(())
}

fn valid_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    key.len() <= MAX_KEY_BYTES
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

fn validate_text(
    key: &str,
    field: &str,
    map: &BTreeMap<String, String>,
    required_en: bool,
) -> Result<(), IntentListError> {
    if map.len() > MAX_LOCALES {
        return Err(IntentListError(format!(
            "intent `{key}` {field} has more than {MAX_LOCALES} locales"
        )));
    }
    if required_en && map.get("en").is_none_or(|text| text.trim().is_empty()) {
        return Err(IntentListError(format!(
            "intent `{key}` {field} needs a non-empty `en` entry"
        )));
    }
    for (locale, text) in map {
        if !valid_locale_tag(locale) {
            return Err(IntentListError(format!(
                "intent `{key}` {field} locale `{locale}` is not a language tag"
            )));
        }
        if text.trim().is_empty() || text.len() > MAX_TEXT_BYTES {
            return Err(IntentListError(format!(
                "intent `{key}` {field} `{locale}` must be 1..={MAX_TEXT_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn valid_locale_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 16
        && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && tag.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
}

/// The JSON the list is stored as.
#[must_use]
pub fn encode_list(list: &[SignupIntent]) -> String {
    serde_json::to_string(list).unwrap_or_else(|_| "[]".to_owned())
}

/// The list a stored value holds. A value that does not parse is no list at
/// all, so a corrupted row cannot make a client demand a choice it never set.
#[must_use]
pub fn decode_list(json: &str) -> Option<Vec<SignupIntent>> {
    serde_json::from_str(json).ok()
}

/// Reads the `intents=` parameter of `/authorize`: comma-separated keys,
/// blanks dropped, duplicates removed, order kept. Whether the keys are
/// allowed is [`check_selection`]'s question, since it needs the client.
#[must_use]
pub fn parse_param(raw: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for key in raw.split(',').map(str::trim).filter(|key| !key.is_empty()) {
        if !keys.iter().any(|known| known == key) {
            keys.push(key.to_owned());
        }
    }
    keys
}

/// Checks a selection against a client's list.
///
/// A key the list does not name is refused, and so is an exclusive intent
/// (`multi: false`) chosen together with any other. An empty selection is
/// allowed: a person may decline to say.
///
/// # Errors
///
/// [`IntentListError`] naming the first key that cannot be accepted.
pub fn check_selection(
    list: &[SignupIntent],
    keys: &[String],
) -> Result<Vec<String>, IntentListError> {
    for key in keys {
        if !list.iter().any(|intent| &intent.key == key) {
            return Err(IntentListError(format!("unknown intent `{key}`")));
        }
    }
    let mut chosen: Vec<String> = Vec::new();
    for key in keys {
        if !chosen.contains(key) {
            chosen.push(key.clone());
        }
    }
    if chosen.len() > 1 {
        for intent in list {
            if !intent.multi && chosen.contains(&intent.key) {
                return Err(IntentListError(format!(
                    "intent `{}` cannot be combined with another",
                    intent.key
                )));
            }
        }
    }
    Ok(chosen)
}

/// The text for `locale` out of a locale map: an exact tag, then its
/// language, then `en`, then whatever entry exists.
#[must_use]
pub fn text_for<'a>(map: &'a BTreeMap<String, String>, locale: &str) -> Option<&'a str> {
    let exact = map.get(locale);
    let language = locale.split('-').next().and_then(|lang| map.get(lang));
    exact
        .or(language)
        .or_else(|| map.get("en"))
        .or_else(|| map.values().next())
        .map(String::as_str)
}

/// The client's registered list, or `None` when it has none (or the stored
/// value is not a list). A client without one never asks and never claims.
///
/// # Errors
///
/// [`DbError`] when the lookup fails.
pub async fn client_list(
    db: &dyn Database,
    client_id: &str,
) -> Result<Option<Vec<SignupIntent>>, DbError> {
    Ok(store::client_signup_intents_json(db, client_id)
        .await?
        .as_deref()
        .and_then(decode_list))
}

/// The keys an account chose for one client, or `None` when it has not
/// chosen (no row).
///
/// # Errors
///
/// [`DbError`] when the lookup fails.
pub async fn chosen(
    db: &dyn Database,
    user_id: &str,
    client_id: &str,
) -> Result<Option<Vec<String>>, DbError> {
    Ok(store::user_client_intents_json(db, user_id, client_id)
        .await?
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok()))
}

/// Records the keys an account chose for one client. The caller has checked
/// them against the client's list with [`check_selection`].
///
/// # Errors
///
/// [`DbError`] when a statement fails.
pub async fn record(
    db: &dyn Database,
    clock: &dyn Clock,
    user_id: &str,
    client_id: &str,
    keys: &[String],
) -> Result<(), DbError> {
    let now = clock
        .now()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| clock.now())
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let json = serde_json::to_string(keys).unwrap_or_else(|_| "[]".to_owned());
    store::set_user_client_intents_json(db, user_id, client_id, &json, &now).await
}

/// The primary language of the request, for the hosted step's labels. `en`
/// when the browser names none.
#[must_use]
pub fn request_locale(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| cratefield_i18n::accept_language(value).into_iter().next())
        .map_or_else(|| "en".to_owned(), |language| language.to_string())
}

/// The step's wording. English only, like every hosted page here: the
/// locale-keyed text is the one the client registers on each intent.
const STEP_TITLE: &str = "What brings you here?";
const STEP_LEGEND: &str = "Choose what applies. You can change this later.";
const STEP_CONTINUE: &str = "Continue";

/// The "What brings you here?" step: a checkbox group, one entry per intent
/// in the client's order. Each label is a real `<label for>`, each description
/// is tied to its checkbox with `aria-describedby`, and the group is a
/// `<fieldset>` with a `<legend>`, so a screen reader announces the question
/// and each answer.
///
/// `action` and `hidden` say where the answer goes and what travels with it
/// (a token, a return path). `selected` pre-ticks keys already chosen.
#[must_use]
pub fn step_page(
    brand: &crate::Brand,
    action: &str,
    hidden: &[(&str, &str)],
    list: &[SignupIntent],
    locale: &str,
    selected: &[String],
) -> axum::response::Response {
    use crate::page::{HostedPage, escape};
    use std::fmt::Write as _;
    let mut fields = String::new();
    for (name, value) in hidden {
        let _ = write!(
            fields,
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escape(name),
            escape(value)
        );
    }
    let mut options = String::new();
    for intent in list {
        let key = escape(&intent.key);
        let label = text_for(&intent.label, locale).unwrap_or(&intent.key);
        let checked = if selected.contains(&intent.key) {
            " checked"
        } else {
            ""
        };
        let description = intent
            .description
            .as_ref()
            .and_then(|map| text_for(map, locale));
        let (hint, described_by) = match description {
            Some(text) => (
                format!(
                    "<p class=\"sub\" id=\"intent-{key}-hint\">{}</p>",
                    escape(text)
                ),
                format!(" aria-describedby=\"intent-{key}-hint\""),
            ),
            None => (String::new(), String::new()),
        };
        let _ = write!(
            options,
            "<div class=\"cf-intent\"><input type=\"checkbox\" id=\"intent-{key}\" \
name=\"intents\" value=\"{key}\"{checked}{described_by}>\
<label for=\"intent-{key}\">{}</label>{hint}</div>",
            escape(label),
        );
    }
    let body = format!(
        "<h1>{title}</h1><form method=\"post\" action=\"{action}\" class=\"cf-form\">{fields}\
<fieldset class=\"cf-intents\"><legend>{legend}</legend>{options}</fieldset>\
<button class=\"cf-primary\" type=\"submit\">{cont}</button></form>",
        title = STEP_TITLE,
        action = escape(action),
        legend = STEP_LEGEND,
        cont = STEP_CONTINUE,
    );
    HostedPage::new(STEP_TITLE).body(body).render(brand)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(key: &str) -> SignupIntent {
        SignupIntent {
            key: key.to_owned(),
            label: BTreeMap::from([("en".to_owned(), key.to_owned())]),
            description: None,
            multi: true,
        }
    }

    #[test]
    fn a_list_needs_english_labels_and_unique_well_formed_keys() {
        assert!(validate_list(&[intent("builder"), intent("buyer")]).is_ok());
        assert!(validate_list(&[]).is_err());
        assert!(validate_list(&[intent("Builder")]).is_err());
        assert!(validate_list(&[intent("1st")]).is_err());
        assert!(validate_list(&[intent("a"), intent("a")]).is_err());
        let mut no_en = intent("builder");
        no_en.label = BTreeMap::from([("de".to_owned(), "Bauherr".to_owned())]);
        assert!(validate_list(&[no_en]).is_err());
        let too_many: Vec<SignupIntent> = (0..=MAX_INTENTS)
            .map(|i| intent(&format!("k{i}")))
            .collect();
        assert!(validate_list(&too_many).is_err());
    }

    #[test]
    fn an_exclusive_intent_refuses_a_combination() {
        let mut browsing = intent("browsing");
        browsing.multi = false;
        let list = vec![intent("builder"), browsing];
        assert_eq!(
            check_selection(&list, &["builder".to_owned()]).unwrap(),
            vec!["builder".to_owned()]
        );
        assert!(check_selection(&list, &["browsing".to_owned(), "builder".to_owned()]).is_err());
        assert!(check_selection(&list, &["unknown".to_owned()]).is_err());
        assert_eq!(check_selection(&list, &[]).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn the_param_is_split_trimmed_and_deduplicated() {
        assert_eq!(
            parse_param(" builder, buyer ,builder,,"),
            vec!["builder".to_owned(), "buyer".to_owned()]
        );
    }

    #[test]
    fn a_locale_falls_back_to_its_language_then_english() {
        let map = BTreeMap::from([
            ("en".to_owned(), "Build".to_owned()),
            ("de".to_owned(), "Bauen".to_owned()),
        ]);
        assert_eq!(text_for(&map, "de-AT"), Some("Bauen"));
        assert_eq!(text_for(&map, "fr"), Some("Build"));
    }

    #[test]
    fn a_stored_list_round_trips_and_a_broken_one_is_no_list() {
        let list = vec![intent("builder")];
        assert_eq!(decode_list(&encode_list(&list)), Some(list));
        assert_eq!(decode_list("not json"), None);
    }
}
