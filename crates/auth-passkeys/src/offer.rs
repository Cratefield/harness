//! The passkey offer after a sign-in: "Sign in faster next time".
//!
//! A person who signed in by magic link or password, and who has no passkey,
//! is offered one before the authorization code is minted. The offer is
//! decided in [`PasskeyOffer`], the [`SignInStep`] this module attaches to
//! `auth-core`'s `/authorize` (see [`crate::Passkeys::sign_in_step`]). It
//! diverts the browser to `GET /v1/auth-passkeys/offer?continue=…`, a page
//! with two choices:
//!
//! - **Add a passkey** runs the same ceremony as the add page, against the
//!   same enrolment gate. A sign-in is fresh for two minutes, which is the
//!   window the first passkey needs, so this works straight after the
//!   magic-link or password sign-in. A stale session is refused by the gate
//!   and the page says so.
//! - **Not now** posts to `POST /v1/auth-passkeys/offer/dismiss`, which
//!   records a dismissal with a timestamp in
//!   `auth_passkeys_offer_dismissals`, per account, so it follows the person
//!   across browsers. The offer stays off for `AUTH_PASSKEYS_OFFER_SNOOZE_DAYS`.
//!
//! Either way the browser returns to the `continue` URL: the original
//! `/authorize` request, byte for byte. Nothing in the OAuth parameters is
//! read, rewritten or re-encoded here; the only thing this module decides is
//! whether to show the page. `continue` is accepted only as a path under
//! `/v1/auth-core/authorize`, so the page is never an open redirect.
//!
//! The offer is not shown when the setting is off, the account has a passkey,
//! the dismissal is inside the snooze, the sign-in was itself a passkey, the
//! request was a step-up or silent, or the client wants no page. A browser
//! without WebAuthn is sent on without being asked (the script checks).

use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use cratefield_auth_core::page::{HostedPage, escape};
use cratefield_auth_core::{
    Brand, CREDENTIAL_PASSKEY, MARKER_COOKIE, SignIn, SignInStep, cookie_value,
    credentials_by_user, csrf, record_notice, require_recent_session, validate,
};
use cratefield_core::{
    BoxFuture, Clock, Config, Database, DbError, ModuleConfig, ModuleContext, Problem, Scope,
    Statement, subject_hash,
};
use sea_query::{Alias, Expr, OnConflict, Query as SqlQuery};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ceremony;
use crate::request::{internal, ports};
use crate::{ModuleState, iso};

/// Where the offer page lives, as the diversion sends the browser to it.
const OFFER_PATH: &str = "/v1/auth-passkeys/offer";
/// Where "Not now" posts.
const DISMISS_PATH: &str = "/v1/auth-passkeys/offer/dismiss";
/// Sends the browser on without an answer, and sets the marker cookie so
/// `/authorize` does not offer again in this sign-in.
const SKIP_PATH: &str = "/v1/auth-passkeys/offer/skip";
/// How long the marker holds: the sign-in window, with some slack.
const MARKER_MAX_AGE_SECS: i64 = 600;
/// The method a passkey sign-in records (`auth-core` stores it on the session).
const AMR_PASSKEY: &str = "passkey";
/// The only page a `continue` may name: the authorization endpoint.
const AUTHORIZE_PATH: &str = "/v1/auth-core/authorize";
/// Longer than any authorization request a client sends, short enough that
/// a page echoing it stays small.
const MAX_CONTINUE: usize = 4096;

/// The default snooze after "Not now": 30 days.
const DEFAULT_SNOOZE_DAYS: i64 = 30;
/// A year at most, so a typo cannot mean the offer is never shown again.
const MAX_SNOOZE_DAYS: i64 = 365;

/// The table that remembers a "Not now", one row per account.
pub(crate) const DISMISSALS_TABLE: &str = "auth_passkeys_offer_dismissals";

/// Whether the offer is on, and for how long a "Not now" holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfferSettings {
    pub(crate) enabled: bool,
    pub(crate) snooze_days: i64,
}

impl OfferSettings {
    /// Reads `AUTH_PASSKEYS_OFFER_AFTER_SIGNIN` (`true` or `false`, default
    /// `false`) and `AUTH_PASSKEYS_OFFER_SNOOZE_DAYS` (1 to 365, default 30).
    pub(crate) fn from_config(cfg: &dyn Config) -> Result<Self, Vec<String>> {
        let module = ModuleConfig::new("auth-passkeys", cfg);
        let mut problems = Vec::new();

        let raw_enabled = module.get_opt("OFFER_AFTER_SIGNIN");
        let enabled = match raw_enabled.as_deref().map(str::trim) {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => {
                problems.push(format!(
                    "{} must be true or false, got {other:?}",
                    module.key("OFFER_AFTER_SIGNIN")
                ));
                false
            }
        };

        let snooze_days = match module.get_opt("OFFER_SNOOZE_DAYS") {
            None => DEFAULT_SNOOZE_DAYS,
            Some(raw) => match raw.trim().parse::<i64>() {
                Ok(days) if (1..=MAX_SNOOZE_DAYS).contains(&days) => days,
                _ => {
                    problems.push(format!(
                        "{} must be a whole number of days from 1 to {MAX_SNOOZE_DAYS}, got {raw:?}",
                        module.key("OFFER_SNOOZE_DAYS")
                    ));
                    DEFAULT_SNOOZE_DAYS
                }
            },
        };

        if problems.is_empty() {
            Ok(Self {
                enabled,
                snooze_days,
            })
        } else {
            Err(problems)
        }
    }
}

/// The `continue` value, if it names the authorization endpoint and nothing
/// else: a path, ASCII, no control characters, and not too long.
pub(crate) fn safe_continue(raw: &str) -> Option<&str> {
    let within = raw.len() <= MAX_CONTINUE && raw.is_ascii() && !raw.chars().any(char::is_control);
    let rest = raw.strip_prefix(AUTHORIZE_PATH)?;
    (within && (rest.is_empty() || rest.starts_with('?'))).then_some(raw)
}

/// The offer's address for a sign-in that continues to `continue_to`.
fn offer_location(continue_to: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("continue", continue_to)
        .finish();
    format!("{OFFER_PATH}?{query}")
}

/// When the account last said "Not now", if it ever did.
async fn dismissed_at(db: &dyn Database, user_id: &str) -> Result<Option<OffsetDateTime>, DbError> {
    let query = SqlQuery::select()
        .column(Alias::new("dismissed_at"))
        .from(Alias::new(DISMISSALS_TABLE))
        .and_where(Expr::col(Alias::new("user_id")).eq(user_id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows
        .rows
        .first()
        .and_then(|row| row.get::<String>("dismissed_at"))
        .and_then(|raw| OffsetDateTime::parse(&raw, &Rfc3339).ok()))
}

/// Whether this account should be offered a passkey now: it has none, and it
/// has not said "Not now" inside the snooze.
pub(crate) async fn offer_due(
    db: &dyn Database,
    clock: &dyn Clock,
    settings: OfferSettings,
    user_id: &str,
) -> Result<bool, DbError> {
    let credentials = credentials_by_user(db, user_id).await?;
    if credentials
        .iter()
        .any(|credential| credential.kind == CREDENTIAL_PASSKEY)
    {
        return Ok(false);
    }
    if let Some(at) = dismissed_at(db, user_id).await? {
        let snoozed_until = at + time::Duration::days(settings.snooze_days);
        if clock.now() < snoozed_until {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Records a "Not now" for the account at `now`, replacing an earlier one.
async fn record_dismissal(db: &dyn Database, user_id: &str, now: &str) -> Result<(), DbError> {
    let mut insert = SqlQuery::insert();
    insert
        .into_table(Alias::new(DISMISSALS_TABLE))
        .columns(["user_id", "dismissed_at"])
        .values_panic([user_id.to_owned().into(), now.to_owned().into()])
        .on_conflict(
            OnConflict::column(Alias::new("user_id"))
                .update_column(Alias::new("dismissed_at"))
                .to_owned(),
        );
    db.execute(&Statement::render(&insert)).await.map(|_| ())
}

/// The sign-in step the passkeys module contributes to `/authorize`.
#[derive(Debug)]
pub(crate) struct PasskeyOffer;

impl SignInStep for PasskeyOffer {
    fn divert<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        sign_in: SignIn<'a>,
    ) -> BoxFuture<'a, Result<Option<String>, Problem>> {
        Box::pin(async move {
            // A passkey sign-in is the thing being offered; nothing to offer.
            if sign_in
                .amr
                .iter()
                .any(|method| method.as_str() == AMR_PASSKEY)
            {
                return Ok(None);
            }
            let settings = match OfferSettings::from_config(&*ctx.config) {
                Ok(settings) => settings,
                Err(problems) => {
                    tracing::error!(
                        problems = problems.join("; "),
                        "passkey offer settings are invalid"
                    );
                    return Ok(None);
                }
            };
            if !settings.enabled {
                return Ok(None);
            }
            let (Some(db), Some(clock)) = (ctx.ports.db.as_deref(), ctx.ports.clock.as_deref())
            else {
                return Ok(None);
            };
            // A failed read means no offer, never a stuck sign-in.
            match offer_due(db, clock, settings, sign_in.user_id).await {
                Ok(true) => Ok(Some(offer_location(sign_in.continue_to))),
                Ok(false) => Ok(None),
                Err(err) => {
                    tracing::error!(error = %err, "could not decide the passkey offer");
                    Ok(None)
                }
            }
        })
    }
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/offer", get(page))
        .route("/offer/dismiss", post(dismiss))
        .route("/offer/skip", get(skip))
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct OfferQuery {
    #[serde(rename = "continue")]
    continue_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DismissForm {
    #[serde(rename = "continue")]
    continue_to: Option<String>,
}

/// `302` after a GET, `303 See Other` after a POST, to `target`. The target
/// was validated by [`safe_continue`], so it is ASCII and fits a header.
fn go(target: &str, status: StatusCode) -> Response {
    match HeaderValue::from_str(target) {
        Ok(value) => (status, [(header::LOCATION, value)]).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "invalid continue").into_response(),
    }
}

/// The page for a `continue` that names no authorization request. It says
/// what happened and where to go, and redirects nowhere.
fn invalid_page(brand: &Brand) -> Response {
    HostedPage::new("This sign-in link has expired")
        .status(StatusCode::BAD_REQUEST)
        .body(
            "<h1>This sign-in link has expired</h1>\
<p class=\"sub\">Start again from the app you were signing in to.</p>",
        )
        .render(brand)
}

async fn page(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<OfferQuery>,
) -> Response {
    match render(&state, &headers, &query).await {
        Ok(response) => response,
        Err(problem) => problem.into_response(),
    }
}

/// The signed-in session behind this request, if there is one.
async fn current_session(
    db: &dyn Database,
    clock: &dyn Clock,
    headers: &HeaderMap,
) -> Result<Option<cratefield_auth_core::ValidSession>, Problem> {
    match cookie_value(headers) {
        Some(value) => validate(db, clock, &value).await.map_err(|err| {
            tracing::error!(error = %err, "session validation failed");
            Problem::internal()
        }),
        None => Ok(None),
    }
}

/// `GET /offer/skip?continue=…`: the browser cannot offer a passkey (no
/// WebAuthn, or "Continue without a passkey"), so it goes on. The marker
/// cookie stops `/authorize` from offering again in this sign-in. Nothing is
/// recorded against the account: this is not a "Not now".
async fn skip(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Query(query): Query<OfferQuery>,
) -> Result<Response, Problem> {
    let brand = Brand::from_config(&*state.ctx.config, &state.ctx.venture);
    let Some(continue_to) = query.continue_to.as_deref().and_then(safe_continue) else {
        return Ok(invalid_page(&brand));
    };
    let (db, clock, _) = ports(&state)?;
    let Some(session) = current_session(db, clock, &headers).await? else {
        return Ok(go(continue_to, StatusCode::FOUND));
    };
    let mut response = go(continue_to, StatusCode::FOUND);
    let marker = format!(
        "{MARKER_COOKIE}={}; Max-Age={MARKER_MAX_AGE_SECS}; Path=/; Secure; HttpOnly; SameSite=Lax",
        session.id
    );
    if let Ok(value) = HeaderValue::from_str(&marker) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(response)
}

async fn render(
    state: &ModuleState,
    headers: &HeaderMap,
    query: &OfferQuery,
) -> Result<Response, Problem> {
    let brand = Brand::from_config(&*state.ctx.config, &state.ctx.venture);
    let Some(continue_to) = query.continue_to.as_deref().and_then(safe_continue) else {
        return Ok(invalid_page(&brand));
    };
    let (db, clock, _) = ports(state)?;

    // Anything that means "no offer" sends the person on to the request they
    // came for, unchanged, so a stale or repeated visit is harmless.
    let Ok(settings) = OfferSettings::from_config(&*state.ctx.config) else {
        return Ok(go(continue_to, StatusCode::FOUND));
    };
    if !settings.enabled {
        return Ok(go(continue_to, StatusCode::FOUND));
    }
    let Some(session) = current_session(db, clock, headers).await? else {
        return Ok(go(continue_to, StatusCode::FOUND));
    };
    // The offer's own gate: the same freshness the add ceremony needs, and
    // the same account rules the diversion applied.
    let fresh = require_recent_session(db, clock, &session.id).await.is_ok();
    let due = fresh
        && offer_due(db, clock, settings, &session.user_id)
            .await
            .map_err(|_| Problem::internal())?;
    if !due {
        return Ok(go(continue_to, StatusCode::FOUND));
    }

    Ok(HostedPage::new("Sign in faster next time")
        .body(offer_body(continue_to))
        .render(&brand))
}

fn offer_body(continue_to: &str) -> String {
    let target = escape(continue_to);
    let skip = escape(&format!(
        "{SKIP_PATH}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("continue", continue_to)
            .finish()
    ));
    let scripts = format!(
        "{}{}",
        ceremony::script(ceremony::CEREMONY_JS),
        ceremony::script(OFFER_BINDING)
    );
    format!(
        "<h1>Sign in faster next time</h1>\
<p class=\"sub\">Add a passkey so you can sign in with your fingerprint, face or device PIN. \
No email needed.</p>\
<div id=\"cf-offer\" data-continue=\"{target}\" data-skip=\"{skip}\">\
<button class=\"cf-primary\" type=\"button\" id=\"cf-offer-add\" hidden>Add a passkey</button>\
<form method=\"post\" action=\"{DISMISS_PATH}\">\
<input type=\"hidden\" name=\"continue\" value=\"{target}\">\
<button class=\"cf-secondary\" type=\"submit\" id=\"cf-offer-later\">Not now</button>\
</form>\
<p class=\"none\" id=\"cf-offer-message\" role=\"status\" hidden></p>\
<p id=\"cf-offer-skip\" hidden><a class=\"method\" id=\"cf-offer-continue\" href=\"{skip}\">\
Continue without a passkey</a></p>\
</div>{scripts}"
    )
}

/// This page's wiring of the shared ceremony. Without WebAuthn there is
/// nothing to offer, so the browser is sent on at once, and no dismissal is
/// recorded for it.
const OFFER_BINDING: &str = r#"(function () {
  "use strict";
  var root = document.getElementById("cf-offer");
  var add = document.getElementById("cf-offer-add");
  var message = document.getElementById("cf-offer-message");
  var skip = document.getElementById("cf-offer-skip");
  if (!root || !add) return;
  var CONTINUE = root.getAttribute("data-continue") || "/";
  if (!window.cfPasskey || !window.cfPasskey.supported()) {
    window.location.replace(root.getAttribute("data-skip") || CONTINUE);
    return;
  }
  add.hidden = false;
  add.addEventListener("click", function () {
    add.disabled = true;
    message.hidden = true;
    window.cfPasskey.add()
      .then(function () {
        window.location.assign(CONTINUE);
      })
      .catch(function (reason) {
        add.disabled = false;
        message.textContent = window.cfPasskey.explain(reason).text;
        message.hidden = false;
        skip.hidden = false;
      });
  });
})();"#;

async fn dismiss(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<DismissForm>,
) -> Result<Response, Problem> {
    // A form post from another site must not be able to dismiss the offer
    // for somebody (login CSRF, issue #439).
    csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let brand = Brand::from_config(&*state.ctx.config, &state.ctx.venture);
    let Some(continue_to) = form.continue_to.as_deref().and_then(safe_continue) else {
        return Ok(invalid_page(&brand));
    };
    let (db, clock, id_gen) = ports(&state)?;
    let Some(session) = current_session(db, clock, &headers)
        .await
        .map_err(|_| internal(&scope))?
    else {
        return Ok(go(continue_to, StatusCode::SEE_OTHER));
    };
    let settings = match OfferSettings::from_config(&*state.ctx.config) {
        Ok(settings) if settings.enabled => settings,
        _ => return Ok(go(continue_to, StatusCode::SEE_OTHER)),
    };
    // Only an offer that was actually due is recorded as declined.
    let due = offer_due(db, clock, settings, &session.user_id)
        .await
        .map_err(|_| internal(&scope))?;
    if due {
        let now = iso(clock.now());
        record_dismissal(db, &session.user_id, &now)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "could not record the passkey offer dismissal");
                internal(&scope)
            })?;
        // Low severity: an in-app notice only, no mail, no security change.
        if let Err(err) = record_notice(
            db,
            clock,
            id_gen,
            &session.user_id,
            "passkey_offer_dismissed",
            "You skipped the offer to add a passkey when you signed in.",
        )
        .await
        {
            tracing::error!(error = %err, "could not record the offer notice");
        }
        tracing::info!(
            audit = true,
            action = "passkey_offer.dismissed",
            severity = "low",
            subject_hash = %subject_hash(&session.user_id),
            "passkey offer dismissed"
        );
    }
    Ok(go(continue_to, StatusCode::SEE_OTHER))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    fn config(pairs: &[(&str, &str)]) -> MapConfig {
        MapConfig::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    #[test]
    fn the_defaults_are_off_for_thirty_days() {
        let settings = OfferSettings::from_config(&config(&[])).expect("valid");
        assert_eq!(
            settings,
            OfferSettings {
                enabled: false,
                snooze_days: 30
            }
        );
    }

    #[test]
    fn the_setting_and_the_snooze_are_read() {
        let settings = OfferSettings::from_config(&config(&[
            ("AUTH_PASSKEYS_OFFER_AFTER_SIGNIN", "true"),
            ("AUTH_PASSKEYS_OFFER_SNOOZE_DAYS", "7"),
        ]))
        .expect("valid");
        assert!(settings.enabled);
        assert_eq!(settings.snooze_days, 7);
    }

    #[test]
    fn only_the_authorization_endpoint_is_a_continue() {
        let good = "/v1/auth-core/authorize?client_id=a&state=b";
        assert_eq!(safe_continue(good), Some(good));
        assert_eq!(
            safe_continue("/v1/auth-core/authorize"),
            Some("/v1/auth-core/authorize")
        );
        for bad in [
            "",
            "https://app.example/",
            "//app.example/v1/auth-core/authorize",
            "/v1/auth-core/authorize/../../x",
            "/v1/auth-core/authorizex?y",
            "/v1/auth-core/authorize?x=\r\nSet-Cookie:a",
            "/v1/auth-core/authorize?x=\u{e9}",
        ] {
            assert_eq!(safe_continue(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_offer_location_carries_the_request_losslessly() {
        let request = "/v1/auth-core/authorize?state=a%20b&code_challenge=x-_.~&nonce=n&redirect_uri=https%3A%2F%2Fapp.example%2Fcb";
        let location = offer_location(request);
        let parsed = url::Url::parse(&format!("https://auth.example{location}")).expect("url");
        let (key, value) = parsed.query_pairs().next().expect("one pair");
        assert_eq!(key, "continue");
        assert_eq!(value, request);
    }
}
