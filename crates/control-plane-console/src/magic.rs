//! The console's magic-link sign-in (issue #3): the one way in that needs
//! no third-party registration at all, and therefore the one that gets
//! used first. A link is mailed to an address; following it proves the
//! address; the address becomes the [`VerifiedIdentity`] that goes through
//! the same [`crate::complete_login`] every other provider ends at.
//!
//! A magic link is a **bearer credential sent over a channel this console
//! does not control**, and an invite-only product's name is on the mail.
//! Three rules follow, and each is the difference between a feature and
//! an incident:
//!
//! 1. **Only ever mail an address already on the allowlist.** The request
//!    handler asks the same [`Allowlist::admit`] gate every login goes
//!    through, and an address it refuses is never mailed. An endpoint that
//!    mailed anybody who typed an address would be an open relay for spam
//!    with this product's name on it.
//! 2. **Answer identically whether or not the address is allowlisted.**
//!    Same status, same body, byte for byte — see
//!    [`request_received_page`]. Otherwise the form is an oracle for "who
//!    has access to this console", which is exactly the list an attacker
//!    wants. One channel remains, said plainly: the allowlisted half does
//!    mail work the refused half skips, so a patient timing probe can
//!    tell them apart. Closing that fully would mean sending mail to
//!    strangers, which rule 1 forbids; the per-address and total rate
//!    limits are what bound the probing.
//! 3. **The link is single-use and short-lived.** 32 random bytes, stored
//!    only as its SHA-256, deleted by the same statement that redeems it
//!    (the delete's row count is what makes single-use hold under two
//!    simultaneous clicks, not a read-then-write race). Default fifteen
//!    minutes. A mail archive is not an authentication factor.
//!
//! **Mail clients prefetch links.** Outlook, corporate scanners and
//! several mobile clients fetch every URL in a message, which against a
//! naive single-use token would spend it before the person clicked. So a
//! `GET` only completes the sign-in when the request looks like a person
//! clicking (`Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`,
//! which current browsers send on top-level navigations); anything else
//! gets a confirm button, including requests with no fetch metadata at
//! all — an old browser must cost one click, never a refusal. What the
//! heuristic cannot catch, said because it matters: a scanner that copies
//! a browser's headers, or renders mail in a real engine. The confirm
//! page is identical for a real and an invented token and reads nothing
//! to produce itself, so it is not an oracle either.
//!
//! **Where no mailer is configured the option does not exist.** The login
//! page checks for the `Mailer` port and `CONSOLE_MAGIC_LINK_FROM` before
//! rendering the form, so the console never takes an address it has no
//! way to mail. A deployment without mail still offers its other ways in.

use axum::extract::{Query, State};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cratefield_access::{Allowlist, VerifiedIdentity};
use cratefield_core::{
    Message, ModuleConfig, ModuleContext, SendOutcome, normalize_email, rate_limit_keys,
    rate_limited,
};
use http::{HeaderMap, StatusCode, header};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

use crate::{BASE, ConsoleState, complete_login, now_rfc3339, page, parse_form};

/// How long a link lasts by default. Long enough for mail to arrive and a
/// person to read it; short enough that a message sitting in an unlocked
/// inbox stops being a way in. `CONSOLE_MAGIC_LINK_TTL_SECS` may move it
/// within 60–86400 (validated at boot; a link that lasts a day is a
/// password with a long tail, one that lasts a minute does not survive a
/// slow mail queue).
pub const DEFAULT_TTL_SECS: i64 = 900;

/// The entropy of a mailed token, in bytes.
const TOKEN_BYTES: usize = 32;

/// The resolved magic-link configuration, or `None` when this deployment
/// cannot offer it. `None` is a valid answer the login page renders
/// honestly: no mailer wired, no `CONSOLE_MAGIC_LINK_FROM`, or no
/// `CONSOLE_BASE_URL` to build the link from.
pub(crate) struct MagicSettings {
    pub mail_from: String,
    pub ttl_secs: i64,
    /// The public origin the mailed link points at. `CONSOLE_BASE_URL`,
    /// shared with the OAuth providers' redirect URIs.
    pub base_url: String,
}

pub(crate) fn settings(ctx: &ModuleContext) -> Option<MagicSettings> {
    // Presence only: the port exists, or the option does not. Probing
    // whether an adapter can actually send would mean sending, which is
    // what the login page avoids by checking here instead.
    ctx.ports.mailer.as_ref()?;
    let cfg = ModuleConfig::new("console", &*ctx.config);
    let mail_from = cfg.get_str("MAGIC_LINK_FROM", "");
    let base_url = cfg.get_str("BASE_URL", "");
    if mail_from.trim().is_empty() || base_url.trim().is_empty() {
        return None;
    }
    // `validate_config` rejects values outside 60..=86400, so a value that
    // reaches here unparseable or out of range is a config the validator
    // never saw (tests, hand-built contexts): the default is the safe
    // answer, not the longest.
    let ttl_secs = cfg
        .get_str("MAGIC_LINK_TTL_SECS", "")
        .parse::<i64>()
        .ok()
        .filter(|ttl| (60..=86_400).contains(ttl))
        .unwrap_or(DEFAULT_TTL_SECS);
    Some(MagicSettings {
        mail_from: mail_from.trim().to_owned(),
        ttl_secs,
        base_url: base_url.trim_end_matches('/').to_owned(),
    })
}

/// The one page the request endpoint ever answers with, allowlisted or
/// not. Static on purpose: no address echoed, nothing time-varying, so
/// the non-disclosure test can require byte equality.
pub(crate) fn request_received_page() -> Response {
    (
        StatusCode::OK,
        Html(page(
            "Check your mail",
            "<div class=\"gate\"><div class=\"dash__card\">\
             <p class=\"dash__card-h\">Check your mail</p>\
             <p class=\"dash__note\">If that address is on this console's invite list, \
             a sign-in link is on its way. The link works once and expires shortly. \
             If no link arrives, the address is not invited — ask an operator to add \
             it, or sign in one of the other ways.</p></div></div>",
        )),
    )
        .into_response()
}

/// `POST /magic-link/request`: rate-limit, check the allowlist silently,
/// mail a link to allowlisted addresses only, and answer with the one page
/// either way.
pub(crate) async fn magic_request(
    State(state): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ctx = &state.ctx;
    let Some(settings) = settings(ctx) else {
        // The form is not rendered when this is unset; a hand-built POST
        // gets the named reason rather than a silent no-op.
        return crate::provider_not_configured(
            "Email sign-in links",
            "a mailer port, CONSOLE_MAGIC_LINK_FROM and CONSOLE_BASE_URL",
        );
    };
    let form = parse_form(&body);
    let raw = form
        .iter()
        .find(|(key, _)| key == "email")
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    let email = normalize_email(raw);

    // Both budgets: a per-address key (hashed — a rate-limit key can end
    // up in limiter logs, and it must not carry the address) and a total
    // one, so one address cannot monopolise the mailer and a distributed
    // probe cannot either. Fail-open on limiter transport failure, the
    // same call auth-oidc makes: the allowlist gate and the single-use
    // TTL tokens are the durable backstops behind it.
    let ip = cratefield_core::client_ip(&headers);
    let mut keys = rate_limit_keys(ip.as_deref(), None);
    keys.push(format!("magic-link:addr:{}", hash_hex(email.as_bytes())));
    keys.push("magic-link:total".to_owned());
    if let cratefield_core::RateLimit::Denied { retry_after } = cratefield_core::check_rate_limit(
        ctx.ports.rate_limiter.as_ref(),
        &keys,
        cratefield_core::RateLimitFailure::FailOpen,
    )
    .await
    {
        return rate_limited(retry_after);
    }

    let (Some(db), Some(mailer), Some(clock)) = (
        ctx.ports.db.clone(),
        ctx.ports.mailer.clone(),
        ctx.ports.clock.clone(),
    ) else {
        // The settings check above means the mailer exists; db and clock
        // are the harness's own ports. Either way the answer is the same
        // page and an error in the log — never a difference the caller
        // can read.
        tracing::error!("magic-link request is missing a port it already had");
        return request_received_page();
    };

    // The gate every provider ends at, asked here so that only invited
    // addresses are ever mailed — and its own normalised identity is what
    // gets stored and mailed, so the row can never disagree with the
    // allowlist about how an address is written. A malformed address is
    // refused by the same gate (nothing matches it) and gets the same
    // page.
    let allowlist = Allowlist::new(Arc::clone(&db));
    let probe = VerifiedIdentity {
        email: normalize_email(raw),
        name: String::new(),
        hosted_domain: None,
    };
    let admitted_identity = allowlist
        .admit(&probe)
        .await
        .ok()
        .and_then(|outcome| match outcome {
            cratefield_access::Admission::Admitted { identity, .. } => Some(identity),
            cratefield_access::Admission::Refused => None,
        });
    if let Some(email) = admitted_identity
        && let Some(token) = mint_token()
    {
        let now = clock.now().unix_timestamp();
        // Swept here rather than by a cron pass: the table is exactly as
        // big as the links that could still work, and a failed sweep is
        // logged and ignored — the rows it missed expire on their own.
        if let Err(err) = db
            .execute(&cratefield_core::Statement::with_values(
                "DELETE FROM magic_link WHERE expires_at <= ?",
                vec![int(now)],
            ))
            .await
        {
            tracing::warn!(error = %err, "the magic-link sweep failed");
        }
        let inserted = db
            .execute(&cratefield_core::Statement::with_values(
                "INSERT INTO magic_link (token_hash, email, expires_at, created_at) \
                 VALUES (?, ?, ?, ?)",
                vec![
                    text(&hash_hex(token.as_bytes())),
                    text(&email),
                    int(now + settings.ttl_secs),
                    text(&now_rfc3339(ctx)),
                ],
            ))
            .await;
        if let Err(err) = inserted {
            tracing::error!(error = %err, "could not record the magic link");
            return request_received_page();
        }
        // `CONSOLE_BASE_URL` is the deployment's **origin** — that is what
        // the Google, Apple and Meta redirect URIs built from it mean, and
        // one variable cannot mean two things. So the console's own mount
        // path belongs here, in the link, exactly as it does in theirs.
        // Without it every mailed link points at `/magic-link/consume`,
        // which is not a route, and every magic link is dead on arrival.
        let link = format!(
            "{base}{console}/magic-link/consume?token={token}",
            base = settings.base_url.trim_end_matches('/'),
            console = crate::BASE,
        );
        match mailer
            .send(mail(settings.mail_from.as_str(), &email, &link))
            .await
        {
            Ok(SendOutcome::Sent { .. }) => {}
            // The page cannot say this — "the mailer is broken" is an
            // answer only the operator can act on, and naming it to the
            // requester would split the two halves of rule 2.
            Ok(SendOutcome::NotConfigured) => {
                tracing::error!("the mailer reported NotConfigured after the form was offered");
            }
            Err(err) => {
                tracing::error!(error = %err, "the magic-link mail failed");
            }
        }
    }
    request_received_page()
}

/// `GET /magic-link/consume?token=…` — the URL in the mail.
///
/// Completes the sign-in only when the request looks like a person
/// clicking; a prefetch or a metadata-less client gets the confirm button,
/// which costs one click and works everywhere. The button page is the
/// same for a real and an invented token, and nothing is read or spent to
/// produce it.
pub(crate) async fn magic_consume_get(
    State(state): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Query(params): Query<ConsumeParams>,
) -> Response {
    if looks_like_a_click(&headers) {
        return finish(state, params.token.unwrap_or_default()).await;
    }
    confirm_page(params.token.as_deref().unwrap_or_default())
}

/// `POST /magic-link/consume` — the confirm button. The token is the
/// credential, posted back by the person holding the mail.
pub(crate) async fn magic_consume_post(
    State(state): State<Arc<ConsoleState>>,
    body: String,
) -> Response {
    let form = parse_form(&body);
    let token = form
        .iter()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    finish(state, token).await
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ConsumeParams {
    pub token: Option<String>,
}

/// Redeems a token: delete-and-return atomically, then through
/// [`complete_login`] like every other provider — admission is re-checked
/// there, so a link mailed yesterday for an address revoked since is
/// refused, not honoured.
async fn finish(state: Arc<ConsoleState>, token: String) -> Response {
    let ctx = &state.ctx;
    let (Some(db), Some(signer), Some(clock)) = (
        ctx.ports.db.clone(),
        ctx.ports.signer.clone(),
        ctx.ports.clock.clone(),
    ) else {
        return crate::internal("a required port is unavailable");
    };
    let now = clock.now().unix_timestamp();
    // The delete's row count is the single-use gate: two simultaneous
    // redeems race inside one statement and exactly one of them sees a
    // row. A read-then-delete would let both through; that shape is the
    // bug this statement exists to not be.
    let rows = db
        .query(&cratefield_core::Statement::with_values(
            "DELETE FROM magic_link WHERE token_hash = ? AND expires_at > ? RETURNING email",
            vec![text(&hash_hex(token.as_bytes())), int(now)],
        ))
        .await;
    let email = match rows {
        Ok(rows) => rows.first().and_then(|row| row.get::<String>("email")),
        Err(err) => {
            tracing::error!(error = %err, "the magic-link redeem failed");
            return crate::internal("could not read the sign-in link");
        }
    };
    let Some(email) = email else {
        return link_invalid_page();
    };
    let identity = VerifiedIdentity {
        email,
        name: String::new(),
        hosted_domain: None,
    };
    let now_u64 = u64::try_from(now).unwrap_or(0);
    match complete_login(signer.as_ref(), &Allowlist::new(db), &identity, now_u64).await {
        Ok(crate::LoginOutcome::Admitted { set_cookie }) => (
            AppendHeaders([(header::SET_COOKIE, set_cookie)]),
            axum::response::Redirect::to(BASE),
        )
            .into_response(),
        Ok(crate::LoginOutcome::Refused) => crate::refused_page(&identity.email),
        Err(err) => {
            tracing::error!(error = %err, "login failed");
            crate::internal("login failed")
        }
    }
}

/// Whether a request looks like a person clicking a link in a mail client:
/// the fetch metadata every current browser sends on a top-level
/// navigation. Deliberately narrow: the cost of a false negative is one
/// extra click on the confirm page, and the cost of a false positive is a
/// prefetch spending a single-use token.
fn looks_like_a_click(headers: &HeaderMap) -> bool {
    let mode = headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok());
    let dest = headers
        .get("sec-fetch-dest")
        .and_then(|value| value.to_str().ok());
    mode == Some("navigate") && dest == Some("document")
}

/// The one page every dead link answers with — used, expired, or never
/// issued. Telling them apart would tell an attacker which third it is.
fn link_invalid_page() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(page(
            "Link no longer valid",
            "<div class=\"gate\"><div class=\"dash__card\">\
             <p class=\"dash__card-h\">That sign-in link is no longer valid</p>\
             <p class=\"dash__note\">It was already used, or it expired. Ask for a \
             fresh one on the sign-in page.</p>\
             <div class=\"dash__act\"><a class=\"btn\" href=\"{BASE}/login\">Back to \
             sign in</a></div></div></div>",
        )),
    )
        .into_response()
}

/// The confirm button a prefetch (or a browser without fetch metadata)
/// gets instead of a spent token.
fn confirm_page(token: &str) -> Response {
    (
        StatusCode::OK,
        Html(page(
            "Confirm sign-in",
            &format!(
                "<div class=\"gate\"><div class=\"dash__card\">\
                 <p class=\"dash__card-h\">Sign in to Cratefield?</p>\
                 <p class=\"dash__note\">This page guards the one-use sign-in link \
                 against mail scanners that visit links before you do.</p>\
                 <form method=\"post\" action=\"{BASE}/magic-link/consume\">\
                 <input type=\"hidden\" name=\"token\" value=\"{}\">\
                 <div class=\"dash__act\"><button class=\"btn btn--primary\" \
                 type=\"submit\">Sign in</button></div></form></div></div>",
                crate::escape(token),
            ),
        )),
    )
        .into_response()
}

/// The mail: the text part carries the raw link, because a client that
/// shows only text must still be usable; the HTML part carries it twice —
/// a button and copyable text — for clients that strip anchors.
fn mail(from: &str, to: &str, link: &str) -> Message {
    Message::new(
        to,
        from,
        "Your Cratefield sign-in link",
        format!(
            "Sign in to Cratefield by opening this link. It works once and \
             expires shortly:\n\n{link}\n\nIf you did not ask for it, ignore \
             this mail; nothing happens."
        ),
        format!(
            "<p>Sign in to Cratefield by opening this link. It works once and \
             expires shortly.</p>\
             <p style=\"margin:1.5rem 0\"><a class=\"btn\" href=\"{link}\">Sign in</a></p>\
             <p>Or copy this link: <code>{link}</code></p>\
             <p>If you did not ask for it, ignore this mail; nothing happens.</p>"
        ),
    )
    .tags(["console-magic-link"])
}

/// 32 random bytes, URL-safe. `None` means the entropy source failed; the
/// caller answers with the ordinary page rather than a distinguishable
/// error.
fn mint_token() -> Option<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(Base64UrlUnpadded::encode_string(&bytes))
}

/// Lowercase hex SHA-256, for the token store key. One-way on purpose:
/// the row key can never become the bearer credential again.
fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

fn int(value: i64) -> sea_query::Value {
    sea_query::Value::BigInt(Some(value))
}
