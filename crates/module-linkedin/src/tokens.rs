//! Token lifecycle (issue #9).
//!
//! LinkedIn access tokens last 60 days and refresh tokens 365, and the refresh
//! TTL **does not extend on use**: refreshing on day 300 leaves 65 days, not
//! another year. When the refresh token dies a person has to re-consent, so
//! the module's job is to see that coming and to say so loudly.
//!
//! Everything that talks to LinkedIn goes through [`session`], which refreshes
//! an access token that is about to expire before handing it out. The 401
//! decision lives here and not in the HTTP client: a rejected call gets one
//! refresh and a replay, and only if that refresh fails does the account flip
//! to `needs_reconnect`.

use cratefield_core::{DbError, ModuleContext, Problem, Scope};
use serde_json::json;
use zeroize::Zeroizing;

use crate::client::{ApiError, Client, TokenResponse};
use crate::handlers::{self, Settings};
use crate::store::{self, AccountRow};
use crate::token;

/// An access token, ready to use, with the account it belongs to.
pub(crate) struct Session {
    pub account_id: String,
    pub access_token: Zeroizing<String>,
}

#[derive(Debug)]
pub(crate) enum TokenTrouble {
    /// Nobody has connected a page yet.
    NotConnected,
    /// LinkedIn will not renew: a human has to authorize again.
    NeedsReconnect,
    /// The module is misconfigured (no seal key, no client credentials) or
    /// the stored blob cannot be opened with the configured key.
    Config(String),
    Upstream(ApiError),
    Db(DbError),
}

impl From<DbError> for TokenTrouble {
    fn from(error: DbError) -> Self {
        TokenTrouble::Db(error)
    }
}

impl TokenTrouble {
    /// The problem a caller should answer with.
    pub(crate) fn problem(&self, scope: &Scope) -> Problem {
        match self {
            TokenTrouble::NotConnected => Problem::new(&handlers::NOT_CONNECTED),
            TokenTrouble::NeedsReconnect => Problem::new(&handlers::RECONNECT_REQUIRED),
            TokenTrouble::Config(detail) => {
                tracing::error!(detail = %detail, "linkedin module is misconfigured");
                Problem::not_ready("the linkedin module is not configured")
            }
            TokenTrouble::Upstream(error) => handlers::upstream_problem(error),
            TokenTrouble::Db(error) => {
                tracing::error!(error = %error, "linkedin database error");
                handlers::internal(scope)
            }
        }
    }
}

/// How close to expiry an access token may be before a call refreshes it
/// inline. Ten minutes: long enough that a scheduled publish at the boundary
/// does not fail, short enough that it is not a refresh every request.
const INLINE_REFRESH_WINDOW_SECS: i64 = 600;

fn open_token(
    ctx: &ModuleContext,
    account: &AccountRow,
    column: &str,
    sealed: &str,
) -> Result<Zeroizing<String>, TokenTrouble> {
    let key = seal_key(ctx)?;
    let aad = token::context(store::ACCOUNTS, &account.id, column);
    token::open(&key, &aad, sealed)
        .map_err(|error| TokenTrouble::Config(format!("stored {column} cannot be opened: {error}")))
}

fn seal_key(ctx: &ModuleContext) -> Result<token::SealKey, TokenTrouble> {
    handlers::seal_key(ctx)
        .ok_or_else(|| TokenTrouble::Config("LINKEDIN_TOKEN_KEY is missing or invalid".to_owned()))
}

/// Whether there is a live connection at all, without opening a token or
/// talking to LinkedIn. Write routes call this so they refuse immediately
/// instead of accepting work the publisher will not be able to do.
pub(crate) async fn require_connected(ctx: &ModuleContext) -> Result<(), TokenTrouble> {
    let db = handlers::db(ctx).map_err(|_| TokenTrouble::Config("no database".to_owned()))?;
    let account = store::load_account(db)
        .await?
        .ok_or(TokenTrouble::NotConnected)?;
    if account.status == store::ACCOUNT_NEEDS_RECONNECT {
        return Err(TokenTrouble::NeedsReconnect);
    }
    Ok(())
}

/// A usable access token, refreshing first when the stored one is inside the
/// inline window. The account row is the single source of truth about which
/// connection is live.
pub(crate) async fn session(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
) -> Result<Session, TokenTrouble> {
    let db = handlers::db(ctx).map_err(|_| TokenTrouble::Config("no database".to_owned()))?;
    let clock = handlers::clock(ctx).map_err(|_| TokenTrouble::Config("no clock".to_owned()))?;
    let account = store::load_account(db)
        .await?
        .ok_or(TokenTrouble::NotConnected)?;
    if account.status == store::ACCOUNT_NEEDS_RECONNECT {
        return Err(TokenTrouble::NeedsReconnect);
    }

    let expires_at = store::parse_iso(&account.access_expires_at);
    let due = expires_at.is_none_or(|expiry| {
        expiry - clock.now() <= time::Duration::seconds(INLINE_REFRESH_WINDOW_SECS)
    });
    if due {
        return refresh(ctx, settings, scope, &account).await;
    }

    let access_token = open_token(ctx, &account, "access_token", &account.access_token)?;
    Ok(Session {
        account_id: account.id,
        access_token,
    })
}

/// Refreshes now, whatever the stored expiry says. Called by [`session`] when
/// a token is near its end, by [`maintain`], and by a caller that just took a
/// 401 from LinkedIn and wants one replay before giving up.
pub(crate) async fn refresh_now(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
) -> Result<Session, TokenTrouble> {
    let db = handlers::db(ctx).map_err(|_| TokenTrouble::Config("no database".to_owned()))?;
    let account = store::load_account(db)
        .await?
        .ok_or(TokenTrouble::NotConnected)?;
    refresh(ctx, settings, scope, &account).await
}

async fn refresh(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
    account: &AccountRow,
) -> Result<Session, TokenTrouble> {
    let db = handlers::db(ctx).map_err(|_| TokenTrouble::Config("no database".to_owned()))?;
    let clock = handlers::clock(ctx).map_err(|_| TokenTrouble::Config("no clock".to_owned()))?;
    let http =
        handlers::http(ctx).map_err(|_| TokenTrouble::Config("no http client".to_owned()))?;
    let (client_id, client_secret) = handlers::client_credentials(ctx).ok_or_else(|| {
        TokenTrouble::Config("LINKEDIN_CLIENT_ID/LINKEDIN_CLIENT_SECRET are missing".to_owned())
    })?;

    let Some(sealed_refresh) = account.refresh_token.as_deref() else {
        // No refresh token at all: the app is not approved for programmatic
        // refresh, or the connect predates it. Nothing to do but reconnect.
        mark_needs_reconnect(ctx, scope, account, "no refresh token stored").await?;
        return Err(TokenTrouble::NeedsReconnect);
    };
    let refresh_token = open_token(ctx, account, "refresh_token", sealed_refresh)?;

    let client = Client::anonymous(http);
    let result = client
        .refresh(&refresh_token, &client_id, &client_secret)
        .await;
    handlers::flush_budget(ctx, client.spent()).await;

    let tokens = match result {
        Ok(tokens) => tokens,
        Err(error) => {
            // `invalid_request` is LinkedIn's answer both to a dead refresh
            // token and to a request that forgot a parameter. Only the first
            // is an expiry; treating the second as one would self-inflict a
            // reconnect on a bug of ours.
            if is_dead_refresh_token(&error) {
                mark_needs_reconnect(ctx, scope, account, "refresh token rejected").await?;
                return Err(TokenTrouble::NeedsReconnect);
            }
            tracing::error!(
                error = %error,
                "linkedin refresh failed without saying the token is dead"
            );
            return Err(TokenTrouble::Upstream(error));
        }
    };

    let now = store::now_iso(clock);
    let stored = store_tokens(ctx, &account.id, &tokens, clock)?;
    store::store_refreshed(
        db,
        &account.id,
        &stored.access,
        &stored.access_expires_at,
        stored.refresh.as_deref(),
        stored.refresh_expires_at.as_deref(),
        &now,
    )
    .await?;

    ctx.events.emit_in(
        scope,
        crate::handlers::EVENT_TOKEN_REFRESHED,
        json!({
            "account_id": account.id,
            "access_expires_at": stored.access_expires_at,
            "refresh_expires_at": stored.refresh_expires_at,
        }),
    );

    let _ = settings;
    Ok(Session {
        account_id: account.id.clone(),
        access_token: Zeroizing::new(tokens.access_token),
    })
}

/// The upkeep both cron passes run: warn while there is still time to act,
/// and refresh an access token before it lapses.
///
/// Safe to call often. It reads one row and only talks to LinkedIn when a
/// refresh is actually due, and a refresh moves the expiry 60 days out, so it
/// cannot spin.
pub(crate) async fn maintain(ctx: &ModuleContext, settings: &Settings, scope: &Scope) {
    let (Ok(db), Ok(clock)) = (handlers::db(ctx), handlers::clock(ctx)) else {
        return;
    };
    let Ok(Some(account)) = store::load_account(db).await else {
        return;
    };
    if account.status == store::ACCOUNT_NEEDS_RECONNECT {
        return;
    }

    // The refresh token cannot be renewed, only replaced by a human
    // authorizing again, so the warning has to come early and exactly once.
    if let Some(expiry) = account
        .refresh_expires_at
        .as_deref()
        .and_then(store::parse_iso)
        && account.expiring_notified_at.is_none()
        && expiry - clock.now() <= time::Duration::days(30)
    {
        ctx.events.emit_in(
            scope,
            crate::handlers::EVENT_TOKEN_EXPIRING,
            json!({
                "account_id": account.id,
                "refresh_expires_at": store::iso(expiry),
                "days_left": (expiry - clock.now()).whole_days(),
            }),
        );
        let now = store::now_iso(clock);
        if let Err(error) = store::mark_expiring_notified(db, &account.id, &now).await {
            tracing::warn!(error = %error, "could not record the expiry warning");
        }
    }

    let due = store::parse_iso(&account.access_expires_at).is_none_or(|expiry| {
        expiry - clock.now() <= time::Duration::days(i64::from(settings.refresh_lead_days))
    });
    if due && let Err(trouble) = refresh(ctx, settings, scope, &account).await {
        tracing::warn!(trouble = ?trouble, "scheduled linkedin token refresh did not succeed");
    }
}

/// LinkedIn's documented wording for a refresh token that is gone. Anything
/// else behind a 400 is our bug, not an expiry.
fn is_dead_refresh_token(error: &ApiError) -> bool {
    match error {
        ApiError::Client {
            status: 400,
            message,
            ..
        } => {
            let message = message.to_ascii_lowercase();
            message.contains("invalid, expired or revoked")
                || message.contains("invalid or expired")
                || message.contains("revoked")
        }
        _ => false,
    }
}

async fn mark_needs_reconnect(
    ctx: &ModuleContext,
    scope: &Scope,
    account: &AccountRow,
    reason: &str,
) -> Result<(), TokenTrouble> {
    let db = handlers::db(ctx).map_err(|_| TokenTrouble::Config("no database".to_owned()))?;
    let clock = handlers::clock(ctx).map_err(|_| TokenTrouble::Config("no clock".to_owned()))?;
    let now = store::now_iso(clock);
    store::set_account_status(db, &account.id, store::ACCOUNT_NEEDS_RECONNECT, &now).await?;
    tracing::warn!(reason = %reason, "linkedin account needs to be reconnected");
    ctx.events.emit_in(
        scope,
        crate::handlers::EVENT_TOKEN_EXPIRED,
        json!({ "account_id": account.id, "reason": reason }),
    );
    Ok(())
}

/// The sealed forms of a token response, plus the expiries to store.
pub(crate) struct StoredTokens {
    pub access: String,
    pub access_expires_at: String,
    pub refresh: Option<String>,
    pub refresh_expires_at: Option<String>,
}

/// Seals a token response for one account row. The expiries are computed
/// from LinkedIn's `expires_in` values and never invented.
pub(crate) fn store_tokens(
    ctx: &ModuleContext,
    account_id: &str,
    tokens: &TokenResponse,
    clock: &dyn cratefield_core::Clock,
) -> Result<StoredTokens, TokenTrouble> {
    let key = seal_key(ctx)?;
    let access = token::seal(
        &key,
        &token::context(store::ACCOUNTS, account_id, "access_token"),
        &tokens.access_token,
    )
    .map_err(|error| TokenTrouble::Config(format!("could not seal the access token: {error}")))?;
    let refresh = tokens
        .refresh_token
        .as_deref()
        .map(|value| {
            token::seal(
                &key,
                &token::context(store::ACCOUNTS, account_id, "refresh_token"),
                value,
            )
        })
        .transpose()
        .map_err(|error| {
            TokenTrouble::Config(format!("could not seal the refresh token: {error}"))
        })?;
    Ok(StoredTokens {
        access,
        access_expires_at: store::iso_in(clock, tokens.expires_in),
        refresh,
        refresh_expires_at: tokens
            .refresh_token_expires_in
            .map(|seconds| store::iso_in(clock, seconds)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_linkedins_expiry_wording_flips_an_account() {
        let dead = ApiError::Client {
            status: 400,
            code: "invalid_request".to_owned(),
            message:
                "The provided authorization grant or refresh token is invalid, expired or revoked"
                    .to_owned(),
        };
        assert!(is_dead_refresh_token(&dead));

        // Same status, same code, our bug: a missing parameter must not cost
        // the account its connection.
        let our_bug = ApiError::Client {
            status: 400,
            code: "invalid_request".to_owned(),
            message: "A required parameter \"grant_type\" is missing".to_owned(),
        };
        assert!(!is_dead_refresh_token(&our_bug));
        assert!(!is_dead_refresh_token(&ApiError::TokenRejected));
        assert!(!is_dead_refresh_token(&ApiError::Transport(
            "dns".to_owned()
        )));
    }
}
