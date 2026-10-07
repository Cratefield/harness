//! The connection lifecycle (issue #624): start, complete, read, refresh,
//! revoke.
//!
//! Two concurrency facts carry the safety: a state is spent with one guarded
//! `UPDATE`, so a replayed callback loses; and a refresh is written with one
//! guarded `UPDATE` keyed on the ciphertext the caller read, so two racing
//! refreshes leave the winner's tokens intact and the loser re-reads them.
//! Tokens leave only through [`AccessToken`], and only after the caller named
//! the connection.

use time::{Duration, OffsetDateTime, UtcOffset};
use zeroize::Zeroizing;

use cratefield_core::{
    Clock, Database, HttpClient, IdGen, ModuleConfig, ModuleContext, SystemClock,
};
use cratefield_oauth_client::{
    OAuthClient, Pkce, ProviderConfig, RandomError, SealError, authorize_url, random_state,
};

use crate::handlers::{self, Settings};
use crate::seal;
use crate::store::{self, NewConnection, NewState, StateRow};
use crate::{AccessToken, AuthorizeUrl, Connection, ConnectionError, Provider, ProviderFailure};

/// How long a connect attempt stays valid. Ten minutes is long enough for a
/// person to sign in at the provider and short enough that a leaked `state`
/// is worthless almost immediately.
pub(crate) const STATE_TTL_SECS: i64 = 600;

/// How long before an access token lapses the module refreshes it, unless the
/// builder said otherwise. A minute is under the shortest lifetime any of the
/// presets hands out and over the worst clock skew between us and a provider.
pub(crate) const DEFAULT_REFRESH_LEAD_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// Time and ids

/// "Now" through the `Clock` port when one is mounted, the system clock
/// otherwise.
pub(crate) fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    ctx.ports
        .clock
        .as_ref()
        .map_or_else(|| SystemClock.now(), |clock| clock.now())
}

/// An RFC 3339 UTC timestamp with whole seconds — the only shape written to
/// or compared against a timestamp column. Always converted to UTC first: the
/// stored values are compared as strings (the refresh scan orders on them), so
/// a stamp written in a `Clock`'s own offset would sort wrongly against a UTC
/// one.
pub(crate) fn stamp(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .ok()
        .and_then(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// Reads a timestamp column back. `None` for a value the module did not
/// write, which is treated as "no recorded expiry" rather than as an error.
pub(crate) fn parse_stamp(raw: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339).ok()
}

/// `seconds` from `at`, in the storage shape.
///
/// Saturating, like every sibling module's `iso_in`: `seconds` reaches this
/// from the provider's `expires_in` and from operator-configured refresh
/// leads, neither of which is bounded before the call, and a plain `+` panics
/// on a value that carries the timestamp out of range — a panic in the OAuth
/// callback rather than a far-future expiry column.
fn iso_in(at: OffsetDateTime, seconds: i64) -> String {
    stamp(at.saturating_add(Duration::seconds(seconds)))
}

fn new_id(ctx: &ModuleContext) -> String {
    ctx.ports
        .id_gen
        .as_ref()
        .map_or_else(|| cratefield_core::UlidIdGen.ulid(), |id_gen| id_gen.ulid())
}

fn db(ctx: &ModuleContext) -> Result<&dyn Database, ConnectionError> {
    ctx.ports
        .db
        .as_deref()
        .ok_or_else(|| ConnectionError::Config("the Database port is not mounted".to_owned()))
}

fn http(ctx: &ModuleContext) -> Result<&dyn HttpClient, ConnectionError> {
    ctx.ports
        .http
        .as_deref()
        .ok_or_else(|| ConnectionError::Config("the HttpClient port is not mounted".to_owned()))
}

// ---------------------------------------------------------------------------
// Configuration

/// `CONNECTIONS_<KEY>`, the env prefix a provider's secrets live under.
pub(crate) fn env_key(key: &str) -> String {
    key.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// The sealing key from `CONNECTIONS_TOKEN_KEY` (and the optional
/// `CONNECTIONS_TOKEN_KEY_ID`).
fn seal_key(ctx: &ModuleContext) -> Result<seal::SealKey, ConnectionError> {
    let cfg = ModuleConfig::new("connections", &*ctx.config);
    let encoded = cfg
        .get_opt("TOKEN_KEY")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ConnectionError::Config("CONNECTIONS_TOKEN_KEY is not configured".to_owned())
        })?;
    let id = cfg
        .get_opt("TOKEN_KEY_ID")
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(1);
    seal::SealKey::from_config(&encoded, id).map_err(ConnectionError::Config)
}

/// The redirect URI the provider sends the browser back to. It is derived
/// from `CONNECTIONS_API_BASE` (or the venture's API domain), never from a
/// request header: a `Host` header an attacker chose must not be able to
/// redirect the code to them.
fn redirect_uri(ctx: &ModuleContext, key: &str) -> String {
    let cfg = ModuleConfig::new("connections", &*ctx.config);
    let base = cfg
        .get_opt("API_BASE")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("https://api.{}", ctx.venture.domain));
    format!(
        "{}/v1/connections/callback/{}",
        base.trim_end_matches('/'),
        key
    )
}

/// The provider's wire configuration, with the client credentials read from
/// the environment at call time (so a rotated secret needs no redeploy).
pub(crate) fn provider_config(
    ctx: &ModuleContext,
    provider: &Provider,
) -> Result<ProviderConfig, ConnectionError> {
    let cfg = ModuleConfig::new("connections", &*ctx.config);
    let prefix = env_key(&provider.key);
    let client_id = cfg
        .get_opt(&format!("{prefix}_CLIENT_ID"))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ConnectionError::Config(format!("CONNECTIONS_{prefix}_CLIENT_ID is not configured"))
        })?;
    let client_secret = cfg
        .get_opt(&format!("{prefix}_CLIENT_SECRET"))
        .filter(|value| !value.trim().is_empty());
    Ok(ProviderConfig {
        authorize_url: provider.authorize_url.clone(),
        token_url: provider.token_url.clone(),
        revoke_url: provider.revoke_url.clone(),
        client_id,
        client_secret,
        scopes: provider.scopes.clone(),
        scope_separator: provider.scope_separator,
        client_auth: provider.client_auth,
    })
}

/// The authorize URL, with the provider's own extra parameters appended (the
/// crate builds the standard set; a provider's out-of-band switches — Google's
/// `access_type=offline`, say — are this module's to add).
fn authorize_url_for(
    config: &ProviderConfig,
    provider: &Provider,
    redirect_uri: &str,
    state: &str,
    pkce: Option<&Pkce>,
) -> String {
    let mut url = authorize_url(config, redirect_uri, state, pkce);
    for (name, value) in &provider.authorize_params {
        url = crate::append_query(&url, name, value);
    }
    url
}

// ---------------------------------------------------------------------------
// The lifecycle

/// Begins a connection: refuses a `return_to` off the venture's allowed
/// origins, writes an unspent state carrying it, and returns the URL the
/// browser opens at the provider.
///
/// # Errors
///
/// An unknown provider, a `return_to` the venture does not vouch for, a
/// missing key or client secret, or a database failure.
pub(crate) async fn start(
    ctx: &ModuleContext,
    settings: &Settings,
    subject: &str,
    provider_key: &str,
    return_to: &str,
) -> Result<AuthorizeUrl, ConnectionError> {
    let provider = settings
        .provider(provider_key)
        .ok_or_else(|| ConnectionError::UnknownProvider(provider_key.to_owned()))?;
    if !settings.allows(return_to) {
        return Err(ConnectionError::OriginNotAllowed(return_to.to_owned()));
    }
    let db = db(ctx)?;
    let key = seal_key(ctx)?;

    let state = random_state().map_err(random_error)?;
    let state_hash = crate::sha256_hex(&state);
    let pkce = if provider.pkce {
        Some(Pkce::new().map_err(random_error)?)
    } else {
        None
    };
    let verifier_sealed = pkce
        .as_ref()
        .map(|pkce| {
            seal::seal(
                &key,
                &seal::context(store::STATES, &state_hash, "verifier_sealed"),
                pkce.verifier(),
            )
            .map_err(|error| seal_error(&error))
        })
        .transpose()?;

    let now = now_of(ctx);
    let expires_at = iso_in(now, STATE_TTL_SECS);
    store::insert_state(
        db,
        &NewState {
            state_hash: &state_hash,
            subject,
            provider: provider_key,
            return_to,
            verifier_sealed: verifier_sealed.as_deref(),
            now: &stamp(now),
            expires_at: &expires_at,
        },
    )
    .await?;

    let config = provider_config(ctx, provider)?;
    let url = authorize_url_for(
        &config,
        provider,
        &redirect_uri(ctx, provider_key),
        &state,
        pkce.as_ref(),
    );
    Ok(AuthorizeUrl {
        url,
        expires_at,
        provider: provider_key.to_owned(),
    })
}

/// Spends a state: exactly one caller per `state` sees `Ok`, and everyone
/// else is told the state is gone. The state reaches the database only as its
/// SHA-256 hash, so a dump holds nothing replayable.
///
/// # Errors
///
/// [`ConnectionError::BadState`] for an unknown, spent or expired state, or a
/// database failure.
pub(crate) async fn spend_state(
    ctx: &ModuleContext,
    state: &str,
) -> Result<StateRow, ConnectionError> {
    let db = db(ctx)?;
    let state_hash = crate::sha256_hex(state);
    let now = stamp(now_of(ctx));
    // Read before spending: a purge only ever deletes a state that is already
    // spent or expired, which is exactly the state the guarded UPDATE below
    // would refuse — so reading first cannot lose a legitimate winner to a
    // purge landing between the UPDATE and a re-read, while the UPDATE's
    // affected-row count still decides the single winner.
    let row = store::find_state(db, &state_hash)
        .await?
        .ok_or(ConnectionError::BadState)?;
    if store::spend_state(db, &state_hash, &now).await? != 1 {
        return Err(ConnectionError::BadState);
    }
    Ok(row)
}

/// Exchanges a spent state's code for tokens, stores the connection and
/// emits `connections.connected`. Split from [`spend_state`] so the callback
/// knows the `return_to` even when the exchange fails — and still never
/// redirects from a state that was not spent.
///
/// # Errors
///
/// The provider's refusal, a missing client secret, a sealing failure, or a
/// database failure. Nothing is stored when any of them happens.
pub(crate) async fn exchange(
    ctx: &ModuleContext,
    settings: &Settings,
    row: &StateRow,
    code: &str,
) -> Result<Connection, ConnectionError> {
    let provider = settings
        .provider(&row.provider)
        .ok_or_else(|| ConnectionError::UnknownProvider(row.provider.clone()))?;
    let db = db(ctx)?;
    let key = seal_key(ctx)?;

    let verifier = row
        .verifier_sealed
        .as_deref()
        .map(|sealed| {
            seal::open(
                &key,
                &seal::context(store::STATES, &row.state_hash, "verifier_sealed"),
                sealed,
            )
            .map_err(|error| seal_error(&error))
        })
        .transpose()?;

    let config = provider_config(ctx, provider)?;
    let client = OAuthClient::new(http(ctx)?, &config);
    let tokens = client
        .exchange_code(
            code,
            &redirect_uri(ctx, &row.provider),
            verifier.as_deref().map(String::as_str),
        )
        .await
        .map_err(|error| ConnectionError::Provider(ProviderFailure::of(&error)))?;

    let id = new_id(ctx);
    let now = now_of(ctx);
    let access_sealed = seal::seal(
        &key,
        &seal::context(store::CONNECTIONS, &id, "access_token_sealed"),
        &tokens.access_token,
    )
    .map_err(|error| seal_error(&error))?;
    let refresh_sealed = tokens
        .refresh_token
        .as_deref()
        .map(|token| {
            seal::seal(
                &key,
                &seal::context(store::CONNECTIONS, &id, "refresh_token_sealed"),
                token,
            )
            .map_err(|error| seal_error(&error))
        })
        .transpose()?;
    let access_expires = (tokens.expires_in > 0).then(|| iso_in(now, tokens.expires_in));
    let refresh_expires = tokens
        .refresh_token_expires_in
        .filter(|seconds| *seconds > 0)
        .map(|seconds| iso_in(now, seconds));

    store::insert_connection(
        db,
        &NewConnection {
            id: &id,
            subject: &row.subject,
            provider: &row.provider,
            scopes: &tokens.scope,
            access_token_sealed: Some(&access_sealed),
            refresh_token_sealed: refresh_sealed.as_deref(),
            access_expires_at: access_expires.as_deref(),
            refresh_expires_at: refresh_expires.as_deref(),
            now: &stamp(now),
        },
    )
    .await?;

    let connection = store::load_connection(db, &id)
        .await?
        .ok_or(ConnectionError::BadState)?
        .into();
    handlers::emit(
        ctx,
        handlers::EVENT_CONNECTED,
        serde_json::json!({
            "connection_id": id,
            "subject": row.subject,
            "provider": row.provider,
        }),
    );
    Ok(connection)
}

/// The callback's whole job: spend the state, then exchange the code.
///
/// # Errors
///
/// As [`spend_state`] and [`exchange`].
pub(crate) async fn complete(
    ctx: &ModuleContext,
    settings: &Settings,
    state: &str,
    code: &str,
) -> Result<Connection, ConnectionError> {
    let row = spend_state(ctx, state).await?;
    exchange(ctx, settings, &row, code).await
}

/// A subject's connections, oldest first. Tokens are never part of a
/// [`Connection`].
///
/// # Errors
/// A database failure.
pub(crate) async fn list(
    ctx: &ModuleContext,
    subject: &str,
) -> Result<Vec<Connection>, ConnectionError> {
    Ok(store::list_connections(db(ctx)?, subject)
        .await?
        .into_iter()
        .map(Connection::from)
        .collect())
}

/// One connection by id.
///
/// # Errors
/// [`ConnectionError::NotFound`] when no row carries the id, or a database
/// failure.
pub(crate) async fn get(ctx: &ModuleContext, id: &str) -> Result<Connection, ConnectionError> {
    store::load_connection(db(ctx)?, id)
        .await?
        .map(Connection::from)
        .ok_or_else(|| ConnectionError::NotFound(id.to_owned()))
}

/// An access token for `connection_id`, refreshed first when it is due.
///
/// This is the hot path: a live token costs one read and one unseal. A token
/// at or within the refresh lead of its expiry — or one with no sealed value
/// at all — is refreshed before it is handed back. A connection whose provider
/// stated no lifetime has nothing to be due against, so its token is handed
/// back as-is; and a refresh only ever replaces the recorded expiry with one
/// the provider actually stated, never wipes it.
///
/// # Errors
///
/// [`ConnectionError::NotFound`] for an unknown id; [`ConnectionError::Revoked`]
/// for a revoked connection; [`ConnectionError::NeedsReconnect`] when the
/// provider rejected the refresh token; [`ConnectionError::Provider`] for a
/// transport or provider failure that did not invalidate the connection.
pub(crate) async fn access_token(
    ctx: &ModuleContext,
    settings: &Settings,
    id: &str,
) -> Result<AccessToken, ConnectionError> {
    let db = db(ctx)?;
    let row = store::load_connection(db, id)
        .await?
        .ok_or_else(|| ConnectionError::NotFound(id.to_owned()))?;

    match crate::ConnectionStatus::parse(&row.status) {
        crate::ConnectionStatus::Revoked => return Err(ConnectionError::Revoked),
        crate::ConnectionStatus::NeedsReconnect => {
            return Err(ConnectionError::NeedsReconnect(
                row.last_error
                    .clone()
                    .unwrap_or_else(|| "the provider requires a new authorization".to_owned()),
            ));
        }
        crate::ConnectionStatus::Active => {}
    }

    if is_due(&row, settings, now_of(ctx)) || row.access_token_sealed.is_none() {
        return refresh(ctx, settings, &row).await;
    }

    let key = seal_key(ctx)?;
    let sealed = row
        .access_token_sealed
        .as_deref()
        .ok_or_else(|| ConnectionError::Config("the connection has no access token".to_owned()))?;
    let token = seal::open(
        &key,
        &seal::context(store::CONNECTIONS, &row.id, "access_token_sealed"),
        sealed,
    )
    .map_err(|error| seal_error(&error))?;
    Ok(AccessToken::new(row.id, token, row.access_expires_at))
}

/// Whether `row`'s access token is at or within the refresh lead of lapsing.
/// A row with no recorded expiry has nothing to be due against.
fn is_due(row: &store::ConnectionRow, settings: &Settings, now: OffsetDateTime) -> bool {
    row.access_expires_at
        .as_deref()
        .and_then(parse_stamp)
        .is_some_and(|expiry| expiry - now <= Duration::seconds(settings.refresh_lead_secs))
}

/// Refreshes `row` and hands back the fresh token.
///
/// The write is the guarded one: it lands only while the refresh ciphertext
/// still equals the one this call read. Losing that race means another worker
/// already refreshed, so the loser re-reads the winner's row and returns its
/// token rather than overwriting it. A refused refresh (`invalid_grant`) is
/// the one failure that means the connection is dead: it moves the row to
/// `needs_reconnect` and emits the event. Every other failure — a timeout, a
/// 502 — leaves the row exactly as it was, so the next attempt can still use
/// the same refresh token.
async fn refresh(
    ctx: &ModuleContext,
    settings: &Settings,
    row: &store::ConnectionRow,
) -> Result<AccessToken, ConnectionError> {
    let db = db(ctx)?;
    let key = seal_key(ctx)?;
    let Some(previous) = row.refresh_token_sealed.clone() else {
        let reason = "the provider issued no refresh token, so the connection cannot be renewed";
        mark_needs_reconnect_row(ctx, row, reason).await?;
        return Err(ConnectionError::NeedsReconnect(reason.to_owned()));
    };
    let refresh_token = seal::open(
        &key,
        &seal::context(store::CONNECTIONS, &row.id, "refresh_token_sealed"),
        &previous,
    )
    .map_err(|error| seal_error(&error))?;

    let provider = settings
        .provider(&row.provider)
        .ok_or_else(|| ConnectionError::UnknownProvider(row.provider.clone()))?;
    let config = provider_config(ctx, provider)?;
    let client = OAuthClient::new(http(ctx)?, &config);
    let tokens = match client.refresh(&refresh_token).await {
        Ok(tokens) => tokens,
        Err(error) if error.is_invalid_grant() => {
            let reason = "the provider rejected the refresh token";
            mark_needs_reconnect_row(ctx, row, reason).await?;
            return Err(ConnectionError::NeedsReconnect(reason.to_owned()));
        }
        // A transport failure is not evidence about the connection: the row
        // keeps its tokens and the next attempt tries again.
        Err(error) => return Err(ConnectionError::Provider(ProviderFailure::of(&error))),
    };

    let now = now_of(ctx);
    let access_sealed = seal::seal(
        &key,
        &seal::context(store::CONNECTIONS, &row.id, "access_token_sealed"),
        &tokens.access_token,
    )
    .map_err(|error| seal_error(&error))?;
    // Rota, then store: `rotated_refresh_token` returns the response's own
    // token when the provider rotated, and the previous one when it did not —
    // never "delete the refresh token". The ciphertext is always fresh, so the
    // guard compares on the value read, not on a value re-derived from it.
    let next_refresh = tokens.rotated_refresh_token(&refresh_token);
    let refresh_sealed = seal::seal(
        &key,
        &seal::context(store::CONNECTIONS, &row.id, "refresh_token_sealed"),
        next_refresh,
    )
    .map_err(|error| seal_error(&error))?;
    // A refresh that states no access lifetime keeps the one already recorded
    // rather than wiping it, the same rule as the refresh lifetime below.
    let access_expires = (tokens.expires_in > 0)
        .then(|| iso_in(now, tokens.expires_in))
        .or_else(|| row.access_expires_at.clone());
    // A refresh response that carries no refresh lifetime does not shorten the
    // one already recorded: the RFC is explicit that it does not extend.
    let refresh_expires = tokens
        .refresh_token_expires_in
        .filter(|seconds| *seconds > 0)
        .map(|seconds| iso_in(now, seconds))
        .or_else(|| row.refresh_expires_at.clone());

    let written = store::store_refreshed(
        db,
        &row.id,
        &previous,
        &access_sealed,
        &refresh_sealed,
        access_expires.as_deref(),
        refresh_expires.as_deref(),
        &stamp(now),
    )
    .await?;

    if written == 0 {
        // Another worker refreshed first (or the row was revoked underneath
        // us). Adopt its outcome rather than writing over it.
        return adopt_winner(&key, db, &row.id).await;
    }

    handlers::emit(
        ctx,
        handlers::EVENT_REFRESHED,
        serde_json::json!({
            "connection_id": row.id,
            "subject": row.subject,
            "provider": row.provider,
        }),
    );
    Ok(AccessToken::new(
        row.id.clone(),
        Zeroizing::new(tokens.access_token),
        access_expires,
    ))
}

/// Re-reads a row whose guarded refresh write lost, and returns whatever the
/// winner left behind.
async fn adopt_winner(
    key: &seal::SealKey,
    db: &dyn Database,
    id: &str,
) -> Result<AccessToken, ConnectionError> {
    let winner = store::load_connection(db, id)
        .await?
        .ok_or_else(|| ConnectionError::NotFound(id.to_owned()))?;
    match crate::ConnectionStatus::parse(&winner.status) {
        crate::ConnectionStatus::Revoked => return Err(ConnectionError::Revoked),
        crate::ConnectionStatus::NeedsReconnect => {
            return Err(ConnectionError::NeedsReconnect(
                winner.last_error.unwrap_or_default(),
            ));
        }
        crate::ConnectionStatus::Active => {}
    }
    let sealed = winner
        .access_token_sealed
        .as_deref()
        .ok_or_else(|| ConnectionError::Config("the connection has no access token".to_owned()))?;
    let token = seal::open(
        key,
        &seal::context(store::CONNECTIONS, &winner.id, "access_token_sealed"),
        sealed,
    )
    .map_err(|error| seal_error(&error))?;
    Ok(AccessToken::new(winner.id, token, winner.access_expires_at))
}

/// Revokes a connection: the provider is asked (best effort) to drop both
/// tokens, the row is marked `revoked` and both ciphertexts are cleared, and
/// `connections.revoked` is emitted. A provider that cannot be reached does
/// not stop the local revocation — the tokens are gone here either way, and
/// the RFC makes provider revocation idempotent.
///
/// # Errors
///
/// [`ConnectionError::NotFound`] for an unknown id, or a database failure
/// when the local revoke is written.
pub(crate) async fn revoke(
    ctx: &ModuleContext,
    settings: &Settings,
    id: &str,
) -> Result<(), ConnectionError> {
    let db = db(ctx)?;
    let row = store::load_connection(db, id)
        .await?
        .ok_or_else(|| ConnectionError::NotFound(id.to_owned()))?;
    if crate::ConnectionStatus::parse(&row.status) == crate::ConnectionStatus::Revoked {
        return Ok(());
    }

    if let (Some(provider), Ok(key)) = (settings.provider(&row.provider), seal_key(ctx))
        && let Ok(config) = provider_config(ctx, provider)
        && let Ok(http) = http(ctx)
    {
        let client = OAuthClient::new(http, &config);
        for (sealed, hint) in [
            (row.access_token_sealed.as_deref(), "access_token"),
            (row.refresh_token_sealed.as_deref(), "refresh_token"),
        ] {
            let Some(sealed) = sealed else { continue };
            let column = format!("{hint}_sealed");
            let Ok(token) = seal::open(
                &key,
                &seal::context(store::CONNECTIONS, &row.id, &column),
                sealed,
            ) else {
                continue;
            };
            if let Err(error) = client.revoke(&token, hint).await {
                // Only the safe, structured facts: the slug, the HTTP status
                // and the §5.2 `error` code. The provider's `error_description`
                // and body can echo the token that was just refused.
                let failure = ProviderFailure::of(&error);
                tracing::warn!(
                    provider = %row.provider,
                    slug = handlers::UPSTREAM.slug,
                    status = ?failure.status,
                    code = %failure.code,
                    "the provider did not confirm the revocation"
                );
            }
        }
    }

    store::set_revoked(db, &row.id, &stamp(now_of(ctx))).await?;
    handlers::emit(
        ctx,
        handlers::EVENT_REVOKED,
        serde_json::json!({
            "connection_id": row.id,
            "subject": row.subject,
            "provider": row.provider,
        }),
    );
    Ok(())
}

/// Marks a connection as needing a fresh authorization, and emits
/// `connections.needs_reconnect`. The tokens are left in place: the person may
/// still be able to see what it was connected to, and a later `revoke` clears
/// them.
///
/// # Errors
///
/// [`ConnectionError::NotFound`] for an unknown id, or a database failure.
pub(crate) async fn mark_needs_reconnect(
    ctx: &ModuleContext,
    id: &str,
    reason: &str,
) -> Result<(), ConnectionError> {
    let db = db(ctx)?;
    let row = store::load_connection(db, id)
        .await?
        .ok_or_else(|| ConnectionError::NotFound(id.to_owned()))?;
    mark_needs_reconnect_row(ctx, &row, reason).await
}

async fn mark_needs_reconnect_row(
    ctx: &ModuleContext,
    row: &store::ConnectionRow,
    reason: &str,
) -> Result<(), ConnectionError> {
    store::set_status(
        db(ctx)?,
        &row.id,
        crate::ConnectionStatus::NeedsReconnect.as_str(),
        Some(reason),
        &stamp(now_of(ctx)),
    )
    .await?;
    handlers::emit(
        ctx,
        handlers::EVENT_NEEDS_RECONNECT,
        serde_json::json!({
            "connection_id": row.id,
            "subject": row.subject,
            "provider": row.provider,
        }),
    );
    Ok(())
}

/// Records the provider identity a venture learned with the access token —
/// the account id and the name to show a person. Neither is a token, and this
/// is what `connection.external_account_id` and `connection.display_name`
/// hold.
///
/// # Errors
///
/// [`ConnectionError::NotFound`] for an unknown id, or a database failure.
pub(crate) async fn set_account(
    ctx: &ModuleContext,
    id: &str,
    external_account_id: Option<&str>,
    display_name: Option<&str>,
) -> Result<(), ConnectionError> {
    let db = db(ctx)?;
    let row = store::load_connection(db, id)
        .await?
        .ok_or_else(|| ConnectionError::NotFound(id.to_owned()))?;
    store::set_account(
        db,
        &row.id,
        external_account_id,
        display_name,
        &stamp(now_of(ctx)),
    )
    .await?;
    Ok(())
}

/// The scheduled pass: delete spent and expired states, then refresh the
/// active connections due within the lead. One `try_spend(1)` guards each
/// unit, so a pass that runs out of budget stops cleanly and the rest is left
/// to the next tick.
///
/// # Errors
///
/// A database failure from the purge or a refresh's guarded write. A failed
/// individual refresh is logged and does not fail the pass.
pub(crate) async fn maintain(
    ctx: &ModuleContext,
    settings: &Settings,
) -> Result<(), ConnectionError> {
    let db = db(ctx)?;
    let now = now_of(ctx);

    if ctx.scheduled.try_spend(1) {
        let purged = store::purge_states(db, &stamp(now)).await?;
        if purged > 0 {
            tracing::info!(purged, "purged spent and expired connection states");
        }
    }

    let not_after = iso_in(now, settings.refresh_lead_secs);
    let due = store::due_connections(db, &not_after).await?;
    for row in due {
        if !ctx.scheduled.try_spend(1) {
            break;
        }
        // `db` and `settings` are borrowed again inside; the pass does not
        // hold a row across the await.
        if let Err(error) = refresh(ctx, settings, &row).await {
            // As with revoke: structured, safe fields only, never the error's
            // `Display`, which for a provider failure would carry the
            // provider-controlled description.
            let failure = error.provider_failure();
            tracing::warn!(
                connection_id = %row.id,
                provider = %row.provider,
                slug = error.slug(),
                status = ?failure.and_then(|failure| failure.status),
                code = failure.map_or("-", |failure| failure.code.as_str()),
                "a scheduled refresh did not complete"
            );
        }
    }
    Ok(())
}

fn seal_error(error: &SealError) -> ConnectionError {
    ConnectionError::Config(format!("a sealed value could not be read: {error}"))
}

fn random_error(error: RandomError) -> ConnectionError {
    ConnectionError::Config(format!("no randomness is available: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock in another offset still writes UTC: the stored timestamps are
    /// compared as strings (the refresh scan orders on `access_expires_at`),
    /// so a local-offset stamp — `+05:30` in the rendered value — would sort
    /// wrongly against a UTC one.
    #[test]
    fn a_stamp_is_always_utc() {
        let epoch = OffsetDateTime::from_unix_timestamp(0).expect("the epoch is in range");
        let shifted = epoch.to_offset(UtcOffset::from_hms(5, 30, 0).expect("a valid offset"));
        assert_eq!(stamp(epoch), "1970-01-01T00:00:00Z");
        assert_eq!(
            stamp(shifted),
            stamp(epoch),
            "the clock's own offset must not reach the stored value"
        );
    }

    /// `expires_in` comes from the provider's token response and
    /// `refresh_lead_secs` from operator configuration. Neither is bounded
    /// before it reaches [`iso_in`], so an absurd value must saturate the way
    /// the sibling modules' `iso_in` does — a plain `+` panics here and takes
    /// the OAuth callback down with it.
    #[test]
    fn an_extreme_offset_saturates_instead_of_panicking() {
        let now =
            OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("the epoch is in range");
        let far = iso_in(now, i64::MAX);
        assert_eq!(
            parse_stamp(&far).map(OffsetDateTime::year),
            Some(9999),
            "a saturated expiry must still be a timestamp this module can read back"
        );
        assert!(
            far.ends_with('Z'),
            "a saturated expiry is still UTC: {far:?}"
        );
    }
}
