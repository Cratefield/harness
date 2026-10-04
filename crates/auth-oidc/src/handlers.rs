//! The routes (issues #15, #16): `/{provider}/start`, and
//! `/{provider}/callback` on the one method that provider uses.
//!
//! All are public. `/start` is guarded by the rate limiter and by nothing
//! else, because there is nothing yet to guard; a callback is guarded by
//! the signed flow cookie, which is the only thing that makes a callback
//! ours rather than anybody's.
//!
//! The callback exists twice because Apple posts where everyone else
//! redirects (ADR 0202). Both methods share one body; each refuses the
//! providers that do not use it, so an authorization response can only be
//! delivered the way its own provider delivers it.

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cratefield_core::{Clock, Database, Problem, Scope};
use cratefield_auth_core::cookie_value as session_cookie_value;
use cratefield_auth_core::{
    STATUS_ACTIVE, SsoConnectionRow, client_by_id, domain_of_email, open_client_secret,
    sso_connection_by_id,
};
use http::{HeaderMap, StatusCode, header};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope as OidcScope,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::apple;
use crate::discovery::{PortHttpClient, key_id_of};
use crate::flow::{self, Flow};
use crate::provider::{self, Provider};
use crate::session::{self, Completed, Identity};
use crate::{
    CALLBACK_REFUSED, ModuleState, PROVIDER_UNAVAILABLE, PROVIDER_UNCONFIGURED, ProviderConfig,
};

/// 32 bytes each for the state, the nonce and the PKCE verifier. Generated
/// here rather than through `openidconnect`'s helpers so every random value
/// in this service comes from the same place.
const RANDOM_BYTES: usize = 32;

/// A `return_to` longer than this is not a path anyone meant.
///
/// Bigger than it looks it needs to be, deliberately. The login chooser
/// sends the whole pending `/authorize` here, and `/authorize` accepts a
/// client `state` of up to 2048 bytes on its own. At 512 a client with a
/// long state silently landed back on `/` with its authorization request
/// gone, and nothing anywhere said so.
const MAX_RETURN_TO: usize = 4096;

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/{provider}/start", get(start))
        // Two methods, one path. A provider uses exactly one of them and
        // the other answers 404 for it, so a `form_post` provider cannot
        // be completed through the query-string route and vice versa.
        .route("/{provider}/callback", get(callback).post(callback_form))
        // Issue #627. An enterprise SSO sign-in is addressed by connection
        // id, because the issuer and the credentials belong to one row.
        // The callback is deliberately ONE fixed path: every organization
        // registers the same redirect URI with its IdP, and the connection
        // is recovered from the signed flow cookie instead. A static
        // segment outranks `{provider}` in axum's router, so `/sso/...`
        // can never reach the two handlers above, and `by_slug("sso")`
        // answers `None` if it ever did.
        .route("/sso/{connection_id}/start", get(sso_start))
        .route("/sso/callback", get(sso_callback))
}

#[derive(Debug, Deserialize)]
pub(crate) struct StartQuery {
    return_to: Option<String>,
}

/// The authorization response, however it arrived.
///
/// Apple's `form_post` carries the same three fields as a redirect plus
/// `user`, which no other provider sends and which arrives only on the
/// very first authorization.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    /// Apple only: JSON with the person's name, once and never again.
    user: Option<String>,
}

/// Where the browser may be sent after signing in.
///
/// Only a path on this service. An absolute URL, a protocol-relative `//`,
/// or a backslash the browser may normalise to one, would each turn this
/// endpoint into an open redirect — the classic way a login flow is used to
/// launder a phishing link.
pub(crate) fn safe_return_to(candidate: Option<&str>) -> Option<String> {
    let value = candidate?.trim();
    if value.len() > MAX_RETURN_TO || !value.starts_with('/') {
        return None;
    }
    if value.starts_with("//") || value.starts_with("/\\") {
        return None;
    }
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn random_token() -> Option<String> {
    let mut bytes = [0u8; RANDOM_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(Base64UrlUnpadded::encode_string(&bytes))
}

fn refused(scope: &Scope) -> Problem {
    Problem::new(&CALLBACK_REFUSED).instance(&scope.request_id)
}

fn unavailable(scope: &Scope) -> Problem {
    Problem::new(&PROVIDER_UNAVAILABLE).instance(&scope.request_id)
}

/// A fixed page for the person at the end of a redirect. Nothing from the
/// request reaches it: a provider can put anything in `error_description`,
/// and reflecting it would be a cross-site scripting hole on our own origin.
fn page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Sign in</title></head>\
<body style=\"font:16px/1.5 system-ui,sans-serif;margin:3rem auto;max-width:32rem;padding:0 1rem\">\
<p>{message}</p></body></html>"
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(body),
    )
        .into_response()
}

async fn limit(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = cratefield_core::client_ip(headers);
    for key in cratefield_core::rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&format!("auth-oidc:{key}")).await {
            Ok(decision) if !decision.ok => {
                return Some(cratefield_core::rate_limited(&decision).into_response());
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the auth-oidc rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

fn provider_of(slug: &str) -> Result<&'static Provider, Problem> {
    provider::by_slug(slug).ok_or_else(Problem::not_found)
}

/// Builds the provider client. The concrete type is not nameable without
/// spelling out openidconnect's type-state, so it is built where it is used.
macro_rules! oidc_client {
    ($metadata:expr, $config:expr, $provider:expr) => {
        RedirectUrl::new($config.redirect_uri.clone()).map(|redirect| {
            CoreClient::from_provider_metadata(
                $metadata,
                ClientId::new($config.client_id.clone()),
                Some(ClientSecret::new($config.client_secret.as_str().to_owned())),
            )
            .set_redirect_uri(redirect)
            // Pinned by the descriptor rather than read from the document.
            .set_auth_type($provider.auth_type.as_oauth())
        })
    };
}

async fn start(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<StartQuery>,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let provider = provider_of(&slug)?;
    let settings = state.settings()?;
    let ctx = state.ctx.as_ref();
    let (Some(http), Some(clock), Some(signer)) = (
        ctx.ports.http.clone(),
        ctx.ports.clock.as_deref(),
        ctx.ports.signer.as_deref(),
    ) else {
        return Err(Problem::not_ready("auth-oidc needs http, clock and signer"));
    };
    let config = state.provider_config(provider, clock)?;

    let metadata = state
        .discovery
        .metadata(provider, http, clock, false)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "provider discovery failed");
            unavailable(&scope)
        })?;

    // Who is signed in *now*. `/start` is same-site, so the session cookie
    // arrives here even for a provider whose callback will not carry it.
    // Sealing the answer into the flow is what makes "add this provider to
    // my account" work for a `form_post` provider at all.
    // Both halves of the answer: who it is, and which session row it is,
    // so the callback can revoke that row even though the cookie naming it
    // will not arrive there (auth #36).
    let signed_in = match (ctx.ports.db.as_deref(), session_cookie_value(&headers)) {
        (Some(db), Some(value)) => cratefield_auth_core::validate(db, clock, &value)
            .await
            .ok()
            .flatten(),
        _ => None,
    };
    let (signed_in_user, signed_in_session_id) = signed_in.map_or((None, None), |session| {
        (Some(session.user_id), Some(session.id))
    });

    let (url, flow) = begin(
        &scope,
        provider,
        &config,
        Begin {
            metadata,
            signed_in_user,
            signed_in_session_id,
            // Addressed by provider, so no connection rides in the flow.
            sso_connection: None,
            return_to: query.return_to.as_deref(),
            default_return_to: &settings.default_return_to,
        },
        clock,
    )?;

    Ok(redirect_response(
        &flow.seal(signer),
        url,
        flow::SameSite::for_provider(provider),
    ))
}

/// Everything a `/start` has gathered by the time its URL is built, apart
/// from the provider and its credentials.
struct Begin<'a> {
    metadata: CoreProviderMetadata,
    signed_in_user: Option<String>,
    signed_in_session_id: Option<String>,
    /// The connection this flow belongs to for an enterprise SSO sign-in
    /// (issue #627), `None` for a provider-addressed one.
    sso_connection: Option<String>,
    return_to: Option<&'a str>,
    default_return_to: &'a str,
}

/// Builds the authorization URL and the flow that will complete it.
///
/// Shared by `/{provider}/start` and `/sso/{connection_id}/start`. The two
/// differ only in where the provider, its credentials and the connection
/// came from; a second copy of this would be a second place for the PKCE,
/// nonce and `return_to` rules to drift apart.
fn begin(
    scope: &Scope,
    provider: &Provider,
    config: &ProviderConfig,
    request: Begin<'_>,
    clock: &dyn Clock,
) -> Result<(String, Flow), Problem> {
    let Begin {
        metadata,
        signed_in_user,
        signed_in_session_id,
        sso_connection,
        return_to,
        default_return_to,
    } = request;
    let (Some(state_token), Some(nonce), Some(verifier)) =
        (random_token(), random_token(), random_token())
    else {
        tracing::error!("entropy source failed");
        return Err(Problem::internal().instance(&scope.request_id));
    };

    let client = oidc_client!(metadata, config, provider).map_err(|err| {
        tracing::error!(error = %err, "the configured redirect uri is not a url");
        unavailable(scope)
    })?;
    let challenge =
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.clone()));
    // `authorize_url` wants `'static` factories, so the closures own their
    // copies rather than borrowing the locals we are about to seal.
    let state_for_url = state_token.clone();
    let nonce_for_url = nonce.clone();
    let mut url_request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(state_for_url.clone()),
            move || Nonce::new(nonce_for_url.clone()),
        )
        .set_pkce_challenge(challenge);
    for scope in provider.scopes {
        url_request = url_request.add_scope(OidcScope::new((*scope).to_owned()));
    }
    if provider.is_form_post() {
        // Apple returns the response as a cross-site POST. It does this
        // anyway once `name` or `email` is requested, but saying so makes
        // the descriptor and the callback route agree out loud rather than
        // by coincidence.
        url_request = url_request.add_extra_param("response_mode", "form_post");
    }
    let (url, csrf, _nonce) = url_request.url();

    Ok((
        url.to_string(),
        Flow {
            provider: provider.slug.to_owned(),
            state: csrf.secret().clone(),
            nonce,
            verifier,
            return_to: safe_return_to(return_to).unwrap_or_else(|| default_return_to.to_owned()),
            expires_at: clock.now().unix_timestamp() + flow::TTL_SECS,
            signed_in_user,
            signed_in_session_id,
            sso_connection,
        },
    ))
}

/// Sends the browser to the provider with the flow sealed into a cookie.
fn redirect_response(sealed: &str, url: String, same_site: flow::SameSite) -> Response {
    (
        StatusCode::FOUND,
        [
            (header::SET_COOKIE, flow::set_cookie(sealed, same_site)),
            (header::LOCATION, url),
        ],
    )
        .into_response()
}

/// The redirect callback: every provider but Apple.
async fn callback(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<CallbackParams>,
) -> Result<Response, Problem> {
    let provider = provider_of(&slug)?;
    if provider.is_form_post() {
        // Apple posts. A GET here is somebody poking at the route, and
        // answering it would mean accepting an authorization response
        // through a path this provider never uses.
        return Err(Problem::not_found());
    }
    complete_callback(state, scope, headers, provider, query).await
}

/// The `form_post` callback: Apple only (#3, #16).
///
/// The body is `application/x-www-form-urlencoded`, which needs the
/// harness's `form` feature (Cratefield/harness#46). The request is
/// cross-site, so the flow cookie only arrives because `/start` set it
/// with `SameSite=None` for this provider.
async fn callback_form(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(slug): Path<String>,
    body: String,
) -> Result<Response, Problem> {
    let provider = provider_of(&slug)?;
    if !provider.is_form_post() {
        return Err(Problem::not_found());
    }
    // Parsed here rather than through the `Form` extractor so a malformed
    // body gets this module's page instead of axum's rejection text, and
    // so the answer is identical to a missing `state`: a body that will
    // not parse is either a spoofed post or a provider change, and neither
    // is worth telling the sender apart.
    // Deliberately does NOT clear the flow cookie. This route is a
    // cross-site POST that carries a `SameSite=None` cookie, so anyone can
    // make a victim's browser send one; clearing on an unverified request
    // would let a stranger abort a sign-in in progress from any page the
    // victim has open. Nothing is cleared until the state matches.
    let Ok(params) = serde_urlencoded::from_str::<CallbackParams>(&body) else {
        return Ok(expired_page());
    };
    complete_callback(state, scope, headers, provider, params).await
}

#[allow(clippy::too_many_lines)]
async fn complete_callback(
    state: Arc<ModuleState>,
    scope: Scope,
    headers: HeaderMap,
    provider: &'static Provider,
    query: CallbackParams,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(http), Some(clock), Some(signer), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.http.clone(),
        ctx.ports.clock.as_deref(),
        ctx.ports.signer.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::not_ready("auth-oidc needs its ports"));
    };
    // The flow cookie is what makes this callback ours. Without it, or with
    // one that does not verify, there is nothing here worth reading.
    let Some(cookie) = flow::cookie_value(&headers) else {
        return Ok(expired_page());
    };
    let Some(flow) = Flow::open(signer, clock, provider.slug, &cookie) else {
        return Ok(expired_page());
    };

    // The state is compared first, on the error path too. The provider
    // returns it with an error response, so checking it first means a
    // stranger cannot abort somebody's login in progress by sending their
    // browser to `/callback?error=...`.
    // Nothing above here clears the cookie, and nothing may: on a
    // `form_post` provider this handler answers a cross-site POST that
    // carries the flow cookie, so a request that has not matched the state
    // is not evidence of anything. Clearing on one would hand a stranger a
    // way to abort somebody's sign-in from any page they have open.
    let Some(returned_state) = query.state.as_deref() else {
        return Ok(expired_page());
    };
    if returned_state != flow.state {
        tracing::warn!("the state in a callback did not match the flow cookie");
        return Ok(refused(&scope).into_response());
    }
    // Past here the request holds a state that matches a cookie this
    // service signed, so it is the flow's own. Now the cookie may be spent,
    // and the client secret is worth minting.
    let config = state.provider_config(provider, clock)?;
    let same_site = flow::SameSite::for_provider(provider);

    // The provider refused, or the person cancelled. Logged, never rendered.
    if let Some(error) = query.error.as_deref() {
        tracing::info!(provider = provider.slug, provider_error = %error, "sign-in was not granted");
        return Ok(clear_flow(
            page(
                StatusCode::OK,
                "Sign-in was not completed. You can close this tab and try again.",
            ),
            same_site,
        ));
    }

    let Some(code) = query.code.as_deref() else {
        return Ok(clear_flow(expired_page(), same_site));
    };

    let mut identity = match exchange(&state, provider, &config, clock, &http, &flow, code).await {
        Ok(identity) => identity,
        Err(problem) => return Ok(clear_flow(problem.into_response(), same_site)),
    };

    // Apple's first-authorization name (#3). It is in the form body, not
    // the ID token, and it arrives exactly once: on every later sign-in
    // this field is absent, so if it is not taken here it is gone. It only
    // fills a gap, never overwrites what the ID token said.
    if provider.is_form_post()
        && identity.name.is_none()
        && let Some(name) = query.user.as_deref().and_then(apple::name_from_user_field)
    {
        identity.name = Some(name);
    }

    finish(
        ctx,
        &scope,
        &headers,
        &session::Ports { db, clock, id_gen },
        provider,
        &flow,
        &identity,
        None,
    )
    .await
}

/// The tail every completed flow shares: apply the account-linking rules
/// and then either sign the person in or render the page that asks them
/// for a decision.
///
/// The caller has already verified the flow, exchanged the code and — for
/// an enterprise SSO sign-in — decided the identity is one the connection
/// vouches for.
#[allow(clippy::too_many_arguments)]
async fn finish(
    ctx: &cratefield_core::ModuleContext,
    scope: &Scope,
    headers: &HeaderMap,
    ports: &session::Ports<'_>,
    provider: &Provider,
    flow: &Flow,
    identity: &Identity,
    sso_connection: Option<&str>,
) -> Result<Response, Problem> {
    let (db, clock) = (ports.db, ports.clock);
    let same_site = flow::SameSite::for_provider(provider);

    // A callback from a signed-in person is somebody adding a provider,
    // and the linking rules need to know. The live cookie is the better
    // answer where it arrives; on a cross-site POST it never does, so the
    // flow carries what `/start` saw, re-checked here because the session
    // may have been revoked in between.
    let presented = session_cookie_value(headers);
    let current_user = match presented.as_deref() {
        Some(value) => cratefield_auth_core::validate(db, clock, value)
            .await
            .ok()
            .flatten()
            .map(|session| session.user_id),
        None => match flow.signed_in_user.as_deref() {
            Some(user_id) => cratefield_auth_core::user_by_id(db, user_id)
                .await
                .ok()
                .flatten()
                .filter(|user| user.status == cratefield_auth_core::STATUS_ACTIVE)
                .map(|user| user.id),
            None => None,
        },
    };

    let ip = cratefield_core::client_ip(headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let caller = session::Caller {
        current_user: current_user.as_deref(),
        presented_cookie: presented.as_deref(),
        presented_session_id: flow.signed_in_session_id.as_deref(),
        ip: ip.as_deref(),
        user_agent,
    };
    let completed = match sso_connection {
        Some(connection_id) => {
            session::complete_sso(
                ctx,
                scope,
                ports,
                provider,
                identity,
                &caller,
                connection_id,
            )
            .await?
        }
        None => session::complete(ctx, scope, ports, provider, identity, &caller).await?,
    };

    Ok(match completed {
        Completed::SignedIn { session } => {
            // Two `Set-Cookie` headers, appended one at a time. An array of
            // header pairs *inserts*, so the second would replace the first
            // and the session cookie would never reach the browser.
            let mut response = (
                StatusCode::FOUND,
                [(header::LOCATION, flow.return_to.clone())],
            )
                .into_response();
            for cookie in [
                session::session_cookie(&session),
                flow::clear_cookie(same_site),
            ] {
                if let Ok(value) = header::HeaderValue::from_str(&cookie) {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
            }
            response
        }
        Completed::NeedsPerson { message } => clear_flow(page(StatusCode::OK, message), same_site),
    })
}

/// Exchanges the code and verifies the ID token, refreshing discovery once
/// if the token names a signing key the cached JWKS has never seen — which
/// is what a key rotation looks like from here.
async fn exchange(
    state: &ModuleState,
    provider: &Provider,
    config: &crate::ProviderConfig,
    clock: &dyn Clock,
    http: &Arc<dyn cratefield_core::HttpClient>,
    flow: &Flow,
    code: &str,
) -> Result<Identity, Problem> {
    let metadata = state
        .discovery
        .metadata(provider, Arc::clone(http), clock, false)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "provider discovery failed");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?;

    // The document decides how the client authenticates, wherever the
    // descriptor does not already pin it — which is every SSO connection
    // (issue #627) and neither Google nor Apple.
    let oidc_http = PortHttpClient::new(Arc::clone(http));
    let token = {
        let effective = provider::with_auth_type(provider, &metadata);
        let client = oidc_client!(metadata.clone(), config, &effective).map_err(|err| {
            tracing::error!(error = %err, "the configured redirect uri is not a url");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?;
        client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|err| {
                tracing::error!(error = %err, "the provider metadata has no token endpoint");
                Problem::new(&PROVIDER_UNAVAILABLE)
            })?
            .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier.clone()))
            .request_async(&oidc_http)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "the token exchange failed");
                Problem::new(&PROVIDER_UNAVAILABLE)
            })?
    };

    let id_token = token
        .extra_fields()
        .id_token()
        .ok_or_else(|| {
            tracing::warn!("the token response carried no id token");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?
        .clone();

    // A key we have never heard of is the one failure worth a second
    // attempt: providers rotate, and a cached JWKS should not lock everyone
    // out until the isolate recycles.
    let unknown_key = key_id_of(&id_token.to_string())
        .is_some_and(|kid| !state.discovery.knows_key(&provider.issuer, &kid));
    let metadata = if unknown_key {
        state
            .discovery
            .metadata(provider, Arc::clone(http), clock, true)
            .await
            .unwrap_or(metadata)
    } else {
        metadata
    };

    let claims = {
        let effective = provider::with_auth_type(provider, &metadata);
        let client = oidc_client!(metadata, config, &effective).map_err(|err| {
            tracing::error!(error = %err, "the configured redirect uri is not a url");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?;
        // The clock comes from the port, never from `chrono::Utc::now`,
        // which panics on wasm32 (ADR 0200).
        let now = || {
            chrono::DateTime::from_timestamp(clock.now().unix_timestamp(), 0).unwrap_or_default()
        };
        let verifier = client
            .id_token_verifier()
            // Pinned here rather than taken from the discovery document.
            // The client holds a secret, and openidconnect verifies an
            // HS256 token with it, so a provider document that listed HS256
            // would quietly turn our own client secret into the signing
            // key. Google lists only RS256; this makes that a rule rather
            // than a coincidence.
            .set_allowed_algs(provider.signing_algorithms.iter().cloned())
            .set_time_fn(now);
        id_token
            .claims(&verifier, &Nonce::new(flow.nonce.clone()))
            .map_err(|err| {
                // Signature, issuer, audience, expiry and nonce all land
                // here, and the caller answers the same way for each.
                tracing::warn!(error = %err, "id token verification failed");
                Problem::new(&CALLBACK_REFUSED)
            })?
            .clone()
    };

    Ok(Identity {
        subject: claims.subject().to_string(),
        // Read out of the verified token rather than echoed from the
        // descriptor, so an SSO callback compares what the IdP actually
        // claimed with what its connection was configured with, and can
        // say so in the log when they differ.
        issuer: claims.issuer().as_str().to_owned(),
        email: claims
            .email()
            .map(|email| cratefield_core::normalize_email(email.as_str())),
        email_verified: claims.email_verified().unwrap_or(false),
        name: claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().to_owned()),
    })
}

// ---------------------------------------------------------------------------
// enterprise SSO (issue #627)

/// The connection a request names, when it exists and is switched on.
///
/// A missing connection and a disabled one answer identically, and what
/// they answer is a 404: the id is attacker-supplied, and there is nothing
/// useful to say about a connection that is not in use. The connection's
/// own client must be active too — the same notion of active `/token`
/// applies to a client — so a disabled venture's connection cannot finish
/// a sign-in even if the connection row itself was never switched off.
async fn active_connection(
    db: &dyn Database,
    connection_id: &str,
    scope: &Scope,
) -> Result<Option<SsoConnectionRow>, Problem> {
    let row = sso_connection_by_id(db, connection_id).await.map_err(|err| {
        tracing::error!(error = %err, connection = %connection_id, "could not load an sso connection");
        Problem::internal().instance(&scope.request_id)
    })?;
    let Some(row) = row.filter(|row| row.status == STATUS_ACTIVE) else {
        return Ok(None);
    };
    let client = client_by_id(db, &row.client_id).await.map_err(|err| {
        tracing::error!(error = %err, connection = %connection_id, "could not load an sso connection's client");
        Problem::internal().instance(&scope.request_id)
    })?;
    Ok(client
        .filter(|client| client.status == STATUS_ACTIVE)
        .map(|_| row))
}

/// Begins an enterprise SSO sign-in for one connection.
///
/// Everything the flow needs is on the row: the issuer to discover, the
/// client credentials to present there, and the domains a returned address
/// must be in. The redirect URI is the module's one SSO callback, so an
/// organization registers a single URL with its `IdP` and no path has to
/// carry a connection id.
async fn sso_start(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(connection_id): Path<String>,
    Query(query): Query<StartQuery>,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(http), Some(clock), Some(signer)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.http.clone(),
        ctx.ports.clock.as_deref(),
        ctx.ports.signer.as_deref(),
    ) else {
        return Err(Problem::not_ready(
            "auth-oidc needs a database, http, clock and signer",
        ));
    };
    let settings = state.settings()?;

    let Some(row) = active_connection(db, &connection_id, &scope).await? else {
        tracing::info!(
            connection = %connection_id,
            "an sso start named a connection that is not active",
        );
        return Err(Problem::not_found());
    };

    // The organization's own client secret, unsealed for the length of
    // this request and zeroized when the guard drops.
    let secret = open_client_secret(&*ctx.config, &row).map_err(|err| {
        tracing::error!(error = %err, "could not open an sso connection's client secret");
        Problem::new(&PROVIDER_UNCONFIGURED).instance(&scope.request_id)
    })?;

    let provider = provider::sso(&row.issuer);
    let metadata = state
        .discovery
        .metadata(&provider, Arc::clone(&http), clock, false)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "sso provider discovery failed");
            unavailable(&scope)
        })?;
    let provider = provider::with_auth_type(&provider, &metadata);

    let config = ProviderConfig {
        client_id: row.oidc_client_id.clone(),
        client_secret: secret,
        redirect_uri: settings.sso_redirect_uri(),
    };

    // Same as `/{provider}/start`: who is signed in now, sealed into the
    // flow so a callback that never sees the session cookie can still tell
    // "sign in" from "add this to my account".
    let signed_in = match session_cookie_value(&headers) {
        Some(value) => cratefield_auth_core::validate(db, clock, &value)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let (signed_in_user, signed_in_session_id) = signed_in.map_or((None, None), |session| {
        (Some(session.user_id), Some(session.id))
    });

    let (url, flow) = begin(
        &scope,
        &provider,
        &config,
        Begin {
            metadata,
            signed_in_user,
            signed_in_session_id,
            // The connection rides in the signed flow, which is how the
            // one fixed callback knows which organization came back.
            sso_connection: Some(row.id.clone()),
            return_to: query.return_to.as_deref(),
            default_return_to: &settings.default_return_to,
        },
        clock,
    )?;

    Ok(redirect_response(
        &flow.seal(signer),
        url,
        flow::SameSite::for_provider(&provider),
    ))
}

/// The one SSO callback, whichever organization's `IdP` came back.
///
/// The connection is recovered from the signed flow cookie rather than
/// from the path, so every customer registers the same redirect URI. All
/// of the ways an SSO assertion can be wrong answer with the same refusal
/// and are told apart only in the log, for the reason the passkey module
/// has a single refusal: which check failed is the useful half of the
/// attack.
async fn sso_callback(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<CallbackParams>,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(http), Some(clock), Some(signer), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.http.clone(),
        ctx.ports.clock.as_deref(),
        ctx.ports.signer.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::not_ready("auth-oidc needs its ports"));
    };
    let settings = state.settings()?;
    // An SSO connection is a `query` flow, so the flow cookie is `Lax` and
    // the clear has to look the same.
    let same_site = flow::SameSite::Lax;

    let Some(cookie) = flow::cookie_value(&headers) else {
        return Ok(expired_page());
    };
    let Some(flow) = Flow::open(signer, clock, provider::SSO_SLUG, &cookie) else {
        return Ok(expired_page());
    };
    // The state is compared first, on the error path too, and nothing
    // clears the cookie before it matches — the same rule the per-provider
    // callback keeps, and for the same reason (auth #36).
    let Some(returned_state) = query.state.as_deref() else {
        return Ok(expired_page());
    };
    if returned_state != flow.state {
        tracing::warn!("the state in an sso callback did not match the flow cookie");
        return Ok(refused(&scope).into_response());
    }
    // A cookie this service signed, for a flow that is not an SSO one, is
    // nothing this route can complete.
    let Some(connection_id) = flow.sso_connection.clone() else {
        return Ok(expired_page());
    };
    let Some(row) = active_connection(db, &connection_id, &scope).await? else {
        tracing::warn!(
            connection = %connection_id,
            "an sso callback named a connection that is not active",
        );
        return Ok(clear_flow(refused(&scope).into_response(), same_site));
    };

    if let Some(error) = query.error.as_deref() {
        tracing::info!(connection = %connection_id, provider_error = %error, "an sso sign-in was not granted");
        return Ok(clear_flow(
            page(
                StatusCode::OK,
                "Sign-in was not completed. You can close this tab and try again.",
            ),
            same_site,
        ));
    }
    let Some(code) = query.code.as_deref() else {
        return Ok(clear_flow(expired_page(), same_site));
    };

    let secret = open_client_secret(&*ctx.config, &row).map_err(|err| {
        tracing::error!(error = %err, "could not open an sso connection's client secret");
        Problem::new(&PROVIDER_UNCONFIGURED).instance(&scope.request_id)
    })?;
    let provider = provider::sso(&row.issuer);
    let config = ProviderConfig {
        client_id: row.oidc_client_id.clone(),
        client_secret: secret,
        redirect_uri: settings.sso_redirect_uri(),
    };
    let mut identity = match exchange(&state, &provider, &config, clock, &http, &flow, code).await {
        Ok(identity) => identity,
        Err(problem) => return Ok(clear_flow(problem.into_response(), same_site)),
    };

    if let Some(problem) = sso_refusal(&scope, &row, &identity) {
        return Ok(clear_flow(problem.into_response(), same_site));
    }

    // The identity belongs to the connection, not to the provider as a
    // whole: the same person at the same IdP through two connections is
    // two identities, and one connection's row can never satisfy another's.
    identity.subject = format!("{connection_id}:{}", identity.subject);

    finish(
        ctx,
        &scope,
        &headers,
        &session::Ports { db, clock, id_gen },
        &provider,
        &flow,
        &identity,
        Some(&connection_id),
    )
    .await
}

/// What makes an assertion an *enterprise* one rather than any federated
/// one (issue #627): the issuer, an address the provider verified, an
/// address at all, and a domain the connection routes.
///
/// `None` when the identity is one this connection vouches for, and the
/// refusal to answer with when it is not — the same refusal in every case,
/// with the reason in the log and never in the response, because which
/// check failed is the useful half of the attack.
fn sso_refusal(
    scope: &Scope,
    connection: &SsoConnectionRow,
    identity: &Identity,
) -> Option<Problem> {
    if identity.issuer != connection.issuer {
        // `openidconnect` already compares the ID token's `iss` with the
        // discovered issuer, and discovery pins that to the stored one, so
        // this can only fire if one of those two ever stops doing so.
        tracing::warn!(
            connection = %connection.id,
            issuer = %identity.issuer,
            "refused an sso sign-in: the id token's issuer is not the connection's",
        );
        return Some(refused(scope));
    }
    if !identity.email_verified {
        tracing::warn!(
            connection = %connection.id,
            "refused an sso sign-in: the id token does not verify the address",
        );
        return Some(refused(scope));
    }
    let Some(email) = identity.email.as_deref() else {
        tracing::warn!(
            connection = %connection.id,
            "refused an sso sign-in: the id token carries no address",
        );
        return Some(refused(scope));
    };
    let Some(domain) = domain_of_email(email) else {
        tracing::warn!(
            connection = %connection.id,
            "refused an sso sign-in: the address is not an address",
        );
        return Some(refused(scope));
    };
    if !connection.domains.iter().any(|allowed| allowed == &domain) {
        // The domain, not the address: it is one of the organization's own
        // configured values or it is the reason the refusal happened, and
        // either way it is the single most useful thing an operator can be
        // told.
        tracing::warn!(
            connection = %connection.id,
            domain = %domain,
            "refused an sso sign-in: the address is outside the connection's domains",
        );
        return Some(refused(scope));
    }
    None
}

fn expired_page() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "That sign-in link has expired or was already used. Start again.",
    )
}

/// Adds the header that clears the flow cookie, so a spent or abandoned
/// flow does not linger in the browser.
///
/// The flow decided the `SameSite`, for the same reason the provider did:
/// a clear that does not look like the cookie it clears is the kind of
/// detail that survives a refactor and then does not.
fn clear_flow(response: Response, same_site: flow::SameSite) -> Response {
    let mut response = response;
    let cookie = flow::clear_cookie(same_site);
    if let Ok(value) = header::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_return_to_may_only_be_a_path_on_this_service() {
        assert_eq!(
            safe_return_to(Some("/account")).as_deref(),
            Some("/account")
        );
        assert_eq!(
            safe_return_to(Some("/v1/auth-core/authorize?client_id=x")).as_deref(),
            Some("/v1/auth-core/authorize?client_id=x")
        );
        // Every one of these is an open redirect if it gets through.
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "http://evil.example",
            "javascript:alert(1)",
            "evil.example",
            "",
        ] {
            assert_eq!(safe_return_to(Some(bad)), None, "{bad} was accepted");
        }
        assert_eq!(safe_return_to(None), None);
        assert_eq!(
            safe_return_to(Some(&format!("/{}", "a".repeat(MAX_RETURN_TO)))),
            None
        );
        // But a maximal `/authorize` must fit, or the login chooser sends a
        // `return_to` this silently drops and the person lands on `/` with
        // their authorization request gone. `state` alone may be 2048.
        let pending = format!(
            "/v1/auth-core/authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fapp.example%2Fcb\
             &code_challenge={}&code_challenge_method=S256&state={}",
            "c".repeat(43),
            "s".repeat(2048)
        );
        assert!(
            safe_return_to(Some(&pending)).is_some(),
            "a maximal /authorize does not fit in {MAX_RETURN_TO} bytes"
        );
        assert_eq!(safe_return_to(Some("/ok\nSet-Cookie: x")), None);
    }

    #[test]
    fn random_tokens_are_url_safe_and_distinct() {
        let first = random_token().expect("entropy");
        let second = random_token().expect("entropy");
        assert_ne!(first, second);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
