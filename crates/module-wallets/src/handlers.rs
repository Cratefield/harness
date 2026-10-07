//! HTTP handlers for `/v1/wallets` (issue #835).
//!
//! Four routes, all requiring a signed-in user (the `Auth` port's `Caller`):
//!
//! - `POST /nonce` — mints a single-use nonce bound to the caller's account.
//! - `POST /verify` — verifies a SIWE/SIWS signature and links the wallet.
//! - `GET /` — lists the caller's linked wallets.
//! - `DELETE /{id}` — unlinks the caller's own wallet.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cratefield_core::{
    Auth, Caller, Clock, ModuleContext, Problem, ProblemDef, RandomBytes, Scope, SystemClock,
};

use crate::Chain;
use crate::crypto;
use crate::store;

// ---------------------------------------------------------------------------
// Problem definitions

pub(crate) const UNAUTHENTICATED: ProblemDef = ProblemDef {
    slug: "wallets/unauthenticated",
    status: StatusCode::UNAUTHORIZED,
    title: "Sign in to manage wallets",
    description: "These routes are available only to a signed-in user.",
};

pub(crate) const INVALID_MESSAGE: ProblemDef = ProblemDef {
    slug: "wallets/invalid-message",
    status: StatusCode::BAD_REQUEST,
    title: "Invalid sign-in message",
    description: "The message could not be parsed as a SIWE or SIWS sign-in message.",
};

pub(crate) const DOMAIN_MISMATCH: ProblemDef = ProblemDef {
    slug: "wallets/domain-mismatch",
    status: StatusCode::BAD_REQUEST,
    title: "Domain mismatch",
    description: "The domain in the sign-in message does not match this service's domain.",
};

pub(crate) const NONCE_INVALID: ProblemDef = ProblemDef {
    slug: "wallets/nonce-invalid",
    status: StatusCode::BAD_REQUEST,
    title: "Invalid or expired nonce",
    description: "The nonce is unknown, already used, issued to another account, or expired.",
};

pub(crate) const MESSAGE_EXPIRED: ProblemDef = ProblemDef {
    slug: "wallets/message-expired",
    status: StatusCode::BAD_REQUEST,
    title: "Message expired or not yet valid",
    description: "The message's expiration time has passed or its not-before time is in the future.",
};

pub(crate) const CHAIN_MISMATCH: ProblemDef = ProblemDef {
    slug: "wallets/chain-mismatch",
    status: StatusCode::BAD_REQUEST,
    title: "Chain mismatch",
    description: "The chain in the message is not the chain this request, and this service, are for.",
};

pub(crate) const SIGNATURE_INVALID: ProblemDef = ProblemDef {
    slug: "wallets/signature-invalid",
    status: StatusCode::BAD_REQUEST,
    title: "Signature verification failed",
    description: "The signature does not prove ownership of the address in the message.",
};

pub(crate) const ADDRESS_ALREADY_LINKED: ProblemDef = ProblemDef {
    slug: "wallets/address-already-linked",
    status: StatusCode::CONFLICT,
    title: "Wallet already linked",
    description: "This wallet is already linked to a different account.",
};

pub(crate) const NOT_FOUND: ProblemDef = ProblemDef {
    slug: "wallets/not-found",
    status: StatusCode::NOT_FOUND,
    title: "No such wallet link",
    description: "No wallet link with that id belongs to your account.",
};

// ---------------------------------------------------------------------------
// Events

pub(crate) const EVENT_LINKED: &str = "wallets.linked";
pub(crate) const EVENT_UNLINKED: &str = "wallets.unlinked";

// ---------------------------------------------------------------------------
// Settings + state

/// The builder's settings, cloned into the router state. Nothing here reads
/// the environment; `validate` does that.
#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) domain: String,
    pub(crate) uri: String,
    pub(crate) statement: Option<String>,
    pub(crate) version: String,
    pub(crate) chain_id_evm: String,
    /// The Solana chain id messages carry. Solana has one cluster id and the
    /// module never varies it, but it is a setting rather than a literal at
    /// each use so that `chain_id_for` is the single place a chain id is
    /// resolved and the one place a message's is checked against.
    pub(crate) chain_id_solana: String,
    pub(crate) nonce_ttl_secs: i64,
    pub(crate) random: Option<Arc<dyn RandomBytes>>,
    pub(crate) contract_verifier: Option<Arc<dyn crypto::ContractSignatureVerifier>>,
}

/// The chain id this service mints messages for on `chain`, and therefore the
/// only one a signed message naming `chain` may carry. This is the single
/// source of truth: the nonce row is stamped with it, the `/nonce` response
/// returns it, `verify` refuses any other, and it — never the message's own
/// text — is what reaches the EIP-1271 verifier.
pub(crate) fn chain_id_for(settings: &Settings, chain: Chain) -> &str {
    match chain {
        Chain::Evm => &settings.chain_id_evm,
        Chain::Solana => &settings.chain_id_solana,
    }
}

pub(crate) struct ModuleState {
    pub(crate) ctx: Arc<ModuleContext>,
    pub(crate) settings: Settings,
}

/// "Now" through the Clock port when present, `SystemClock` otherwise.
pub(crate) fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    ctx.ports
        .clock
        .as_ref()
        .map_or_else(|| SystemClock.now(), |clock| clock.now())
}

/// An RFC 3339 UTC timestamp with whole seconds.
pub(crate) fn stamp(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Identifies the caller, or answers a 401 problem. An anonymous caller is
/// refused; a credential that did not verify is an error.
pub(crate) async fn require_subject(
    ctx: &ModuleContext,
    headers: &axum::http::HeaderMap,
    scope: &Scope,
) -> Result<String, Problem> {
    let auth = ctx
        .ports
        .auth
        .clone()
        .ok_or_else(|| Problem::new(&UNAUTHENTICATED).instance(&scope.request_id))?;
    match auth.identify(headers).await {
        Ok(Caller::Subject(subject)) => Ok(subject.id),
        // Anonymous, any other caller shape, and a failing authenticator are
        // all the same answer: this module has nothing to say without a
        // session, and it does not distinguish them to the caller.
        Ok(_) | Err(_) => Err(Problem::new(&UNAUTHENTICATED).instance(&scope.request_id)),
    }
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

/// The module's routes, mounted at `/v1/wallets`.
pub(crate) fn router(ctx: ModuleContext, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState {
        ctx: Arc::new(ctx),
        settings,
    });
    axum::Router::new()
        .route("/nonce", post(create_nonce))
        .route("/verify", post(verify))
        .route("/", get(list))
        .route("/{id}", delete(unlink))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// POST /v1/wallets/nonce

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct NonceBody {
    /// `"evm"` or `"solana"`.
    pub chain: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct NonceResponse {
    pub nonce: String,
    pub chain: String,
    pub domain: String,
    pub uri: String,
    pub statement: Option<String>,
    pub version: String,
    pub chain_id: String,
    pub issued_at: String,
    pub expiration_time: String,
}

async fn create_nonce(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<NonceBody>,
) -> Result<Response, Problem> {
    let chain = body.chain.parse::<Chain>().map_err(|_| {
        Problem::validation_failed(format!(
            "chain must be \"evm\" or \"solana\", got {:?}",
            body.chain
        ))
        .instance(&scope.request_id)
    })?;
    let account_id = require_subject(&state.ctx, &headers, &scope).await?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let Some(random) = state.settings.random.clone() else {
        return Err(internal(&scope));
    };
    let now = now_of(&state.ctx);
    let expires_at = now + time::Duration::seconds(state.settings.nonce_ttl_secs);
    let nonce = match new_nonce(&*random) {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(error = %err, "the entropy source failed to mint a nonce");
            return Err(internal(&scope));
        }
    };
    // The chain id is stamped on the row at mint time, so the nonce is bound
    // to the chain it was issued for rather than to the coarse family name.
    let chain_id = chain_id_for(&state.settings, chain).to_owned();
    store::insert_nonce(
        &*db,
        &nonce,
        &account_id,
        chain.as_str(),
        &chain_id,
        &stamp(now),
        &stamp(expires_at),
    )
    .await
    .map_err(|_| internal(&scope))?;

    Ok(Json(NonceResponse {
        nonce,
        chain: chain.as_str().to_owned(),
        domain: state.settings.domain.clone(),
        uri: state.settings.uri.clone(),
        statement: state.settings.statement.clone(),
        version: state.settings.version.clone(),
        chain_id,
        issued_at: stamp(now),
        expiration_time: stamp(expires_at),
    })
    .into_response())
}

/// A random ≥ 8-character alphanumeric nonce from the CSPRNG.
fn new_nonce(random: &dyn RandomBytes) -> Result<String, cratefield_core::RandomError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = [0u8; 12];
    random.fill(&mut buf)?;
    let nonce: String = buf
        .iter()
        .copied()
        .map(|b| ALPHABET[usize::from(b) % ALPHABET.len()] as char)
        .collect();
    Ok(nonce)
}

// ---------------------------------------------------------------------------
// POST /v1/wallets/verify

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct VerifyBody {
    /// `"evm"` or `"solana"`.
    pub chain: String,
    /// The SIWE/SIWS sign-in message the wallet signed.
    pub message: String,
    /// The signature: hex (with or without `0x`) for EVM, base58 for Solana.
    /// Base64 is also accepted for Solana.
    pub signature: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct LinkResponse {
    pub id: String,
    pub chain: String,
    pub address: String,
    pub linked_at: String,
}

/// Whether a parsed message may still be signed for at `now` — an expired
/// message and a not-yet-valid one are the same refusal, because in both the
/// answer is "sign again". A field the server cannot read is not a reason to
/// refuse: it was checked where it was minted, and failing closed on a parse
/// error would refuse a message this server itself wrote.
fn message_is_current(parsed: &crypto::ParsedMessage, now: OffsetDateTime) -> bool {
    if let Some(exp) = &parsed.expiration_time
        && let Ok(exp_time) = OffsetDateTime::parse(exp, &Rfc3339)
        && exp_time < now
    {
        return false;
    }
    if let Some(nbf) = &parsed.not_before
        && let Ok(nbf_time) = OffsetDateTime::parse(nbf, &Rfc3339)
        && nbf_time > now
    {
        return false;
    }
    true
}

/// Proves the caller controls the address `parsed` names, by verifying
/// `signature` over `message` on `chain`, and returns the address in the
/// normalised form the module stores. Every failure — a malformed signature,
/// a bad one, a contract the venture has no verifier for — is the same
/// refusal, because to the caller they are the same thing.
///
/// `chain_id` is the server's configured chain id, never `parsed.chain_id`:
/// the message's own chain id has already been checked against it by the
/// caller, and an EIP-1271 verifier turns this string into an `eth_call`
/// target, so a message must never get to choose which chain is asked.
async fn prove_ownership(
    state: &ModuleState,
    chain: &Chain,
    chain_id: &str,
    parsed: &crypto::ParsedMessage,
    message: &str,
    signature: &str,
    scope: &Scope,
) -> Result<String, Problem> {
    let invalid = || Problem::new(&SIGNATURE_INVALID).instance(&scope.request_id);
    Ok(match chain {
        Chain::Evm => {
            let signature = decode_evm_signature(signature).ok_or_else(invalid)?;
            crypto::verify_evm(
                &parsed.address,
                message,
                &signature,
                chain_id,
                state.settings.contract_verifier.as_ref(),
            )
            .await
            .map_err(|_| invalid())?
        }
        Chain::Solana => {
            let signature = decode_solana_signature(signature).ok_or_else(invalid)?;
            crypto::verify_solana(&parsed.address, message, &signature).map_err(|_| invalid())?
        }
    })
}

/// Binds `parsed` to this service: the domain must be ours, the chain family
/// must be the one the request asked for, and the chain id must be the one
/// this service is configured for. Returns that chain id, which is the only
/// value any later step — the nonce row's own `chain_id`, and the EIP-1271
/// verifier — is allowed to see.
///
/// A message minted for another domain or another chain is the same phishing
/// shape as a message from another site, so both are refused before a
/// signature is checked and before any chain is named.
fn bind_message(
    settings: &Settings,
    parsed: &crypto::ParsedMessage,
    body_chain: Chain,
    scope: &Scope,
) -> Result<String, Problem> {
    if parsed.domain != settings.domain {
        return Err(Problem::new(&DOMAIN_MISMATCH).instance(&scope.request_id));
    }
    if parsed.chain != body_chain {
        return Err(Problem::new(&CHAIN_MISMATCH).instance(&scope.request_id));
    }
    let chain_id = chain_id_for(settings, body_chain).to_owned();
    if parsed.chain_id != chain_id {
        return Err(Problem::new(&CHAIN_MISMATCH).instance(&scope.request_id));
    }
    Ok(chain_id)
}

async fn verify(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Result<Response, Problem> {
    let body_chain = body.chain.parse::<Chain>().map_err(|_| {
        Problem::validation_failed(format!(
            "chain must be \"evm\" or \"solana\", got {:?}",
            body.chain
        ))
        .instance(&scope.request_id)
    })?;
    let account_id = require_subject(&state.ctx, &headers, &scope).await?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };

    // Parse the message.
    let parsed = crypto::parse_sign_in_message(&body.message)
        .map_err(|_| Problem::new(&INVALID_MESSAGE).instance(&scope.request_id))?;

    // Domain, chain and chain-id binding. The chain id is checked here, not
    // left to the signature check, because everything downstream of it —
    // above all the EIP-1271 `eth_call` — must run on the chain this service
    // is configured for, never on the one the message names.
    let chain_id = bind_message(&state.settings, &parsed, body_chain, &scope)?;

    // The nonce must exist, belong to this account, and have been minted for
    // this chain and this chain id.
    let nonce_row = store::find_nonce(&*db, &parsed.nonce)
        .await
        .map_err(|_| internal(&scope))?;
    let nonce_row =
        nonce_row.ok_or_else(|| Problem::new(&NONCE_INVALID).instance(&scope.request_id))?;
    if nonce_row.account_id != account_id
        || nonce_row.chain != body_chain.as_str()
        || nonce_row.chain_id != parsed.chain_id
    {
        return Err(Problem::new(&NONCE_INVALID).instance(&scope.request_id));
    }

    let now = now_of(&state.ctx);
    let now_stamp = stamp(now);

    if !message_is_current(&parsed, now) {
        return Err(Problem::new(&MESSAGE_EXPIRED).instance(&scope.request_id));
    }

    // Consume the nonce atomically — one caller per nonce wins.
    let consumed = store::consume_nonce(&*db, &parsed.nonce, &now_stamp)
        .await
        .map_err(|_| internal(&scope))?;
    if consumed != 1 {
        return Err(Problem::new(&NONCE_INVALID).instance(&scope.request_id));
    }

    // Verify the signature — against the chain this service is configured
    // for, which is the only chain id the EIP-1271 verifier is ever told.
    let normalised_address = prove_ownership(
        &state,
        &body_chain,
        &chain_id,
        &parsed,
        &body.message,
        &body.signature,
        &scope,
    )
    .await?;

    // Insert the link.
    let id = state.ctx.ports.id_gen.as_ref().map_or_else(
        || {
            format!(
                "wlt_{}",
                &normalised_address[..8.min(normalised_address.len())]
            )
        },
        |idgen| idgen.ulid(),
    );
    let outcome = store::insert_link(
        &*db,
        &id,
        &account_id,
        body_chain.as_str(),
        &normalised_address,
        &now_stamp,
    )
    .await
    .map_err(|_| internal(&scope))?;

    let row = match outcome {
        store::InsertOutcome::Created(row) => {
            state.ctx.events.emit_in(
                &scope,
                EVENT_LINKED,
                json!({
                    "link_id": row.id,
                    "account_id": row.account_id,
                    "chain": row.chain,
                    "address": row.address,
                }),
            );
            row
        }
        store::InsertOutcome::SameAccount(row) => {
            // Idempotent: the wallet is already linked to this account.
            row
        }
        store::InsertOutcome::DifferentAccount => {
            return Err(Problem::new(&ADDRESS_ALREADY_LINKED).instance(&scope.request_id));
        }
    };

    Ok(Json(LinkResponse {
        id: row.id,
        chain: row.chain,
        address: row.address,
        linked_at: row.linked_at,
    })
    .into_response())
}

/// Decodes an EVM hex signature (strips `0x` prefix if present), or `None`
/// when the bytes are not hex. Both outcomes are a refusal to the caller —
/// why a signature cannot be decoded is not something the person signing
/// needs to know, and is not something this module has an opinion about.
fn decode_evm_signature(raw: &str) -> Option<Vec<u8>> {
    let stripped = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    hex::decode(stripped).ok()
}

/// Decodes a Solana signature: base58 first, then base64 (standard) — the
/// two encodings Solana wallets return between them. `None` means neither
/// read, which is a refusal for the same reason as the EVM decoder's.
fn decode_solana_signature(raw: &str) -> Option<Vec<u8>> {
    if let Ok(bytes) = bs58::decode(raw).into_vec() {
        return Some(bytes);
    }
    base64::engine::general_purpose::STANDARD.decode(raw).ok()
}

// ---------------------------------------------------------------------------
// GET /v1/wallets

async fn list(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: axum::http::HeaderMap,
) -> Result<Response, Problem> {
    let account_id = require_subject(&state.ctx, &headers, &scope).await?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let links = store::links_for_account(&*db, &account_id)
        .await
        .map_err(|_| internal(&scope))?;
    let body: Vec<LinkResponse> = links
        .into_iter()
        .map(|row| LinkResponse {
            id: row.id,
            chain: row.chain,
            address: row.address,
            linked_at: row.linked_at,
        })
        .collect();
    Ok(Json(body).into_response())
}

// ---------------------------------------------------------------------------
// DELETE /v1/wallets/{id}

async fn unlink(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let account_id = require_subject(&state.ctx, &headers, &scope).await?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let deleted = store::delete_link(&*db, &id, &account_id)
        .await
        .map_err(|_| internal(&scope))?;
    if deleted != 1 {
        return Err(Problem::new(&NOT_FOUND).instance(&scope.request_id));
    }
    state.ctx.events.emit_in(
        &scope,
        EVENT_UNLINKED,
        json!({
            "link_id": id,
            "account_id": account_id,
        }),
    );
    Ok(Json(json!({ "ok": true })).into_response())
}

// ---------------------------------------------------------------------------
// Self-check

/// The composition a build must refuse, reported by [`Module::self_check`].
#[must_use]
pub(crate) fn self_check(settings: &Settings) -> Vec<String> {
    let mut problems = Vec::new();
    if settings.domain.is_empty() {
        problems.push(
            "wallets: no domain is set, so every SIWE/SIWS message would be refused — \
             add `.domain(..)`"
                .to_owned(),
        );
    }
    if settings.random.is_none() {
        problems.push(
            "wallets: no entropy source is set, so no nonce can be minted — add `.random(..)`"
                .to_owned(),
        );
    }
    problems
}
