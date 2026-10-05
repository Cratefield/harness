//! The `Actors` port on Cloudflare: each actor is a Durable Object
//! (issue #583).
//!
//! **The Durable Object class lives in the venture, not here.** `#[durable_object]`
//! is a `wasm_bindgen` export and a library crate cannot export one on a
//! venture's behalf — the same split as [`RoomDriver`](super::realtime::RoomDriver).
//! The venture writes a two-method class and forwards it to [`ActorDriver`],
//! which owns the protocol, the verification and the calls into the module's
//! [`ActorHandler`](cratefield_core::ActorHandler). One object holds one actor:
//! the Worker addresses it by `<kind>:<key>`, so two calls for the same key
//! land on the same object and are serialized by the runtime.
//!
//! ```ignore
//! #[durable_object]
//! pub struct Actors { driver: ActorDriver }
//!
//! impl DurableObject for Actors {
//!     fn new(state: State, env: Env) -> Self {
//!         Self { driver: ActorDriver::new(state, &env, actor_handlers()) }
//!     }
//!     async fn fetch(&self, req: Request) -> Result<Response> { self.driver.fetch(req).await }
//!     async fn alarm(&self) -> Result<Response> { self.driver.alarm().await }
//! }
//! ```
//!
//! `wrangler.toml` binds the class and declares it in a migration — a new
//! class the runtime has not migrated is not created:
//!
//! ```toml
//! [[durable_objects.bindings]]
//! name = "ACTORS"
//! class_name = "Actors"
//!
//! [[migrations]]
//! tag = "v2"
//! new_sqlite_classes = ["Actors"]
//! ```
//!
//! # The protocol
//!
//! The Worker names the object `<kind>:<key>` and POSTs one binary frame:
//!
//! ```text
//! kind length (u8) | kind | key length (u16, big endian) | key | message
//! ```
//!
//! It signs the frame with `HMAC-SHA256(k, frame)`, where `k` is
//! domain-separated from the signer's tokens:
//! `k = HMAC-SHA256(HARNESS_SECRET, "cratefield actor protocol v1")`, and sends
//! `base64url-nopad` of the HMAC in the `x-cratefield-actor-signature` header.
//! The object recomputes it and compares in constant time, accepting the
//! current secret and `HARNESS_SECRET_PREVIOUS` when configured. Anything
//! unsigned or wrongly signed is refused **403** before the frame is parsed or
//! storage is touched. A body over the largest frame the protocol can carry is
//! refused **413** before it is buffered.
//!
//! Statuses: 200 with the reply bytes; 403 unsigned or wrongly signed; 400 a
//! malformed frame, an invalid kind/key, or a frame that names a different
//! actor; 404 no handler for the kind (the client maps it to
//! [`ActorError::NotConfigured`]); 413 [`ActorError::TooLarge`]; 422 with the
//! text [`ActorError::Handler`]; 500 with the text [`ActorError::Operation`].
//! The client maps them back; a transport failure is an `Operation`.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cratefield_core::{
    ActorError, ActorHandlers, ActorStore, ActorWrites, Actors, HarnessConfig, MAX_ACTOR_KEY_BYTES,
    MAX_ACTOR_KIND_BYTES, MAX_ACTOR_MESSAGE_BYTES, check_actor_call, run_actor_alarm,
    run_actor_message, validate_actor_key, validate_actor_kind,
};
use futures_util::lock::Mutex;
use hmac::{Hmac, KeyInit, Mac};
use serde::de::DeserializeOwned;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use worker::d1::serde_wasm_bindgen;
use worker::js_sys::futures::{JsFuture, future_to_promise};
use worker::js_sys::{Date, Function, Promise, Reflect, Uint8Array};
use worker::send::{IntoSendFuture, SendWrapper};
use worker::wasm_bindgen::JsCast;
use worker::wasm_bindgen::JsValue;
use worker::wasm_bindgen::closure::Closure;
use worker::worker_sys::{DurableObjectState, DurableObjectStorage, DurableObjectTransaction};
use worker::{
    Env, Headers, ListOptions, Method, ObjectNamespace, Request, RequestInit, Response,
    Result as WorkerResult, State,
};

use super::WorkersClock;

type HmacSha256 = Hmac<Sha256>;

/// The header carrying the frame's `base64url-nopad` HMAC.
const SIGNATURE_HEADER: &str = "x-cratefield-actor-signature";

/// The domain-separation label the protocol key is derived with, so it can
/// never be the signer's token key even if both are `HARNESS_SECRET`.
const KEY_LABEL: &[u8] = b"cratefield actor protocol v1";

/// The reserved key the actor's kind is persisted under, so an alarm — which
/// arrives with no request and therefore no frame — can still name its actor.
const META_KIND_KEY: &str = "\u{0}kind";

/// The reserved key the actor's key is persisted under.
const META_KEY_KEY: &str = "\u{0}key";

/// The namespace a handler's storage keys are stored under, so they cannot
/// collide with the reserved metadata keys above. `u:` is a prefix no reserved
/// key uses, and the reserved keys use a NUL no handler key realistically can.
const USER_PREFIX: &str = "u:";

/// The storage key one of a handler's keys lives at.
fn storage_key(key: &str) -> String {
    format!("{USER_PREFIX}{key}")
}

/// The largest frame the protocol can carry: the u8 kind length, a maximum
/// kind, the u16 key length, a maximum key and a maximum message — the frame
/// `encode_frame` produces at the encoder's bounds. The object refuses a body
/// larger than this before it buffers one, and again if the read body lies
/// about its size.
const MAX_FRAME_BYTES: usize =
    1 + MAX_ACTOR_KIND_BYTES + 2 + MAX_ACTOR_KEY_BYTES + MAX_ACTOR_MESSAGE_BYTES;

/// Whether a frame's `(kind, key)` is this object's identity.
///
/// The Worker addresses the object with `id_from_name("<kind>:<key>")`, so a
/// frame routed here for a *different* name — a signed frame for another
/// actor, or a misroute — must not overwrite this object's state. Two halves
/// are checked:
///
/// * `name` is `state.id().name()`, the string the object was named with, or
///   `None` when workerd does not expose it (it is not available in the
///   constructor, and a `new_unique_id` object has no name);
/// * `stored` is the `(kind, key)` a previous commit persisted under the
///   reserved metadata keys, or `None` for an object that has never
///   committed.
///
/// Either half that is present and disagrees refuses; a half that is absent
/// is not a mismatch, because the other still applies.
fn frame_matches_identity(
    name: Option<&str>,
    stored: Option<(&str, &str)>,
    kind: &str,
    key: &str,
) -> bool {
    let named = name.is_none_or(|name| name == format!("{kind}:{key}"));
    let persisted =
        stored.is_none_or(|(stored_kind, stored_key)| stored_kind == kind && stored_key == key);
    named && persisted
}

/// The protocol key derived from `secret` — `HMAC-SHA256(secret, label)`.
fn protocol_key(secret: &[u8]) -> [u8; 32] {
    hmac_sha256(secret, KEY_LABEL)
}

/// `HMAC-SHA256(key, data)`. Any key length is accepted, so this cannot fail.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Encodes one request frame: kind length, kind, key length, key, message.
///
/// # Errors
///
/// [`ActorError::TooLarge`] when the kind or key cannot fit its length field —
/// it cannot happen for a validated kind/key, but the wire format is what the
/// decoder trusts, so the encoder is bounded too.
fn encode_frame(kind: &str, key: &str, message: &[u8]) -> Result<Vec<u8>, ActorError> {
    let kind_len = u8::try_from(kind.len()).map_err(|_| {
        ActorError::TooLarge(format!(
            "actor kind of {} bytes overflows the frame",
            kind.len()
        ))
    })?;
    let key_len = u16::try_from(key.len()).map_err(|_| {
        ActorError::TooLarge(format!(
            "actor key of {} bytes overflows the frame",
            key.len()
        ))
    })?;
    let mut frame = Vec::with_capacity(1 + kind.len() + 2 + key.len() + message.len());
    frame.push(kind_len);
    frame.extend_from_slice(kind.as_bytes());
    frame.extend_from_slice(&key_len.to_be_bytes());
    frame.extend_from_slice(key.as_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}

/// Decodes one request frame. The whole frame is consumed: a trailing byte
/// that is not part of the message is impossible, because the message is
/// whatever is left.
///
/// # Errors
///
/// [`ActorError::Operation`] when the frame is shorter than its length fields
/// claim.
fn decode_frame(frame: &[u8]) -> Result<(String, String, Vec<u8>), ActorError> {
    let mut cursor = frame;
    let (&kind_len, rest) = cursor.split_first().ok_or_else(malformed)?;
    cursor = rest;
    let kind_len = usize::from(kind_len);
    let (kind, rest) = split_at(cursor, kind_len)?;
    let (key_len, rest) = split_at(rest, 2)?;
    let key_len = usize::from(u16::from_be_bytes([key_len[0], key_len[1]]));
    let (key, message) = split_at(rest, key_len)?;
    let kind = std::str::from_utf8(kind)
        .map_err(|_| ActorError::Operation("actor frame kind is not utf-8".to_owned()))?;
    let key = std::str::from_utf8(key)
        .map_err(|_| ActorError::Operation("actor frame key is not utf-8".to_owned()))?;
    Ok((kind.to_owned(), key.to_owned(), message.to_vec()))
}

fn split_at(bytes: &[u8], at: usize) -> Result<(&[u8], &[u8]), ActorError> {
    if bytes.len() < at {
        return Err(malformed());
    }
    Ok(bytes.split_at(at))
}

fn malformed() -> ActorError {
    ActorError::Operation("actor frame is malformed".to_owned())
}

/// Signs `frame` with `key`, `base64url-nopad`.
fn sign_frame(key: &[u8], frame: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(hmac_sha256(key, frame))
}

/// Whether `signature` is `HMAC-SHA256(key, frame)`, compared in constant time.
///
/// A malformed signature is refused without a MAC, and a well-formed one is
/// compared with `subtle` rather than `==`, so the comparison does not leak how
/// many leading bytes matched.
fn verify_frame(signature: &str, key: &[u8], frame: &[u8]) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(expected) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    bool::from(hmac_sha256(key, frame).ct_eq(&expected))
}

/// The keys a deployment verifies with: the current secret first, the previous
/// one second when `HARNESS_SECRET_PREVIOUS` is set.
fn verification_keys(config: &HarnessConfig) -> Vec<[u8; 32]> {
    let mut keys = vec![protocol_key(config.harness_secret.as_bytes())];
    if let Some(previous) = &config.harness_secret_previous {
        keys.push(protocol_key(previous.as_bytes()));
    }
    keys
}

/// Forwards a Durable Object's `fetch` and `alarm` entry points to the module's
/// [`ActorHandler`](cratefield_core::ActorHandler)s.
pub struct ActorDriver {
    /// The object's raw state. It is held raw rather than as `worker::State`
    /// because the transaction needs the `DurableObjectTransaction`'s alarm
    /// methods, which `worker::Storage::transaction` hides — see `commit`.
    /// `State::_inner` is the one way to reach the raw handle, and the
    /// worker library offers no other way to reach them.
    state: DurableObjectState,
    handlers: ActorHandlers,
    /// The keys a frame may be signed with — current, then previous.
    keys: Vec<[u8; 32]>,
    /// Serializes messages and alarms. A Durable Object already delivers one
    /// request at a time, but a handler that awaits lets workerd interleave
    /// the next event's *read* of storage with this one, so the runner's
    /// read-modify-write is only safe behind a lock this driver holds.
    lock: Mutex<()>,
}

impl ActorDriver {
    /// Builds the driver from the object's `State`, its `Env` (for the signing
    /// key) and the handlers the venture registered.
    ///
    /// A deployment whose `HARNESS_SECRET` is missing or too short derives no
    /// key, and every request is then refused 403 rather than served.
    #[must_use]
    pub fn new(state: State, env: &Env, handlers: ActorHandlers) -> Self {
        let keys = match HarnessConfig::from_config(&crate::config::EnvConfig(env.clone())) {
            Ok(config) => verification_keys(&config),
            Err(_) => Vec::new(),
        };
        Self {
            state: state._inner(),
            handlers,
            keys,
            lock: Mutex::new(()),
        }
    }

    /// Handles one signed message frame.
    ///
    /// # Errors
    ///
    /// A `worker::Error` only from reading the request body; every protocol
    /// failure is a status on the response, because the caller is a Worker that
    /// maps statuses back to [`ActorError`]s.
    pub async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        let mut req = req;
        let Ok(Some(signature)) = req.headers().get(SIGNATURE_HEADER) else {
            return Response::error("actor request is not signed", 403);
        };
        // Bound the body before buffering it. `Content-Length` is checked
        // first, so a declared-oversized body is refused without reading it;
        // the read length is checked again, because the header can lie. The
        // signature still verifies before anything is parsed or stored.
        if declared_content_length(&req).is_some_and(|length| length > MAX_FRAME_BYTES) {
            return Response::error("actor frame is too large", 413);
        }
        let frame = req.bytes().await?;
        if frame.len() > MAX_FRAME_BYTES {
            return Response::error("actor frame is too large", 413);
        }
        if !self
            .keys
            .iter()
            .any(|key| verify_frame(&signature, key, &frame))
        {
            return Response::error("actor request signature is invalid", 403);
        }
        let Ok((kind, key, message)) = decode_frame(&frame) else {
            return Response::error("actor frame is malformed", 400);
        };
        if validate_actor_kind(&kind).is_err() || validate_actor_key(&key).is_err() {
            return Response::error("actor kind or key is invalid", 400);
        }
        let Some(handler) = self.handlers.get(&kind) else {
            return Response::error("no handler for this actor kind", 404);
        };

        let _serialized = self.lock.lock().await;
        // The frame must name *this* object. The Worker routes by
        // `id_from_name("<kind>:<key>")`, so a signed frame for another actor
        // reaching here is refused before storage is touched: a mismatching
        // name (where workerd exposes one) or a stored identity that disagrees
        // with the frame.
        let stored = read_meta(&self.state).await?;
        let named_identity = self.state.id()?.name();
        if !frame_matches_identity(
            named_identity.as_deref(),
            stored
                .as_ref()
                .map(|(kind, key)| (kind.as_str(), key.as_str())),
            &kind,
            &key,
        ) {
            return Response::error("actor frame names a different actor", 400);
        }
        let store = DurableActorStore::new(&self.state, &kind, &key);
        match run_actor_message(
            handler.as_ref(),
            &store,
            &WorkersClock,
            &kind,
            &key,
            &message,
        )
        .await
        {
            Ok(reply) => Response::from_bytes(reply),
            Err(error) => actor_error_response(&error),
        }
    }

    /// Runs the actor's alarm. The actor's kind and key come from the reserved
    /// keys a previous message committed, because an alarm carries no frame.
    ///
    /// # Errors
    ///
    /// When a storage read fails, and — deliberately — when the handler fails:
    /// a failed alarm commits nothing, so workerd's retry of a throwing alarm
    /// handler is the retry the port's contract promises. It is **not** logged
    /// and swallowed the way [`RoomDriver`](super::realtime::RoomDriver)'s tick
    /// is, because a room tick that is missed is a tick, and an actor alarm
    /// that is missed is a lease that never expired.
    pub async fn alarm(&self) -> WorkerResult<Response> {
        let _serialized = self.lock.lock().await;
        let Some((kind, key)) = read_meta(&self.state).await? else {
            // No message was ever committed against this object, so it has no
            // actor identity and nothing to run.
            return Response::empty();
        };
        let Some(handler) = self.handlers.get(&kind) else {
            return Response::empty();
        };
        let store = DurableActorStore::new(&self.state, &kind, &key);
        match run_actor_alarm(handler.as_ref(), &store, &WorkersClock, &kind, &key).await {
            Ok(()) => Response::empty(),
            Err(error) => Err(worker::Error::RustError(error.to_string())),
        }
    }
}

/// The `Content-Length` a request declares, if it is present and parseable. A
/// missing or unparseable header is `None`, and the read-length check in
/// `fetch` still applies.
fn declared_content_length(req: &Request) -> Option<usize> {
    req.headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|value| value.parse().ok())
}

/// The actor's kind and key, persisted under the reserved keys on the first
/// commit, or `None` for an object that has never committed.
async fn read_meta(state: &DurableObjectState) -> WorkerResult<Option<(String, String)>> {
    let storage = state.storage()?;
    let kind = storage_get::<String>(&storage, META_KIND_KEY).await?;
    let key = storage_get::<String>(&storage, META_KEY_KEY).await?;
    Ok(match (kind, key) {
        (Some(kind), Some(key)) => Some((kind, key)),
        _ => None,
    })
}

/// Reads one value through the raw storage handle.
///
/// The driver works in terms of `DurableObjectStorage` rather than
/// `worker::Storage` because it needs the raw handle for the transaction's
/// alarm methods; a `worker::State` cannot give one back. This mirrors
/// `worker::Storage::get`, including reading an `undefined` as `None`.
async fn storage_get<T: DeserializeOwned>(
    storage: &DurableObjectStorage,
    key: &str,
) -> WorkerResult<Option<T>> {
    let value = JsFuture::from(storage.get(key)?).into_send().await?;
    if value.is_undefined() {
        return Ok(None);
    }
    Ok(Some(serde_wasm_bindgen::from_value(value)?))
}

/// Every `(raw key, value)` under `prefix`, sorted by key, through the raw
/// storage handle. The one place a listing is decoded, shared by the store's
/// `list_prefix` and its `clear_all` key set.
async fn storage_list(
    storage: &DurableObjectStorage,
    prefix: &str,
) -> WorkerResult<BTreeMap<String, Vec<u8>>> {
    let options = ListOptions::new().prefix(prefix);
    let promise = storage.list_with_options(serde_wasm_bindgen::to_value(&options)?.into())?;
    let listed = JsFuture::from(promise).into_send().await?;
    serde_wasm_bindgen::from_value(listed).map_err(Into::into)
}

/// The pending alarm as milliseconds since the epoch, through the raw storage
/// handle, or `None` when none is set.
async fn storage_alarm(storage: &DurableObjectStorage) -> WorkerResult<Option<i64>> {
    let value = JsFuture::from(storage.get_alarm(JsValue::NULL.into())?)
        .into_send()
        .await?;
    // The alarm is milliseconds since the epoch, a whole number well inside
    // `i64`'s range; the cast only narrows the `f64` a JS number arrives as.
    #[allow(clippy::cast_possible_truncation)]
    Ok(value.as_f64().map(|ms| ms as i64))
}

/// Maps a runner failure onto the status the Worker maps back to an
/// [`ActorError`].
fn actor_error_response(error: &ActorError) -> WorkerResult<Response> {
    let (status, detail) = match error {
        ActorError::TooLarge(detail) => (413, detail.clone()),
        ActorError::Handler(detail) => (422, detail.clone()),
        ActorError::NotConfigured => (404, "no handler for this actor kind".to_owned()),
        ActorError::Timeout | ActorError::Operation(_) => (500, error.to_string()),
    };
    Response::error(detail, status)
}

fn store_error(error: &worker::Error) -> ActorError {
    ActorError::Operation(error.to_string())
}

/// A `JsValue` failure — from a raw binding rather than a `worker::Error` —
/// as an [`ActorError`].
fn js_error(error: JsValue) -> ActorError {
    store_error(&worker::Error::from(error))
}

/// The store one Durable Object instance reads and writes through. Core owns
/// the staging and the all-or-nothing rule; this only has to make
/// [`commit`](ActorStore::commit) atomic and keep the reserved keys out of the
/// handler's namespace.
struct DurableActorStore<'a> {
    state: &'a DurableObjectState,
    kind: String,
    key: String,
}

impl<'a> DurableActorStore<'a> {
    fn new(state: &'a DurableObjectState, kind: &str, key: &str) -> Self {
        Self {
            state,
            kind: kind.to_owned(),
            key: key.to_owned(),
        }
    }

    /// The object's raw storage handle.
    fn storage(&self) -> Result<DurableObjectStorage, ActorError> {
        self.state.storage().map_err(js_error)
    }
}

#[async_trait]
impl ActorStore for DurableActorStore<'_> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ActorError> {
        let storage = self.storage()?;
        storage_get::<Vec<u8>>(&storage, &storage_key(key))
            .await
            .map_err(|error| store_error(&error))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, ActorError> {
        let storage = self.storage()?;
        // The values were stored through `put`, so each is a JSON-ish array of
        // numbers in JS; deserializing through the same serde stack is what
        // reads them back as bytes.
        let entries = storage_list(&storage, &storage_key(prefix))
            .await
            .map_err(|error| store_error(&error))?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, value)| {
                key.strip_prefix(USER_PREFIX)
                    .map(|key| (key.to_owned(), value))
            })
            .collect())
    }

    async fn alarm(&self) -> Result<Option<OffsetDateTime>, ActorError> {
        let storage = self.storage()?;
        match storage_alarm(&storage)
            .await
            .map_err(|error| store_error(&error))?
        {
            Some(ms) => Ok(Some(ms_to_alarm(ms)?)),
            None => Ok(None),
        }
    }

    async fn commit(&self, writes: ActorWrites) -> Result<(), ActorError> {
        let ActorWrites {
            clear_all,
            entries,
            alarm,
        } = writes;
        let kind = self.kind.clone();
        let key = self.key.clone();
        let entries: Vec<(String, Option<Vec<u8>>)> = entries.into_iter().collect();

        // **`deleteAll` is refused inside a transaction** (workerd: "Cannot
        // call deleteAll() within a transaction"), so a `clear_all` is carried
        // out as an explicit delete of every existing key *inside* the same
        // transaction. The key set is read first, which is safe because the
        // driver holds the per-actor lock: no other message or alarm for this
        // actor can write between the read and the commit.
        let clearing: Vec<String> = if clear_all {
            let storage = self.storage()?;
            storage_list(&storage, USER_PREFIX)
                .await
                .map_err(|error| store_error(&error))?
                .into_keys()
                .collect()
        } else {
            Vec::new()
        };

        // The values **and the alarm** commit as one atomic unit, inside one
        // `storage.transaction`: workerd applies every put, delete and alarm
        // change in the closure or none of them. This is why the driver holds
        // the raw `DurableObjectState`: `worker::Storage::transaction` hands a
        // `worker::Transaction` whose inner JS object is private, and
        // `worker-sys` 0.8.5 does not bind the transaction's `getAlarm`,
        // `setAlarm` or `deleteAlarm`, even though the JS object has them
        // (Cloudflare's `DurableObjectTransaction` interface). Applying the
        // alarm *after* the value transaction — as an earlier version did —
        // lets a value land and the alarm write fail: an `expiring` value
        // stored with no expiry, or an alarm handler re-run against already
        // committed values.
        let storage = self.storage()?;
        let closure: Box<dyn FnOnce(DurableObjectTransaction) -> Promise> =
            Box::new(move |tx: DurableObjectTransaction| -> Promise {
                future_to_promise(AssertUnwindSafe(async move {
                    apply_writes(tx, clearing, entries, kind, key, alarm).await
                }))
            });
        // A `Closure` is not `Send` (it holds a JS handle), and the store's
        // `commit` is an `async_trait` method whose future must be; Workers is
        // single-threaded, so wrapping the handle to hold it across the await
        // is sound.
        let closure = SendWrapper::new(Closure::once_assert_unwind_safe(closure));
        JsFuture::from(storage.transaction(&closure).map_err(js_error)?)
            .into_send()
            .await
            .map_err(js_error)?;
        Ok(())
    }
}

/// Applies one commit inside the object's transaction: the explicit deletes a
/// `clear_all` needs, the staged puts and deletes, the reserved identity keys,
/// and then the alarm. Runs as the transaction closure's future; a failure
/// rolls the whole transaction back.
// `Option<Option<_>>` mirrors [`ActorWrites::alarm`]'s documented tri-state —
// `Some(Some(at))` sets, `Some(None)` cancels, `None` leaves it untouched — so
// a named enum here would only be a second spelling of the same three cases.
#[allow(clippy::option_option)]
async fn apply_writes(
    tx: DurableObjectTransaction,
    clearing: Vec<String>,
    entries: Vec<(String, Option<Vec<u8>>)>,
    kind: String,
    key: String,
    alarm: Option<Option<OffsetDateTime>>,
) -> Result<JsValue, JsValue> {
    for stored in clearing {
        JsFuture::from(tx.delete(&stored)?).await?;
    }
    for (entry_key, value) in entries {
        let stored = storage_key(&entry_key);
        match value {
            Some(bytes) => {
                let value = serde_wasm_bindgen::to_value(&bytes)?;
                JsFuture::from(tx.put(&stored, value)?).await?;
            }
            None => {
                JsFuture::from(tx.delete(&stored)?).await?;
            }
        }
    }
    // Written last, so they survive a `clear_all` that wiped them first: the
    // alarm that follows still knows whose it is.
    JsFuture::from(tx.put(META_KIND_KEY, serde_wasm_bindgen::to_value(&kind)?)?).await?;
    JsFuture::from(tx.put(META_KEY_KEY, serde_wasm_bindgen::to_value(&key)?)?).await?;

    if let Some(alarm) = alarm {
        let this: &JsValue = tx.as_ref();
        if let Some(at) = alarm {
            // Epoch milliseconds: an integer that a `Date` takes as a number,
            // and `f64` represents every such value exactly up to year 287396.
            #[allow(clippy::cast_precision_loss)]
            let when = Date::new(&JsValue::from_f64(alarm_epoch_ms(at) as f64));
            let set = transaction_method(&tx, "setAlarm")?;
            let promise: Promise = set.call2(this, &when, &JsValue::NULL)?.unchecked_into();
            JsFuture::from(promise).await?;
        } else {
            let delete = transaction_method(&tx, "deleteAlarm")?;
            let promise: Promise = delete.call1(this, &JsValue::NULL)?.unchecked_into();
            JsFuture::from(promise).await?;
        }
    }
    Ok(JsValue::UNDEFINED)
}

/// Looks up one of the transaction's JS methods `worker-sys` does not bind —
/// `setAlarm` or `deleteAlarm`. The transaction is a JS object, so the method
/// is read off it with `Reflect`; no `unsafe` and no new binding are needed.
fn transaction_method(tx: &DurableObjectTransaction, name: &str) -> Result<Function, JsValue> {
    let object: &JsValue = tx.as_ref();
    Reflect::get(object, &JsValue::from_str(name))?.dyn_into()
}

/// A pending alarm as milliseconds since the epoch, or an error if the stored
/// value is not a representable time.
fn ms_to_alarm(ms: i64) -> Result<OffsetDateTime, ActorError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|error| ActorError::Operation(format!("stored alarm is not a time: {error}")))
}

/// The alarm time as milliseconds since the epoch — what a Durable Object's
/// `setAlarm` takes as a `Date`.
fn alarm_epoch_ms(at: OffsetDateTime) -> i64 {
    let nanos = at.unix_timestamp_nanos();
    let ms = nanos / 1_000_000;
    // Bounded for the wire: a time no `i64` can hold is clamped to the end it
    // fell off, and one that far out is a caller bug, not a schedule.
    i64::try_from(ms).unwrap_or(if ms.is_negative() { i64::MIN } else { i64::MAX })
}

/// The `Actors` host: names the object `<kind>:<key>`, signs the frame and
/// maps the object's status back to an [`ActorError`].
pub(crate) struct DurableActors {
    namespace: ObjectNamespace,
    signing_key: Vec<u8>,
}

impl DurableActors {
    /// Builds the host from the `ACTORS` binding and the deployment's key. The
    /// current secret signs; a rotation is picked up by the next isolate.
    pub(crate) fn new(namespace: ObjectNamespace, config: &HarnessConfig) -> Self {
        Self {
            namespace,
            signing_key: protocol_key(config.harness_secret.as_bytes()).to_vec(),
        }
    }
}

#[async_trait]
impl Actors for DurableActors {
    async fn call(&self, kind: &str, key: &str, message: &[u8]) -> Result<Vec<u8>, ActorError> {
        check_actor_call(kind, key, message)?;
        if self.signing_key.is_empty() {
            return Err(ActorError::Operation(
                "actor host has no signing key: HARNESS_SECRET is not configured".to_owned(),
            ));
        }

        let frame = encode_frame(kind, key, message)?;
        let signature = sign_frame(&self.signing_key, &frame);
        let mut init = RequestInit::new();
        init.method = Method::Post;
        let headers = Headers::new();
        headers
            .set(SIGNATURE_HEADER, &signature)
            .map_err(|error| store_error(&error))?;
        init.headers = headers;
        init.with_body(Some(Uint8Array::from(frame.as_slice()).into()));

        // A Durable Object stub routes by the id the name was hashed to, so the
        // URL is a stand-in origin: workerd refuses a request with no absolute
        // URL, and nothing reads the authority.
        let request = Request::new_with_init("https://actors.invalid/", &init)
            .map_err(|error| store_error(&error))?;
        let stub = self
            .namespace
            .id_from_name(&format!("{kind}:{key}"))
            .map_err(|error| store_error(&error))?
            .get_stub()
            .map_err(|error| store_error(&error))?;
        let mut response = stub
            .fetch_with_request(request)
            .into_send()
            .await
            .map_err(|error| store_error(&error))?;

        match response.status_code() {
            200 => response
                .bytes()
                .into_send()
                .await
                .map_err(|error| store_error(&error)),
            404 => Err(ActorError::NotConfigured),
            413 => Err(ActorError::TooLarge(response_text(&mut response).await)),
            422 => Err(ActorError::Handler(response_text(&mut response).await)),
            status => Err(ActorError::Operation(format!(
                "actor host answered {status}: {}",
                response_text(&mut response).await
            ))),
        }
    }
}

async fn response_text(response: &mut Response) -> String {
    response.text().into_send().await.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deployment's two keys, so the tests do not re-derive by hand.
    fn keys() -> (HarnessConfig, [u8; 32], Option<[u8; 32]>) {
        let config = HarnessConfig {
            harness_secret: "test-secret-0123456789abcdef-0123".to_owned(),
            harness_secret_previous: Some("previous-secret-0123456789abcdef".to_owned()),
            harness_secret_revoked: Vec::new(),
            harness_venture: None,
            admin_token: None,
            env: cratefield_core::VentureEnv::Development,
        };
        let current = protocol_key(config.harness_secret.as_bytes());
        let previous = config
            .harness_secret_previous
            .as_ref()
            .map(|secret| protocol_key(secret.as_bytes()));
        (config, current, previous)
    }

    #[test]
    fn a_frame_round_trips() {
        let frame = encode_frame("counter", "user-7", b"inc").expect("fits");
        assert_eq!(
            decode_frame(&frame).expect("decodes"),
            ("counter".to_owned(), "user-7".to_owned(), b"inc".to_vec())
        );
        // The message is whatever is left, including an empty one.
        let frame = encode_frame("counter", "k", b"").expect("fits");
        assert_eq!(decode_frame(&frame).expect("decodes").2, Vec::<u8>::new());
    }

    #[test]
    fn a_malformed_frame_is_refused() {
        // Shorter than its kind length claims.
        assert!(decode_frame(&[4, b'a']).is_err());
        // Shorter than its key length claims.
        assert!(decode_frame(&[1, b'a', 0, 9, b'k']).is_err());
        // No length byte at all.
        assert!(decode_frame(&[]).is_err());
        // A non-UTF-8 kind.
        assert!(decode_frame(&[1, 0xff, 0, 1, b'k']).is_err());
    }

    #[test]
    fn a_signature_verifies_and_a_tampered_frame_does_not() {
        let (_, current, _) = keys();
        let frame = encode_frame("counter", "k", b"inc").expect("fits");
        let signature = sign_frame(&current, &frame);
        assert!(verify_frame(&signature, &current, &frame));

        let mut tampered = frame.clone();
        tampered[0] = tampered[0].wrapping_add(1);
        assert!(!verify_frame(&signature, &current, &tampered));
    }

    #[test]
    fn a_signature_over_a_different_kind_or_key_is_refused() {
        let (_, current, _) = keys();
        let signature = sign_frame(
            &current,
            &encode_frame("counter", "one", b"m").expect("fits"),
        );
        assert!(!verify_frame(
            &signature,
            &current,
            &encode_frame("counter", "two", b"m").expect("fits")
        ));
        assert!(!verify_frame(
            &signature,
            &current,
            &encode_frame("other", "one", b"m").expect("fits")
        ));
    }

    #[test]
    fn a_wrong_secret_is_refused_and_the_previous_one_is_accepted() {
        let (config, current, previous) = keys();
        let frame = encode_frame("counter", "k", b"inc").expect("fits");

        let previous = previous.expect("the fixture sets one");
        let previous_signature = sign_frame(&previous, &frame);
        assert!(!verify_frame(&previous_signature, &current, &frame));
        // The driver tries both, so a frame minted before a rotation verifies.
        let accepted = verification_keys(&config)
            .iter()
            .any(|key| verify_frame(&previous_signature, key, &frame));
        assert!(accepted, "the previous secret was not accepted");

        let other = protocol_key(b"a secret nobody configured");
        let signature = sign_frame(&other, &frame);
        assert!(
            !verification_keys(&config)
                .iter()
                .any(|key| verify_frame(&signature, key, &frame))
        );
    }

    #[test]
    fn a_malformed_signature_is_refused() {
        let (_, current, _) = keys();
        let frame = encode_frame("counter", "k", b"inc").expect("fits");
        assert!(!verify_frame("not base64!", &current, &frame));
        assert!(!verify_frame("", &current, &frame));
        // Valid base64, wrong length.
        assert!(!verify_frame(
            &URL_SAFE_NO_PAD.encode(b"short"),
            &current,
            &frame
        ));
    }

    #[test]
    fn the_protocol_key_is_domain_separated_from_the_secret() {
        // The key is not the secret (or a bare hash of it): a token the signer
        // mints from `HARNESS_SECRET` can never verify an actor frame.
        let (_, current, _) = keys();
        assert_ne!(&current[..], b"test-secret-0123456789abcdef-0123");
    }

    #[test]
    fn an_alarm_round_trips_through_epoch_milliseconds() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(
            alarm_epoch_ms(now + time::Duration::milliseconds(1500)),
            1500
        );
        assert_eq!(
            ms_to_alarm(1500).expect("a time"),
            now + time::Duration::milliseconds(1500)
        );
        assert_eq!(alarm_epoch_ms(now), 0);
    }

    #[test]
    fn a_frame_matches_its_identity() {
        // The name half: `id_from_name("counter:k")` must only serve a frame
        // that names `counter`/`k`.
        assert!(frame_matches_identity(
            Some("counter:k"),
            None,
            "counter",
            "k"
        ));
        assert!(!frame_matches_identity(
            Some("counter:other"),
            None,
            "counter",
            "k"
        ));
        assert!(!frame_matches_identity(
            Some("other:k"),
            None,
            "counter",
            "k"
        ));
        // A name workerd does not expose is not a mismatch — the persisted
        // half still applies.
        assert!(frame_matches_identity(None, None, "counter", "k"));

        // The persisted half: metadata a previous commit wrote must agree.
        assert!(frame_matches_identity(
            None,
            Some(("counter", "k")),
            "counter",
            "k"
        ));
        assert!(!frame_matches_identity(
            None,
            Some(("counter", "other")),
            "counter",
            "k"
        ));
        assert!(!frame_matches_identity(
            None,
            Some(("other", "k")),
            "counter",
            "k"
        ));
        // Both halves present: either one disagreeing refuses.
        assert!(!frame_matches_identity(
            Some("counter:k"),
            Some(("counter", "other")),
            "counter",
            "k"
        ));
    }
}
