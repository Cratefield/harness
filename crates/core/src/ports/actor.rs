//! The `Actors` port (issue #583): per-key serialized state with
//! transactional storage and an alarm, the Durable Object pattern behind a
//! runtime-neutral trait.
//!
//! Every call to one `(kind, key)` runs **one at a time** — the host
//! serializes them — so a handler needs no locking to keep a counter, a
//! cursor, or a small state machine consistent. The writes one call makes
//! are **all-or-nothing**: they accumulate in memory and reach the store in
//! a single [`ActorStore::commit`], and a handler that returns an error, or
//! a reply over [`MAX_ACTOR_REPLY_BYTES`], commits nothing. Each actor has
//! **one alarm**, a single point in time it asks to be woken at, re-armed by
//! a handler or cancelled by not re-arming.
//!
//! A module declares the actor kinds it owns (`Module::actor_kinds`) and a
//! handler per kind (`HarnessBuilder::actor`); the harness wraps the host in
//! a [`ScopedActors`] that refuses an undeclared kind, the actor equivalent
//! of the table-ownership rule. See `docs/ACTORS.md` for the host contract.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use time::OffsetDateTime;

use super::Clock;
use super::clock::timeout;

/// Hard ceiling on one stored value. An actor holds small coordination
/// state, not a store: past this bound the state belongs in the database,
/// reached through `Ports::db`.
pub const MAX_ACTOR_VALUE_BYTES: usize = 1024 * 1024;

/// Hard ceiling on one message sent to an actor.
pub const MAX_ACTOR_MESSAGE_BYTES: usize = 1024 * 1024;

/// Hard ceiling on one reply an actor returns.
pub const MAX_ACTOR_REPLY_BYTES: usize = 1024 * 1024;

/// The longest an actor key or a storage key may be. Both are bounded by the
/// same constant, the way they are addressed (`"<kind>:<key>"`).
pub const MAX_ACTOR_KEY_BYTES: usize = 512;

/// The longest an actor kind may be. Kind names are `[a-z0-9_-]`, so
/// `"<kind>:<key>"` splits unambiguously.
pub const MAX_ACTOR_KIND_BYTES: usize = 64;

/// How long one [`Actors::call`] may take before the caller gives up. The
/// host keeps serializing the actor; the caller just stops waiting.
pub const ACTOR_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Actor failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ActorError {
    /// No actor host is wired, or it has no handler for this kind.
    #[error("no actor host or handler is configured")]
    NotConfigured,
    /// A message, reply, key or value over its bound.
    #[error("actor rejected by size: {0}")]
    TooLarge(String),
    /// A call did not return within [`ACTOR_CALL_TIMEOUT`].
    #[error("actor call timed out")]
    Timeout,
    /// The handler returned an error. Nothing it staged was committed.
    #[error("actor handler failed: {0}")]
    Handler(String),
    /// A storage, transport or validation failure.
    #[error("actor operation failed: {0}")]
    Operation(String),
}

/// Rejects an actor kind that is not `1..=MAX_ACTOR_KIND_BYTES` of
/// `[a-z0-9_-]`, so `"<kind>:<key>"` is unambiguous.
///
/// # Errors
///
/// [`ActorError::Operation`] for an empty, over-long, or otherwise invalid
/// kind.
pub fn validate_actor_kind(kind: &str) -> Result<(), ActorError> {
    let valid = !kind.is_empty()
        && kind.len() <= MAX_ACTOR_KIND_BYTES
        && kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        });
    if valid {
        return Ok(());
    }
    Err(ActorError::Operation(format!(
        "actor kind `{kind}` must be 1..={MAX_ACTOR_KIND_BYTES} bytes of [a-z0-9_-]"
    )))
}

/// Rejects an actor key or storage key that is empty or longer than
/// [`MAX_ACTOR_KEY_BYTES`].
///
/// # Errors
///
/// [`ActorError::Operation`] for an empty key, [`ActorError::TooLarge`] for
/// one over the bound.
pub fn validate_actor_key(key: &str) -> Result<(), ActorError> {
    if key.is_empty() {
        return Err(ActorError::Operation(
            "an actor key cannot be empty".to_owned(),
        ));
    }
    if key.len() > MAX_ACTOR_KEY_BYTES {
        return Err(ActorError::TooLarge(format!(
            "actor key of {} bytes exceeds the {MAX_ACTOR_KEY_BYTES}-byte bound",
            key.len()
        )));
    }
    Ok(())
}

/// Validates the `(kind, key, message)` one call carries: the kind, the key
/// and the message size. Shared by both runners, the scoped view and the
/// Cloudflare host, so all of them refuse a call the same way — the message
/// bound is checked here rather than only inside a handler.
///
/// # Errors
///
/// [`ActorError::TooLarge`] for a message or key over its bound,
/// [`ActorError::Operation`] for an invalid kind or an empty key.
pub fn check_actor_call(kind: &str, key: &str, message: &[u8]) -> Result<(), ActorError> {
    validate_actor_kind(kind)?;
    validate_actor_key(key)?;
    if message.len() > MAX_ACTOR_MESSAGE_BYTES {
        return Err(ActorError::TooLarge(format!(
            "actor message of {} bytes exceeds the {MAX_ACTOR_MESSAGE_BYTES}-byte bound",
            message.len()
        )));
    }
    Ok(())
}

/// Rejects a `list_prefix` prefix over [`MAX_ACTOR_KEY_BYTES`]. Unlike a key,
/// a prefix may be empty — that lists everything in the actor.
fn check_prefix(prefix: &str) -> Result<(), ActorError> {
    if prefix.len() > MAX_ACTOR_KEY_BYTES {
        return Err(ActorError::TooLarge(format!(
            "actor key prefix of {} bytes exceeds the {MAX_ACTOR_KEY_BYTES}-byte bound",
            prefix.len()
        )));
    }
    Ok(())
}

/// An actor host: it owns serialization and durable storage for every actor
/// instance on the runtime. Implemented by the runtime adapters (a Durable
/// Object namespace on Cloudflare, an in-process registry natively, a fake
/// in tests); a module only ever reaches a [`ScopedActors`].
#[async_trait]
pub trait Actors: Send + Sync {
    /// Sends `message` to the actor named `key` of `kind` and returns its
    /// reply.
    ///
    /// Calls to the same `(kind, key)` are serialized: one runs at a time.
    async fn call(&self, kind: &str, key: &str, message: &[u8]) -> Result<Vec<u8>, ActorError>;
}

/// The protocol for one kind of actor. A module implements it and registers
/// it with [`HarnessBuilder::actor`](crate::HarnessBuilder::actor); the host
/// owns the serialization and calls these.
///
/// Implementations must be **stateless** — all state lives in the actor and
/// is reached through [`ActorContext`] — so a host that drops the handler
/// between events (a hibernating Durable Object) can reconstruct it.
#[async_trait]
pub trait ActorHandler: Send + Sync {
    /// A message arrived. Writes staged on `ctx` commit only if this returns
    /// `Ok` with a reply within [`MAX_ACTOR_REPLY_BYTES`].
    async fn on_message(
        &self,
        ctx: &mut dyn ActorContext,
        message: &[u8],
    ) -> Result<Vec<u8>, ActorError>;

    /// The alarm fired. Writes staged on `ctx` commit only if this returns
    /// `Ok`; a handler that does not re-arm leaves no alarm set.
    async fn on_alarm(&self, ctx: &mut dyn ActorContext) -> Result<(), ActorError>;
}

/// The operations an [`ActorHandler`] performs on its actor while handling a
/// message or an alarm. Writes are staged and committed together by the
/// [`run_actor_message`] / [`run_actor_alarm`] runners.
#[async_trait]
pub trait ActorContext: Send {
    /// The actor's kind.
    fn kind(&self) -> &str;
    /// The actor's key.
    fn key(&self) -> &str;
    /// Wall time, from the runtime's [`Clock`].
    fn now(&self) -> OffsetDateTime;
    /// Fetches the value at `key`, seeing this call's staged writes first.
    async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, ActorError>;
    /// Stages a write of `value` at `key`, replacing any existing value.
    async fn put(&mut self, key: &str, value: Vec<u8>) -> Result<(), ActorError>;
    /// Stages a delete of `key`. Idempotent: deleting a missing key is `Ok`.
    async fn delete(&mut self, key: &str) -> Result<(), ActorError>;
    /// Stages a delete of every key in this actor. Also drops writes staged
    /// before it, so `delete_all` followed by nothing leaves the actor empty.
    async fn delete_all(&mut self) -> Result<(), ActorError>;
    /// Every `(key, value)` whose key starts with `prefix`, sorted by key,
    /// seeing this call's staged writes first.
    async fn list_prefix(&mut self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, ActorError>;
    /// Sets the actor's one alarm to fire at `at`, replacing any pending one.
    async fn set_alarm(&mut self, at: OffsetDateTime) -> Result<(), ActorError>;
    /// The pending alarm, or `None` if none is set. Sees a staged alarm
    /// first.
    async fn alarm(&mut self) -> Result<Option<OffsetDateTime>, ActorError>;
    /// Clears the pending alarm.
    async fn cancel_alarm(&mut self) -> Result<(), ActorError>;
}

/// The writes one handler call staged, applied by [`ActorStore::commit`].
///
/// `clear_all` runs first, then `entries` in key order (`Some` puts, `None`
/// deletes); `alarm` is applied last. An empty set ([`Self::is_empty`]) means
/// the host skips the commit entirely.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActorWrites {
    /// Delete every key in the actor before applying `entries`.
    pub clear_all: bool,
    /// Staged writes: `Some` is a put, `None` a delete.
    pub entries: BTreeMap<String, Option<Vec<u8>>>,
    /// The alarm to apply: `Some(Some(at))` sets, `Some(None)` cancels,
    /// `None` leaves it untouched.
    pub alarm: Option<Option<OffsetDateTime>>,
}

impl ActorWrites {
    /// Whether there is nothing to apply.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.clear_all && self.entries.is_empty() && self.alarm.is_none()
    }
}

/// The backing store for **one** actor instance. An adapter implements this
/// per instance; core owns the atomicity, so an implementation need only
/// make [`commit`](ActorStore::commit) apply its whole set or none of it.
#[async_trait]
pub trait ActorStore: Send + Sync {
    /// The value at `key`, or `None` if there is none.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ActorError>;
    /// Every `(key, value)` whose key starts with `prefix`, sorted by key.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, ActorError>;
    /// The pending alarm, or `None`.
    async fn alarm(&self) -> Result<Option<OffsetDateTime>, ActorError>;
    /// Applies every write in `writes`, or none.
    async fn commit(&self, writes: ActorWrites) -> Result<(), ActorError>;
}

/// A handler's view of one actor, staged over the store: reads see the writes
/// this call has staged first, writes only accumulate in an [`ActorWrites`].
/// A private type — callers hold an `&mut dyn ActorContext`.
struct StagedContext<'a> {
    store: &'a dyn ActorStore,
    clock: &'a dyn Clock,
    kind: &'a str,
    key: &'a str,
    writes: ActorWrites,
}

impl<'a> StagedContext<'a> {
    fn new(store: &'a dyn ActorStore, clock: &'a dyn Clock, kind: &'a str, key: &'a str) -> Self {
        Self {
            store,
            clock,
            kind,
            key,
            writes: ActorWrites::default(),
        }
    }

    fn into_writes(self) -> ActorWrites {
        self.writes
    }
}

#[async_trait]
impl ActorContext for StagedContext<'_> {
    fn kind(&self) -> &str {
        self.kind
    }

    fn key(&self) -> &str {
        self.key
    }

    fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, ActorError> {
        validate_actor_key(key)?;
        if let Some(value) = self.writes.entries.get(key) {
            return Ok(value.clone());
        }
        if self.writes.clear_all {
            return Ok(None);
        }
        self.store.get(key).await
    }

    async fn put(&mut self, key: &str, value: Vec<u8>) -> Result<(), ActorError> {
        validate_actor_key(key)?;
        if value.len() > MAX_ACTOR_VALUE_BYTES {
            return Err(ActorError::TooLarge(format!(
                "actor value of {} bytes exceeds the {MAX_ACTOR_VALUE_BYTES}-byte bound",
                value.len()
            )));
        }
        self.writes.entries.insert(key.to_owned(), Some(value));
        Ok(())
    }

    async fn delete(&mut self, key: &str) -> Result<(), ActorError> {
        validate_actor_key(key)?;
        self.writes.entries.insert(key.to_owned(), None);
        Ok(())
    }

    async fn delete_all(&mut self) -> Result<(), ActorError> {
        self.writes.clear_all = true;
        self.writes.entries.clear();
        Ok(())
    }

    async fn list_prefix(&mut self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, ActorError> {
        check_prefix(prefix)?;
        let mut merged: BTreeMap<String, Vec<u8>> = if self.writes.clear_all {
            BTreeMap::new()
        } else {
            self.store.list_prefix(prefix).await?.into_iter().collect()
        };
        for (key, value) in &self.writes.entries {
            if key.starts_with(prefix) {
                match value {
                    Some(value) => {
                        merged.insert(key.clone(), value.clone());
                    }
                    None => {
                        merged.remove(key);
                    }
                }
            }
        }
        Ok(merged.into_iter().collect())
    }

    async fn set_alarm(&mut self, at: OffsetDateTime) -> Result<(), ActorError> {
        self.writes.alarm = Some(Some(at));
        Ok(())
    }

    async fn alarm(&mut self) -> Result<Option<OffsetDateTime>, ActorError> {
        match &self.writes.alarm {
            Some(pending) => Ok(*pending),
            None => self.store.alarm().await,
        }
    }

    async fn cancel_alarm(&mut self) -> Result<(), ActorError> {
        self.writes.alarm = Some(None);
        Ok(())
    }
}

/// Runs one message: validates the kind, key and message size, runs the
/// handler against a staged context, checks the reply size, and only then
/// commits the staged writes. A handler error or an oversized reply commits
/// nothing.
///
/// # Errors
///
/// [`ActorError::TooLarge`] for a message or reply over its bound (or a key
/// over [`MAX_ACTOR_KEY_BYTES`]), [`ActorError::Operation`] for an invalid
/// kind or empty key, and whatever the handler returns.
pub async fn run_actor_message(
    handler: &dyn ActorHandler,
    store: &dyn ActorStore,
    clock: &dyn Clock,
    kind: &str,
    key: &str,
    message: &[u8],
) -> Result<Vec<u8>, ActorError> {
    check_actor_call(kind, key, message)?;
    let mut ctx = StagedContext::new(store, clock, kind, key);
    let reply = handler.on_message(&mut ctx, message).await?;
    if reply.len() > MAX_ACTOR_REPLY_BYTES {
        return Err(ActorError::TooLarge(format!(
            "actor reply of {} bytes exceeds the {MAX_ACTOR_REPLY_BYTES}-byte bound",
            reply.len()
        )));
    }
    commit_if_any(store, ctx.into_writes()).await?;
    Ok(reply)
}

/// Commits `writes` unless there is nothing to commit — the shared tail of
/// both runners, so an empty staged set never reaches the store.
async fn commit_if_any(store: &dyn ActorStore, writes: ActorWrites) -> Result<(), ActorError> {
    if writes.is_empty() {
        return Ok(());
    }
    store.commit(writes).await
}

/// Runs a fired alarm. The staged context starts with the alarm cancelled, so
/// a handler that does not re-arm leaves none set; a handler error commits
/// nothing and returns the error, and the host retries.
///
/// # Errors
///
/// [`ActorError::Operation`] for an invalid kind or empty key, and whatever
/// the handler returns.
pub async fn run_actor_alarm(
    handler: &dyn ActorHandler,
    store: &dyn ActorStore,
    clock: &dyn Clock,
    kind: &str,
    key: &str,
) -> Result<(), ActorError> {
    validate_actor_kind(kind)?;
    validate_actor_key(key)?;
    let mut ctx = StagedContext::new(store, clock, kind, key);
    ctx.writes.alarm = Some(None);
    handler.on_alarm(&mut ctx).await?;
    commit_if_any(store, ctx.into_writes()).await?;
    Ok(())
}

/// The handlers a venture registered, by kind. Built from the
/// [`HarnessBuilder::actor`](crate::HarnessBuilder::actor) registrations so an
/// in-process actor host can dispatch to them.
#[derive(Clone, Default)]
pub struct ActorHandlers {
    handlers: BTreeMap<String, Arc<dyn ActorHandler>>,
}

impl ActorHandlers {
    /// No handlers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a handler for `kind`, replacing any already registered for it.
    #[must_use]
    pub fn with(mut self, kind: &str, handler: Arc<dyn ActorHandler>) -> Self {
        self.handlers.insert(kind.to_owned(), handler);
        self
    }

    /// The handler for `kind`, if one is registered.
    #[must_use]
    pub fn get(&self, kind: &str) -> Option<Arc<dyn ActorHandler>> {
        self.handlers.get(kind).map(Arc::clone)
    }

    /// Every registered kind, sorted.
    pub fn kinds(&self) -> impl Iterator<Item = &str> {
        self.handlers.keys().map(String::as_str)
    }
}

impl std::fmt::Debug for ActorHandlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorHandlers")
            .field("kinds", &self.kinds().collect::<Vec<_>>())
            .finish()
    }
}

/// Wraps an [`Actors`] so a module only reaches the kinds it declared in
/// [`Module::actor_kinds`](crate::Module::actor_kinds), the actor equivalent
/// of the table-ownership rule. When the module has a [`Clock`] wired, every
/// call is also bounded by [`ACTOR_CALL_TIMEOUT`]; with no clock there is
/// nothing to measure the wait with, so the call is made straight through and
/// the host still serializes it. The harness applies this in `Ports::view_for`.
pub struct ScopedActors {
    inner: Arc<dyn Actors>,
    module: String,
    kinds: &'static [&'static str],
    clock: Option<Arc<dyn Clock>>,
}

impl ScopedActors {
    /// Scopes `inner` to `module`'s declared `kinds`, bounding each call with
    /// `clock` when one is present.
    #[must_use]
    pub fn new(
        inner: Arc<dyn Actors>,
        module: &str,
        kinds: &'static [&'static str],
        clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        Self {
            inner,
            module: module.to_owned(),
            kinds,
            clock,
        }
    }
}

#[async_trait]
impl Actors for ScopedActors {
    async fn call(&self, kind: &str, key: &str, message: &[u8]) -> Result<Vec<u8>, ActorError> {
        if !self.kinds.contains(&kind) {
            return Err(ActorError::Operation(format!(
                "module `{}` does not declare actor kind `{kind}`",
                self.module
            )));
        }
        check_actor_call(kind, key, message)?;
        let inner = Arc::clone(&self.inner);
        let kind = kind.to_owned();
        let key = key.to_owned();
        let message = message.to_vec();
        let reply = match &self.clock {
            Some(clock) => timeout(
                clock.as_ref(),
                async move { inner.call(&kind, &key, &message).await },
                ACTOR_CALL_TIMEOUT,
            )
            .await
            .ok_or(ActorError::Timeout)??,
            // No clock is wired, so there is nothing to measure a timeout
            // against. The host still serializes the call; the caller just
            // has no deadline of its own to impose.
            None => inner.call(&kind, &key, &message).await?,
        };
        if reply.len() > MAX_ACTOR_REPLY_BYTES {
            return Err(ActorError::TooLarge(format!(
                "actor reply of {} bytes exceeds the {MAX_ACTOR_REPLY_BYTES}-byte bound",
                reply.len()
            )));
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    // Test fixtures are not request state (ADR 0007); the scoped allow
    // follows the policy in the workspace clippy.toml, as the sibling port
    // tests do.
    #![allow(clippy::disallowed_types)]

    use super::*;
    use std::sync::Mutex;

    /// Records every call so a test can prove a refused one never arrived.
    #[derive(Default)]
    struct RecordingActors {
        seen: Mutex<Vec<(String, String)>>,
        reply: Vec<u8>,
    }

    #[async_trait]
    impl Actors for RecordingActors {
        async fn call(
            &self,
            kind: &str,
            key: &str,
            _message: &[u8],
        ) -> Result<Vec<u8>, ActorError> {
            self.seen
                .lock()
                .unwrap()
                .push((kind.to_owned(), key.to_owned()));
            Ok(self.reply.clone())
        }
    }

    #[pollster::test]
    async fn a_scoped_actors_refuses_an_undeclared_kind_before_the_host() {
        let host = Arc::new(RecordingActors::default());
        let scoped = ScopedActors::new(
            host.clone(),
            "cms",
            &["counter"],
            Some(Arc::new(crate::ports::SystemClock)),
        );
        let err = scoped.call("other", "k", b"x").await.unwrap_err();
        assert!(
            matches!(err, ActorError::Operation(ref m) if m.contains("does not declare actor kind `other`")),
            "got {err}"
        );
        assert!(host.seen.lock().unwrap().is_empty());
    }

    #[pollster::test]
    async fn a_message_at_the_bound_passes_and_one_over_is_refused() {
        let host = Arc::new(RecordingActors::default());
        let scoped = ScopedActors::new(
            host.clone(),
            "cms",
            &["counter"],
            Some(Arc::new(crate::ports::SystemClock)),
        );
        let exact = vec![0_u8; MAX_ACTOR_MESSAGE_BYTES];
        scoped.call("counter", "k", &exact).await.expect("at bound");
        let over = vec![0_u8; MAX_ACTOR_MESSAGE_BYTES + 1];
        let err = scoped.call("counter", "k", &over).await.unwrap_err();
        assert!(matches!(err, ActorError::TooLarge(_)), "got {err}");
        assert_eq!(
            host.seen.lock().unwrap().len(),
            1,
            "the oversized message never reached the host"
        );
    }

    #[pollster::test]
    async fn an_oversized_reply_is_refused() {
        let host = Arc::new(RecordingActors {
            seen: Mutex::new(Vec::new()),
            reply: vec![0_u8; MAX_ACTOR_REPLY_BYTES + 1],
        });
        let scoped = ScopedActors::new(
            host,
            "cms",
            &["counter"],
            Some(Arc::new(crate::ports::SystemClock)),
        );
        let err = scoped.call("counter", "k", b"x").await.unwrap_err();
        assert!(matches!(err, ActorError::TooLarge(_)), "got {err}");
    }

    #[pollster::test]
    async fn a_call_without_a_clock_reaches_the_host_with_no_timeout() {
        let host = Arc::new(RecordingActors::default());
        let scoped = ScopedActors::new(host.clone(), "cms", &["counter"], None);
        // With no clock there is no timeout to impose, so the call goes
        // straight through to the host rather than being refused.
        scoped.call("counter", "k", b"x").await.expect("no clock");
        assert_eq!(
            host.seen.lock().unwrap().as_slice(),
            &[("counter".to_owned(), "k".to_owned())]
        );
    }

    /// An in-memory one-actor store: a map plus an optional alarm. `commit`
    /// applies the whole set, the way a real adapter must.
    #[derive(Default)]
    struct MemStore {
        values: Mutex<BTreeMap<String, Vec<u8>>>,
        alarm: Mutex<Option<OffsetDateTime>>,
    }

    #[async_trait]
    impl ActorStore for MemStore {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ActorError> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, ActorError> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
        async fn alarm(&self) -> Result<Option<OffsetDateTime>, ActorError> {
            Ok(*self.alarm.lock().unwrap())
        }
        async fn commit(&self, writes: ActorWrites) -> Result<(), ActorError> {
            let mut values = self.values.lock().unwrap();
            if writes.clear_all {
                values.clear();
            }
            for (key, value) in writes.entries {
                match value {
                    Some(value) => {
                        values.insert(key, value);
                    }
                    None => {
                        values.remove(&key);
                    }
                }
            }
            if let Some(alarm) = writes.alarm {
                *self.alarm.lock().unwrap() = alarm;
            }
            Ok(())
        }
    }

    /// A handler whose behaviour a test sets: it stages a put, optionally
    /// errs or returns an oversized reply, and optionally re-arms the alarm.
    struct ScriptedHandler {
        put: Option<(String, Vec<u8>)>,
        fail: bool,
        reply_len: usize,
        rearm: bool,
    }

    #[async_trait]
    impl ActorHandler for ScriptedHandler {
        async fn on_message(
            &self,
            ctx: &mut dyn ActorContext,
            _message: &[u8],
        ) -> Result<Vec<u8>, ActorError> {
            if let Some((key, value)) = &self.put {
                ctx.put(key, value.clone()).await?;
            }
            if self.fail {
                return Err(ActorError::Handler("boom".to_owned()));
            }
            Ok(vec![0_u8; self.reply_len])
        }

        async fn on_alarm(&self, ctx: &mut dyn ActorContext) -> Result<(), ActorError> {
            if let Some((key, value)) = &self.put {
                ctx.put(key, value.clone()).await?;
            }
            if self.fail {
                return Err(ActorError::Handler("boom".to_owned()));
            }
            if self.rearm {
                ctx.set_alarm(OffsetDateTime::UNIX_EPOCH).await?;
            }
            Ok(())
        }
    }

    fn clock() -> crate::ports::SystemClock {
        crate::ports::SystemClock
    }

    #[pollster::test]
    async fn a_handler_error_commits_nothing() {
        let store = MemStore::default();
        let handler = ScriptedHandler {
            put: Some(("k".to_owned(), b"v".to_vec())),
            fail: true,
            reply_len: 0,
            rearm: false,
        };
        let err = run_actor_message(&handler, &store, &clock(), "counter", "a", b"m")
            .await
            .unwrap_err();
        assert!(matches!(err, ActorError::Handler(_)), "got {err}");
        assert!(store.get("k").await.unwrap().is_none());
    }

    #[pollster::test]
    async fn an_oversized_reply_commits_nothing() {
        let store = MemStore::default();
        let handler = ScriptedHandler {
            put: Some(("k".to_owned(), b"v".to_vec())),
            fail: false,
            reply_len: MAX_ACTOR_REPLY_BYTES + 1,
            rearm: false,
        };
        assert!(matches!(
            run_actor_message(&handler, &store, &clock(), "counter", "a", b"m")
                .await
                .unwrap_err(),
            ActorError::TooLarge(_)
        ));
        assert!(store.get("k").await.unwrap().is_none());
    }

    #[pollster::test]
    async fn a_successful_message_commits_its_writes() {
        let store = MemStore::default();
        let handler = ScriptedHandler {
            put: Some(("k".to_owned(), b"v".to_vec())),
            fail: false,
            reply_len: 3,
            rearm: false,
        };
        let reply = run_actor_message(&handler, &store, &clock(), "counter", "a", b"m")
            .await
            .unwrap();
        assert_eq!(reply, vec![0_u8; 3]);
        assert_eq!(store.get("k").await.unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[pollster::test]
    async fn an_oversized_put_is_refused() {
        let store = MemStore::default();
        let handler = ScriptedHandler {
            put: Some(("k".to_owned(), vec![0_u8; MAX_ACTOR_VALUE_BYTES + 1])),
            fail: false,
            reply_len: 0,
            rearm: false,
        };
        assert!(matches!(
            run_actor_message(&handler, &store, &clock(), "counter", "a", b"m")
                .await
                .unwrap_err(),
            ActorError::TooLarge(_)
        ));
        assert!(store.values.lock().unwrap().is_empty());
    }

    /// Stages a put, then reads it back, deletes everything, and lists —
    /// exercising the staged-view semantics through one handler.
    struct StageReader;

    #[async_trait]
    impl ActorHandler for StageReader {
        async fn on_message(
            &self,
            ctx: &mut dyn ActorContext,
            _message: &[u8],
        ) -> Result<Vec<u8>, ActorError> {
            ctx.put("a/1", b"one".to_vec()).await?;
            ctx.put("b/1", b"two".to_vec()).await?;
            assert_eq!(ctx.get("a/1").await?.as_deref(), Some(&b"one"[..]));
            assert_eq!(ctx.list_prefix("a/").await?.len(), 1);
            ctx.delete("a/1").await?;
            assert!(ctx.get("a/1").await?.is_none());
            assert!(ctx.list_prefix("a/").await?.is_empty());
            Ok(Vec::new())
        }

        async fn on_alarm(&self, _ctx: &mut dyn ActorContext) -> Result<(), ActorError> {
            Ok(())
        }
    }

    #[pollster::test]
    async fn a_handler_sees_its_own_staged_writes() {
        let store = MemStore::default();
        run_actor_message(&StageReader, &store, &clock(), "counter", "a", b"m")
            .await
            .unwrap();
        // `a/1` was deleted and `b/1` put; the commit reflects both.
        assert_eq!(
            store.get("b/1").await.unwrap().as_deref(),
            Some(&b"two"[..])
        );
        assert!(store.get("a/1").await.unwrap().is_none());
    }

    /// `delete_all` after a staged put leaves the actor empty.
    struct ClearAfterPut;

    #[async_trait]
    impl ActorHandler for ClearAfterPut {
        async fn on_message(
            &self,
            ctx: &mut dyn ActorContext,
            _message: &[u8],
        ) -> Result<Vec<u8>, ActorError> {
            ctx.put("k", b"v".to_vec()).await?;
            ctx.delete_all().await?;
            assert!(ctx.get("k").await?.is_none());
            Ok(Vec::new())
        }

        async fn on_alarm(&self, _ctx: &mut dyn ActorContext) -> Result<(), ActorError> {
            Ok(())
        }
    }

    #[pollster::test]
    async fn delete_all_drops_staged_writes() {
        let store = MemStore::default();
        let mut seeded = BTreeMap::new();
        seeded.insert("old".to_owned(), b"x".to_vec());
        *store.values.lock().unwrap() = seeded;
        run_actor_message(&ClearAfterPut, &store, &clock(), "counter", "a", b"m")
            .await
            .unwrap();
        assert!(store.values.lock().unwrap().is_empty());
    }

    #[pollster::test]
    async fn an_alarm_is_cancelled_unless_re_armed() {
        let store = MemStore::default();
        *store.alarm.lock().unwrap() = Some(OffsetDateTime::UNIX_EPOCH);
        let quiet = ScriptedHandler {
            put: None,
            fail: false,
            reply_len: 0,
            rearm: false,
        };
        run_actor_alarm(&quiet, &store, &clock(), "counter", "a")
            .await
            .unwrap();
        assert!(store.alarm().await.unwrap().is_none());

        *store.alarm.lock().unwrap() = Some(OffsetDateTime::UNIX_EPOCH);
        let rearming = ScriptedHandler {
            put: None,
            fail: false,
            reply_len: 0,
            rearm: true,
        };
        run_actor_alarm(&rearming, &store, &clock(), "counter", "a")
            .await
            .unwrap();
        assert_eq!(
            store.alarm().await.unwrap(),
            Some(OffsetDateTime::UNIX_EPOCH)
        );
    }

    #[pollster::test]
    async fn a_failing_alarm_commits_nothing() {
        let store = MemStore::default();
        *store.alarm.lock().unwrap() = Some(OffsetDateTime::UNIX_EPOCH);
        let handler = ScriptedHandler {
            put: Some(("k".to_owned(), b"v".to_vec())),
            fail: true,
            reply_len: 0,
            rearm: false,
        };
        assert!(
            run_actor_alarm(&handler, &store, &clock(), "counter", "a")
                .await
                .is_err()
        );
        // The alarm is still set: a failed run commits neither the write nor
        // the cancel, so the host retries.
        assert_eq!(
            store.alarm().await.unwrap(),
            Some(OffsetDateTime::UNIX_EPOCH)
        );
        assert!(store.get("k").await.unwrap().is_none());
    }

    #[test]
    fn kind_and_key_validation() {
        assert!(validate_actor_kind("counter").is_ok());
        assert!(validate_actor_kind("a-b_9").is_ok());
        for bad in [
            "",
            "Counter",
            "a b",
            "a:b",
            &"a".repeat(MAX_ACTOR_KIND_BYTES + 1),
        ] {
            assert!(
                matches!(validate_actor_kind(bad), Err(ActorError::Operation(_))),
                "kind `{bad}` should be refused"
            );
        }
        assert!(validate_actor_key("k").is_ok());
        assert!(matches!(
            validate_actor_key(""),
            Err(ActorError::Operation(_))
        ));
        assert!(matches!(
            validate_actor_key(&"k".repeat(MAX_ACTOR_KEY_BYTES + 1)),
            Err(ActorError::TooLarge(_))
        ));
    }
}
