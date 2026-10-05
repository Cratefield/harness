//! The drain: lease due outbox rows within the invocation's
//! [`ScheduledBudget`] (ADR 0023), sign and POST each one, and file the
//! outcome — complete, retry with backoff, or dead-letter. This is the
//! whole delivery policy of the module, in one place.

use bytes::Bytes;
use cratefield_core::{
    Clock, DbError, DrainOptions, HttpClient, HttpError, IdGen, ModuleConfig, ModuleContext,
    Outbox, OutboxRecord, Processed, ScheduledBudget, UlidIdGen,
};
use hmac::{Hmac, KeyInit, Mac};
use http::header::CONTENT_TYPE;
use http::{Request, StatusCode};
use serde::Serialize;
use sha2::Sha256;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use time::OffsetDateTime;

use crate::clock::iso;
use crate::store::{self, DeadLetterReason, DeliveryJob, GiveUp};

/// The one header a delivery is verified by, Stripe-style:
/// `t=<unix seconds>,v1=<lowercase hex>`. The same scheme
/// `cratefield-adapter-webhook-tracker` signs with, so one receiver-side
/// verifier covers both.
pub const SIGNATURE_HEADER: &str = "Cratefield-Signature";
/// The event's identity, so a receiver can dedupe the at-least-once
/// redeliveries the outbox contract promises.
pub const EVENT_ID_HEADER: &str = "Cratefield-Event-Id";
/// What happened, in the caller's own vocabulary.
pub const EVENT_TYPE_HEADER: &str = "Cratefield-Event-Type";

/// The first retry delay; each further attempt doubles it.
const BACKOFF_BASE_SECS: u64 = 30;
/// The ceiling on the doubling.
const BACKOFF_MAX_SECS: u64 = 3_600;
/// How long a claimed row stays leased to one drainer.
const LEASE_SECS: i64 = 300;
/// Rows claimed per pass, before the budget caps it further. A pass
/// delivers sequentially — webhook receivers answer well within the
/// [`LEASE_SECS`] the claim holds, and a sequential pass keeps the
/// delivery log in attempt order.
const DRAIN_BATCH: u64 = 16;
/// What the [`ScheduledBudget`] charges per row processed: one subrequest
/// per delivery attempt — at most one outbound POST — a conservative count
/// (ADR 0023 counts the unit of work, not the database writes around it).
const SUBREQUESTS_PER_DELIVERY: u32 = 1;

/// What one drain pass did.
///
/// A per-row failure never aborts the pass; it is counted in `failed` and
/// the row is due again when its five-minute lease would have lapsed,
/// exactly the posture `module-notifications`' drain takes. The pass does
/// stop early — releasing the rest, still due, for the next tick — when
/// the invocation's [`ScheduledBudget`] runs out, which `deferred` counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Rows this pass processed — one subrequest charged each; the budget
    /// allowed this many.
    pub claimed: usize,
    /// Answered 2xx: the row is completed.
    pub delivered: usize,
    /// Failed and scheduled for another attempt.
    pub retried: usize,
    /// Given up on, in `webhooks_dead_letters`, replayable.
    pub dead_lettered: usize,
    /// Dropped without an attempt: the endpoint was deleted between the
    /// enqueue and the drain.
    pub dropped: usize,
    /// Rows whose delivery errored in a way this pass could not file —
    /// the log write itself failed. The row is due again when its lease
    /// would have lapsed.
    pub failed: usize,
    /// Claimed rows released untouched because the budget ran out: still
    /// queued, due immediately, for the next tick.
    pub deferred: u64,
}

/// The filing of one claimed row: what the report counts, and what the
/// drain maps to a [`Processed`] for the outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filed {
    /// 2xx: the row completes.
    Delivered,
    /// Transient failure: retry at this instant, counting one attempt.
    Retried(OffsetDateTime),
    /// Terminal: dead-lettered, the row already moved out of the outbox.
    DeadLettered,
    /// The endpoint is gone: the row completes — nobody is subscribed.
    Dropped,
}

/// The handler's outcome counters.
///
/// Atomics rather than a `Cell`/`RefCell`: the `scheduled` future is `Send`
/// (core's `BoxFuture` carries `+ Send`) and a `&RefCell<T>` is not, so the
/// handler cannot hold one across an await. `&Counters` is `Send + Sync`,
/// and the handler runs one row at a time, so nothing contends.
#[derive(Debug, Default)]
struct Counters {
    delivered: AtomicUsize,
    retried: AtomicUsize,
    dead_lettered: AtomicUsize,
    dropped: AtomicUsize,
    failed: AtomicUsize,
}

/// The delivery as the receiver sees it: the event's identity, the
/// subject it is about, when it was enqueued, and the caller's payload
/// under `data`.
#[derive(Serialize)]
struct Envelope<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    event_type: &'a str,
    subject: &'a str,
    created_at: &'a str,
    data: &'a serde_json::Value,
}

/// Signs `body` at `signed_at` and renders the [`SIGNATURE_HEADER`] value:
/// `t=<unix seconds>,v1=<lowercase hex>`, both parts in one header.
///
/// The MAC is HMAC-SHA256 over the bytes `{signed_at}.{body}` — the
/// timestamp is bound INTO the signature, so a captured delivery cannot be
/// replayed with a fresh timestamp: the re-stamp invalidates the MAC. That
/// is the reason for this scheme over a separate, unsigned timestamp
/// header, which a replay would carry untouched.
pub(crate) fn signature_header(secret: &str, signed_at: i64, body: &[u8]) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(signed_at.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Some(format!(
        "t={signed_at},v1={}",
        lower_hex(&mac.finalize().into_bytes())
    ))
}

/// Lowercase hex, the case the Stripe-style verifiers expect.
fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The retry delay after `attempts_made` failed attempts: 30s doubling to
/// a 1h ceiling.
pub(crate) fn backoff(attempts_made: i64) -> Duration {
    let doublings = u32::try_from(attempts_made.saturating_sub(1).clamp(0, 63)).unwrap_or(63);
    Duration::from_secs(
        BACKOFF_BASE_SECS
            .saturating_mul(1_u64 << doublings)
            .min(BACKOFF_MAX_SECS),
    )
}

/// The clock reading one pass works in: the stored RFC 3339 spelling for
/// every database timestamp, Unix seconds for the signature, and the
/// `OffsetDateTime` itself for the timestamps the outbox applies.
struct Timestamps {
    at: OffsetDateTime,
    iso: String,
    unix: i64,
}

/// Now, through the deployment's `Clock` port — which [`drain`] has
/// already hard-required, so there is no silent wall-clock fallback to
/// mask a mis-wired context (tests would otherwise sign and stamp with a
/// clock they never pinned).
fn now_timestamps(clock: &Arc<dyn Clock>) -> Timestamps {
    let at = clock.now();
    Timestamps {
        at,
        iso: iso(at),
        unix: at.unix_timestamp(),
    }
}

/// Delivers as many due outbox rows as this pass can lease **within the
/// invocation's [`ScheduledBudget`]** (ADR 0023), through the ports of
/// `ctx` — the entry point the venture's scheduled invocation must use
/// (a cron invocation builds no router, so a context parked at
/// router-build time is exactly what this must not depend on).
///
/// Each row is signed and delivered once per pass: 2xx completes it,
/// anything else retries with exponential backoff (410 Gone and
/// SSRF-blocked destinations dead-letter immediately), and `MAX_ATTEMPTS`
/// failures dead-letter it for [`Webhooks::replay`]. One delivery attempt
/// spends one subrequest; when the budget runs out the rows it never
/// reached are released, still due, for the next tick and counted in
/// [`DrainReport::deferred`].
///
/// # Errors
///
/// [`DeliveryError`] when a port is missing, the claim fails, or the
/// outbox refuses a completion write. A per-row *delivery* failure never
/// aborts the pass: it is counted in [`DrainReport::failed`] and the row
/// is due again when its lease would have lapsed.
pub(crate) async fn drain(
    ctx: &ModuleContext,
    max_attempts: u32,
) -> Result<DrainReport, DeliveryError> {
    let db = ctx
        .ports
        .db
        .clone()
        .ok_or(DeliveryError::MissingPort("Database"))?;
    let http = ctx
        .ports
        .http
        .clone()
        .ok_or(DeliveryError::MissingPort("HttpClient"))?;
    // `requires()` declares this port, so its absence is a wiring bug —
    // refused here, not papered over with the wall clock.
    let clock = ctx
        .ports
        .clock
        .clone()
        .ok_or(DeliveryError::MissingPort("Clock"))?;
    let max_attempts = i64::from(
        ModuleConfig::new(crate::MODULE_NAME, &*ctx.config).get_u32("MAX_ATTEMPTS", max_attempts),
    );

    let counters = Counters::default();
    let budget: &ScheduledBudget = &ctx.scheduled;
    let core_report = Outbox::new(store::OUTBOX)
        .drain_within(
            &*db,
            &*clock,
            budget,
            DrainOptions {
                limit: DRAIN_BATCH,
                lease: time::Duration::seconds(LEASE_SECS),
                subrequests_per_item: SUBREQUESTS_PER_DELIVERY,
            },
            |record| {
                // Clone the ports into the future: a `FnMut` handler cannot
                // hand out borrows of its captures across an await.
                let db = Arc::clone(&db);
                let http = Arc::clone(&http);
                let clock = Arc::clone(&clock);
                let counters = &counters;
                async move {
                    let now = now_timestamps(&clock);
                    match deliver_one(&*db, &*http, &record, max_attempts, &now).await {
                        Ok(Filed::Delivered) => {
                            counters.delivered.fetch_add(1, Ordering::Relaxed);
                            Processed::Done
                        }
                        Ok(Filed::Retried(at)) => {
                            counters.retried.fetch_add(1, Ordering::Relaxed);
                            Processed::RetryAt(at)
                        }
                        Ok(Filed::DeadLettered) => {
                            counters.dead_lettered.fetch_add(1, Ordering::Relaxed);
                            // The dead letter already dropped the outbox row.
                            Processed::Done
                        }
                        Ok(Filed::Dropped) => {
                            counters.dropped.fetch_add(1, Ordering::Relaxed);
                            Processed::Done
                        }
                        // The row keeps its lease: released due when that
                        // lapses, without counting an attempt. Abandoning
                        // the rest of the pass over one error would leave
                        // every row behind it leased and untouched for the
                        // whole lease.
                        Err(error) => {
                            counters.failed.fetch_add(1, Ordering::Relaxed);
                            tracing::error!(row = %record.id, %error, "delivering a webhook failed");
                            Processed::NextAt(
                                now.at.saturating_add(time::Duration::seconds(LEASE_SECS)),
                            )
                        }
                    }
                }
            },
        )
        .await?;

    Ok(DrainReport {
        claimed: usize::try_from(core_report.processed).unwrap_or(usize::MAX),
        delivered: counters.delivered.load(Ordering::Relaxed),
        retried: counters.retried.load(Ordering::Relaxed),
        dead_lettered: counters.dead_lettered.load(Ordering::Relaxed),
        dropped: counters.dropped.load(Ordering::Relaxed),
        failed: counters.failed.load(Ordering::Relaxed),
        deferred: core_report.released,
    })
}

/// One row: parse, resolve the endpoint, sign, send, and report how it was
/// filed. The outbox row itself is left to [`drain_within`], which applies
/// the [`Processed`] the caller maps this [`Filed`] to — except the
/// dead-letter and drop paths, which move or remove the row here (a dead
/// letter must be atomic with its row's removal).
///
/// [`drain_within`]: cratefield_core::Outbox::drain_within
async fn deliver_one(
    db: &dyn cratefield_core::Database,
    http: &dyn HttpClient,
    record: &OutboxRecord,
    max_attempts: i64,
    now: &Timestamps,
) -> Result<Filed, DeliveryError> {
    let Ok(job) = serde_json::from_str::<DeliveryJob>(&record.payload) else {
        return dead_letter_malformed(db, record, now).await;
    };

    // One read for URL and secret: the listable endpoint type carries no
    // secret, so this is the only query that ever selects one. `None` is
    // an endpoint deleted between the enqueue and the drain: nobody is
    // subscribed at the other end any more. Dropped, not dead-lettered —
    // a replay would have nothing to deliver to either.
    let Some(target) = store::delivery_target(db, &job.subject, &job.endpoint_id).await? else {
        return Ok(Filed::Dropped);
    };

    let body = serde_json::to_vec(&Envelope {
        id: &job.event_id,
        event_type: &job.event_type,
        subject: &job.subject,
        created_at: &job.created_at,
        data: &job.data,
    })
    .map_err(|error| DeliveryError::Encode(error.to_string()))?;

    let attempt = record.attempts + 1;
    match post(http, &target.url, &target.secret, &job, &body, now.unix).await {
        Ok(status) if status.is_success() => {
            log_attempt(
                db,
                &job,
                attempt,
                Some(i64::from(status.as_u16())),
                None,
                now,
            )
            .await?;
            // Completed by the drain, off this outcome.
            Ok(Filed::Delivered)
        }
        // The endpoint said never again: a permanent refusal no retry
        // fixes, so it does not burn the remaining attempts.
        Ok(StatusCode::GONE) => {
            reject_now(
                db,
                &job,
                record,
                attempt,
                "endpoint answered 410 Gone",
                Some(i64::from(StatusCode::GONE.as_u16())),
                now,
            )
            .await
        }
        Ok(status) => {
            let why = format!("endpoint answered {status}");
            retry_or_give_up(
                db,
                &job,
                record,
                now,
                max_attempts,
                Failure {
                    attempt,
                    why: &why,
                    status_code: Some(i64::from(status.as_u16())),
                },
            )
            .await
        }
        // A blocked destination is a permanent configuration problem (the
        // `HttpClient` port's contract: loopback, private and metadata
        // addresses are refused) — every retry would be blocked too.
        Err(HttpError::BlockedDestination(why)) => {
            let why = format!("destination refused by outbound policy: {why}");
            reject_now(db, &job, record, attempt, &why, None, now).await
        }
        // Transport trouble, a deadline, an oversized reply: weather.
        // Retry with backoff to a bound.
        Err(error) => {
            let why = error.to_string();
            retry_or_give_up(
                db,
                &job,
                record,
                now,
                max_attempts,
                Failure {
                    attempt,
                    why: &why,
                    status_code: None,
                },
            )
            .await
        }
    }
}

/// The filing when the outbox payload is not a delivery job at all: log
/// it, dead-letter it as `malformed` — a bug or a hand-edited database,
/// not weather — and keep the pass moving.
async fn dead_letter_malformed(
    db: &dyn cratefield_core::Database,
    record: &OutboxRecord,
    now: &Timestamps,
) -> Result<Filed, DeliveryError> {
    tracing::error!(row = %record.id, "outbox row is not a webhooks delivery job");
    let why = "outbox payload is not a webhooks delivery job";
    let broken = broken_job(&record.payload, &record.topic);
    log_attempt(db, &broken, 1, None, Some(why), now).await?;
    store::dead_letter(
        db,
        &UlidIdGen.ulid(),
        &broken,
        &GiveUp {
            outbox_row_id: &record.id,
            attempts: record.attempts + 1,
            reason: DeadLetterReason::Malformed,
            last_error: why,
            status_code: None,
            created_at: &broken.created_at,
            failed_at: &now.iso,
        },
    )
    .await?;
    Ok(Filed::DeadLettered)
}

/// A failure no retry fixes (`410 Gone`, or the `HttpClient` port
/// refusing the destination outright): log the attempt and dead-letter
/// immediately as `rejected`, without burning the remaining attempts.
async fn reject_now(
    db: &dyn cratefield_core::Database,
    job: &DeliveryJob,
    record: &OutboxRecord,
    attempt: i64,
    why: &str,
    status_code: Option<i64>,
    now: &Timestamps,
) -> Result<Filed, DeliveryError> {
    log_attempt(db, job, attempt, status_code, Some(why), now).await?;
    store::dead_letter(
        db,
        &UlidIdGen.ulid(),
        job,
        &GiveUp {
            outbox_row_id: &record.id,
            attempts: attempt,
            reason: DeadLetterReason::Rejected,
            last_error: why,
            status_code,
            created_at: &job.created_at,
            failed_at: &now.iso,
        },
    )
    .await?;
    Ok(Filed::DeadLettered)
}

/// A payload that failed to parse, for the dead letter's own columns. The
/// topic is all the identity that survives; `data` keeps the raw payload
/// so nothing a debugger needs is silently dropped. It names no endpoint
/// and no subject, because none could be read.
fn broken_job(payload: &str, topic: &str) -> DeliveryJob {
    DeliveryJob {
        endpoint_id: String::new(),
        event_id: String::new(),
        event_type: topic.to_owned(),
        subject: String::new(),
        created_at: String::new(),
        data: serde_json::Value::String(payload.to_owned()),
    }
}

/// POSTs the signed envelope. Returns the status of any answered request;
/// transport failures are [`HttpError`]s.
async fn post(
    http: &dyn HttpClient,
    url: &str,
    secret: &str,
    job: &DeliveryJob,
    body: &[u8],
    unix_now: i64,
) -> Result<StatusCode, HttpError> {
    let signature = signature_header(secret, unix_now, body)
        .ok_or_else(|| HttpError::Transport("signing failed".to_owned()))?;
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header(CONTENT_TYPE, "application/json")
        .header(SIGNATURE_HEADER, signature)
        .header(EVENT_ID_HEADER, job.event_id.as_str())
        .header(EVENT_TYPE_HEADER, job.event_type.as_str())
        .body(Bytes::copy_from_slice(body))
        .map_err(|error| HttpError::Transport(error.to_string()))?;
    Ok(http.send(request).await?.status())
}

/// Logs one attempt, whatever its outcome.
async fn log_attempt(
    db: &dyn cratefield_core::Database,
    job: &DeliveryJob,
    attempt: i64,
    status_code: Option<i64>,
    error: Option<&str>,
    now: &Timestamps,
) -> Result<(), DbError> {
    store::record_delivery(
        db,
        &UlidIdGen.ulid(),
        job,
        attempt,
        status_code,
        error,
        &now.iso,
    )
    .await
}

/// What a transient failure looked like to the attempt that saw it.
struct Failure<'a> {
    attempt: i64,
    why: &'a str,
    status_code: Option<i64>,
}

/// The transient-failure policy: back off to a bound, then dead-letter.
/// Never a dead letter before the log row is written — the delivery log
/// is how an operator finds out what the last attempt saw.
async fn retry_or_give_up(
    db: &dyn cratefield_core::Database,
    job: &DeliveryJob,
    record: &OutboxRecord,
    now: &Timestamps,
    max_attempts: i64,
    failure: Failure<'_>,
) -> Result<Filed, DeliveryError> {
    let (attempt, why, status_code) = (failure.attempt, failure.why, failure.status_code);
    log_attempt(db, job, attempt, status_code, Some(why), now).await?;
    if attempt >= max_attempts {
        store::dead_letter(
            db,
            &UlidIdGen.ulid(),
            job,
            &GiveUp {
                outbox_row_id: &record.id,
                attempts: attempt,
                reason: DeadLetterReason::AttemptsExhausted,
                last_error: &format!("gave up after {attempt} attempts: {why}"),
                status_code,
                created_at: &job.created_at,
                failed_at: &now.iso,
            },
        )
        .await?;
        return Ok(Filed::DeadLettered);
    }
    // The outbox counts this attempt when it applies `Processed::RetryAt`.
    let delay = backoff(attempt);
    let seconds = i64::try_from(delay.as_secs()).unwrap_or(i64::from(u32::MAX));
    Ok(Filed::Retried(
        now.at.saturating_add(time::Duration::seconds(seconds)),
    ))
}

/// Why a whole drain pass cannot start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    /// A port the module requires is absent from this deployment.
    MissingPort(&'static str),
    /// The database refused a read or a write.
    Database(DbError),
    /// The envelope could not be serialised. Cannot happen for a payload
    /// that parsed on the way in, but a serde error is not a panic.
    Encode(String),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryError::MissingPort(port) => write!(f, "webhooks: missing port {port}"),
            DeliveryError::Database(error) => write!(f, "webhooks: {error}"),
            DeliveryError::Encode(error) => write!(f, "webhooks: {error}"),
        }
    }
}

impl std::error::Error for DeliveryError {}

impl From<DbError> for DeliveryError {
    fn from(error: DbError) -> Self {
        DeliveryError::Database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_header_carries_a_bound_timestamp_and_lowercase_hex() {
        let header =
            signature_header("a test secret", 1_234, b"body bytes").expect("hmac accepts any key");
        assert!(header.starts_with("t=1234,v1="), "{header}");
        let hex = header.trim_start_matches("t=1234,v1=");
        assert_eq!(hex.len(), 64, "SHA-256 in hex: {header}");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "the hex is lowercase: {header}"
        );
    }

    #[test]
    fn the_signature_binds_the_body_so_a_restamp_invalidates_it() {
        let a = signature_header("secret", 1_234, b"one body").expect("signs");
        let b = signature_header("secret", 1_234, b"another body").expect("signs");
        let c = signature_header("secret", 1_235, b"one body").expect("signs");
        assert_ne!(a, b, "a different body signs differently");
        assert_ne!(a, c, "a different timestamp signs differently");
    }

    #[test]
    fn backoff_doubles_from_thirty_seconds_to_the_one_hour_ceiling() {
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(3), Duration::from_secs(120));
        assert_eq!(backoff(8), Duration::from_secs(3_600));
        assert_eq!(backoff(20), Duration::from_secs(3_600), "capped");
        assert_eq!(backoff(0), Duration::from_secs(30), "floor at one attempt");
    }

    #[test]
    fn the_envelope_names_the_event_its_subject_and_its_data() {
        let job = store::test_job();
        let body = serde_json::to_vec(&Envelope {
            id: &job.event_id,
            event_type: &job.event_type,
            subject: &job.subject,
            created_at: "2026-09-27T00:00:00Z",
            data: &job.data,
        })
        .expect("serialises");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
        assert_eq!(parsed["id"], "ev");
        assert_eq!(parsed["type"], "order.paid");
        assert_eq!(parsed["subject"], "acct");
        assert_eq!(parsed["created_at"], "2026-09-27T00:00:00Z");
        assert_eq!(parsed["data"]["amount"], 1);
    }

    /// The receiver's side of the contract, exactly as a customer would
    /// implement it: recompute the MAC over `{t}.{body}` and compare.
    #[test]
    fn a_receiver_recomputing_the_mac_verifies_the_delivery() {
        let secret = "whsec_generated_by_create_endpoint";
        let body = b"{\"id\":\"ev\",\"type\":\"order.paid\"}";
        let signed_at = 1_792_000_000;
        let header = signature_header(secret, signed_at, body).expect("signs");

        let (t, v1) = header
            .split_once(",v1=")
            .map(|(t, v1)| (t.trim_start_matches("t="), v1))
            .expect("the header shape");
        assert_eq!(t, "1792000000");

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key");
        mac.update(t.as_bytes());
        mac.update(b".");
        mac.update(body);
        assert_eq!(lower_hex(&mac.finalize().into_bytes()), v1);
    }

    #[test]
    fn dead_letter_reasons_round_trip_their_column_values() {
        for (reason, stored) in [
            (DeadLetterReason::AttemptsExhausted, "attempts_exhausted"),
            (DeadLetterReason::Rejected, "rejected"),
            (DeadLetterReason::Malformed, "malformed"),
        ] {
            assert_eq!(reason.as_str(), stored);
        }
    }
}
