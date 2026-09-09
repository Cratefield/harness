//! `cratefield-core` is the runtime-agnostic kernel of the Factory Zero harness:
//! the [`Module`] contract, the [`Harness`] builder, port traits, RFC 9457
//! problem+json errors, the request [`Scope`], an in-process [`EventBus`] and
//! a [`TemplateRegistry`] (ADR 0001, 0002, 0007).
//!
//! Core depends only on `http`, `axum` (default features off), `serde`,
//! `tracing`, `sea-query` and pure-Rust crypto. It must never depend on
//! `worker`, `wasm-bindgen`, `tokio`, `reqwest`, `sqlx` or `rusqlite`, and
//! never touches `std::fs` or `std::net` — CI enforces this with a
//! `cargo tree` check and the wasm build of `examples/venture`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod admin;
mod config;
mod cooldown;
mod csv;
mod email;
mod events;
mod harness;
mod http;
mod idempotency;
mod lint;
mod logging;
mod module;
mod outbox;
mod ports;
mod problem;
mod problems;
mod rate_limit;
mod route_policy;
mod scope;
mod sidecar;
mod signer;
mod surface;
mod template;
mod venture;

pub use admin::{bearer_token, constant_time_eq, require_admin};
pub use config::{Config, ConfigError, EmptyConfig, HarnessConfig, MapConfig, ModuleConfig};
pub use cooldown::SendCooldown;
pub use csv::{FORMULA_PREFIXES, MAX_EXPORT_ROWS, escape as csv_escape, row as csv_row};
pub use email::{
    MAX_EMAIL_BYTES, MAX_LOCAL_BYTES, invalid_email_problem, is_valid,
    normalize as normalize_email, validation_error,
};
pub use events::{AnyError, EventBus, EventHandler, EventName};
pub use harness::{Harness, HarnessBuilder, Runtime};
pub use http::{Form, Json, MAX_BODY_BYTES, X_REQUEST_ID, rate_limited, request_id_is_valid};
pub use idempotency::Inbox;
pub use lint::{card_data_hit, lint_card_data, lint_portable_sql};
pub use logging::{
    RedactingVisitor, is_email_field, is_secret_field, redacted_value, scrub_text,
    set_error_forwarder, set_log_pseudonym_key, subject_hash,
};
pub use module::{
    BoxFuture, HARNESS_API, Migrations, Module, ModuleContext, SqlMigration, assert_migration_set,
    harness_api_mismatch, migration_checksum, migration_edited,
};
pub use outbox::{Outbox, OutboxRecord};
pub use ports::{
    Blob, BlobError, BlobObject, BoundedHttpClient, Captcha, CaptchaBinding, CaptchaError, Charge,
    CheckoutRequest, CheckoutSession, Clock, ConnectAccountLink, ConnectAccountLinkRequest,
    DEFAULT_RESPONSE_TIMEOUT, Database, DbError, Decision, Defer, DispatchError, Dispatcher,
    HttpClient, HttpError, HttpPolicy, IdGen, KeyValue, Kid, KvError, LineItem, LocKeys,
    MAX_BLOB_BYTES, MAX_CONCURRENT_REQUESTS, MAX_KID_NAME, MAX_RESPONSE_BYTES,
    MAX_RESPONSE_TIMEOUT, MailError, Mailer, Member, Message, Money, NoopDefer, Notification,
    Payload, Payments, PaymentsError, Platform, Port, Ports, Priority, Push, PushError,
    PushOutcome, RateLimitError, RateLimiter, Realtime, RealtimeError, Recipient, Refund,
    RefundRequest, RoomContext, RoomHandler, RoutingPush, Row, Rows, ScopedBlob, SendOutcome,
    SignatureError, Signer, Statement, SubscriptionCheckoutRequest, SystemClock, TransferCharge,
    TryFromValue, UlidIdGen, Verdict, WebhookEvent, check_blob_size, declared_content_length,
    timeout, ttl_secs,
};
pub use problem::Problem;
pub use problems::{ProblemDef, SLUGS, registry as problem_registry};
pub use rate_limit::{RateLimit, RateLimitFailure, check_rate_limit, client_ip, rate_limit_keys};
pub use route_policy::{
    ALLOW_UNPROTECTED_WRITES, RoutePolicy, WriteGuards, captcha_effective, deployed_env,
    env_disagreement, payments_effective, production_readiness, signer_effective,
    unprotected_writes_override, verify_human_form,
};
pub use scope::Scope;
pub use sidecar::{
    GATEWAY_ADMIN_PURPOSE, GATEWAY_PURPOSE, GATEWAY_TOKEN_TTL_SECS, HARNESS_ONE_WORKER,
    HARNESS_SIDECARS, SIDECAR_GATEWAY_SECRET, SIDECAR_REQUIRE_GATEWAY, SidecarMount, SidecarMounts,
    X_HARNESS_API, X_HARNESS_GATEWAY, X_HARNESS_MODULE,
};
pub use signer::{
    CONFIRM_TOKEN_MAX_TTL_SECS, DEFAULT_TOKEN_MAX_TTL_SECS, HmacSigner, KeyRing, KeyState,
    MIN_SECRET_BYTES, RingKey, STATUS_TOKEN_MAX_TTL_SECS, SignerError, TokenPolicy,
    UNSUBSCRIBE_ACTION,
};
pub use surface::{
    Action, Audience, Column, HINT_KEYWORDS, MAX_SIDECAR_ACTIONS, MAX_SIDECAR_SURFACE_BYTES,
    MAX_SIDECAR_VIEWS, ModuleSurface, Outcome, RenderedSurface, SURFACE_API, Surface,
    SurfaceDocument, SurfaceSource, UiContext, UiMount, VentureSurface, View, hint_field,
    schema_for,
};
pub use template::{Rendered, Template, TemplateError, TemplateRegistry};
pub use venture::{Brand, Venture, VentureEnv};
