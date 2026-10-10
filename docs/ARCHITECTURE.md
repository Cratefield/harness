# Factory Zero backend harness — architecture

Status: v2 (Rust), adopted 2026-09-05, ADR 0008 added 2026-09-06, ADR 0009 added 2026-09-06. Owner: Factory Zero. Decisions are
recorded in [docs/adr](adr). Supersedes the TypeScript v1 design entirely.

## 1. What this is

One reusable, open-source backend harness, written in **Rust**, that every
Factory Zero venture compiles its own backend from. A venture's backend is a
small Cargo project that depends on the harness crates it wants, wires
adapters, and builds **one stateless Cloudflare Worker** (Rust compiled to
WebAssembly via `workers-rs`). Nothing is shared at runtime between ventures:
each venture has its own Worker, its own database, its own secrets.

Modules are Rust crates resolved at compile time. The kernel and most modules
are public; some modules are private. Cloudflare D1 is the database today; the
design keeps compute and storage swappable so everything can move to a
self-hosted native binary later without rewriting modules.

First deliverables: an **email signup** module (double opt-in via Resend) and
a **waitlist** module, deployed for factory0.ventures.

## 2. Principles

1. **Modules only see ports.** A module never touches a Cloudflare binding,
   `std::env`, or a vendor client. It receives trait objects: `Database`,
   `Mailer`, `Captcha`, `RateLimiter`, `Signer`, `KeyValue`, `Clock`, `IdGen`,
   `Actors`. Adapters implement the traits. This is what makes the self-hosted
   move a change of one runtime crate, not a rewrite.
2. **Compile-time composition.** A venture backend lists module crates in
   `Cargo.toml` and composes them in `src/lib.rs`. The wasm binary contains
   exactly those modules it serves in-process. No runtime plugin loading, no
   registry service. Cargo features select adapters. One narrowing, ADR 0009: a
   module whose source must stay with its owner may run as a **sidecar**, its
   own Worker reached over a service binding and mounted at the same
   `/v1/<name>`. It is still composed, just not into the same binary.
3. **Stateless by construction.** No `static mut`, no `thread_local!` state
   that outlives a request, no per-isolate caches of request data. Anything
   that must persist goes through `Database` or `KeyValue`. Confirmation and
   unsubscribe links are HMAC-signed tokens, so they need no server-side
   session. Request scope (request id, tracing span, `wait_until`) travels in
   axum request extensions, never in shared mutable state.
4. **Runtime-agnostic kernel.** `cratefield-core` depends on `http`, `axum`
   (default features off), `serde`, `tracing`, and pure-Rust crypto. It has no
   `wasm-bindgen`, `worker`, `tokio` or `std::fs` dependency. Runtime-specific
   code lives in `cratefield-runtime-cloudflare` (wasm) and, later,
   `cratefield-runtime-native` (tokio).
5. **Portable SQL.** Migrations are hand-written SQL in a subset that both
   SQLite (D1) and Postgres accept, with per-dialect overrides only when
   unavoidable. Queries are built with `sea-query`, which renders the same
   query for either backend; execution goes through the `Database` trait.
6. **Small surface, boring crates.** axum, serde, sea-query, tracing, hmac,
   sha2, base64, subtle, ulid, askama, clap. No framework of our own beyond the
   `Module` trait.

## 3. Crate map

Crate names encode visibility and distribution. There are no scopes on
crates.io, so the prefix does the job.

Every crate lives in this repository (ADR 0013). The prefix says who owns
the name and whether it is published; `publish = false` in the manifest is
what actually keeps a crate off crates.io.

| Prefix | Distribution | Visibility |
|---|---|---|
| `cratefield-*` | crates.io, except where `publish = false` | public, MIT |
| `cratefield-auth-*` | never published (except `cratefield-auth-client`) | public source, deployed as one branded instance per app |
| `fz-*` | never published | public source, Factory Zero's module |

### The published crates

| Crate | Role |
|---|---|
| `cratefield-core` | `Module` trait, `Harness` builder, axum router assembly, port traits, typed config, problem+json errors, request scope, tracing setup, in-process event bus, template registry. |
| `cratefield-runtime-cloudflare` | `#[event(fetch)]` and `#[event(scheduled)]` entry points on `workers-rs`. Maps bindings to ports: D1 -> `Database` (sea-query -> `D1PreparedStatement`), KV -> `KeyValue`, Rate Limiting binding -> `RateLimiter`, D1 -> per-key `RateLimiter` (issue #538), `HARNESS_SECRET` -> `Signer`, `Context::wait_until` -> `Defer`. |
| `cratefield-adapter-resend` | `Mailer` over the Resend REST API using the runtime's `HttpClient` port (no vendor SDK). Idempotency keys, error mapping, `NotConfigured` mode when the key is absent. |
| `cratefield-adapter-turnstile` | `Captcha` over Cloudflare Turnstile siteverify. |
| `cratefield-adapter-anthropic` | `TextModel` over the Anthropic Messages API using the runtime's `HttpClient` port (no vendor SDK). One prompt in, one completion out — no streaming, no retries inside the adapter; a JSON schema is requested as a forced tool call and returned as the tool input; error mapping puts 429/5xx in `Transient` (the provider's `Retry-After` honoured in both RFC 9110 forms), the provider's 4xx refusals in `Rejected`, and everything that stops the call completing in `Transport`; `NotConfigured` mode when the key is absent. Image input (issue #628) is reported through `Capability::Images`: a turn's `Part::Image`s ride as base64 content blocks — at most 4 images, 3.75 MiB encoded each, 4 MiB total, refused before sending. |
| `cratefield-adapter-apns` | `Push` over Apple Push Notification service using the runtime's `HttpClient` port (no vendor SDK). Serves `Recipient::Apns` and rejects the other transports (ADR 0015); maps `ttl` to the absolute `apns-expiration`, `silent` to a background push, `badge`/`url`/`loc` into the payload. `Unregistered` (410) vs retryable error mapping with the provider's `Retry-After`, `NotConfigured` mode when the `.p8` is absent. |
| `cratefield-adapter-fcm` | `Push` over Firebase Cloud Messaging on the **HTTP v1** API using the runtime's `HttpClient` port (no Firebase Admin SDK — there is none for Rust). Serves `Recipient::Fcm` and rejects the other transports (ADR 0015); OAuth 2.0 bearer token from a Google service account, cached and re-exchanged once on a `401`; maps `ttl` to `android.ttl`, `silent` to a data-only message, `category`/`url` into `android.notification`, and stringifies every `data` value because FCM takes no other kind (`thread_id` is dropped: v1 has no grouping field and `tag` replaces rather than groups). Error mapping keys off `error.details[].errorCode` — `UNREGISTERED` is the prune signal and nothing else is, since a bare `404` is a missing *project* — with the HTTP status as the fallback and the provider's `Retry-After` honoured in both RFC 9110 forms, `NotConfigured` mode when the service account is absent. |
| `cratefield-push-auth` | The provider tokens the push adapters present: `Es256Signer` (APNs today, VAPID next), `Rs256Signer` (Google service accounts), and a keyed `CachedToken` for mint-once-reuse. Pure Rust, wasm32, no `jsonwebtoken`/`ring`. |
| `cratefield-adapter-webpush` | `Push` over Web Push using the runtime's `HttpClient` port (no vendor SDK): RFC 8030 delivery, RFC 8188/8291 `aes128gcm` payload encryption, RFC 8292 VAPID. Serves `Recipient::WebPush` and rejects the other transports (ADR 0015); one adapter for browsers **and** Google-free Android, because UnifiedPush distributors accept the same request. Fresh P-256 key and salt per message, payload limit computed from the record size, `Topic`/`TTL`/`Urgency` headers, VAPID token cached per push-service origin, `410` → `Unregistered` and **`404` deliberately not** — RFC 8030 defines only `410`, and a `404` is what a proxy that came back without its routes answers for every path, so pruning on it would delete a venture's whole register in one pass and no server can recreate a Web Push subscription. `NotConfigured` mode when the VAPID key is absent. |
| `cratefield-adapter-stripe` | `Payments` over the Stripe REST API using the runtime's `HttpClient` port (no vendor SDK). Form-encoded requests with idempotency keys, hosted Checkout/Connect flows, destination charges with an application fee, HMAC webhook verification with a timestamp tolerance, `NotConfigured` mode when the key is absent. No card data crosses the adapter. |
| `cratefield-adapter-polar` | `Payments` over Polar, a Merchant of Record (issue #690, ADR 0027), using the runtime's `HttpClient` port (no vendor SDK). Hosted checkout for a product (monthly or annual), usage meters through event ingestion deduplicated on the report identifier, customer-portal sessions, net refunds made idempotent through refund metadata, disputes read and accepted through the API (Polar sends no dispute webhook), Standard Webhooks verification under both of Polar's key derivations, sandbox or production by config. Connect and destination charges are `Unsupported`. |
| `cratefield-adapter-sqlite` | `Database` over `rusqlite` (bundled). Used by every test, and viable for a single-node self-hosted deployment. |
| `cratefield-mail-templates` | Branded transactional mail (issue #715, ADR 0028): one email-client-safe layout and a plain-text twin per message, themed per venture with a `MailTheme` (logo, light and dark palettes, fonts, footer). Every module that sends mail renders through it. |
| `cratefield-module-email-signup` | Collect an email, double opt-in, unsubscribe, admin export. |
| `cratefield-module-waitlist` | Join a per-product waitlist, confirm, position, referral codes, admin export. |
| `cratefield-module-telemetry` | Aggregate usage counts from clients (issue #413): closed event and module vocabularies, a batched counts-only payload, a machine-readable consent notice, opt-out via a local switch or `DO_NOT_TRACK`/`CI`, and aggregate admin rows. No third-party analytics, no free text ([TELEMETRY.md](TELEMETRY.md)). |
| `cratefield-signer` | Key-reference signing (issue #761): the `KeySigner` port (create/describe/sign — no method returns key material), `Payload::{EvmTransaction, UserOperation, Eip712, SolanaMessage}` with the signing hashes computed in-crate, the `Guardrails` seam with a `StaticGuardrails` allowlist + value cap + kill switch, a sha256-chained `SignAudit`, and `GuardedSigner`, which runs decode → guardrails → audit → provider in that order and fails closed. `SecretsSigner` mints secp256k1/ed25519 **session keys** into the Secrets store, unsealed only inside `sign` |
| `cratefield-adapter-turnkey` | The signer port's Turnkey provider (issue #761): `CREATE_SUB_ORGANIZATION_V7` roots a sub-organization in the end user's passkey with the backend as a delegated access user whose API key (P-256, in the Secrets store) stamps `X-Stamp`; `EFFECT_ALLOW` policies scope it to the venture's rules (`eth.tx.to/chain_id/value`, the calldata selector, Solana `program_key`) before `UPDATE_ROOT_QUORUM` hands the root to the user alone, and an `EFFECT_DENY` kill switch freezes it. Signing is `SIGN_TRANSACTION_V2` (the one activity the policy engine parses) or `SIGN_RAW_PAYLOAD_V2` for digests, by key reference; REJECTED/CONSENSUS_NEEDED map to the port's `Denied` |
| `cratefield-cli` | Binary `fz`: `fz migrations collect`, `fz doctor`, `fz modules`. Run from the venture repo with `cargo run -p` or installed. |
| `cratefield-testing` | Conformance kit for modules: fake mailer, fake captcha, fake rate limiter, fixed clock, in-memory `Database`, request helpers over the axum router (no network). Used by public and private modules alike. |
| `cratefield-adapter-postgres` | `Database` over `sqlx` Postgres, for the native runtime. The parity suite runs module suites against both SQLite and Postgres (`.github/workflows/parity.yml`). |
| `cratefield-runtime-native` | The same harness served by axum on tokio as a single binary, for the self-hosted move (one venture per process; the multi-tenant layer of ADR 0008 is still unbuilt). |

### The unpublished crates

**The auth service** (`crates/auth-*`, packages `cratefield-auth-*`). One
crate per login method over a shared `auth-core`, plus the deployable
`auth-worker`, deployed as one branded instance per app (`instances/<app>/`,
issue #777). Its ADRs are the 0200 block. It moved here from
`Factory-Zero/auth`; the packages were renamed from `factory0-auth-*` on
2026-10-05 (ADR 0011 amendment).

**Private modules** are `fz-*` crates alongside the public ones and pass the
same `cratefield-testing` conformance kit in this repo's own CI.
`fz-module-linkedin` runs a LinkedIn Company Page from the harness.

**The control plane** (`crates/control-plane*`) is the managed service: sign
up, pick modules, connect Cloudflare and SSO, and get a running harness
venture. It is itself a harness venture. See
[`docs/control-plane/`](control-plane/).

Three native `fz` binaries — `crates/auth-fz`, `crates/control-plane-fz`,
`crates/control-plane-dev` — are **excluded** from the workspace so their
`clap`/`rusqlite` dependencies never reach a wasm graph. They use path
dependencies and are built from their own directories.

### `ventures/`

A venture is a Worker composing modules. There is no template to copy: a new
one starts from a manifest — `fz init` writes `venture.json` (name and host,
no modules), `fz add` mounts modules onto it, and `fz build` generates the
crate: `src/lib.rs` (Worker entry via the runtime crate and the generated
`harness()`), `src/fz_main.rs` (the `fz` bin target), a `wrangler.toml` with
a D1 binding, and a `migrations/` dir maintained by `fz migrations collect`.

| Venture | Serves |
|---|---|
| `cratefield-waitlist` | `api.cratefield.com` — Cratefield's own early-access waitlist |
| `factory0` | `api.factory0.ventures` — signup and waitlist for factory0.ventures. Not deployed |

Deployable Workers that are crates rather than ventures keep their
`migrations/` beside the crate: `crates/auth-worker` and
`crates/control-plane`. The control plane's `wrangler.toml` sits beside it
too. The auth Worker is deployed once per app, so its configurations live
in `instances/<app>/wrangler.toml`, each building the same crate (issue
#777).

## 4. The module contract

```rust
// cratefield-core
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;              // "email-signup" -> mounted at /v1/email-signup
    fn version(&self) -> &'static str;           // env!("CARGO_PKG_VERSION"), for /__health
    fn harness_api(&self) -> u32 { HARNESS_API } // contract version, checked by Harness::build
    fn requires(&self) -> &'static [Port];       // [Port::Db, Port::Mailer]; missing = build error
    fn optional(&self) -> &'static [Port] { &[] }
    fn tables(&self) -> &'static [&'static str] { &[] }
    fn emits(&self) -> &'static [&'static str] { &[] }
    fn public_writes(&self) -> bool { false }    // drives the production-captcha rule
    fn migrations(&self) -> Migrations;          // include_str! SQL per dialect
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError>;
    fn router(&self, ctx: ModuleContext) -> axum::Router;
    fn surface(&self) -> Surface { Surface::none() } // UI actions + views, ADR 0010
    fn events(&self) -> Vec<(EventName, EventHandler)> { Vec::new() }
    fn scheduled<'a>(&'a self, ctx: &'a ModuleContext, cron: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

pub struct ModuleContext {
    pub ports: Ports,            // Arc<dyn Database>, Option<Arc<dyn Mailer>>, ... only what was declared
    pub config: Arc<dyn Config>, // module keys are prefixed: EMAIL_SIGNUP_CONFIRM_TTL_DAYS
    pub events: EventBus,
    pub templates: Arc<TemplateRegistry>,
    pub venture: Arc<Venture>,   // name, domain, public_url, cors_origins, env
}

/// Per-request scope, inserted by core middleware into axum extensions.
pub struct Scope { pub request_id: String, pub defer: Defer, pub span: tracing::Span }
```

Handlers get the request scope as an axum extractor: `Scope` implements
`FromRequestParts`, so `async fn join(scope: Scope, State(ctx): State<Arc<ModuleContext>>, Json(body): Json<JoinBody>)`.
`ctx.events.emit_in(&scope, "waitlist.confirmed", payload)` runs handlers in
that request's `wait_until`. There is no ambient "current request".

A venture composes:

```rust
// src/lib.rs in a venture repo
use cratefield_core::{Harness, Venture};
use cratefield_runtime_cloudflare::Cloudflare;
use cratefield_adapter_resend::Resend;
use cratefield_adapter_turnstile::Turnstile;
use cratefield_module_email_signup::EmailSignup;
use cratefield_module_waitlist::Waitlist;

pub fn harness() -> Harness {
    Harness::builder()
        .venture(Venture::new("factory0", "factory0.ventures")
            .public_url("https://factory0.ventures")
            .cors_origins(["https://factory0.ventures"]))
        .module(EmailSignup::new().double_opt_in(true))
        .module(Waitlist::new().products(["kontinuum", "undercover-rockstars"]))
        .runtime(Cloudflare::new().db("DB").mailer(Resend::from_env()).captcha(Turnstile::from_env()))
        .build()
        .expect("harness configuration is invalid")
}
```

`Harness::build()` fails when a module requires a port the runtime does not
provide, when two modules claim the same route prefix or table, when a module's
`harness_api` differs from core's, or when a template override names an unknown
module. In a generated venture the `harness()` ends in
`.expect("generated venture harness is valid")`, so a bad composition fails
at first compose; `examples/tables-canary/tests/boots.rs` composes the
generated venture, which turns a bad composition into a
`cargo test --workspace` failure.

## 5. Ports

| Port | Trait (sketch) | Cloudflare adapter | Self-hosted adapter |
|---|---|---|---|
| `Database` | `execute(&Statement) -> Result<u64>`, `query(&Statement) -> Result<Rows>`, `batch(&[Statement])` (atomic where the engine supports it); `Statement` = sea-query `(sql, values)` | D1 via `worker::D1Database` | Postgres via `sqlx`; SQLite via `rusqlite` |
| `Mailer` | `send(Message) -> Result<SendOutcome>` where `SendOutcome::{Sent{id}, NotConfigured}`, plus `providers() -> Vec<MailProvider>` naming the providers behind it for `/__health` (name, configured, and healthy when the adapter can probe it; never a credential, issue #793) | Resend over `HttpClient` | Resend (unchanged); Owlpost (`cratefield-adapter-owlpost`) |
| `Captcha` | `verify(token, remote_ip) -> Result<Verdict>` | Turnstile over `HttpClient` | Turnstile |
| `RateLimiter` | `limit(key) -> Result<Decision{ok, retry_after, quota}>` | Workers Rate Limiting binding (one limit per namespace); D1 per-key fixed window (`D1RateLimiter`, ship `RATE_LIMIT_COUNTERS_SQL` as a migration) | Redis |
| `Signer` | `sign(Payload) -> String`, `verify(token, purpose) -> Option<Payload>` | HMAC-SHA256 (`hmac` + `sha2`) with `HARNESS_SECRET`; in core | same |
| `KeyValue` | `get/put/delete` with TTL | KV | Redis |
| `Blob` | `put(key, bytes, content_type)`, `get -> Option<BlobObject>`, `delete` (idempotent), `signed_url(key, ttl)` (presigned GET) and `signed_put_url(key, content_type, content_length, ttl) -> PresignedPut` (presigned PUT; the returned headers are the signed ones); TTLs are bounded to `1 s ..= MAX_PRESIGN_TTL` (`DEFAULT_PRESIGN_TTL` one hour, `MAX_PRESIGN_TTL` seven days; a sub-second TTL would sign `X-Amz-Expires=0`); keys are module-prefixed and the harness hands each module a `ScopedBlob` so it cannot name another's objects | R2 via `worker::Bucket`; presigned GET and PUT via the R2 S3 API when `blob_presign` reads the access key and secret from the Worker `Env` (region `auto`, service `s3`; verify in `wrangler dev`) | directory (`DirBlob`) — no presigned URLs (`Unsupported`); S3-compatible later |
| `Push` | `send(&Recipient, &Notification) -> Result<PushOutcome>` where `Recipient::{Apns, Fcm, WebPush}` names the transport (ADR 0015), `PushOutcome::{Delivered{id}, NotConfigured}`, `PushError::Unregistered` tells the caller to delete a dead recipient and `PushError::Transient{retry_after}` carries the provider's back-off. `RoutingPush` (in core) dispatches by variant; an unwired transport is `NotConfigured`, not `Rejected` | APNs over `HttpClient` (`cratefield-adapter-apns`, ES256 provider JWT from `cratefield-push-auth`; verify against Apple sandbox) | APNs, FCM and Web Push all shipped; see [NOTIFICATIONS.md](NOTIFICATIONS.md) for which are live-proven (none yet, issue #186) |
| `Payments` | hosted checkout, subscription checkout, Connect account link, `charge_with_transfer` (destination charge + application fee), `refund`, `verify_webhook` (HMAC + timestamp), `verify_webhook_request` (multi-header schemes), optional `report_usage`, `create_portal_session`, `get_subscription` / `list_subscriptions`, `get_dispute` / `list_disputes` / `close_dispute` (ADR 0027) — Stripe identifiers and hosted URLs only, never card data (`docs/PAYMENTS.md`) | Stripe over `HttpClient` (`cratefield-adapter-stripe`; verify with test-mode keys), or Polar as Merchant of Record (`cratefield-adapter-polar`; verify against the sandbox) | Stripe (unchanged) |
| `Tracker` | `file(&Destination, &Credential, &TicketDraft) -> Result<Filed, TrackerError>`, `status(&Destination, &Credential, external_id) -> Result<TicketStatus, TrackerError>` where `Destination::{GitHub, Jira, Linear, Zendesk, Freshdesk, Intercom, Salesforce, HubSpot, Slack, Webhook, Colonizer}` names the tracker and `Filed{external_id, url}` carries the id `status` polls by; `comment(&Destination, &Credential, external_id, &TicketComment)` notes an existing ticket (a duplicate report links to the ticket it duplicates), and a `StatusWebhook` verifies then parses the vendor's inbound status delivery (`receive_status`); `TrackerError::{NotConfigured, Unauthorized, Rejected(String), Transient{retry_after}}`; the credential is a per-call argument, not adapter construction state — one hosted Worker serves many customer companies, each with its own token, stored envelope-encrypted by `cratefield-secrets` and decrypted immediately before the call, and `Credential` wraps `zeroize::Zeroizing` with a redacting `Debug`. `RoutingTracker` (in core) dispatches by variant; an unwired destination is `NotConfigured` | adapter-injected like `Payments`: the venture constructs its tracker adapter and passes it via `tracker`/`tracker_arc`; four ship, all over `HttpClient` — `cratefield-adapter-github-issues`, `cratefield-adapter-webhook-tracker`, `cratefield-adapter-jira` and `cratefield-adapter-linear` (the matrix in [MODULE-AUTHORING.md](MODULE-AUTHORING.md)) — and `Cloudflare::provides()` lists `Port::Tracker` once wired; `FakeTracker` stands in for tests | same — the same four adapters, adapter-injected via `tracker_arc`; `FakeTracker` stands in for tests |
| `Realtime` | rooms of WebSocket clients that share a clock and chat: a module implements `RoomHandler` (`on_join`/`on_message`/`on_leave`/`on_alarm`), the port owns the sockets; `Realtime` (`broadcast`/`members`) pokes a room from outside a socket | Durable Object + WebSocket hibernation (`RoomDriver`; the `#[durable_object]` class lives in the venture, see [REALTIME.md](REALTIME.md)). The socket half is proven under `wrangler dev` with two sockets in CI. **The `Realtime` half — `broadcast`/`members` from outside a socket — has no Workers adapter yet**, so `Cloudflare::provides()` does not list this port and a module's `optional()` realtime path is inert there | in-process registry (`InProcessRealtime`) over tokio |
| `Actors` | per-`(kind, key)` serialized calls with all-or-nothing writes and one alarm: a module implements `ActorHandler` (`on_message`/`on_alarm`) against an `ActorContext`, declares its kinds in `Module::actor_kinds` and registers a handler with `HarnessBuilder::actor`; the host owns serialization and durability (`run_actor_message`/`run_actor_alarm`), and `ScopedActors` refuses an undeclared kind ([ACTORS.md](ACTORS.md)) | Durable Object + `ActorDriver` (the `#[durable_object]` class lives in the venture, one object per `<kind>:<key>`); the Worker signs the frame so the object refuses anything else 403, proven under `wrangler dev` in CI | not yet (#584) |
| `TextModel` | `complete(&Prompt) -> Result<Completion>` where `Prompt` names a `ModelTier::{Fast, Strong}` — never a vendor — plus the turns, an optional JSON schema and a token ceiling; `Completion` carries the text, the parsed JSON when a schema was given, the model that answered and the token usage. `RoutingTextModel` (in core, ADR 0002/ADR 0015) dispatches by tier; an unwired tier is `TextModelError::NotConfigured`, so a venture can put drafting on one vendor and an independent judge on another without either module knowing. Tools arrived in issue #665 — a `Prompt` may carry `ToolSpec`s and a `ToolChoice`, a `Completion` may carry `ToolCall`s, an adapter that can carry them reports `TextModel::supports(tier, Capability::Tools)`, a venture asserts at compose time with `router.supports(ModelTier::Strong, Capability::Tools)`, and `run_tool_loop` drives the call/execute/feed-back cycle within a `ToolBudget`, refusing a tools-bearing prompt to a model that cannot carry it; image input arrived in issue #628 — a `Turn` may carry `Part`s (text and images in order), an adapter that can carry them reports `TextModel::supports(tier, Capability::Images)`, and `Prompt::check_images` (at most 4 images, 3.75 MiB encoded each, 4 MiB total) refuses an over-limit prompt before any network call; structured output rides on `TextModelExt` (issue #580, [TEXT-MODEL.md](TEXT-MODEL.md)) — `complete_json`/`complete_as` check the schema against the tool loop's subset before the call, validate the answer (provider-native or parsed from text) and allow one repair retry, so a caller holds a conforming value or `TextModelError::SchemaViolation`, never a partial one; embeddings live on the separate `Embedder` port, and streaming stays out — the Workers runtime buffers whole responses, so a stream has nowhere to arrive | none yet — any `TextModel` over `HttpClient` | none yet — any `TextModel` over `HttpClient` |
| `Classifier` | `ask(state, &BTreeMap<String, Question>) -> Result<BTreeMap<String, Answer>>` where `Question::{Choice, Score, Noul}` — the questions of one call are a set, because the provider evaluates them against one `state` in parallel; `Answer` carries the value, the probability mass per label and a `confidence` that is **not comparable across adapters** (`ClassifierProfile::calibration` names which family the numbers come from), and `state` past `profile().max_state_chars` is truncated by the adapter — deterministically, on a char boundary, with a log line, because a silently trimmed state answers confident and wrong (issue #456, [CLASSIFIER.md](CLASSIFIER.md)); `validate_questions` makes a malformed set a `ClassifierError::Rejected`, never a panic; an unwired port is `ClassifierError::NotConfigured` | `cratefield-adapter-typesafe` (the operator's own key, over `HttpClient`), `cratefield-adapter-workers-ai` (the `env.AI` binding, no key) and `cratefield-adapter-classifier-llm` (over the `TextModel` port) | same three — the Workers AI adapter is the only one that needs the binding |
| `Speech` | `transcribe(&TranscribeRequest) -> Result<Transcript, SpeechError>` and `synthesize(&SynthesizeRequest) -> Result<Synthesis, SpeechError>` (the audio is a `ResponseStream`), plus `voices(language)`, `capabilities()` and `limits()`; `check_transcribe`/`check_synthesize` refuse an over-limit ask locally, before any network call (defaults: 25 MiB, 600 s of audio, 4 096 characters — OpenAI's documented caps), and every answer carries `SpeechUsage { audio_millis, characters }`, the provider's own billing units, for spend caps; an unwired port is `SpeechError::NotConfigured` (ADR 0029; `Port::Speech` wiring is a follow-up) | Workers AI binding (`cratefield-adapter-workers-ai`: Deepgram nova-3 or Whisper STT, Deepgram aura-2-en/aura-1 TTS, streamed) | OpenAI-compatible `/audio/transcriptions` + `/audio/speech` over `HttpClient` (`cratefield-adapter-openai-compatible`; any base URL, e.g. a Regolo-hosted Whisper) — synthesis buffered until a streaming client (#859) |
| `HttpClient` | `send(http::Request<Bytes>) -> http::Response<Bytes>` | `worker::Fetch` | `reqwest` |
| `Clock`, `IdGen` | `now() -> OffsetDateTime`, `ulid() -> String` | in core | in core |
| `Defer` | `wait_until(BoxFuture)` | `worker::Context::wait_until` | `tokio::spawn` |

All port traits are `Send + Sync`. On Workers the JS handles are `!Send`; the
Cloudflare adapters wrap them in `worker::send::SendWrapper`, which is sound
because a Workers isolate is single-threaded (ADR 0002). Async methods use
`async_trait` until native `async fn` in traits with `Send` bounds is
ergonomic for trait objects.

## 6. HTTP conventions

- Prefix `/v1/<module>`; `GET /__health` lists each module with its version, the ports it requires and uses when present, and the tables it owns; each mounted sidecar appears too, with its own contract number, module name and version, and the verdict of the last probe (`ok`, `mismatch` or `unreachable`). The per-sidecar entry is probed lazily and cached for a short window — the stamp on each forwarded response is the real contract check (issue #61), the probe exists only so an operator can see both numbers without reading logs; the wired `Mailer` also lists the providers behind it under `mailers`, each with its name and whether it is configured and healthy (issue #793) — names and verdicts only, never a credential; `GET /__ready` runs `SELECT 1` through `Database`; `GET /__surface` serves the composed UI surface (ADR 0010): public actions and views, plus admin ones when the admin bearer is presented, with a strong `ETag` per variant. With `cratefield-ui` mounted, `/ui/<module>/<action>` renders that surface as HTML and a form post there is dispatched in-process to the module route (`docs/UI.md`). Sidecar modules' public surfaces are fetched over their bindings and merged in per request — the fetch carries the gateway stamp when configured, and each merged document is byte-capped, contract-checked, limited to the mounted module's public part, validated, and stripped of captcha-demanding actions on a production host with no Captcha port (issue #131).
- JSON in, JSON out. Bodies deserialize with serde into types whose constructors validate. Errors are RFC 9457 `application/problem+json` with a stable `type` URI per error (`<public_url>/problems/<slug>` under the serving venture's own base; `about:blank` when it has no public URL), `instance` = request id.
- CORS allowlist from `venture.cors_origins` via `tower-http`. No wildcard in production. The list also takes the three browser-extension origins — `chrome-extension://<id>` (32 chars, `a`–`p`), `moz-extension://<uuid>` (lowercase) and `safari-web-extension://<uuid>` (either case) — as exact-match origins (issue #579). Credentials stay off, so a cross-origin caller sends only a bearer token it was given. `docs/VENTURE-GUIDE.md` §8 spells out the shapes.
- Every response carries `x-request-id` (accepted from the client if it matches `^[A-Za-z0-9_-]{8,128}$`, else a fresh ULID). Tracing spans carry it; logs are JSON keyed by it.
- Public write endpoints require a Turnstile token when the `Captcha` port is configured, and are rate limited per IP and per email.
- Admin endpoints (`/v1/<module>/admin/*`) require `Authorization: Bearer <ADMIN_TOKEN>` and are disabled when the token is unset.
- Sidecar modules (ADR 0009) are mounted from `HARNESS_SIDECARS`, a JSON object of `{"<module name>": "<service binding>"}` read from configuration, never from the composition, so the same artifact serves ventures with and without them. A mount whose name collides with an in-process module is ignored and logged; the in-process module keeps its prefix. A mount with no dispatcher, no binding or no answer returns `503 sidecar-unavailable` on **that prefix only**, and a sidecar answering a different `HARNESS_API` returns `503 sidecar-contract-mismatch`. The contract is checked per response, not at cold start (issue #61): an isolate can outlive a sidecar redeploy for hours, so a cached cold-start verdict would keep serving a contract that no longer holds, and Workers forbid the global-scope I/O a true cold-start probe would need. Instead every harness response is stamped with `x-harness-api` (and `x-harness-module` when the deployment serves exactly one module — the sidecar shape), and the host reads the stamp back on every forwarded response, refusing the prefix on a wrong number. The stamp costs one header insert and catches a redeploy within one request; no `/__harness` identity endpoint exists and none is needed. The mount is a trust boundary (issue #131, ADR 0009 amendment): the forwarded request carries an allowlist — `content-type`, `content-length`, `accept`, `accept-language`, `user-agent`, the host's `x-request-id`, a `cf-connecting-ip` the host resolved itself, and a short-lived `x-harness-gateway` token when `SIDECAR_GATEWAY_SECRET` is configured; `authorization` and `cookie` never cross, and a response returns through an allowlist that drops `set-cookie`. Admin paths under a mount are authorized by the host before forwarding. Forwarded writes pass the host's rate limiter and fail closed. A sidecar that sets `SIDECAR_REQUIRE_GATEWAY` answers `401 sidecar-unauthorized` for `/v1/*` and `/__surface` requests whose token it cannot verify, and fails closed (`503`) if the secret is missing. A truthy `HARNESS_ONE_WORKER` with a non-empty mount table is rejected where the table is read.

### Bodies and memory

Bodies are **buffered by default**, in both directions. A buffered request body
is capped at 64 KiB (`MAX_BODY_BYTES`), raised per module by
`Module::max_body_bytes` and enforced by axum's `DefaultBodyLimit` once resident;
a declared `content-length` over it is refused **before any byte is read** — the
`413 request-too-large` pre-check of issue #440. A buffered response is read into
the Workers runtime's 1 MiB response buffer (a const private to
`cratefield-runtime-cloudflare`) before it becomes a Worker `Response`. That
default lets a route answer problem+json before doing any work, but nothing it
carries may be larger than memory.

A Workers isolate has **128 MB**, so a body that fits in neither direction
cannot ride that path. A module opts a route out by naming it in
`Module::streaming_routes()` — one `StreamRoute` per route (a `const`
`post`/`put`/`get`) with its own `max_bytes` ceiling. There the handler extracts
a `RequestStream` and reads it chunk by chunk, and the route's ceiling replaces
`Module::max_body_bytes` **for that route only**. The declaration governs the
**request** body and its ceiling; a `ResponseStream` is honoured on **any**
route, declared or not, because the marker rides on the response. A `HEAD` to a
streaming `GET` route answers headers only, with no body read.

Each runtime carries the stream its own way. On Workers, `serve()` does not read
a declared route's body: it hands the router an empty body plus a `RequestStream`
over the worker-native `Request::stream()`, carried in the request's extensions
(bridging a `worker::Body` through axum hangs the isolate), and
`response_to_worker` builds the Worker `Response` from the `ResponseStream` with
`Response::from_stream` instead of the 1 MiB buffer. On native and in the test
kit, core's own request layer converts the buffered hyper/axum body into a
`RequestStream`. Either way the request still passes **through** the router, so
the request id, CORS, security headers, the rate limiter and `RoutePolicy` all
apply — unlike the `Realtime` route ([REALTIME.md](REALTIME.md)), which bypasses
it.

Mid-stream, a chunk that crosses the ceiling is refused the moment it arrives
(the stream fuses); a declared over-ceiling `content-length` is the same `413
request-too-large`, answered before the handler. Cloudflare itself caps the
request before it reaches the Worker: **100 MB on Free and Pro; 200 MB Business,
500 MB Enterprise** by default. A body over the account's limit cannot be
streamed at any ceiling — it must be uploaded in parts (multipart objects, issue
#586, not yet available).

### Email signup module

| Route | Behaviour |
|---|---|
| `POST /v1/email-signup` `{ email, source?, locale?, captchaToken? }` | Always `202` with an identical body. Creates or refreshes a `subscribers` row in `pending`; sends the confirmation mail with a signed link. Does not reveal whether the email already existed. |
| `GET /v1/email-signup/confirm?token=` | Verifies signature and TTL, flips to `confirmed`, `303` to the configured confirmed URL. |
| `GET /v1/email-signup/unsubscribe?token=` | **Confirms; does not act** (issue #243). Renders a one-button form with no `action`, so it posts back to the same URL and the token stays out of the markup. A mail gateway that fetches every link — Safe Links, URL Defense — changes nothing. |
| `POST /v1/email-signup/unsubscribe` (`?token=` from that form, or `{ token }` as a body) | Flips to `unsubscribed` immediately, which is what RFC 8058 one-click needs. Link is in every mail. |
| `GET /v1/email-signup/admin/export.csv` | Admin. |
| `DELETE /v1/email-signup/admin/subscribers/:id` | Admin. Hard delete for deletion requests, keyed on the opaque row id — an email never travels in a path (issue #135). |

Table `subscribers(id, email, email_normalized unique, status, source, locale, confirmed_at, unsubscribed_at, created_at, updated_at)`.

### Waitlist module

| Route | Behaviour |
|---|---|
| `POST /v1/waitlist` `{ email, product, ref?, answers?, captchaToken? }` | `202` always, whatever the mailer does; the confirmation mail goes out after the response. Row in `waitlist_entries` as `pending`. `product` must be in the configured list. |
| `GET /v1/waitlist/confirm?token=` | Confirms, assigns `position` (max+1 per product) inside a `batch`, credits the referrer, `303` to the status page with the entry's own referral code. |
| `GET /v1/waitlist/status?token=` | `{ product, position, referrals, referralCode, shareUrl }`. |
| `GET /v1/waitlist/admin/export.csv?product=` | Admin. |

Table `waitlist_entries(id, email, email_normalized, product, status, position, referral_code unique, referred_by, referrals, answers, created_at, confirmed_at)`, unique on `(email_normalized, product)`.

Emits `waitlist.confirmed`; a venture can subscribe that event to also add the address to the signup list.

### Telemetry module

| Route | Behaviour |
|---|---|
| `POST /v1/telemetry/events` | A batch of counted events under schema version 1: enums, bounded counts, duration buckets, a 32-hex install id — no free text anywhere ([TELEMETRY.md](TELEMETRY.md)). `202 {"ok":true}`. Unauthenticated by design, because the caller is a CLI, not a browser; guarded by the `RateLimiter` port, the 64-event batch cap and a closed-vocabulary parser that rejects unknown fields and never echoes an offending value in its error body — `Batch::parse`, hand-written over `serde_json::Value` precisely so a rejection cannot quote the value the way serde's own errors would. |
| `GET /v1/telemetry/notice` | The machine-readable consent notice: the exact first-run text, the opt-out command, and every payload field with its permitted vocabulary. Unauthenticated — a notice you must authenticate to read is not a notice. |
| `GET /v1/telemetry/admin/usage` | Admin. Aggregate rows only; no per-install rows. |

Table `telemetry_events(bucket_key, day, install_id, client_kind, client_version, platform, arch, event, outcome, error_kind, duration_bucket, events, first_seen_at, last_seen_at)`, one accumulation bucket per row — no row per event — and `telemetry_modules(install_id, day, module)` for the payload's `modules` list.

Emits `telemetry.recorded` when a batch is accepted.

## 7. Migrations

- Each module ships `migrations/sqlite/NNNN_<name>.sql` (and `migrations/postgres/` when the SQL differs), embedded with `include_str!` so the crate carries its own SQL.
- `fz migrations collect` in the venture repo writes `migrations/<GGGG>_<module>_<NNNN>_<name>.sql` for `wrangler d1 migrations apply`. A lockfile `migrations/.harness-lock.json` pins module migration -> global file so adding a module later appends and never renumbers, and detects edits to already-applied SQL by content hash.
- Portable subset: `TEXT` ids (ULID), ISO-8601 `TEXT` timestamps, `INTEGER` counters, no `AUTOINCREMENT`, no dialect-specific functions in DDL. `fz doctor` lints it.
- Postgres later: same files run through the `cratefield-adapter-postgres` migrator.

Every applied migration is recorded in `harness_migrations` as
`<module>/<id>` with the **sha256 of its SQL**. A later run compares
that hash: unchanged is a skip, changed is a hard error naming the
migration. Forward-only is therefore enforced by each database rather
than by one repository's lockfile, which cannot see a deployment that
already ran the old SQL. Rows written before checksums were recorded
carry `NULL` and read as "applied, unverifiable" rather than as a
mismatch.

## 8. Tooling and release

- Cargo workspace, `rust-toolchain.toml` pinning stable, `rustfmt` + `clippy -D warnings`, `cargo test` for core and modules against `cratefield-adapter-sqlite`, `cargo deny` for licenses and advisories.
- Target `wasm32-unknown-unknown` built with `worker-build`; CI runs `worker-build --release` on the example venture to catch wasm-incompatible dependencies (anything pulling `tokio`, `mio`, `std::fs` at runtime).
- Release with `release-plz`: it opens a release PR with per-crate version bumps and changelogs from conventional commits; merging publishes `cratefield-*` to crates.io using **trusted publishing** (OIDC from GitHub Actions, no long-lived token). Private crates are tagged, never published.
- Ventures pin exact crate versions; Renovate (cargo manager) opens bumps.
- `HARNESS_API` is bumped only on breaking contract changes; `cratefield-core`'s major follows it.

## 9. Deployment

- One Worker per venture per environment (`<venture>-api-staging`, `<venture>-api`), custom domain `api.<venture domain>`. `wrangler.toml` uses `main = "build/worker/shim.mjs"` and `[build] command = "cargo install -q worker-build && worker-build --release"`.
- Secrets: `HARNESS_SECRET`, `RESEND_API_KEY`, `TURNSTILE_SECRET`, `ADMIN_TOKEN`. Set with `wrangler secret put` by a human for production; staging via GitHub Environment secrets. Ventures with public writes or admin routes also declare the Workers Rate Limiting binding (`RATE_LIMITER`, a `[[ratelimits]]` stanza in wrangler.toml — a binding, not a secret): readiness refuses the guarded routes unless it resolves, or the operator records `HARNESS_ALLOW_UNLIMITED_PUBLIC_ROUTES=<reason>` (issue #437). Optional signer entries: `HARNESS_SECRET_PREVIOUS` (demoted, verification-only), `HARNESS_SECRET_REVOKED` (key ids whose signatures are refused while configured), `HARNESS_VENTURE` (the `iss` binding label; a name, not a secret).
- Mail sends from a **verified sending subdomain** `send.<domain>` (never the apex, which carries inbound Email Routing MX). Until verified, the adapter reports `NotConfigured`; only the orgs invitation endpoints turn that into `503 problem type=mail-not-configured` so forms can show a direct address, while the waitlist logs it and still answers `202`.
- Deploy workflow: `main` -> staging automatically; tag `v*` -> production behind a GitHub Environment approval.

## 10. Migration path to self-hosted

Phase 3 introduces `cratefield-adapter-postgres` and `cratefield-runtime-native`.
The move for a venture is:

1. Stand up Postgres, run the same module migrations (postgres set).
2. Copy D1 data with `fz data export` / `fz data import`.
3. Switch the composition in `src/lib.rs` to `.runtime(Native::new().db(Postgres::from_env()).rate_limiter(Redis::from_env()))`, keep `Resend` and `Turnstile`. Build a native binary. The Dockerfile to ship is `examples/venture-native/Dockerfile` (distroless, the binary and nothing else); the repo's other Dockerfile, `docker/Dockerfile`, is the forge build image (a standalone `fz` plus a wasm toolchain), not a runtime image.
4. Point `api.<domain>` at the new host.

No module code changes. The parity suite in `cratefield-testing` runs every
module's tests against SQLite and Postgres in CI from phase 3 onward.

## 11. Security and privacy rules

- **No enumeration.** Signup and waitlist always answer `202` with the same body whether the address is new, pending, confirmed or unsubscribed.
- **Tokens carry a purpose.** Signed payload is `{ purpose, subject, exp?, kid, iss? }`. Lifetimes are a mint-time policy, not a caller habit: `confirm` expires in 7 days, `status` in 90, anything else in 30; only the `unsubscribe` action has a deliberately non-expiring ceiling (ADR 0014), and the never-dying unsubscribe link now also has an opaque per-subscription form in `module-email-signup` that revocation can reach. A confirm token is single-use because the row state is checked before flipping.
- **Key rotation.** `Signer` verifies against a bounded key ring (four entries: `HARNESS_SECRET` signs; `HARNESS_SECRET_PREVIOUS` verifies only; ids named in `HARNESS_SECRET_REVOKED` are refused even while configured); tokens name their `kid`, so rotation never breaks links in flight, and revocation kills a key's signatures without a deletion race. New tokens carry a venture/environment `iss` binding, so one venture's links never verify in another. MAC comparison uses `subtle::ConstantTimeEq`, over every live key with no early exit.
- **Fixed redirects.** Confirm endpoints redirect only to URLs from `Venture` config. No `redirect` query parameter.
- **Admin auth** uses a constant-time compare and is disabled entirely when `ADMIN_TOKEN` is unset. CSV exports escape leading `= + - @ \t \r` to block formula injection.
- **Rate limits** apply to every public endpoint, including confirm and status, keyed by IP (`cf-connecting-ip`, never `x-forwarded-for` on Workers) and, for writes, by normalized email.
- **Captcha is mandatory in production** when a module declares a `HumanForm` write, or has `public_writes() == true` and declares no route policy at all (the conservative fallback). A write proved by an artifact this service issued — a magic link, a passkey or OAuth challenge — declares `RoutePolicy::SignedLink` instead, or `Module::public_write_policy` for a module with no surface, and needs a usable `Signer` rather than a `Captcha` (issue #143). A `RoutePolicy::Signature` write is proved by the module's declared verifier — `Payments::verify_webhook` by default, or the core `webhook_signature` HMAC scheme keyed by the module's own config secret (issue #533) — and production demands exactly what the module named: a `Payments` port, or the secret key set. The environment enforced against is the stricter of the venture's compiled `VentureEnv` and the deployment's `ENV` binding: they used to disagree silently in favour of the weaker one. `Harness::build` refuses the composition, `Harness::router` re-checks it against the resolved ports and answers `503 not-production-ready` on guarded routes, and `fz doctor` re-reports it. Both escapes are recorded: `fz doctor --allow-no-captcha <reason>` for previews, `HARNESS_ALLOW_UNPROTECTED_WRITES=<reason>` on a deployment.
- **PII minimalism.** Store the email, its normalized form, timestamps, source and locale. Do not store IP addresses or user agents. Admin delete is a hard delete. A `retention` option purges `pending` rows older than N days from the scheduled handler.
- **Secrets never reach logs.** The tracing layer redacts fields matching `(?i)secret|token|key|authorization|password`; emails are logged only as a truncated SHA-256 `subject_hash`.
- **No `unsafe`** outside the Cloudflare adapters' `SendWrapper` use, and `#![forbid(unsafe_code)]` in core and every module.

## 12. Non-goals for v1

- Authentication and user accounts (later module).
- Payments (later, and only through the ports pattern).
- Multi-tenant single deployment **on the Worker path**. One venture = one Worker by design. The phase-3 native runtime does serve many tenants, one database each, with a separate control database; see ADR 0008, [RECONCILIATION.md](RECONCILIATION.md) for how a boot reconciles them, and issues #23 to #44.
- Runtime plugin loading. Unchanged by ADR 0009 (when to use the sidecar mount at all: [MOUNTING.md](MOUNTING.md)): Cloudflare's
  `WebAssembly.instantiate()` accepts only pre-compiled modules, so nothing is
  loaded at request time. A sidecar is a separately deployed Worker, not a
  plugin.
