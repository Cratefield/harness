# Upgrading cratefield-core

A checklist of every **source-breaking** change in `cratefield-core` since
0.5.0, one section per minor, so a venture can move its
`cratefield-core` requirement forward and know what the compiler is going
to say about it. Behaviour changes are noted only where they change what
a test expects.

Two rules make most of this list shorter than it looks, and both are worth
adopting before you need them:

- **Prefer a constructor or a builder to a struct literal.** Where core
  marks a struct `#[non_exhaustive]` — `Prompt` and `Completion` since
  0.6, `Turn` since 0.8 — the compiler forces this, and a literal stops
  compiling every time the struct grows a field.
- **Prefer `..Default::default()` or a wildcard arm to an exhaustive
  `match`.** Every enum in this list that lacks `#[non_exhaustive]` is a
  match that will need editing again at the next minor.

This document covers source breaks only. For everything else — features,
fixes, adapter changes — read [`crates/core/CHANGELOG.md`](../crates/core/CHANGELOG.md),
which is the complete record. For the version ranges and the contract-version
rule, see [COMPATIBILITY.md](COMPATIBILITY.md).

A venture jumping more than one minor works through the sections in order:
0.5 → 0.6 → 0.7 → 0.8. Several changes commonly attributed to 0.7 landed
in 0.6.

---

## Upgrading to 0.8 (from 0.7)

- [ ] **`ports::text_model::Turn` is `#[non_exhaustive]` and no longer
  derives `Eq`.** A struct literal `Turn { role, content }` no longer
  compiles outside core, and code that asserted `Turn: Eq` (a `HashSet`
  of turns, an `assert_eq!` in a `#[derive(Eq)]` test struct) no longer
  compiles either. Build turns with `Turn::user`,
  `Turn::assistant`, `Turn::assistant_tool_calls` or `Turn::tool_results`
  and compare them with `assert_eq!` on the individual fields rather than
  on a derived `Eq` bound.
- [ ] **`ports::text_model::TextModelError` is `#[non_exhaustive]`.** A
  `match` over it outside core needs a wildcard arm. Map the wildcard to
  whatever a transport-shaped failure would mean for the caller — a
  502, a retry, a degraded answer.
- [ ] **`Prompt` gained `tools` and `tool_choice`.** Not a source break on
  its own (`Prompt` was already `#[non_exhaustive]` and built with
  `Prompt::new(..)` plus builders), but a prompt that answers structured
  tool calls now carries `Completion::tool_calls`. A handler that only
  reads `Completion::text` keeps working; one that round-trips a
  conversation must carry the tool turns back.
- [ ] **New `Payments` methods, all defaulted** —
  `verify_webhook_request`, `create_portal_session`, `get_dispute`,
  `list_disputes`, `close_dispute` (0.8.0), then `get_subscription` and
  `list_subscriptions` (0.8.1). Each has a default implementation,
  so an existing adapter compiles unchanged; all but
  `verify_webhook_request` answer `PaymentsError::Unsupported`, and it
  reads the `stripe-signature` header and delegates to `verify_webhook`.
  An adapter that implements any of them now has to handle
  `PaymentsError::Unsupported` from its own `match` on the enum (see the
  0.7 note on that variant).
- [ ] **`DisputeStatus` and `SubscriptionStatus` are new
  `#[non_exhaustive]` enums** and `Dispute`, `DisputePhase`,
  `DisputeListRequest`, `DisputePage`, `Subscription` are new types.
  Nothing to fix unless you read them.

### Pending, unreleased

`Port::Actor`, `Ports::actors`, `Module::actor_kinds` and
`Module::max_blob_object_bytes` are merged but past the last published
release, so they carry into the next core minor (issue
[#583](https://github.com/Cratefield/harness/issues/583)). `Port` and
`Ports` are exhaustive: expect one more variant and one more field. No
action yet.

---

## Upgrading to 0.7 (from 0.6)

- [ ] **`Problem::type_uri` takes the venture's base.**
  `type_uri(&self) -> String` became `type_uri(&self, base: &str) ->
  String`. Take the base from `Venture::problem_type_base()` — the
  venture's explicit `Venture::problem_base` override, else
  `<public_url>/problems/`, else `about:blank` — rather than writing a
  domain into an assertion:

  ```rust
  let venture = Venture::new("acme", "acme.test").public_url("https://api.example.test");
  let problem = Problem::not_found();
  assert_eq!(
      problem.type_uri(&venture.problem_type_base()),
      "https://api.example.test/problems/not-found",
  );
  ```

  Any assertion that read `https://factory0.ventures/problems/<slug>` is
  now wrong twice over: the base is the serving venture's, and matching
  the full URI at all is the mistake. **Match on the slug** — the part
  after `/problems/`, an `auth/…` namespace included — never on the URI.
  The slug list itself moved in this minor too (see `allowance_exhausted`
  below); [ERRORS.md](ERRORS.md) is the current list.
- [ ] **`Problem::into_response` renders the context-free `about:blank`
  `type`.** A test that asserted a URI out of a bare `into_response` now
  sees `about:blank`; the harness's outermost layer re-renders the body
  under the venture's base. Where a runtime serves a problem from
  *outside* that layer — a native `421`, a Worker `413`, an
  unresolved-limiter `503` — use the new
  `Problem::into_response_with_base(base)`.
- [ ] **`Port` gained `VectorIndex`, `Embedder` and `CustomHostnames`.**
  `Port` is exhaustive, so a `match` over it stops compiling. Add the
  three arms, or a wildcard.
- [ ] **`Ports` gained `vector_index`, `embedder` and
  `custom_hostnames`.** All three are `Option`, and `Ports` is not
  `#[non_exhaustive]`, so a struct literal needs all three fields. A
  `Ports` built by the runtime resolves them itself; only a hand-built
  test context needs the fields.
- [ ] **`tracker::Destination` gained `Freshdesk { domain }` and
  `Colonizer { repo }`.** `Destination` is exhaustive: a `match` over it
  needs the two new arms. `RoutingTracker` grew `freshdesk` and
  `colonizer` to wire them.
- [ ] **`surface::Action` gained `verification`** — the
  `Option<SignatureVerification>` a single route uses to override the
  module-level default. Not serialized, so the surface document's wire
  shape is unchanged; set it with the `.verification(v)` builder, or add
  the field to a struct literal (`None` is the default).
- [ ] **`WriteGuards` gained `rate_limiter_modules` and
  `signature_routes`.** Both are `pub` fields on a struct core builds
  from a module's surface (`WriteGuards::collect`), so a hand-built
  `WriteGuards` literal needs them. `signature_routes` is
  `Vec<(String, String, SignatureVerification)>` — module, mounted
  route, verifier — and adds a per-route view of which verifier a
  module used.
- [ ] **`problems::Slugs` gained `allowance_exhausted`.** `Slugs` is a
  struct of `pub` fields with a const `SLUGS`; a module that builds its
  own slug table from a literal needs the field.
- [ ] **`Venture` gained `problem_base: Option<String>`.** `Venture` is
  not `#[non_exhaustive]` and every field is `pub`, so a venture that
  builds one from a literal needs `problem_base: None`. `Venture::new`
  followed by the builders fills it.
- [ ] **`PaymentsError` gained `Unsupported(&'static str)`.** The enum is
  exhaustive, so a `match` over it needs the new arm. It is what every
  defaulted `Payments` method returns, so an adapter that forwards a
  default result has to handle it rather than let it reach a handler
  that only knows `NotConfigured`.
- [ ] **New defaulted trait methods, nothing to implement:**
  `Tracker::comment` (refuses with `TrackerError::Rejected` naming the
  tracker by default), `Payments::report_usage` (answers
  `PaymentsError::Unsupported`), `Module::streaming_routes`, and the new
  `StatusWebhook` trait served by the `receive_status` function. Existing
  adapters compile unchanged.

---

## Upgrading to 0.6 (from 0.5)

- [ ] **`rate_limiter::Decision` gained `quota: Option<Quota>`.** The
  struct is not `#[non_exhaustive]` and has no constructor, so every
  `Decision` literal — in a fake limiter, a test double, an adapter —
  needs `quota: None`. `None` means "this limiter cannot know its
  budget", which is true of the Cloudflare Rate Limiting binding and of
  a sliding window with no count. `Quota` itself (`limit`, `remaining`,
  `reset`) is new and public.
- [ ] **`rate_limited` takes the decision, not the pause.** The exported
  helper went from `rate_limited(Option<Duration>)` to
  `rate_limited(&Decision)`, so it can put the `RateLimit-*` headers on
  the response. A caller that had a `Duration` in hand now passes the
  `Decision` it came from.
- [ ] **`ModuleContext` gained `scheduled: Arc<ScheduledBudget>`.** Every
  hand-built context needs the field. Outside a scheduled invocation the
  budget is unbounded, which is exactly what the core itself builds:

  ```rust
  ModuleContext {
      // …the fields you already had…
      scheduled: Arc::new(ScheduledBudget::unbounded()),
  }
  ```

  Prefer `Harness::module_context(module, &ports)` over a literal where
  you can — it fills the field, and the fields it fills are the ones
  that cannot be guessed.
- [ ] **`Port` gained `Auth`, `TextModel`, `Tracker` and `Classifier`.**
  Exhaustive: a `match` over `Port` needs four more arms.
- [ ] **`Ports` gained `auth`, `tracker`, `text_model` and
  `classifier`.** All `Option`; a literal needs all four.
- [ ] **`Action` gained `output: Option<Schema>`** — the JSON Schema of
  the body a `Json`-outcome action answers with. `Surface::validate`
  now refuses an output schema that is not an object, or an output on an
  action whose outcome is not `Json`, so a surface that previously
  validated may not. The builders `.output::<T>()` and
  `.output_schema(schema)` are the way to set it.
- [ ] **`Audience` gained `Subject`** — "a credential is needed, and the
  route decides which rows the caller sees". Exhaustive: a `match` over
  `Audience` needs the arm, and it is exempt from the "under `/admin/`"
  rule in `Surface::validate` alongside `Public` and `Link`.
- [ ] **`RoutePolicy` gained `ApiKey`** — a route gated by a
  developer API key rather than a captcha, a signature or a signed link.
  Exhaustive: a `match` over `RoutePolicy` needs the arm.
- [ ] **`WriteGuards` gained `payments_signature_modules`,
  `hmac_signature_modules`, `has_public_writes` and
  `has_admin_routes`.** A `Signature`-guarded write no longer has
  one list of modules; it has the modules that verify through the
  `Payments` port and the modules that verify through a core
  `webhook_signature` scheme keyed by a module-scoped config secret.
  The two booleans answer whether the composition exposes any public
  write at all and whether it has an admin plane.
- [ ] **`problems::Slugs` gained `unauthenticated`,
  `api_key_unauthorized` and `api_key_forbidden`**, and `Slugs` itself
  became an exported type. A module matching on 401s now sees two slugs
  where it saw none, and a 403 (`api_key_forbidden`) beside them.
- [ ] **New defaulted `Module` methods:** `signature_verification` (which
  verifier proves a `Signature` route) and `max_body_bytes`. Neither
  needs implementing.
- [ ] **The `TextModel` port is new in this minor** (`ModelTier`,
  `Prompt`, `Turn`, `Completion`, `TextModelError`, `RoutingTextModel`).
  Nothing to migrate, but a module that called a vendor SDK directly now
  has a port to declare in `requires()`/`optional()` instead.