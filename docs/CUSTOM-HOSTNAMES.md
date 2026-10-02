# Custom hostnames

Issue #590. A venture serves its own customers on **their** hostname:
`share.acme.com` is `CNAMEd` at the venture, Cloudflare answers TLS for
it, and the module that owns the domain never learns the request went out
through a vendor. The port is `cratefield_core::CustomHostnames`
(`Port::CustomHostnames`), the adapter
`cratefield-adapter-cloudflare-saas`, the port's code in
`crates/core/src/ports/custom_hostnames.rs`, and the test fake in
`crates/testing/src/fakes.rs`.

## 1. What it is

The venture holds an `Arc<dyn CustomHostnames>` and calls four methods —
`create(&HostnameClaim)`, `get(hostname)` (returning `Ok(None)` when the
provider has no such name), `delete(hostname)` (idempotent), and
`refresh(hostname)` (re-run DCV now).

`CustomHostname` carries `status` and `certificate` separately, because a
name can be validated before its certificate is issued. `is_live()` is both
`Active`. `validation` is the DNS records the customer must publish — a
`TXT` pre-validation record or the `CNAME` to cut over — each with a
`record_type`, `name` and `value`. `HostnameClaim::new("share.acme.com")`
validates over HTTP by default; `.with_method(ValidationMethod::Txt)` asks
for `TXT` DCV; the module never names Cloudflare.

**Refusal happens before any provider call.** `check_hostname(hostname,
own_zone)` normalises the name (trimmed, lowercased, one trailing root dot
stripped) and refuses, in order: empty, over 253 characters, a wildcard, an
address literal, malformed labels, a name inside the deployment's own zone
or its subdomains, and finally an apex (two labels, no third). The refusal
is a **recorded failure** (`CustomHostnameError::Refused(HostnameRefusal)`),
not a pending state, and never reaches the provider. The apex check counts
labels and holds no public-suffix list, so `acme.co.uk` is not caught here.

Out of scope, named so the boundary reads as a decision: **apex hostnames**
(`acme.com`), since the flow hands the customer a `CNAME` an apex cannot
carry and Cloudflare's apex paths need a proxying entitlement and `A`
records; **routing a request to a tenant by its hostname** — this port only
registers a name and reports its state (see
[TENANT-ROUTING.md](TENANT-ROUTING.md)); and **certificate renewal** —
Cloudflare renews on its own, and `refresh` only re-runs DCV.

## 2. Operator setup, once per zone

Every step here is **Human** (Cloudflare dashboard or an authenticated
call) and carries `needs-human` in the issue tracker: the harness deploys
the code, but the entitlement, the records and the token are the
operator's. Once per zone, not per customer.

1. **Enable Cloudflare for SaaS on the zone** (dashboard: SSL/TLS → Custom
   Hostnames). Names outside the zone cannot be claimed until this is on,
   and it is a paid entitlement
   ([control-plane/PRICING.md](control-plane/PRICING.md)).

2. **Create the fallback origin** — the origin every custom hostname falls
   through to when no route terminates it. Make a proxied DNS record in the
   zone (`fallback.<zone>` `AAAA 100::`, the discard address, or the Worker
   route), then set it with
   `PUT /zones/{zone_id}/custom_hostnames/fallback_origin`, body
   `{"origin": "fallback.<zone>"}`, and wait for it to read `active`.
   Optionally publish a friendly target `customers.<zone>` as a proxied
   `CNAME` to the fallback, so the customer's record reads as a product
   name. **The Worker route must also match custom hostnames** — a `*/*`
   route on the zone is the usual shape; widen its `wrangler.toml` routes,
   since a custom hostname is not one of the venture's own routes.

3. **Create a scoped API token and set the variables.** Zone → *SSL and
   Certificates: Edit*, Zone Resources → include **only** that zone — an
   account-wide token can mint certificates for any account zone. Store it
   as a Worker secret with `wrangler secret put CF_SAAS_API_TOKEN`, set
   `CF_SAAS_ZONE_ID` and `CF_SAAS_ZONE_NAME` as vars, and
   `CF_SAAS_CNAME_TARGET` (`customers.<zone>`) if the friendly target
   exists. The token is scrubbed from logs by field name, not by value:
   `cratefield_core::logging::is_secret_field` matches `token`, so a field
   named `api_token` renders `[redacted]` (issue #235).

## 3. Wiring the adapter

The adapter is portable over the `HttpClient` port, so the wiring is the
same on either runtime: on Workers the values come from `Env` (the token is
a Worker secret, the ids are vars); on native `from_env` reads `std::env`.

```rust
// Workers: the http handle is an `Arc<dyn HttpClient>` over the runtime's
// FetchClient, as `examples/venture` builds one for Resend. The values come
// from the Worker's `Env` — the token is a secret, the ids are vars — read
// through the runtime's `EnvConfig`. `CloudflareSaas::from_env` reads the
// process environment and so is for native, not Workers.
use cratefield::Config;
use cratefield::cloudflare::{Cloudflare, EnvConfig, FetchClient};
use cratefield::cloudflare_saas::{
    API_TOKEN_VAR, CNAME_TARGET_VAR, CloudflareSaas, CloudflareSaasConfig, ZONE_ID_VAR,
    ZONE_NAME_VAR,
};

let http: std::sync::Arc<dyn cratefield::HttpClient> = std::sync::Arc::new(FetchClient);
let vars = EnvConfig(env);
let config = CloudflareSaasConfig::from_vars(
    vars.get(ZONE_ID_VAR),
    vars.get(ZONE_NAME_VAR),
    vars.get(API_TOKEN_VAR),
    vars.get(CNAME_TARGET_VAR),
);
let saas = match config {
    Some(config) => CloudflareSaas::new(http, config),
    None => CloudflareSaas::not_configured(http),
};
let runtime = Cloudflare::new().db("DB").custom_hostnames(saas);
```

On native, build the handle the way `examples/venture-native` does for
Resend — `Arc::new(ReqwestClient::new())` as an `Arc<dyn HttpClient>` — and
pass it to `CloudflareSaas::new(http, CloudflareSaasConfig { zone_id,
zone_name, api_token, cname_target })`, then `.custom_hostnames(saas)` on
`Native::new()`. The facade feature is `cloudflare-saas`.

**Missing configuration is not a crash.** Without all three of
`CF_SAAS_ZONE_ID`, `CF_SAAS_ZONE_NAME` and `CF_SAAS_API_TOKEN`, the adapter
answers `NotConfigured` to every call and makes no request, so a venture
can still mount modules that treat custom hostnames as optional. A module
declares the port like any other:

```rust
fn requires(&self) -> &'static [Port] {
    &[Port::Db, Port::CustomHostnames]
}
```

## 4. What a customer does

One record to start, once their name is claimed:

```
share.acme.com.   CNAME   customers.<zone>.
```

With HTTP DCV — the default — that is the whole customer step, but it works
**only once the CNAME resolves to Cloudflare**, because the provider
fetches a token from the name. A customer who wants TLS ready *before*
moving traffic, or who is behind another proxy or a CAA record that forbids
the issuer, should ask for `TXT` validation
(`.with_method(ValidationMethod::Txt)`); the claim's `validation` list then
carries `_cf-custom-hostname.<host>` (ownership, published first) and
`_acme-challenge.<host>` (DCV). Show the `name` and `value` exactly as
returned. Call `delete` when the customer removes the domain; it is
idempotent.

## 5. How a module reacts to status

`get` and `refresh` return the pair `(status, certificate)`, and the module
turns it into something a customer can act on — every combination maps:

| status | certificate | What the module shows / does |
|---|---|---|
| `Pending` | `Pending` | Show each `validation` record to publish. Poll with `get`. |
| `Pending` | `Pending` (records added) | `refresh` once to re-run DCV — not in a tight loop; Cloudflare backs off, and hammering earns `RateLimited`. |
| `Active` | `Pending` | "Issuing certificate." Validated, not yet serving; keep polling. |
| `Active` | `Active` | `is_live()`: serve. The name works over TLS. |
| `Failed { reason }` (either field) | | Record the failure and show the provider's `reason`; it is scrubbed in `Display`, so it is safe to render. |
| `Refused` / `Unauthorized` / `Rejected` / `NotConfigured` | | A **recorded failure**, not a pending state. Show it as a stop; do not retry blindly. |

Two shape notes: **`AlreadyExists` on `create` is success on an
ensure-shaped retry** — the claim is already there, so map it to success
and read the current state, as the control-plane dashboard does; and
**`delete`**, how a customer removes a domain, is idempotent.

The in-repo consumer is the control-plane dashboard's domains screen
(`crates/control-plane-dashboard/src/domains.rs`): it records the claim,
shows the record and advances it on check, but its default `Unwired`
adapter answers `CustomHostnameError::NotConfigured` to every call, so
today it records a failure instead of pretending the hostname is live.
Wiring a real `CloudflareSaas` turns those recorded failures into retries
through the same code path.

## 6. Testing

`cratefield_testing::FakeCustomHostnames::new(own_zone)` is in-memory and
records every call. It runs `check_hostname` first, exactly as a real
adapter must, so a test can drive the `Refused` arm without a provider.
`activate` walks a claim to `Active`/`Active`, `fail` records a provider
reason, `refuse_next` scripts the next call's error, `calls()` is the
assertion that a refusal never reached the provider, and the fake's own
behaviour is pinned by `crates/testing/tests/custom_hostnames.rs`.

```rust
let api = FakeCustomHostnames::new("cratefield.app");
let claim = api.create(&HostnameClaim::new("Share.Acme.COM.")).await?;
assert_eq!(claim.status, ProviderStatus::Pending);
api.activate("share.acme.com");                       // pending -> live
assert!(api.refresh("share.acme.com").await?.is_live());
api.fail("share.acme.com", "CAA forbids issuance");
api.refuse_next(CustomHostnameError::RateLimited);
assert_eq!(api.calls(), vec!["create Share.Acme.COM.", "refresh share.acme.com"]);
```
