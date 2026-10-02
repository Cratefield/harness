<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-cloudflare-saas"><img src="https://img.shields.io/crates/v/cratefield-adapter-cloudflare-saas.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-cloudflare-saas on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-cloudflare-saas"><img src="https://img.shields.io/docsrs/cratefield-adapter-cloudflare-saas?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-cloudflare-saas documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-cloudflare-saas

[`CustomHostnames`] port over [Cloudflare for `SaaS`](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/)
custom hostnames (issue #590) for the Cratefield harness. Uses the runtime's
[`HttpClient`] port — no `reqwest`, no vendor SDK — so it runs unchanged on
Workers (`worker::Fetch`) and natively, and inherits that port's destination
vetting, deadline and response-size caps.

A venture serving `share.acme.com` registers the claim here, shows the
customer the `TXT`/`CNAME` record to publish, and reads the claim back until
the hostname and its certificate are both live. The venture holds
`Arc<dyn CustomHostnames>` and never learns the provider is Cloudflare; see
[docs/CUSTOM-HOSTNAMES.md](https://github.com/Cratefield/harness/blob/main/docs/CUSTOM-HOSTNAMES.md)
for the flow and the dashboard's domains screen.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_cloudflare_saas::{CloudflareSaas, CloudflareSaasConfig};
use cratefield_core::{CustomHostnames, HostnameClaim, ValidationMethod};
use cratefield_runtime_cloudflare::FetchClient;

// A scoped API token: "SSL and Certificates: Edit" on this one zone only.
let hostnames = CloudflareSaas::new(
    Arc::new(FetchClient),
    CloudflareSaasConfig {
        zone_id: zone_id,
        zone_name: "cratefield.app".to_owned(),
        api_token: token,
        // The record the customer points their CNAME at, shown until live.
        cname_target: Some("origin.cratefield.app".to_owned()),
    },
);

let claim = HostnameClaim::new("share.acme.com").with_method(ValidationMethod::Txt);
let created = hostnames.create(&claim).await?;
for record in &created.validation {
    println!("{} {}", record.record_type.as_str(), record.name);
}
// Without a zone or token (degraded mode): every call answers
// CustomHostnameError::NotConfigured, with no network call.
let degraded = CloudflareSaas::not_configured(Arc::new(FetchClient));
```

`CloudflareSaas::from_env(http)` reads `CF_SAAS_ZONE_ID`,
`CF_SAAS_ZONE_NAME` and `CF_SAAS_API_TOKEN` (all required and non-empty)
and the optional `CF_SAAS_CNAME_TARGET` from the process environment
(native/self-hosted); any missing required value yields the
`not_configured` adapter. On Workers, read the secrets from the venture's
`Env` — the token is a Worker secret — and call `CloudflareSaas::new`
(`std::env` has no Workers vars).

## The API token scope

Create a Cloudflare API token scoped to the single zone that serves the
custom hostnames, with the zone permission **SSL and Certificates: Edit**
(and nothing else). Cloudflare for `SaaS` will not issue a certificate for
a hostname claimed with a token that lacks it, and a token scoped to one
zone cannot touch any other account or zone if it leaks. The adapter sends
`Authorization: Bearer <token>` on every request and never logs or formats
the token — its `Debug` prints `api_token: "[redacted]"`.

## Behaviour and error mapping

Every hostname argument passes [`check_hostname`] against the configured
zone **before** any request: an apex, an IP literal, a wildcard, a
malformed name, or a name inside the deployment's own zone is a
[`CustomHostnameError::Refused`] with no request sent. With no configuration
the adapter answers [`CustomHostnameError::NotConfigured`] first, also with
no request.

| Condition | Error |
|---|---|
| HTTP 409 or provider code 1406 | `AlreadyExists` |
| HTTP 404 or provider code 1436 | `NotFound` |
| HTTP 401/403, code 1403, codes 1000–1005, 10000, 9109 | `Unauthorized` |
| HTTP 403 with quota code 1404/1405 | `Rejected` |
| HTTP 429 | `RateLimited` |
| Other 4xx | `Rejected` |
| 5xx, an unparseable success body, `success: false` | `Provider` |
| Any `HttpClient` failure: socket, DNS, deadline, or a response over the cap | `Transport` |

`delete` is idempotent: it looks the hostname up by id first, and a
hostname that is not there — or a 404 on the `DELETE` itself — is `Ok(())`.
`refresh` re-runs domain control validation with the same method and
certificate type the hostname was created with and returns the fresh state;
a hostname that is not there is `NotFound`.

The adapter attaches no `HttpPolicy` extension: every response is bounded by
the `HttpClient` port's default policy (the 4 MiB body cap and 10 s
deadline `BoundedHttpClient` enforces), which is ample for a single
custom-hostname object or a page of them.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
