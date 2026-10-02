# cratefield-module-device-auth

The OAuth 2.0 **device authorization grant** (RFC 8628) for a Cratefield
venture: the flow for a client that has no browser and no keyboard — a
CLI, a TV app, an appliance. It shows a short code, a signed-in person
approves it in a browser, and the venture mints the credential.

Most OAuth flows hand the browser a redirect. This one hands the client a
pair of codes and a URL, because there is no browser to redirect:

1. The client posts to `/v1/device-auth/code` and gets back a
   `device_code` (long, secret, for the client), a `user_code` (short, for
   the person) and the URL to visit.
2. The client shows the person the code and the URL, then starts polling
   `/v1/device-auth/token`.
3. The person opens the URL, signs in if they have not, types the code,
   and presses Approve.
4. The next poll that has waited out its interval is answered with the
   credential the venture's issuer minted.

## Composition

```rust
use cratefield_core::{RandomBytes, RandomError};
use cratefield_module_device_auth::{DeviceAuth, DeviceClient, IssueRequest, Issuer, IssuerError};

// The two hooks a venture supplies: what a credential is, and where the
// entropy for the codes comes from. `docs/DEVICE-AUTH.md` works the first
// one through `ApiKeys`.
struct SealbKeys;
#[async_trait::async_trait]
impl Issuer for SealbKeys {
    async fn issue(&self, request: IssueRequest) -> Result<serde_json::Value, IssuerError> {
        // In a venture this calls the key-minting you already have.
        Ok(serde_json::json!({ "api_key": "sealb_live_…", "subject": request.subject }))
    }
}
struct OsEntropy;
impl RandomBytes for OsEntropy {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        // In a venture this is the platform CSPRNG (e.g. `getrandom`).
        for byte in dest.iter_mut() {
            *byte = 0x2a;
        }
        Ok(())
    }
}

let module = DeviceAuth::builder()
    .client(DeviceClient::new("sealb-cli").scopes(["read", "write"]))
    .issuer(SealbKeys)
    .random(OsEntropy)
    .sign_in_url("/login")           // where CallerApprover sends anonymous visitors
    .expires_in(time::Duration::seconds(600))
    .interval(time::Duration::seconds(5))
    .max_wrong_entries(5)
    .build();
```

`.approver(..)` overrides the approver. Left unset, the module uses
`CallerApprover`, which reads the `Auth` port's caller and sends an
anonymous browser to the sign-in URL with `return_to` appended, so the
person comes straight back to the code.

`self_check` refuses a composition that cannot work: no clients, no
issuer, no entropy source, or a client whose id or scopes are malformed.

## The two hooks

- **`Approver`** answers *who is asking to approve*. `CallerApprover` is
  the stock one over the `Auth` port; a venture with its own session
  scheme implements the trait directly.
- **`Issuer`** answers *what credential does this client get*. It is
  called **exactly once** per approved request and returns the JSON body
  the client receives. `docs/DEVICE-AUTH.md` shows an issuer built on
  `ApiKeys::issue`.

## The endpoints

| Route | Who calls it | What it answers |
|---|---|---|
| `POST /v1/device-auth/code` | the client | the code pair and the verification URL |
| `POST /v1/device-auth/token` | the client | the credential, or an OAuth error while pending |
| `GET /v1/device-auth` | the browser | the code form, or the Approve/Deny page |
| `POST /v1/device-auth/approve` | the browser | an approval page |
| `POST /v1/device-auth/deny` | the browser | a denial page |

The two machine routes take their parameters as a JSON body or an
`application/x-www-form-urlencoded` form, and answer RFC 6749 §5.2 errors
(`{"error": ..., "error_description": ...}`) with a 400. `slow_down` and
`authorization_pending` are normal parts of the flow, not failures.

## Storage

One table, `device_auth_codes`, in the venture's own database. Both codes
are stored **only** as SHA-256 hashes — there is no clear-text column —
so a dump, a backup or a query log cannot be replayed as a code. The
migration is `crates/module-device-auth/migrations/sqlite/0001_init.sql`.

## The client side

`cratefield_oauth_client::device` is the client half: it runs the
request-code / poll / handle-`slow_down` loop for a binary that is
already using the OAuth client crate.

## Ports

| Port | How |
|---|---|
| `Database` | required — the codes, their state and their expiry live here |
| `RateLimiter` | required — the abuse control the public routes have (issue #562) |
| `Clock` | optional — what makes expiry and the poll interval deterministic |
| `Auth` | optional — what `CallerApprover` identifies callers with |

## Documentation

- `docs/DEVICE-AUTH.md` — the flow, the endpoints, the hooks, and the
  at-most-once credential rule.
