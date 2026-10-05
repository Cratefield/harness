# Enterprise SSO, per organization

An **SSO connection** is one organization's own OpenID Connect identity
provider: the issuer to send its people to, the client credentials to present
there, and the email domains that route a sign-in to it. A venture backend
creates a connection per customer organization; its people get the same
session and tokens as everyone else.

SSO is OpenID Connect only — SAML is not supported. One connection belongs to
one venture client, and one email domain routes to at most one **active**
connection of that client.

## Deployer setup

SSO needs one key, because a connection's OIDC client secret is sealed at
rest and never stored in the clear:

```sh
openssl rand -base64 32            # AUTH_CORE_SSO_TOKEN_KEY: 32 bytes, base64
```

Set it as a **secret** (never in `wrangler.toml`) on every deployment where a
connection will be created; standard or URL-safe base64 works. The optional
`AUTH_CORE_SSO_TOKEN_KEY_ID` (a small integer, default `1`) is the key id a
sealed secret carries, so it exists for rotating the key: keep the old id
resolvable until every connection is re-sealed. With neither set — or a key
that is not 32 bytes — creating a connection or rotating its secret answers
`503 auth/sso-unconfigured`, and a sign-in cannot open the secret (admin reads
still work). See [DEPLOYING.md](DEPLOYING.md) for the rest of the variables.

## Creating a connection

The admin API takes **HTTP Basic**, with the venture's own client id and
secret — the same credentials `/token` checks, and the same Argon2id path. A
public client has no secret and can never authenticate here. The party who may
register an app is the party who may point it at an `IdP`.

```sh
curl -fsS https://auth.example.com/v1/auth-core/sso/connections \
  -u 'client_abc:client_secret_placeholder' \
  -H 'content-type: application/json' \
  -d '{"org_ref":"acme","issuer":"https://idp.acme.example",
       "oidc_client_id":"0oa-example","oidc_client_secret":"secret-from-the-idp",
       "domains":["acme.example"]}'
```

`201` returns the connection — never the secret:

```json
{"id":"ssoc_…","org_ref":"acme","issuer":"https://idp.acme.example",
 "oidc_client_id":"0oa-example","domains":["acme.example"],
 "status":"active","created_at":"…","updated_at":"…"}
```

- **List** — `GET /v1/auth-core/sso/connections`, optionally `?org_ref=acme`.
  Only the authenticated client's own connections are ever returned.
- **Read** — `GET /v1/auth-core/sso/connections/{id}`.
- **Disable** (or re-enable) — `PATCH` `{ "status": "disabled" | "active" }`.
  A disabled connection signs nobody in, and frees its domains for another
  connection.
- **Rotate the secret** — `PATCH` `{ "oidc_client_secret": "…" }`.
- **Replace the domains** — `PATCH` `{ "domains": ["acme.example","acme.co.uk"] }`
  (the whole set replaces the old one).

`org_ref`, `issuer` and `oidc_client_id` are fixed at create; delete or make a
new connection to change them. Another client's connection answers `404`, the
same as one that does not exist. Errors: `401 auth/sso-unauthorized` (with
`WWW-Authenticate: Basic`), `409 auth/sso-domain-claimed`, `503
auth/sso-unconfigured`; all are in [../ERRORS.md](../ERRORS.md).

## What the customer's IT admin configures

An **OIDC web application** in their provider, with this one redirect URI —
the same URL for every organization, whatever the venture:

```
https://auth.example.com/v1/auth-oidc/sso/callback
```

Ask for the authorization-code flow and the scopes `openid email profile`, then
collect back:

| Provider | Where |
|---|---|
| **Okta** | Applications → an OIDC **Web Application**; issuer is the org authorization server, `https://<org>.okta.com` |
| **Entra ID** | App registrations → Authentication → add a **Web** redirect URI → Certificates & secrets; issuer is `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| **Google Workspace** | Credentials → an **OAuth client ID**, type Web application; issuer is `https://accounts.google.com` |

1. **Issuer** — the exact `https` base URL, no trailing slash, pinned: the ID
   token's `iss` must equal it. Use the tenant-specific Entra issuer so one
   customer's directory cannot admit another's people.
2. **Client id** and **client secret** — into `oidc_client_id` and
   `oidc_client_secret`.
3. **Email domains** — the domains the organization owns, into `domains`.

The token-endpoint authentication method (`client_secret_basic` or
`client_secret_post`) is not a setting: it is read from the provider's
discovery document.

## How a sign-in is routed

Send people to `/authorize` as usual, plus one of:

- `connection=<id>` — sign in through that connection, **forced**: even a
  visitor with a live session from another method is sent to the `IdP` to
  become an SSO session. Only the client's own active connections route.
- `login_hint=<email>` — routes to the connection whose domain owns the
  address, but only when the visitor has **no** session yet. It is a hint: an
  unmatched domain falls through to the normal login chooser rather than
  refusing, and it can never reach another client's connection.

## What is refused

An SSO assertion is accepted only if all of these hold; otherwise the sign-in
is refused with the same generic page, and the reason is logged, never
returned:

- the connection is **active**, and so is the venture client that owns it;
- the ID token's `iss` equals the connection's issuer;
- `email_verified` is `true`;
- the address's domain is one of the connection's `domains`.

## Enforcing SSO in the venture

A token minted through a connection carries `sso_connection: "<id>"` (present
only while the connection belongs to the token's own client **and is still
active**) and `amr: ["sso"]`. `Claims::signed_in_via_sso` requires both, so a
token that names a connection without the `amr` does not count. Disabling a
connection drops the claim on the next refresh, so enforcement that keeps
sending the user to `/authorize?connection=…` finds it no longer routable and
gets refused. The gate looks like this:

```rust
use cratefield_auth_client::Claims;

/// Who the caller is — and, for an organization that mandates SSO, whether
/// they came in the way that organization requires.
fn gate(claims: &Claims, org: &Org, authorization_url: &str) -> Result<(), Redirect> {
    if org.requires_sso && !claims.signed_in_via_sso(&org.sso_connection_id) {
        // Send them through the organization's connection; on return the
        // code redeems to a token whose `sso_connection` is set.
        let url = format!(
            "{authorization_url}?response_type=code&client_id={client}\
             &redirect_uri={redirect}&code_challenge={challenge}\
             &code_challenge_method=S256&connection={connection}",
            connection = org.sso_connection_id,
        );
        return Err(Redirect::to(&url));
    }
    Ok(())
}
```

## Out of scope

SAML, SCIM provisioning, and per-organization session policies (idle and
absolute timeouts, device rules). A connection can be enabled or disabled, but
not given a policy of its own.
