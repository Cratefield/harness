# cratefield-oauth-client

OAuth 2.0 for the harness (issue #531): the authorize URL, the code
exchange, the refresh and the revocation, spoken once over the harness's
[`HttpClient`](https://docs.rs/cratefield-core) port — so a module runs it
unchanged on Workers and native. No provider SDK, no discovery document:
the provider's three URLs are configuration.

- **`ProviderConfig`** names the endpoints, the client credentials, the
  scopes, and where the credentials go on token calls (form body, or HTTP
  Basic per RFC 6749 §2.3.1).
- **`OAuthClient`** speaks the token endpoint: authorization-code exchange
  (with PKCE, RFC 7636, when the provider supports it), refresh, and
  RFC 7009 revocation. Failures come back as `OAuthError`, which carries
  the RFC 6749 §5.2 `error` / `error_description` pair *and* the raw body,
  because providers put provider-specific meaning in that prose.
- **`TokenSealer`** is how a caller stores what came back. The trait is the
  future seam for the secrets store; `XChaChaSealer` is the implementation
  the harness already chose (ADR 0102): XChaCha20-Poly1305, a fresh nonce
  per encryption, the ciphertext bound to its row and column.
- **`send_with_refresh`** is the whole 401 policy: one refresh, one replay,
  never a loop.
- **`device`** speaks RFC 8628 device authorization: `request_code` gets a
  `user_code` the human types at the verification URI, and `poll` waits out
  the interval (honouring `slow_down`) until the venture issues its
  credential. The credential is the venture's own contract, so `poll`
  returns the raw JSON — `poll_as::<T>` when the caller has a type.

```ignore
let client = OAuthClient::new(http, &config);
let tokens = client.exchange_code(&code, &redirect_uri, None).await?;
let kept = tokens.rotated_refresh_token(&previous_refresh_token);
```

Device authorization (RFC 8628), for the client that has no browser — a CLI
or a screen. The human approves on another device; the poll runs on `clock`,
so it obeys the server's interval without a timer of its own:

```ignore
let auth = request_code(http, "https://api.example.com/v1/device-auth/code",
                       "client-1", Some("read"), Some("My CLI")).await?;
println!("Go to {} and enter {}", auth.verification_uri, auth.user_code);
let credential: Credential = poll_as(http, clock, "https://api.example.com/v1/device-auth/token",
                                     "client-1", &auth).await?;
```

wasm-safe: randomness comes from `getrandom` (wasm backend enabled on
wasm32), time stays in the caller, HTTP goes through the port.
