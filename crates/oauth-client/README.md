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

```ignore
let client = OAuthClient::new(http, &config);
let tokens = client.exchange_code(&code, &redirect_uri, None).await?;
let kept = tokens.rotated_refresh_token(&previous_refresh_token);
```

wasm-safe: randomness comes from `getrandom` (wasm backend enabled on
wasm32), time stays in the caller, HTTP goes through the port.
