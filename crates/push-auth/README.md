<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-push-auth

Provider-token signing for the harness's push adapters (issue #178). Three
adapters, one signer, one cache:

| Who | Construction |
|---|---|
| APNs | ES256 JWT, `iss` = team id, `kid` = key id, reused ≤ 60 min |
| VAPID (RFC 8292) | the *same* ES256 JWT with `aud` = the push-service origin, `sub` = a `mailto:`, plus the public key on the wire as `k=` |
| Google (FCM v1) | RS256 JWT from the service-account key, exchanged for a bearer token |

Pure Rust, `forbid(unsafe_code)`, and it builds for `wasm32-unknown-unknown`:
no `jsonwebtoken`, no `ring`, no OpenSSL. Signing is deterministic
(RFC 6979 for ES256, PKCS#1 v1.5 for RS256), so nothing here needs an RNG on
a Workers isolate. That is portability, not hardening: RSA signing without an
RNG is *unblinded*, and it is safe here only because there is no decryption
oracle, the claims are ours rather than an attacker's, and the token is minted
off the request path where its timing cannot be observed (see the
RUSTSEC-2023-0071 acceptance in `deny.toml`).

## Usage

```rust,ignore
use std::time::Duration;
use cratefield_push_auth::{CachedToken, Es256Signer};
use serde_json::json;

let signer = Es256Signer::from_p8_pem(&key_p8_pem)?;

// One provider token, reused for its TTL; `invalidate` forces a re-mint
// when the provider says the token expired.
let cache: CachedToken<()> = CachedToken::new(Duration::from_secs(3_000));
let jwt = cache.get_or_mint(clock.as_ref(), &(), |now| {
    signer.sign_jwt(
        &json!({ "alg": "ES256", "kid": key_id }),
        &json!({ "iss": team_id, "iat": now }),
    )
});
```

VAPID caches per push-service **origin**, because `aud` differs per browser
vendor — that is what the key parameter is for:

```rust,ignore
let cache: CachedToken<String> = CachedToken::new(Duration::from_secs(12 * 3_600));
let origin = "https://fcm.googleapis.com".to_owned();
let jwt = cache.get_or_mint(clock.as_ref(), &origin, |now| {
    signer.sign_jwt(
        &json!({ "alg": "ES256", "typ": "JWT" }),
        &json!({ "aud": origin, "sub": "mailto:ops@example.test", "exp": now + 12 * 3_600 }),
    )
});
let k = base64url(signer.public_key_uncompressed()); // the VAPID `k=` parameter
```

Google's bearer token is not minted, it is **exchanged** over HTTP, and no
lock may be held across an `await` — so the same cache splits into a read and
a write:

```rust,ignore
if let Some(token) = cache.cached(clock.as_ref(), &()) { return Ok(token); }
let (token, expires_in) = exchange_the_signed_assertion().await?;
// Reused for what the provider stated less a safety margin, capped by the
// cache's own TTL. `saturating_sub`, not `-`: `Duration` subtraction panics
// on underflow, so a provider that states a lifetime shorter than the margin
// (`expires_in: 60`) would take the send down instead of simply not caching.
// Do the same arithmetic inside a `get_or_mint` closure and it is worse
// still — that closure runs while the cache's mutex is held, so the panic
// poisons it and every later call panics too.
cache.store(clock.as_ref(), &(), &token, expires_in.saturating_sub(Duration::from_secs(300)));
```

Two sends racing a cold cache then cost one extra exchange, which Google is
happy to serve — `get_or_mint` stays the right call wherever minting is local,
because Apple is not.

## What it does not do

Verification — that is the auth service's job — and key rotation UX, which
belongs to the secrets layer.
