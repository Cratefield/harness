<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-auth-client.png" alt="cratefield-auth-client — Who the caller is." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-auth-client"><img src="https://img.shields.io/crates/v/cratefield-auth-client.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-auth-client on crates.io"></a>
  <a href="https://docs.rs/cratefield-auth-client"><img src="https://img.shields.io/docsrs/cratefield-auth-client?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-auth-client documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-auth-client

Verify auth-service tokens in a consuming app: JWKS fetch and cache,
ES256 verification with the audience check that hand-rolled verifiers
forget, and an axum extractor. Issue #11.

## Freshness and roles (issue #912)

Verification proves who signed a token and that it was minted for this
client. It does not prove that the person just proved who they are. A
relying party that is about to approve something (a payment, an offer, a
change of ownership) must check that itself:

```ignore
if !claims.authenticated_within(300, now) {
    // ask the person to sign in again, with prompt=login
}
```

`auth_time` is epoch seconds of the person's last real sign-in ceremony. A
refresh never moves it, so a long-lived session does not look fresh. `roles`
lists the account's roles in the issuing instance (`owner`, `admin`,
`member`) when the client was registered to receive them, and is empty
otherwise. Only access tokens verify here: a token whose `typ` is not
`at+jwt` (an ID token, for one) is refused.

---

MIT. Part of the [Cratefield harness](https://github.com/Cratefield/harness).
