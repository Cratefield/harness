<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-kms.png" alt="cratefield-kms — Wrap and unwrap." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-kms"><img src="https://img.shields.io/crates/v/cratefield-kms.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-kms on crates.io"></a>
  <a href="https://docs.rs/cratefield-kms"><img src="https://img.shields.io/docsrs/cratefield-kms?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-kms documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-kms

The KMS port (issue #40, ADR 0102, `docs/SECRETS-DESIGN.md`). Wrapping and
unwrapping a data key is the only thing the KMS does for the harness, so it
is the only thing this trait can ask; the cipher that seals a secret, the
data that binds a ciphertext to its row, and where the wrapped key is
stored all belong elsewhere.

`LocalFileKms` is the development provider. It uses the same real AEAD, but
its master key sits on a local disk where anything that can read the file
can read the key, so it **refuses to construct when the environment is
production**.

`WorkerSecretKms` (issue #535, ADR 0103) is the production provider for the
Cloudflare path. Its KEK is a versioned set of Worker secrets —
`HARNESS_KEK_CURRENT` names the version that wraps, `HARNESS_KEK_V1`,
`HARNESS_KEK_V2`, … hold the material — read once at construction, and
unwrap dispatches on the version header in the blob, so rotation is put
the next version, point, redeploy, re-wrap, delete (`docs/KEY-ROTATION.md`).
It does not refuse production: the KEK lives in the platform's secret
store, never on a host disk. It is not an HSM KMS and is not claimed as one.

Managed providers (AWS KMS, Google Cloud KMS) are not implemented yet: they
need credentials and a nightly job against the real service, and an
unexercised vendor integration in this position is worse than an absent one.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
