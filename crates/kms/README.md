<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
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

Managed providers (AWS KMS, Google Cloud KMS) are not implemented yet: they
need credentials and a nightly job against the real service, and an
unexercised vendor integration in this position is worse than an absent one.
