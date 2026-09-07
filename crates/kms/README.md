# factory0-kms

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
