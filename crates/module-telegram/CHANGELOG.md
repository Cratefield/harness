# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- First release, 0.1.0: Telegram in a venture, mounted at `/v1/telegram`. It verifies the secret-token webhook, links Telegram accounts with one-time codes, and sends consent buttons that can deny anything and approve anything harmless, but only arm a value-moving action until the owner confirms it with a passkey. With the `notifications` feature it is also a `module-notifications` channel ([#764](https://github.com/Cratefield/harness/issues/764)).
