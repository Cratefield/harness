# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- First release, 0.1.0: the `TelegramBot` port over the Telegram Bot API, through the `HttpClient` and `Clock` ports. It sends, edits and deletes messages and answers callback queries under global and per-chat rate budgets, parses typed inbound updates, and verifies the secret-token webhook. The bot token never rides a log line ([#764](https://github.com/Cratefield/harness/issues/764)).
