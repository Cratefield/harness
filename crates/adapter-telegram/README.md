<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-telegram"><img src="https://img.shields.io/crates/v/cratefield-adapter-telegram.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-telegram on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-telegram"><img src="https://img.shields.io/docsrs/cratefield-adapter-telegram?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-telegram documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-telegram

The `TelegramBot` port over the Telegram Bot API for the Cratefield harness
(issue #764): `sendMessage`, `editMessageText`, `deleteMessage` and
`answerCallbackQuery`, plus the typed inbound update and the
secret-token webhook — all through the runtime's `HttpClient` and `Clock`
ports. No vendor SDK, no `reqwest`, so the same adapter runs unchanged on
Cloudflare Workers and natively.

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_telegram::{HttpTelegramBot, InlineButton, OutgoingMessage};

let bot = HttpTelegramBot::new(Arc::new(fetch), Arc::new(clock), "123456:ABC-DEF…");
let sent = bot
    .send_message(
        OutgoingMessage::new(chat_id, "Deployment finished")
            .row(vec![InlineButton::callback("Acknowledge", "deploy:ack")?]),
    )
    .await?;
// sent.message_id — the id later edit_message and delete_message calls address.
```

## Local rate budgets, per instance

`HttpTelegramBot` keeps token buckets in a mutex inside the client: a
global one (30 calls/second), one per private chat (1/second) and one per
group (20/minute, for every `chat_id` below zero), all fed by the injected
`Clock` so tests move time by hand. When a bucket is empty the call is
refused with `TelegramError::RateLimited` **before any HTTP request is
sent**, so a chatty module cannot spend the bot's real budget. A `429`
from Telegram names a `retry_after`; the client records a not-before
deadline for that chat and refuses further sends there locally until it
passes.

The buckets are **per client instance** — in wasm terms, per isolate.
Telegram's budget is per bot across everything, so a deployment running
several isolates shares nothing: gate the fan-out through the runtime's
`RateLimiter` port instead, or accept that each isolate budgets its own
share.

## The bot token never rides an error

Telegram authenticates the bot by the URL path — `POST {base}/bot{token}/{method}`
— so the token sits in a place most HTTP clients happily quote in an error.
Every string this crate puts into a `TelegramError`, a `Display`, a `Debug`
or a log line is scrubbed of the token first, and the client's own `Debug`
prints a placeholder for it. Errors carry Telegram's `description` text,
never the request that produced it.

## The inbound half

`parse_update` reads one webhook delivery into a typed `Update`: messages,
`/command[@bot] args`, inline-keyboard callback queries and channel posts;
anything else (`edited_message`, shipping events, …) is `UpdateKind::Other`.
Entity offsets are UTF-16 code units, exactly as Telegram counts them, so a
link sliced out of a text that opens with an emoji lands on the right
characters.

`webhook::parse_verified` checks the `X-Telegram-Bot-Api-Secret-Token`
header against the secret **before** the body is parsed — verify first,
parse second, the same order every inbound crate here keeps. Telegram's
secret alphabet is 1–256 characters of `A-Z a-z 0-9 _ -`; `is_valid_secret`
mirrors it for configuration checks. A shared token proves the sender but
nothing stops a replay: claim each `update_id` through a dedup ledger
(`cratefield_core::Inbox`) before acting on it.

## Shape of the mapping

Statuses map to `TelegramError`: `429` → `RateLimited` (`parameters.retry_after`
from the body, else the `Retry-After` header through core's parser, else one
second), `401` → `Unauthorized`, `403` → `Forbidden` with Telegram's
description, any other `4xx` (including `400` and `404`) → `Invalid`, and
`5xx`, transport failures and unparseable responses → `Transient`.
`InlineButton::callback` refuses locally what Telegram would refuse on the
wire: `callback_data` outside 1..=64 bytes. Message text is sent with
`link_preview_options.is_disabled` set only when the caller disabled the
preview, so the payload stays minimal.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
