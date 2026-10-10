# cratefield-module-telegram

Telegram in a Cratefield venture: the secret-token webhook, account
linking, and consent buttons with a rule this module does not bend —
**a tap in Telegram can deny anything, approve anything harmless, and
only arm — never finish — anything that moves value.**

The module mounts at `/v1/telegram` and owns four tables
(`telegram_inbox`, `telegram_link_codes`, `telegram_links`,
`telegram_actions`), shipped as one migration.

## Routes

| Route | Who | What |
|---|---|---|
| `POST /webhook` | Telegram | One verified delivery in. Dispatched to the venture's hooks and to the two flows below. |
| `POST /link-codes` | signed-in caller | Issues a one-time code (43 base64url characters) and, when `TELEGRAM_BOT_USERNAME` is set, a ready-to-open deep link. |
| `DELETE /link` | signed-in caller | Unlinks the caller's Telegram account. Idempotent. |
| `POST /actions/{action_id}/confirm` | signed-in owner | The web app's passkey confirmation for a value-moving action. |

## Configuration

Every key is optional at boot — the module fails closed per request
instead — but set-and-blank fails `validate_config`:

| Key | Means |
|---|---|
| `TELEGRAM_WEBHOOK_SECRET` | The `X-Telegram-Bot-Api-Secret-Token` shared secret. Absent: every delivery answers `503`. Set: checked over the raw body before any JSON is read, 1–256 characters of `A-Z a-z 0-9 _ -`. |
| `TELEGRAM_BOT_TOKEN` | Used to build a bot when none was injected with `.bot(..)`. Never logged. |
| `TELEGRAM_BOT_USERNAME` | Present: `/link-codes` answers a `https://t.me/<username>?start=<code>` deep link. Absent: the code is issued and the deep link is omitted. |
| `TELEGRAM_ACTION_SECRET` | The HMAC key the action buttons' tokens are signed with. Absent or blank: prompts cannot be issued and every tap is refused. |
| `TELEGRAM_APPROVAL_URL` | The web app base URL a value-moving action's confirm button points at, with `?action=<action_id>` appended. |

## Linking

The signed-in app calls `/link-codes` and shows the deep link. The code
is stored only as a SHA-256 hash, works for ten minutes, and works once.
`/start <code>` in a **private** chat consumes it (a conditional update,
so a code pasted twice links once), refuses a Telegram user already
linked to a different account — out loud, in the chat — and answers
`linked`. `on_linked` fires with the subject, the Telegram user id and
the chat id.

## Action buttons

`send_action_prompt` sends a subject's linked chat a text with Approve
and Deny buttons. Each button carries its own compact token in
`callback_data` (Telegram caps it at 64 bytes):

```text
a1.<base64url(action_id[16] ‖ decision[1] ‖ exp_unix[4 BE] ‖ tag[12])>
```

The tag is HMAC-SHA256 over the action id, the decision, the expiry and
the **intended Telegram user**, verified in constant time — so a button
forwarded to a group is dead paper, and so is a replayed one: the
decision is a conditional update out of `pending`, judged by rows
affected.

What a tap does:

- **Deny** — the action is `denied`, `on_action` fires, done.
- **Approve, not value-moving** — the action is `approved`,
  `on_action` fires with `passkey_confirmed: false`, done.
- **Approve, value-moving** — the action only moves to
  `awaiting_passkey`, **no hook fires**, and the bot replies with a URL
  button to `TELEGRAM_APPROVAL_URL?action=<action_id>`.

## The passkey rule

`awaiting_passkey` has exactly one exit: `POST
/actions/{action_id}/confirm`, from the web app, by the subject who owns
the action, while the action is unexpired, with a configured
[`StepUp`](src/step_up.rs) willing to swear the request carries a **fresh
passkey ceremony**. No `StepUp` injected — `403`, always. Only then does
the confirmation commit (single-use) and `on_action` fire with
`passkey_confirmed: true`.

There is deliberately **no stock `StepUp` implementation** here. One that
reads the bearer token's `amr` and `iat` claims would be unsound: the
auth service stores the login's methods in the session and copies them
into *every* token it mints, stamping each mint with a fresh `iat` — the
refresh grant included. A token refreshed hours after a passkey login
carries `passkey` and a seconds-old `iat` while proving nothing about
the last minutes, and no access-token claim (there is no `auth_time`)
tells the two apart.

An implementation must therefore prove what the trait's documentation
says: **a passkey assertion completed for this subject within this
request, or within a freshness window it names** — a WebAuthn ceremony
it observed, not a passkey-born session. Being signed in is not being
present; a consent button that moves value requires the second one.

If the hook behind a finished confirmation fails, the route rolls the
action back to `awaiting_passkey` — only while it still carries
`approved` — and answers `5xx`, so the caller's retry can run the
confirmation again; the same is true of a Telegram tap whose `on_action`
hook fails, and of a `/start <code>` whose `on_linked` hook fails (the
code is put back; the redelivery re-runs the linking).

## Composition

```rust,ignore
use std::sync::Arc;
use cratefield_module_telegram::{Telegram, TelegramEvents, StepUp};

let module = Telegram::new(
    TelegramEvents::new()
        .on_message(|message| Box::pin(async move { Ok(()) }))
        .on_linked(|linked| Box::pin(async move {
            println!("{} linked telegram user {}", linked.subject, linked.telegram_user_id);
            Ok(())
        }))
        .on_action(|decision| Box::pin(async move { Ok(()) })),
)
// .bot(Arc::new(HttpTelegramBot::new(http, clock, token)))  // or TELEGRAM_BOT_TOKEN
//     .random(rng)                                            // required: codes and ids
//     .step_up(Arc::new(MyStepUp::new(...)));                 // see `StepUp`: a fresh passkey assertion, per request
```

`.random(..)` should always be there — `self_check` names its absence;
without it no link code or action id can be drawn.
